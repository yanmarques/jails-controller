package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/plumbing/transport/http"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/mod/semver"
)

const DEFAULT_CONFIG_PATH = "/usr/local/etc/jails-controllers.toml"
const DEFAULT_IMAGE_CIDR = "10.100.0.0/16"
const DEFAULT_JAIL_CIDR = "10.200.0.0/16"
const PUBKEY_PATH_IN_JAIL = "/var/run/jails-controller.pubkey"
const CONFIG_DIR = "/usr/local/etc/jails-controller"
const PRIVKEY_PATH = CONFIG_DIR + "/controller.key"
const PUBKEY_PATH = CONFIG_DIR + "/controller.pubkey"
const DEFAULT_CMD_TIMEOUT_SMALL = 60
const DEFAULT_CMD_TIMEOUT_LARGE = 600

var oops *ErrAggregator

type Reconciler struct {
	Repo      *git.Repository
	State     *State
	ImageIpam *IPManager
	JailIpam  *IPManager
	Config    Config
	Zfs       *Zfs
	Notifier  *LazyEventNotifier
	Keypair   Keypair
}

type ErrAggregator struct {
	Errors []error
}

type CmdOptions struct {
	Path     string
	Args     []string
	Timeout  int
	CloseFds bool
}

type Keypair struct {
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

type Config struct {
	// Git repository to fetch
	RepoUrl string
	// If repository requires authentication, use this token
	RepoToken string
	// Path inside repo where bastille stuff lives
	RepoPath string
	// How long to wait between fetching attempts
	PollInterval int
	// Path to the directory where the repository will be cloned
	Directory string

	ZfsRoot       string
	ZfsMountpoint string

	LogDir string

	PrivateKeyPath string
}

type State struct {
	LastTag     string
	Images      map[string]string
	Jails       map[string]*Jail
	Volumes     map[string]*VolumeManifest
	Subscribers map[string]Subscriber
}

type DesiredState struct {
	Jails   map[string]*Manifest
	Images  map[string]*Manifest
	Volumes map[string]*VolumeManifest
}

type JailUserParams map[string]any

type JailAction struct {
	Type string
	// Run action
	Command        string
	CommandTimeout int
	Args           []string
	// Copy action
	Src   string
	Dest  string
	Owner string
	Group string
	Mode  string
}

type JailMount struct {
	Volume string
	Dest   string
	Owner  string
	Group  string
	Mode   string
}

type EventSubscription struct {
	ServerCertPath    string
	ServerPort        int
	ServerFingerprint string
}

func (e EventSubscription) Empty() bool {
	return e.ServerPort == 0 && e.ServerCertPath == ""
}

type Subscriber struct {
	Jail         *Jail
	Subscription EventSubscription
}

type Manifest struct {
	Type              string
	Disabled          bool
	Name              string
	Base              string
	Params            JailUserParams
	EventSubscription EventSubscription
	Actions           []JailAction
	Mounts            []JailMount

	// metadata used internally to copy files
	originalHostPath string
}

type VolumeManifest struct {
	Name    string
	MaxSize string

	// metadata used internally
	quota int
}

type IPSlot struct {
	IP    netip.Addr
	InUse bool
}

type IPManager struct {
	Slots   []IPSlot
	Network netip.Prefix
}

type EventJailSync struct {
	Name   string
	IpAddr string
}

type EventSyncState struct {
	Signature    string
	Verification string
	Jails        []EventJailSync
}

func NewState() *State {
	return &State{
		Jails:       map[string]*Jail{},
		Images:      map[string]string{},
		Volumes:     map[string]*VolumeManifest{},
		Subscribers: map[string]Subscriber{},
		LastTag:     "",
	}
}

func NewErrAggregator() *ErrAggregator {
	return &ErrAggregator{
		Errors: []error{},
	}
}

func (e *ErrAggregator) Err(err error) error {
	if err != nil {
		log.Printf("[ERROR] %v", err)
		e.Errors = append(e.Errors, err)
	}

	return err
}

func (c JailUserParams) JailParams() (JailParams, error) {
	params := JailParams{}
	for key, value := range c {
		switch v := value.(type) {
		case string:
			params[key] = v
		case int:
		case int32:
		case int64:
			params[key] = fmt.Sprintf("%d", v)
		case []string:
			params[key] = strings.Join(v, ",")

		default:
			return nil, fmt.Errorf(`unsupported jail directive %v with that type. 
				only string, integer, and list of strings are supported: %v`, key, v)
		}
	}

	return params, nil
}

func runCmd(options *CmdOptions) ([]byte, []byte, error) {
	if options.Timeout <= 0 {
		options.Timeout = DEFAULT_CMD_TIMEOUT_SMALL
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(options.Timeout)*time.Second)
	defer cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.CommandContext(ctx, options.Path, options.Args...)

	if options.CloseFds {
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
	} else {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}

	// this WaitDelay addresses a bug on Go command execution,
	// maybe on FreeBSD only, when an open file descriptor is not
	// closed by the callee process (identified here by [`command`]),
	// causing Go I/O coroutines to wait forever.
	cmd.WaitDelay = time.Duration(DEFAULT_CMD_TIMEOUT_SMALL) * time.Second

	err := cmd.Run()

	stdoutB := stdout.Bytes()
	stderrB := stderr.Bytes()

	if ctx.Err() == context.DeadlineExceeded {
		return stdoutB, stderrB, fmt.Errorf("command timed out: stdout=%s stderr=%s: %v %v",
			strings.TrimSpace(string(stdoutB)), strings.TrimSpace(string(stderrB)),
			options.Path, options.Args)
	}

	if err != nil {
		return stdoutB, stderrB, fmt.Errorf("%v: stdout=%s stderr=%s: %v %v",
			err, strings.TrimSpace(string(stdoutB)), strings.TrimSpace(string(stderrB)),
			options.Path, options.Args)
	}

	return stdoutB, stderrB, nil
}

func jailListAll() (map[string]bool, error) {
	out, _, err := runCmd(&CmdOptions{
		Path: "/usr/sbin/jls",
		Args: []string{"name"},
	})
	if err != nil {
		return nil, err
	}

	stdout := strings.TrimSpace(string(out))
	jails := map[string]bool{}

	for line := range strings.SplitSeq(stdout, "\n") {
		if len(line) > 0 {
			jails[line] = true
		}
	}

	return jails, nil
}

func copyFile(src, dest string, perm os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	err = os.Chmod(dest, perm)
	if err != nil {
		return err
	}

	_, err = io.Copy(destFile, srcFile)
	return err
}

func NewIPManager(prefix string) (*IPManager, error) {
	network, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil, err
	}

	return &IPManager{
		Slots:   []IPSlot{},
		Network: network,
	}, nil
}

func (i *IPManager) AllocateIP() (*netip.Addr, error) {
	for idx, slot := range i.Slots {
		if !slot.InUse {
			i.Slots[idx].InUse = true
			return &slot.IP, nil
		}
	}

	var addr netip.Addr
	if len(i.Slots) == 0 {
		addr = i.Network.Addr().Next()
	} else {
		lastInSlot := i.Slots[len(i.Slots)-1]
		addr = lastInSlot.IP.Next()
	}

	if !i.Network.Contains(addr) {
		return nil, fmt.Errorf("ipmanager: no more IPs available")
	}

	i.Slots = append(i.Slots, IPSlot{
		IP:    addr,
		InUse: true,
	})

	return &addr, nil
}

func (i *IPManager) Free(ipAddr netip.Addr) error {
	for idx, slot := range i.Slots {
		if slot.IP == ipAddr {
			i.Slots[idx].InUse = false
			return nil
		}
	}

	return fmt.Errorf("unknown IP address: %v", ipAddr)
}

func (i *IPManager) Import(ipAddr netip.Addr) error {
	if !i.Network.Contains(ipAddr) {
		return fmt.Errorf("IP address %v is outside the network: %v", ipAddr.String(), i.Network.String())
	}

	for idx, slot := range i.Slots {
		if slot.IP == ipAddr {
			i.Slots[idx].InUse = true
			return nil
		}
	}

	i.Slots = append(i.Slots, IPSlot{
		IP:    ipAddr,
		InUse: true,
	})

	return nil
}

func volumeSize(size string) (int, error) {
	if size == "none" {
		return -1, nil
	}

	idx := len(size)
	if strings.HasSuffix(size, "G") {
		idx--
	}

	log.Printf("volume size: %s", size[:idx])
	n, err := strconv.Atoi(size[:idx])
	if err != nil {
		return 0, err
	}

	if n < 1 {
		return 0, fmt.Errorf("volume size can not be lower than 1 GB")
	}

	return n, nil
}

func safePathJoin(base string, untrusted ...string) string {
	base = filepath.Clean(base)
	u := []string{base}
	for _, p := range untrusted {
		u = append(u, p)
	}
	path := filepath.Join(u...)
	if !strings.HasPrefix(path, base) {
		return ""
	}

	return path
}

func PrepareJailBeforeStart(jail *Jail, hostPath string, actions []JailAction, mounts []JailMount, config Config) error {
	// TODO: check for volume existence prior to this
	for _, mnt := range mounts {
		src := safePathJoin(config.ZfsMountpoint, "volumes", mnt.Volume)
		if len(src) == 0 {
			return fmt.Errorf("invalid mount src path: can not mount outside jail path: %s", mnt.Volume)
		}

		err := jail.Mount(src, mnt.Dest, mnt.Owner, mnt.Group, mnt.Mode)
		if err != nil {
			return err
		}
	}

	for _, action := range actions {
		switch action.Type {
		case "exec":
			continue
		case "copy":
			path := safePathJoin(hostPath, action.Src)
			if len(path) == 0 {
				return fmt.Errorf("invalid copy src path: can not copy outside manifest path: %s", action.Src)
			}

			err := jail.Copy(path, action.Dest, action.Owner, action.Group, action.Mode)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown action type: %v", action.Type)
		}
	}

	return nil
}

func PrepareJailAfterStart(jail *Jail, hostPath string, actions []JailAction, mounts []JailMount, config Config) error {
	for _, action := range actions {
		switch action.Type {
		case "exec":
			timeout := action.CommandTimeout
			if timeout <= 0 {
				timeout = DEFAULT_CMD_TIMEOUT_SMALL
			}

			err := jail.Exec(timeout, action.Command, action.Args...)
			if err != nil {
				return err
			}
		case "copy":
			continue
		default:
			return fmt.Errorf("unknown action type: %v", action.Type)
		}
	}

	return nil
}

func NewDesiredState() *DesiredState {
	return &DesiredState{
		Jails:   map[string]*Manifest{},
		Images:  map[string]*Manifest{},
		Volumes: map[string]*VolumeManifest{},
	}
}

func (d *DesiredState) addJail(path string, jail *Manifest) error {
	if len(jail.Name) == 0 {
		oops.Err(fmt.Errorf(
			"manifest with empty jail name, ignoring: %v",
			path))
		return nil
	}

	if jail.EventSubscription.ServerPort <= 0 && !jail.EventSubscription.Empty() {
		return fmt.Errorf("invalid event port %d in jail manifest %s", jail.EventSubscription.ServerPort, jail.Name)
	}

	if !jail.EventSubscription.Empty() {
		serverCertPath := safePathJoin(filepath.Dir(path), jail.EventSubscription.ServerCertPath)
		if serverCertPath == "" {
			return fmt.Errorf("invalid server cert path %s: can not copy outside manifest jail: %s",
				jail.EventSubscription.ServerCertPath, jail.Name)
		}

		content, err := os.ReadFile(serverCertPath)
		if err != nil {
			return err
		}

		pemDecoded, _ := pem.Decode(content)
		fingerprint, err := sumFingerprint(pemDecoded.Bytes)
		if err != nil {
			return err
		}

		jail.EventSubscription.ServerFingerprint = hex.EncodeToString(fingerprint[:])
	}

	_, ok := d.Jails[jail.Name]
	if ok {
		return fmt.Errorf("duplicate jail name definitions: %s, aborting", jail.Name)
	}

	jail.originalHostPath = filepath.Dir(path)
	d.Jails[jail.Name] = jail

	return nil
}

func (d *DesiredState) addImage(path string, image *Manifest) error {
	if len(image.Name) == 0 {
		return fmt.Errorf(
			"manifest with empty image name: %v",
			path)
	}

	_, ok := d.Images[image.Name]
	if ok {
		return fmt.Errorf("duplicate image name definitions: %s", image.Name)
	}

	if len(image.Mounts) > 0 {
		log.Printf("[WARN] images don't support mounts, but image %s have mounts, ignoring", image.Name)
		image.Mounts = []JailMount{}
	}

	image.originalHostPath = path
	d.Images[image.Name] = image

	return nil
}

func (d *DesiredState) addVolume(path string, vol *VolumeManifest) error {
	if len(vol.Name) == 0 {
		return fmt.Errorf(
			"volume with empty name: %v",
			path)
	}

	if len(vol.MaxSize) == 0 {
		return fmt.Errorf(
			"volume with empty maxSize: %v",
			vol.Name)
	}

	_, ok := d.Volumes[vol.Name]
	if ok {
		return fmt.Errorf("duplicate volume name definitions: %s", vol.Name)
	}

	quota, err := volumeSize(vol.MaxSize)
	if err != nil {
		return fmt.Errorf("invalid volume maxSize %s at %s: %v", vol.MaxSize, path, err)
	}

	vol.quota = quota
	d.Volumes[vol.Name] = vol

	return nil
}

func (r *Reconciler) decodeFile(path string, content []byte, desiredState *DesiredState) error {
	decoder := toml.NewDecoder(bytes.NewBuffer(content))
	decoder.DisallowUnknownFields()

	var manifest Manifest
	err := decoder.Decode(&manifest)
	if err == nil {
		if manifest.Disabled {
			log.Printf("manifest is marked disabled %s", path)
			return nil
		}

		switch manifest.Type {
		case "image":
			return desiredState.addImage(path, &manifest)
		case "jail":
			return desiredState.addJail(path, &manifest)
		default:
			return fmt.Errorf("invalid manifest at %s of type %s, only jail or image is supported", path, manifest.Type)
		}
	}

	decoder = toml.NewDecoder(bytes.NewBuffer(content))
	decoder.DisallowUnknownFields()

	var volume VolumeManifest
	volumeErr := decoder.Decode(&volume)
	if volumeErr != nil {
		var strictErr *toml.StrictMissingError

		if errors.As(err, &strictErr) {
			return fmt.Errorf("file %s: %s", path, strictErr.String())
		}

		return fmt.Errorf("file %s does not seem to be a valid manifest for jail, image or volume, check for typos: %v", path, err)
	}

	return desiredState.addVolume(path, &volume)
}

func (r *Reconciler) Reconcile() {
	log.Println("git fetch...")

	fakeGit := os.Getenv("FAKE_GIT") == "1"

	err := r.Repo.Fetch(&git.FetchOptions{
		Auth: &http.BasicAuth{
			Username: "token",
			Password: r.Config.RepoToken,
		},
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		oops.Err(err)
	}

	allTags := []object.Tag{}
	log.Println("git tags...")
	iter, err := r.Repo.TagObjects()
	if err != nil {
		oops.Err(err)
	} else {
		err = iter.ForEach(func(tag *object.Tag) error {
			allTags = append(allTags, *tag)
			return nil
		})
		if err != nil {
			oops.Err(err)
		}
	}

	if len(allTags) == 0 && !fakeGit {
		log.Println("no tags to reconcile yet")
		return
	}

	sort.Slice(allTags, func(i, j int) bool {
		return semver.Compare(allTags[i].Name, allTags[j].Name) == -1
	})

	var currentGitTag object.Tag
	if fakeGit {
		currentGitTag = object.Tag{
			Hash: plumbing.NewHash("fake"),
		}
	} else {
		currentGitTag = allTags[len(allTags)-1]
	}

	if r.State.LastTag == currentGitTag.Hash.String() && !fakeGit {
		log.Println("up to date")
		return
	}

	if !fakeGit {
		log.Printf("git checkout: %v\n", currentGitTag.Name)
		w, err := r.Repo.Worktree()
		if err != nil {
			oops.Err(err)
			return
		}

		err = w.Checkout(&git.CheckoutOptions{
			Hash: currentGitTag.Hash,
		})
		if err != nil {
			oops.Err(err)
			return
		}
	}

	desiredState := NewDesiredState()

	// for volume claims sanity check
	volumeClaims := map[string][]string{}

	repoPath := filepath.Join(r.Config.Directory, r.Config.RepoPath)

	repoEntries, err := os.ReadDir(repoPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("repository doesn't have images")
		} else {
			oops.Err(err)
		}
	} else {
		log.Printf("reading manifests %s %d", repoPath, len(repoEntries))

		for _, entry := range repoEntries {
			if entry.IsDir() {
				dir := filepath.Join(repoPath, entry.Name())
				log.Printf("reading subdirectory %s", dir)
				innerEntries, err := os.ReadDir(dir)
				if err != nil {
					if !os.IsNotExist(err) {
						oops.Err(err)
					}

					continue
				}

				for _, innerEntry := range innerEntries {
					if !innerEntry.Type().IsRegular() ||
						innerEntry.IsDir() ||
						filepath.Ext(innerEntry.Name()) != ".toml" {
						continue
					}

					path := filepath.Join(dir, innerEntry.Name())
					log.Printf("reading file: %s", path)
					content, err := os.ReadFile(path)
					if err != nil {
						if !os.IsNotExist(err) {
							oops.Err(err)
						}
					} else {
						err := oops.Err(r.decodeFile(path, content, desiredState))
						if err != nil {
							return
						}
					}
				}
			} else {
				if !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".toml" {
					continue
				}

				path := filepath.Join(repoPath, entry.Name())
				content, err := os.ReadFile(path)
				if err != nil {
					if !os.IsNotExist(err) {
						oops.Err(err)
					}
				} else {
					err := oops.Err(r.decodeFile(path, content, desiredState))
					if err != nil {
						return
					}
				}
			}

		}
	}

	// order of creation: images, volumes, jails
	// order of deletion: jails, volumes, images

	volumesToDestroy := []*VolumeManifest{}

	for _, vol := range r.State.Volumes {
		_, alive := desiredState.Volumes[vol.Name]
		if !alive {
			volumesToDestroy = append(volumesToDestroy, vol)
		}
	}

	jailstoCreate := []*Manifest{}
	jailstoDestroy := []*Jail{}

	for _, manifest := range desiredState.Jails {
		_, exists := r.State.Jails[manifest.Name]
		if exists {
			continue
		}

		jailstoCreate = append(jailstoCreate, manifest)
		for _, mnt := range manifest.Mounts {
			volumeClaims[mnt.Volume] = append(volumeClaims[mnt.Volume], manifest.Name)
		}
	}

	for _, jail := range r.State.Jails {
		_, alive := desiredState.Jails[jail.Name]
		if alive {
			for _, volume := range jail.Mounts {
				volumeClaims[volume] = append(volumeClaims[volume], jail.Name)
			}
			continue
		}

		jailstoDestroy = append(jailstoDestroy, jail)
	}

	for volume, claims := range volumeClaims {
		if len(claims) > 1 {
			oops.Err(fmt.Errorf("multiple claims to volume %s: %v", volume, claims))
			return
		}
	}

	log.Printf("jails to create %v, existing jails %v", len(jailstoCreate), len(r.State.Jails))

	// destroy jails
	for _, jail := range jailstoDestroy {
		oops.Err(r.JailIpam.Free(jail.IpAddr))

		// TODO: track jails already shutdown, otherwise it will be stuck on this call
		err = oops.Err(jail.Shutdown())
		if err != nil {
			continue
		}

		err = oops.Err(jail.Destroy())
		if err == nil {
			delete(r.State.Jails, jail.Name)
			delete(r.State.Subscribers, jail.Name)
		}
	}

	// destroy volumes
	for _, vol := range volumesToDestroy {
		claims, ok := volumeClaims[vol.Name]
		if ok {
			oops.Err(fmt.Errorf("can not destroy volume %s because is claimed by %v", vol.Name, claims))
			continue
		}

		log.Printf("destroying volume %s", vol.Name)
		err = oops.Err(r.Zfs.Destroy("volumes/"+vol.Name, true))
		if err == nil {
			delete(r.State.Volumes, vol.Name)
		}
	}

	// destroy images
	for _, image := range r.State.Images {
		_, alive := desiredState.Images[image]
		if alive {
			continue
		}

		err = oops.Err(r.Zfs.Destroy("images/"+image+"@base", true))
		if err != nil {
			continue
		}

		err = oops.Err(r.Zfs.Destroy("images/"+image, true))
		if err != nil {
			continue
		}

		delete(r.State.Images, image)
	}

	// create images
	for name, manifest := range desiredState.Images {
		_, ok := r.State.Images[name]
		if ok {
			continue
		}

		ipAddr, err := r.ImageIpam.AllocateIP()
		if err != nil {
			oops.Err(err)
			break
		}

		defer r.ImageIpam.Free(*ipAddr)

		jail, err := NewJail(manifest, r.Zfs, r.Config, "images", *ipAddr)
		if err != nil {
			oops.Err(err)
			break
		}

		err = oops.Err(PrepareJailBeforeStart(jail, manifest.originalHostPath, manifest.Actions, manifest.Mounts, r.Config))
		if err != nil {
			break
		}

		err = oops.Err(jail.Start())
		if err != nil {
			break
		}

		err = oops.Err(PrepareJailAfterStart(jail, manifest.originalHostPath, manifest.Actions, manifest.Mounts, r.Config))

		oops.Err(jail.Shutdown())
		if err != nil {
			oops.Err(jail.Destroy())
		} else {
			r.State.Images[name] = name
		}
	}

	// create volumes
	for volName, vol := range desiredState.Volumes {
		_, exists := r.State.Volumes[volName]
		if exists {
			if r.State.Volumes[volName].quota == -1 {
				oops.Err(fmt.Errorf(
					`volume %s have unlimeted size, this shouldn't happen, it was likely created from the outside.
						not a good idea to change it's quota size`,
					volName))
				break
			}

			if vol.quota < r.State.Volumes[volName].quota {
				oops.Err(fmt.Errorf(
					"volume %s max size %v can not be lower than current size %v",
					volName, vol.quota, r.State.Volumes[volName].quota))
				break
			}

			if vol.quota > r.State.Volumes[volName].quota {
				err = r.Zfs.Set(&ZfsCreateOptions{
					Filesystem: "volumes/" + volName,
					QuotaSize:  vol.quota,
				})
			}
		} else {
			err = r.Zfs.Create(&ZfsCreateOptions{
				Filesystem: "volumes/" + volName,
				QuotaSize:  vol.quota,
			})
			if err == nil {
				r.State.Volumes[vol.Name] = vol
			}
		}

		if err != nil {
			oops.Err(err)
			return
		}
	}

	// create jails
	for _, manifest := range jailstoCreate {
		log.Printf("jails will be created %v", manifest.Name)

		ipAddr, err := r.JailIpam.AllocateIP()
		if err != nil {
			oops.Err(err)
			break
		}

		jail, err := NewJail(manifest, r.Zfs, r.Config, "containers", *ipAddr)
		if err != nil {
			oops.Err(jail.Shutdown())
			oops.Err(jail.Destroy())
			oops.Err(r.JailIpam.Free(*ipAddr))
			oops.Err(err)
			break
		}

		err = oops.Err(PrepareJailBeforeStart(jail, manifest.originalHostPath, manifest.Actions, manifest.Mounts, r.Config))
		if err != nil {
			oops.Err(jail.Shutdown())
			oops.Err(jail.Destroy())
			oops.Err(r.JailIpam.Free(*ipAddr))
			oops.Err(err)
			break
		}

		if !manifest.EventSubscription.Empty() {
			err = jail.Copy(PUBKEY_PATH, PUBKEY_PATH_IN_JAIL, "root", "wheel", "644")
			if err != nil {
				oops.Err(jail.Shutdown())
				oops.Err(jail.Destroy())
				oops.Err(r.JailIpam.Free(*ipAddr))
				oops.Err(err)
				break
			}
		}

		err = oops.Err(jail.Start())
		if err != nil {
			oops.Err(jail.Shutdown())
			oops.Err(jail.Destroy())
			oops.Err(r.JailIpam.Free(*ipAddr))
			oops.Err(err)
			break
		}

		err = oops.Err(PrepareJailAfterStart(jail, manifest.originalHostPath, manifest.Actions, manifest.Mounts, r.Config))
		if err != nil {
			oops.Err(jail.Shutdown())
			oops.Err(jail.Destroy())
			oops.Err(r.JailIpam.Free(*ipAddr))
			oops.Err(err)
		} else {
			// add jail to internal state
			r.State.Jails[jail.Name] = jail

			if !manifest.EventSubscription.Empty() {
				sub := Subscriber{
					Jail:         jail,
					Subscription: manifest.EventSubscription,
				}
				r.State.Subscribers[jail.Name] = sub
			}
		}
	}

	if err != nil {
		if !os.IsNotExist(err) {
			oops.Err(err)
		}
	}

	if len(jailstoCreate)+len(jailstoDestroy) > 0 {
		msg := make([]byte, 32)
		rand.Read(msg)

		signature := ed25519.Sign(r.Keypair.Priv, msg)

		jailsSync := EventSyncState{
			Signature:    hex.EncodeToString(signature),
			Verification: hex.EncodeToString(msg),
			Jails:        []EventJailSync{},
		}

		for _, jail := range r.State.Jails {
			jailsSync.Jails = append(jailsSync.Jails, EventJailSync{
				Name:   jail.Name,
				IpAddr: jail.IpAddr.String(),
			})
		}

		for _, subscriber := range r.State.Subscribers {
			fingerprint, err := hex.DecodeString(subscriber.Subscription.ServerFingerprint)
			if err != nil {
				oops.Err(err)
				continue
			}

			event := LazyEvent{
				Server:            subscriber.Jail.Name,
				ServerFingerprint: fingerprint,
				Address: ServerAddr{
					IpAddr: subscriber.Jail.IpAddr,
					Port:   subscriber.Subscription.ServerPort,
				},
				Payload: jailsSync,
			}

			oops.Err(r.Notifier.Notify(&event))
		}
	} else {
		confirmedOnes := map[string]ServerAddr{}

		for _, sub := range r.State.Subscribers {
			confirmedOnes[sub.Jail.Name] = ServerAddr{
				IpAddr: sub.Jail.IpAddr,
				Port:   sub.Subscription.ServerPort,
			}
		}

		r.Notifier.RetryFailures(confirmedOnes)
	}

	r.State.LastTag = currentGitTag.Hash.String()
}

func ParseEventSync(body []byte, pubKey ed25519.PublicKey) (*EventSyncState, error) {
	var event EventSyncState

	err := json.Unmarshal(body, &event)
	if err != nil {
		return nil, fmt.Errorf("parsing json body: %v", err)
	}

	msg, err := hex.DecodeString(event.Verification)
	if err != nil {
		return nil, fmt.Errorf("parsing verification message: %v", err)
	}

	sig, err := hex.DecodeString(event.Signature)
	if err != nil {
		return nil, fmt.Errorf("parsing signature: %v", err)
	}

	if !ed25519.Verify(pubKey, msg, sig) {
		return nil, fmt.Errorf("wrong signature: %s", sig)
	}

	return &event, nil
}

func NewReconcilerOrFail(configPath string) *Reconciler {
	oops = NewErrAggregator()

	privkeyContent, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatal(err)
	}

	var config Config
	err = toml.Unmarshal(privkeyContent, &config)
	if err != nil {
		log.Fatal(err)
	}

	absPath, err := filepath.Abs(config.Directory)
	if err != nil {
		log.Fatal(err)
	}

	config.Directory = absPath

	err = os.Mkdir(CONFIG_DIR, os.FileMode(0700))
	if err != nil && !os.IsExist(err) {
		log.Fatal(err)
	}

	var privKey ed25519.PrivateKey
	var pubKey ed25519.PublicKey

	privkeyContent, privkeyErr := os.ReadFile(PRIVKEY_PATH)
	pubkeyContent, pubkeyErr := os.ReadFile(PUBKEY_PATH)
	if privkeyErr != nil {
		if os.IsNotExist(privkeyErr) {
			pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				log.Fatal(err)
			}

			err = os.WriteFile(PRIVKEY_PATH, privKey, os.FileMode(0700))
			if err != nil {
				log.Fatal(err)
			}

			err = os.WriteFile(PUBKEY_PATH, pubKey, os.FileMode(0755))
			if err != nil {
				os.Remove(PRIVKEY_PATH)
				log.Fatal(err)
			}

		} else {
			log.Fatal(privkeyErr)
		}
	} else {
		if pubkeyErr != nil {
			log.Fatal(pubkeyErr)
		}

		if len(privkeyContent) != ed25519.PrivateKeySize {
			log.Fatal(fmt.Errorf("invalid ed25519 private key at %s", PRIVKEY_PATH))
		}

		if len(pubkeyContent) != ed25519.PublicKeySize {
			log.Fatal(fmt.Errorf("invalid ed25519 public key %s", PUBKEY_PATH))
		}

		privKey = privkeyContent
		pubKey = pubkeyContent
	}

	imageIpam, err := NewIPManager(DEFAULT_IMAGE_CIDR)
	if err != nil {
		log.Fatal(err)
	}

	jailIpam, err := NewIPManager(DEFAULT_JAIL_CIDR)
	if err != nil {
		log.Fatal(err)
	}

	repo, err := git.PlainClone(config.Directory, &git.CloneOptions{
		URL: config.RepoUrl,
		Auth: &http.BasicAuth{
			Username: "token",
			Password: config.RepoToken,
		},
	})

	if err != nil {
		if errors.Is(err, git.ErrTargetDirNotEmpty) {
			repo, err = git.PlainOpen(config.Directory)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			log.Fatal(err)
		}
	}

	zfs := NewZfs(config.ZfsRoot)

	err = zfs.Create(&ZfsCreateOptions{
		Filesystem: "/",
		Mountpoint: config.ZfsMountpoint,
		ExistOk:    true,
	})
	if err != nil {
		log.Fatal(err)
	}
	err = zfs.Create(&ZfsCreateOptions{
		Filesystem: "media",
		ExistOk:    true,
	})
	if err != nil {
		log.Fatal(err)
	}
	err = zfs.Create(&ZfsCreateOptions{
		Filesystem: "releases",
		ExistOk:    true,
	})
	if err != nil {
		log.Fatal(err)
	}
	err = zfs.Create(&ZfsCreateOptions{
		Filesystem: "images",
		ExistOk:    true,
	})
	if err != nil {
		log.Fatal(err)
	}
	err = zfs.Create(&ZfsCreateOptions{
		Filesystem: "containers",
		ExistOk:    true,
	})
	if err != nil {
		log.Fatal(err)
	}

	err = zfs.Create(&ZfsCreateOptions{
		Filesystem: "volumes",
		ExistOk:    true,
	})
	if err != nil {
		log.Fatal(err)
	}

	basetxz := filepath.Join(config.ZfsMountpoint, "media/15.0-RELEASE-base.txz")
	_, err = os.Stat(basetxz)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Fatal(err)
		}

		_, _, err = runCmd(&CmdOptions{
			Path:    "/usr/bin/fetch",
			Args:    []string{"https://download.freebsd.org/ftp/releases/amd64/amd64/15.0-RELEASE/base.txz", "-o", basetxz},
			Timeout: DEFAULT_CMD_TIMEOUT_LARGE,
		})
		if err != nil {
			log.Fatal(err)
		}
	}

	releasePath := filepath.Join(config.ZfsMountpoint, "releases/15.0-RELEASE")
	_, err = os.Stat(releasePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Fatal(err)
		}

		err = zfs.Create(&ZfsCreateOptions{
			Filesystem: "releases/15.0-RELEASE",
			ExistOk:    true,
		})
		if err != nil {
			log.Fatal(err)
		}

		_, _, err = runCmd(&CmdOptions{
			Path:    "/usr/bin/tar",
			Args:    []string{"-xf", basetxz, "-C", releasePath, "--unlink"},
			Timeout: DEFAULT_CMD_TIMEOUT_LARGE,
		})
		if err != nil {
			log.Fatal(err)
		}

		err := copyFile("/etc/resolv.conf", filepath.Join(releasePath, "etc/resolv.conf"), os.FileMode(0644))
		if err != nil {
			log.Fatal(err)
		}

		_, _, err = runCmd(&CmdOptions{
			Path:    "/usr/sbin/freebsd-update",
			Args:    []string{"-b", releasePath, "fetch", "install"},
			Timeout: DEFAULT_CMD_TIMEOUT_LARGE,
		})
		if err != nil {
			log.Fatal(err)
		}

		zfs.CreateSnapshot("releases/15.0-RELEASE", "base", true)
	}

	state := NewState()
	existingJails, err := jailListAll()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("existing jails %v", len(existingJails))

	hadErrors := false
	for name := range existingJails {
		result, err := JailImport(name, zfs, config.ZfsMountpoint, "containers")
		if err != nil {
			oops.Err(err)
			hadErrors = true
		} else {
			if result != nil {
				err = oops.Err(jailIpam.Import(result.Jail.IpAddr))
				if err == nil {
					log.Printf("imported jails %v", name)
					state.Jails[name] = result.Jail

					if !result.Events.Empty() {
						state.Subscribers[name] = Subscriber{
							Jail:         result.Jail,
							Subscription: *result.Events,
						}
					}
				} else {
					hadErrors = true
				}
			} else {
				log.Printf("jail is not managed by us %v", name)
			}
		}
	}

	log.Printf("imported jails %v", len(state.Jails))

	if hadErrors {
		log.Fatalf("found errors import existing jails")
	}

	state.Volumes, err = zfs.ListFilesystems("volumes")
	if err != nil {
		log.Fatal(err)
	}

	hostImages, err := zfs.ListFilesystems("images")
	if err != nil {
		log.Fatal(err)
	}

	for _, vol := range hostImages {
		state.Images[vol.Name] = vol.Name
	}

	reconciler := &Reconciler{
		State:     state,
		ImageIpam: imageIpam,
		JailIpam:  jailIpam,
		Config:    config,
		Repo:      repo,
		Zfs:       zfs,
		Notifier:  NewEventNotifier(5, 15*time.Second),
		Keypair: Keypair{
			Priv: privKey,
			Pub:  pubKey,
		},
	}

	return reconciler
}
