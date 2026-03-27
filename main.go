package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/plumbing/transport/http"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/mod/semver"
)

const DEFAULT_PREFIX string = "/usr/local/jails"
const DEFAULT_CONFIG_PATH = "/usr/local/etc/bastille-poller.json"
const DEFAULT_IMAGE_CONF = "image.conf"
const DEFAULT_JAIL_CONF = "jail.conf"
const DEFAULT_VOLUME_CONF = "volume.conf"
const DEFAULT_IMAGE_CIDR = "10.100.0.0/16"
const DEFAULT_JAIL_CIDR = "10.200.0.0/16"

var oops *ErrAggregator

type Reconciler struct {
	Repo      *git.Repository
	State     *State
	ImageIpam *IPManager
	JailIpam  *IPManager
	Config    Config
}

type ErrAggregator struct {
	Errors []error
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
}

type State struct {
	LastTag string
	Images  map[string]string
	Jails   map[string]*Jail
	Volumes map[string]*VolumeManifest
}

type DesiredState struct {
	Jails   map[string]*Manifest
	Images  map[string]*Manifest
	Volumes map[string]*VolumeManifest
}

type JailUserParams map[string]any
type JailParams map[string]string

type JailAction struct {
	Type string
	// Run action
	Command string
	Args    []string
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

type Manifest struct {
	Type     string
	Disabled bool
	Name     string
	Base     string
	Params   JailUserParams
	Actions  []JailAction
	Mounts   []JailMount

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

type ZfsCreateOptions struct {
	Filesystem string
	Mountpoint string
	QuotaSize  int
}

func NewState() *State {
	return &State{
		Jails:   map[string]*Jail{},
		Images:  map[string]string{},
		Volumes: map[string]*VolumeManifest{},
		LastTag: "",
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

func runCmd(command string, args ...string) error {
	out, err := exec.Command(command, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %v: %v %v", err, strings.TrimSpace(string(out)), command, args)
	}

	return nil
}

func runCmdOutput(command string, args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	cmd := exec.Command(command, args...)
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%v: stdout=%v stderr=%v: %v %v",
			err, strings.TrimSpace(string(out)), strings.TrimSpace(stderr.String()), cmd.Path, cmd.Args)
	}

	return out, nil
}
func jailListAll() (map[string]bool, error) {
	out, err := runCmdOutput("/usr/sbin/jls", "name")
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

func zfsClone(snapshot string, dest string) error {
	out, err := exec.Command("/sbin/zfs", "list", "-t", "snapshot", snapshot).CombinedOutput()
	if err != nil {
		return fmt.Errorf("no such snapshot: %v: %v", snapshot, err)
	}

	out, err = exec.Command("/sbin/zfs", "clone", snapshot, dest).CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 1 && strings.Contains(string(out), "dataset already exists") {
				return &os.PathError{
					Op:   "clone",
					Path: dest,
					Err:  os.ErrExist,
				}
			}
		}

		return fmt.Errorf("%v: %v", err, string(out))
	}

	return nil
}

func zfsCreateSnapshot(filesystem string, name string) error {
	out, err := exec.Command("/sbin/zfs", "snapshot", fmt.Sprintf("%s@%s", filesystem, name)).CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError

		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 1 && strings.Contains(string(out), "dataset already exists") {
				return nil
			}
		}

		return fmt.Errorf("%v: %v", err, string(out))
	}

	return nil
}

func zfsDestroy(filesystem string) error {
	return runCmd("/sbin/zfs", "destroy", filesystem)
}

func zfsListFilesystems(root string) (map[string]*VolumeManifest, error) {
	out, err := runCmdOutput("/sbin/zfs", "list", "-o", "name,quota", "-t", "filesystem", "-H", "-d", "1", "-r", root)
	if err != nil {
		return nil, err
	}

	volumes := map[string]*VolumeManifest{}
	rootSlash := fmt.Sprintf("%s/", strings.TrimSuffix(root, "/"))

	stdout := strings.TrimSpace(string(out))
	for line := range strings.SplitSeq(stdout, "\n") {
		elements := strings.SplitN(line, "\t", 2)
		if elements[0] != root {
			volName := strings.TrimPrefix(elements[0], rootSlash)
			maxSize := elements[1]

			quota, err := volumeSize(maxSize)
			if err != nil {
				return nil, err
			}

			volumes[volName] = &VolumeManifest{
				Name:    volName,
				MaxSize: maxSize,
				quota:   quota,
			}
		}
	}

	return volumes, nil
}

func zfsSet(options *ZfsCreateOptions) error {
	args := []string{
		"set",
	}
	if options.QuotaSize > 0 {
		args = append(args, fmt.Sprintf("quota=%dG", options.QuotaSize))
	}

	args = append(args, options.Filesystem)

	return runCmd("/sbin/zfs", args...)
}

func zfsCreate(options *ZfsCreateOptions) error {
	args := []string{
		"create",
	}
	if len(options.Mountpoint) > 0 {
		args = append(args, "-o")
		args = append(args, fmt.Sprintf("mountpoint=%s", options.Mountpoint))
	}

	if options.QuotaSize > 0 {
		args = append(args, "-o")
		args = append(args, fmt.Sprintf("quota=%dG", options.QuotaSize))
	}

	args = append(args, options.Filesystem)

	out, err := exec.Command("/sbin/zfs", args...).CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError

		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 1 && strings.Contains(string(out), "dataset already exists") {
				return nil
			}
		}

		return fmt.Errorf("%v: %v", err, string(out))
	}

	return nil
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

func PrepareJail(jail *Jail, hostPath string, actions []JailAction, mounts []JailMount, config Config) error {
	for _, action := range actions {
		switch action.Type {
		case "exec":
			err := jail.Exec(action.Command, action.Args...)
			if err != nil {
				return err
			}
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

	// TODO: check for volume existance prior to this
	for _, mnt := range mounts {
		src := safePathJoin(DEFAULT_PREFIX, "volumes", mnt.Volume)
		if len(src) == 0 {
			return fmt.Errorf("invalid mount src path: can not mount outside jail path: %s", mnt.Volume)
		}

		err := jail.Mount(src, mnt.Dest, mnt.Owner, mnt.Group, mnt.Mode)
		if err != nil {
			return err
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
		return fmt.Errorf("file %s does not seem to be a valid manifest for jail, image or volume: %v: %v", path, err, volumeErr)
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

		jail, err := JailCreate("images", manifest, *ipAddr)
		if err != nil {
			oops.Err(err)
			break
		}

		oops.Err(PrepareJail(jail, manifest.originalHostPath, manifest.Actions, manifest.Mounts, r.Config))

		oops.Err(jail.Shutdown())

		r.State.Images[name] = name
	}

	// destroy images
	for _, image := range r.State.Images {
		_, alive := desiredState.Images[image]
		if alive {
			continue
		}

		oops.Err(zfsDestroy(fmt.Sprintf("zroot/jails/images/%s@base", image)))
		oops.Err(zfsDestroy(fmt.Sprintf("zroot/jails/images/%s", image)))

		delete(r.State.Images, image)
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
				err = zfsSet(&ZfsCreateOptions{
					Filesystem: fmt.Sprintf("zroot/jails/volumes/%s", volName),
					QuotaSize:  vol.quota,
				})
			}
		} else {
			err = zfsCreate(&ZfsCreateOptions{
				Filesystem: fmt.Sprintf("zroot/jails/volumes/%s", volName),
				QuotaSize:  vol.quota,
			})
		}

		if err != nil {
			oops.Err(err)
			return
		}
	}

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

	// destroy
	for _, jail := range jailstoDestroy {
		oops.Err(jail.Shutdown())
		oops.Err(jail.Destroy())
		oops.Err(r.JailIpam.Free(jail.IpAddr))

		delete(r.State.Jails, jail.Name)
	}

	// create
	for _, manifest := range jailstoCreate {
		ipAddr, err := r.JailIpam.AllocateIP()
		if err != nil {
			oops.Err(err)
			break
		}

		jail, err := JailCreate("containers", manifest, *ipAddr)
		if err != nil {
			r.JailIpam.Free(*ipAddr)
			oops.Err(err)
			break
		}

		err = PrepareJail(jail, manifest.originalHostPath, manifest.Actions, manifest.Mounts, r.Config)
		if err != nil {
			oops.Err(err)

			oops.Err(jail.Shutdown())
			oops.Err(jail.Destroy())
			oops.Err(r.JailIpam.Free(*ipAddr))
		} else {
			// add jail to internal state
			r.State.Jails[jail.Name] = jail
		}
	}

	if err != nil {
		if !os.IsNotExist(err) {
			oops.Err(err)
		}
	}

	for _, vol := range volumesToDestroy {
		claims, ok := volumeClaims[vol.Name]
		if ok {
			oops.Err(fmt.Errorf("can not destroy volume %s because is claimed by %v", vol.Name, claims))
			continue
		}

		log.Printf("destroying volume %s", vol.Name)
		oops.Err(zfsDestroy(fmt.Sprintf("zroot/jails/volumes/%s", vol.Name)))

		delete(r.State.Volumes, vol.Name)
	}

	r.State.LastTag = currentGitTag.Hash.String()
}

func main() {
	configPath := flag.String("config", DEFAULT_CONFIG_PATH, "Path to configuration")

	flag.Parse()

	oops = NewErrAggregator()

	log.SetFlags(log.LstdFlags | log.Ldate | log.Lshortfile)
	log.Printf("config path: %s\n", *configPath)

	content, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	var config Config
	err = json.Unmarshal(content, &config)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("config.repoUrl: %v\n", config.RepoUrl)
	log.Printf("config.repoPath: %v\n", config.RepoPath)
	log.Printf("config.pollInterval: %v\n", config.PollInterval)
	log.Printf("config.directory: %v\n", config.Directory)

	absPath, err := filepath.Abs(config.Directory)
	if err != nil {
		log.Fatal(err)
	}

	config.Directory = absPath

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

	err = zfsCreate(&ZfsCreateOptions{
		Filesystem: "zroot/jails",
		Mountpoint: DEFAULT_PREFIX,
	})
	if err != nil {
		log.Fatal(err)
	}
	err = zfsCreate(&ZfsCreateOptions{
		Filesystem: "zroot/jails/media",
	})
	if err != nil {
		log.Fatal(err)
	}
	err = zfsCreate(&ZfsCreateOptions{
		Filesystem: "zroot/jails/releases",
	})
	if err != nil {
		log.Fatal(err)
	}
	err = zfsCreate(&ZfsCreateOptions{
		Filesystem: "zroot/jails/images",
	})
	if err != nil {
		log.Fatal(err)
	}
	err = zfsCreate(&ZfsCreateOptions{
		Filesystem: "zroot/jails/containers",
	})
	if err != nil {
		log.Fatal(err)
	}

	err = zfsCreate(&ZfsCreateOptions{
		Filesystem: "zroot/jails/volumes",
	})
	if err != nil {
		log.Fatal(err)
	}

	basetxz := filepath.Join(DEFAULT_PREFIX, "media/15.0-RELEASE-base.txz")
	_, err = os.Stat(basetxz)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Fatal(err)
		}

		err = runCmd("/usr/bin/fetch", "https://download.freebsd.org/ftp/releases/amd64/amd64/15.0-RELEASE/base.txz", "-o", basetxz)
		if err != nil {
			log.Fatal(err)
		}
	}

	releasePath := filepath.Join(DEFAULT_PREFIX, "releases/15.0-RELEASE")
	_, err = os.Stat(releasePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Fatal(err)
		}

		err = zfsCreate(&ZfsCreateOptions{
			Filesystem: "zroot/jails/releases/15.0-RELEASE",
		})
		if err != nil {
			log.Fatal(err)
		}

		err = runCmd("/usr/bin/tar", "-xf", basetxz, "-C", releasePath, "--unlink")
		if err != nil {
			log.Fatal(err)
		}

		err := copyFile("/etc/resolv.conf", filepath.Join(releasePath, "etc/resolv.conf"), os.FileMode(0644))
		if err != nil {
			log.Fatal(err)
		}

		err = runCmd("/usr/sbin/freebsd-update", "-b", releasePath, "fetch", "install")
		if err != nil {
			log.Fatal(err)
		}

		zfsCreateSnapshot("zroot/jails/releases/15.0-RELEASE", "base")
	}

	state := NewState()
	reconciler := &Reconciler{
		State:     state,
		ImageIpam: imageIpam,
		JailIpam:  jailIpam,
		Config:    config,
		Repo:      repo,
	}

	existingJails, err := jailListAll()
	if err != nil {
		log.Fatal(err)
	}

	for name := range existingJails {
		jail, err := JailImport(name, "containers")
		if err != nil {
			oops.Err(err)
		} else {
			if jail != nil {
				err = oops.Err(jailIpam.Import(jail.IpAddr))
				if err == nil {
					state.Jails[name] = jail
				}
			}
		}
	}

	if len(oops.Errors) > 0 {
		log.Fatalf("found errors import existing jails")
	}

	state.Volumes, err = zfsListFilesystems("zroot/jails/volumes")
	if err != nil {
		log.Fatal(err)
	}

	hostImages, err := zfsListFilesystems("zroot/jails/images")
	if err != nil {
		log.Fatal(err)
	}

	for _, vol := range hostImages {
		state.Images[vol.Name] = vol.Name
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		cancel()
	}()

	reconciler.Reconcile()

	for {
		timer := time.After(time.Duration(config.PollInterval) * time.Second)
		select {
		case <-ctx.Done():
			return
		case <-timer:
			reconciler.Reconcile()
		}

	}
}
