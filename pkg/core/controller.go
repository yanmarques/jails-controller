package controller

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
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
const DEFAULT_CMD_TIMEOUT_SMALL = 60
const DEFAULT_CMD_TIMEOUT_LARGE = 600
const DEFAULT_IPAM_TTL = 10080 // 7 days

const SPECIAL_LOGS_VOLUME = ":logs:"
const PUBKEY_PATH_IN_JAIL = "/etc/jails-controller.pubkey"
const CONFIG_DIR = "/usr/local/etc/jails-controller"
const PRIVKEY_PATH = CONFIG_DIR + "/controller.key"
const PUBKEY_PATH = CONFIG_DIR + "/controller.pubkey"

var oops *ErrAggregator

type Reconciler struct {
	Repo     *git.Repository
	State    *State
	Ipam     map[string]*IPManager
	Config   Config
	Zfs      *Zfs
	Notifier *LazyEventNotifier
	Rctl     *JailResourceManager
	Keypair  Keypair
	FirstRun bool
}

type ErrAggregator struct {
	Errors []error
}

type CmdOptions struct {
	Path     string
	Args     []string
	Timeout  int
	CloseFds bool
	Stdin    io.Reader
}

type Keypair struct {
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

type Subnet struct {
	Id   string
	Cidr string
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
	Subnets        []Subnet
	// Whitelist of jail params that any jail can use
	AllowedJailParams []string
	// Params applied to all jails by default, but overridable
	DefaultJailParams JailParams
}

type State struct {
	LastTag     string
	Images      map[string]string
	Jails       map[string]*Jail
	Volumes     map[string]*VolumeManifest
	Subscribers map[string]Subscriber
}

type DesiredState struct {
	BaseManifests map[string]*Manifest
	Jails         map[string]*Manifest
	Images        map[string]*Manifest
	Volumes       map[string]*VolumeManifest
}

type JailUserParams map[string]any

type JailAction struct {
	Type        string
	BeforeStart bool
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
	Volume    string
	Dest      string
	Owner     string
	Group     string
	Mode      string
	ReadWrite bool
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

// Only parameters that are considered for state changes
type HasheableManifest struct {
	Base              string
	Network           NetworkManifest
	Params            JailParams
	EventSubscription EventSubscription
	Actions           []JailAction
	Mounts            []JailMount
	Hints             map[string]string
}

type NetworkManifest struct {
	SubnetId string
	StaticIp string
}

type Manifest struct {
	Type              string
	Name              string
	Base              string
	Include           string
	Params            JailUserParams
	EventSubscription EventSubscription
	Actions           []JailAction
	Mounts            []JailMount
	Rlimits           []ResourceLimit
	Hints             map[string]string
	Network           NetworkManifest

	// metadata used internally to copy files
	originalHostPath string
}

type VolumeManifest struct {
	Name    string
	MaxSize string

	// metadata used internally
	quota int
}

type EventJailSync struct {
	Name     string
	Hostname string
	IpAddr   string
	Hints    map[string]string
}

type EventSyncState struct {
	Signature    string
	Verification string
	Jails        []EventJailSync
}

func (m *Manifest) Hash() (string, error) {
	params, err := m.Params.JailParams()
	if err != nil {
		return "", err
	}

	manifest := HasheableManifest{
		Base:              m.Base,
		Network:           m.Network,
		Params:            params,
		EventSubscription: m.EventSubscription,
		Actions:           m.Actions,
		Mounts:            m.Mounts,
		Hints:             m.Hints,
	}

	out, err := json.Marshal(&manifest)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:]), nil
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

func PrepareJailBeforeStart(jail *Jail, hostPath string, actions []JailAction, mounts []JailMount, config Config) error {
	var err error
	// TODO: check for volume existence prior to this
	for _, mnt := range mounts {
		if mnt.Volume == SPECIAL_LOGS_VOLUME {
			err = jail.Mount(config.LogDir, mnt.Dest, "", "", "755", false, true)
			if err != nil {
				return err
			}

			continue
		}

		src := safePathJoin(config.ZfsMountpoint, "volumes", mnt.Volume)
		if len(src) == 0 {
			return fmt.Errorf("invalid mount src path: can not mount outside jail path: %s", mnt.Volume)
		}

		err = jail.Mount(src, mnt.Dest, mnt.Owner, mnt.Group, mnt.Mode, mnt.ReadWrite, true)
		if err != nil {
			return err
		}
	}

	for _, action := range actions {
		switch action.Type {
		case "exec":
			continue
		case "copy":
			if !action.BeforeStart {
				continue
			}

			path := safePathJoin(hostPath, action.Src)
			if len(path) == 0 {
				return fmt.Errorf("invalid copy src path: can not copy outside manifest path: %s", action.Src)
			}

			err = jail.Copy(path, action.Dest, action.Owner, action.Group, action.Mode)
			if err != nil {
				return err
			}
		default:
			if action.Type == "" {
				return fmt.Errorf("empty action type in jail %s", jail.Name)
			}

			return fmt.Errorf("unknown action type %v in jail %s", action.Type, jail.Name)
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
			if action.BeforeStart {
				continue
			}

			path := safePathJoin(hostPath, action.Src)
			if len(path) == 0 {
				return fmt.Errorf("invalid copy src path: can not copy outside manifest path: %s", action.Src)
			}

			err := jail.Copy(path, action.Dest, action.Owner, action.Group, action.Mode)
			if err != nil {
				return err
			}
		default:
			if action.Type == "" {
				return fmt.Errorf("empty action type in jail %s", jail.Name)
			}

			return fmt.Errorf("unknown action type %v in jail %s", action.Type, jail.Name)
		}
	}

	return nil
}

func NewDesiredState() *DesiredState {
	return &DesiredState{
		BaseManifests: map[string]*Manifest{},
		Jails:         map[string]*Manifest{},
		Images:        map[string]*Manifest{},
		Volumes:       map[string]*VolumeManifest{},
	}
}

func (m *Manifest) Merge(other *Manifest) {
	if m.Params == nil {
		m.Params = JailUserParams{}
	}

	if m.Hints == nil {
		m.Hints = map[string]string{}
	}

	for key, value := range other.Params {
		_, ok := m.Params[key]
		if !ok {
			m.Params[key] = value
		}
	}

	for key, value := range other.Hints {
		_, ok := m.Hints[key]
		if !ok {
			m.Hints[key] = value
		}
	}

	for _, action := range other.Actions {
		m.Actions = append(m.Actions, action)
	}

	for _, mount := range other.Mounts {
		m.Mounts = append(m.Mounts, mount)
	}

	for _, rlimit := range other.Rlimits {
		m.Rlimits = append(m.Rlimits, rlimit)
	}

	if m.EventSubscription.Empty() {
		m.EventSubscription = other.EventSubscription
	}

	if m.Network.SubnetId == "" {
		m.Network.SubnetId = other.Network.SubnetId
	}

	// why would anyone do this?
	if m.Network.StaticIp == "" {
		m.Network.StaticIp = other.Network.StaticIp
	}
}

func (m *Manifest) ValidateJailManifest(path string) error {
	if m.Name == "" {
		return fmt.Errorf(
			"manifest with empty name, ignoring: %v",
			path)
	}

	if m.EventSubscription.ServerPort <= 0 && !m.EventSubscription.Empty() {
		return fmt.Errorf("invalid event port %d in jail manifest %s", m.EventSubscription.ServerPort, m.Name)
	}

	if !m.EventSubscription.Empty() {
		serverCertPath := safePathJoin(filepath.Dir(path), m.EventSubscription.ServerCertPath)
		if serverCertPath == "" {
			return fmt.Errorf("invalid server cert path %s: can not copy outside m m: %s",
				m.EventSubscription.ServerCertPath, m.Name)
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

		m.EventSubscription.ServerFingerprint = hex.EncodeToString(fingerprint[:])
	}

	for idx := range m.Rlimits {
		err := m.Rlimits[idx].Validate()
		if err != nil {
			return err
		}
	}

	if m.Network.SubnetId == "" {
		m.Network.SubnetId = "jails"
	}

	if m.Network.StaticIp != "" {
		_, err := netip.ParseAddr(m.Network.StaticIp)
		if err != nil {
			return fmt.Errorf("invalid static ip %s in jail manifest %s", m.Network.StaticIp, m.Name)
		}
	}

	for idx, action := range m.Actions {
		if action.BeforeStart {
			continue
		}

		// jail actions after start are useless
		m.Actions[idx].BeforeStart = true
	}

	return nil
}

func (d *DesiredState) addBaseManifest(path string, manifest *Manifest) error {
	err := manifest.ValidateJailManifest(path)
	if err != nil {
		return err
	}

	_, ok := d.BaseManifests[manifest.Name]
	if ok {
		return fmt.Errorf("duplicate base name definitions: %s", manifest.Name)
	}

	manifest.originalHostPath = filepath.Dir(path)
	d.BaseManifests[manifest.Name] = manifest

	return nil
}

func (d *DesiredState) addJail(path string, jail *Manifest) error {
	err := jail.ValidateJailManifest(path)
	if err != nil {
		return err
	}

	_, ok := d.Jails[jail.Name]
	if ok {
		return fmt.Errorf("duplicate jail name definitions: %s", jail.Name)
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

	if image.Network.SubnetId == "" {
		image.Network.SubnetId = "images"
	}

	_, ok := d.Images[image.Name]
	if ok {
		return fmt.Errorf("duplicate image name definitions: %s", image.Name)
	}

	if len(image.Mounts) > 0 {
		log.Printf("[WARN] images don't support mounts, but image %s have mounts, ignoring", image.Name)
		image.Mounts = []JailMount{}
	}

	image.originalHostPath = filepath.Dir(path)
	d.Images[image.Name] = image

	return nil
}

func (d *DesiredState) addVolume(path string, vol *VolumeManifest) error {
	if vol.Name == "" {
		return fmt.Errorf(
			"volume with empty name: %v",
			path)
	}

	if vol.Name == SPECIAL_LOGS_VOLUME {
		return fmt.Errorf(
			"volume name %s is reserved",
			vol.Name)
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

	quota, err := VolumeSize(vol.MaxSize)
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
		switch manifest.Type {
		case "image":
			return desiredState.addImage(path, &manifest)
		case "jail":
			return desiredState.addJail(path, &manifest)
		case "base":
			return desiredState.addBaseManifest(path, &manifest)
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

	for _, manifest := range desiredState.Jails {
		if manifest.Include == "" {
			continue
		}

		baseManifest, ok := desiredState.BaseManifests[manifest.Include]
		if !ok {
			log.Printf("jail %s includes %s, but that base does not exist", manifest.Name, manifest.Include)
			continue
		}

		manifest.Merge(baseManifest)
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

	imagestoCreate := []*Manifest{}
	imagestoDestroy := []string{}
	jailstoCreate := []*Manifest{}
	jailstoDestroy := []*Jail{}
	existingJailsToRecreate := map[string]bool{}
	existingJailsToRctl := []*Manifest{}

	for name, manifest := range desiredState.Images {
		_, exists := r.State.Images[name]
		if exists {
			continue
		}

		imagestoCreate = append(imagestoCreate, manifest)
	}

	for _, name := range r.State.Images {
		_, alive := desiredState.Images[name]
		if !alive {
			imagestoDestroy = append(imagestoDestroy, name)
		}
	}

	for _, manifest := range desiredState.Jails {
		existingJail, exists := r.State.Jails[manifest.Name]
		if exists {
			manifestHash, err := manifest.Hash()
			if err != nil {
				oops.Err(err)
				break
			}

			existingJailsToRctl = append(existingJailsToRctl, manifest)

			if existingJail.Hash == manifestHash {
				continue
			}

			jailstoDestroy = append(jailstoDestroy, existingJail)
			existingJailsToRecreate[manifest.Name] = true
		}

		jailstoCreate = append(jailstoCreate, manifest)
		for _, mnt := range manifest.Mounts {
			if mnt.ReadWrite {
				volumeClaims[mnt.Volume] = append(volumeClaims[mnt.Volume], manifest.Name)
			}
		}
	}

	for _, jail := range r.State.Jails {
		_, alive := desiredState.Jails[jail.Name]
		if alive {
			// if will recreate, can skip account for volume claims verification for this jail
			_, willRecreate := existingJailsToRecreate[jail.Name]
			if !willRecreate {
				for _, mnt := range jail.Mounts {
					if mnt.ReadWrite {
						volumeClaims[mnt.Volume] = append(volumeClaims[mnt.Volume], jail.Name)
					}
				}
			}
		} else {
			jailstoDestroy = append(jailstoDestroy, jail)
		}
	}

	for volume, claims := range volumeClaims {
		if len(claims) > 1 {
			oops.Err(fmt.Errorf("multiple claims to volume %s: %v", volume, claims))
			return
		}
	}

	log.Printf("jails to create %v, existing jails %v", len(jailstoCreate), len(r.State.Jails))

	for _, manifest := range existingJailsToRctl {
		// TODO: what do I want to do here on failure?
		err = oops.Err(r.Rctl.Add(manifest.Name, manifest.Rlimits))
	}

	// destroy jails
	for _, jail := range jailstoDestroy {
		ipam, ok := r.Ipam[jail.SubnetId]
		if !ok {
			oops.Err(fmt.Errorf("unkown subnet id %s for jails %s", jail.SubnetId, jail.Name))
			continue
		}

		log.Printf("destroying jail %s", jail.Name)

		oops.Err(ipam.Free(jail.IpAddr))
		hasErr := false

		// TODO: track jails already shutdown, otherwise it will be stuck on this call
		err = oops.Err(jail.Shutdown())
		hasErr = hasErr || err != nil

		err = oops.Err(r.Rctl.DestroyAll(jail.Name))
		hasErr = hasErr || err != nil

		err = oops.Err(jail.Destroy())
		hasErr = hasErr || err != nil
		if !hasErr {
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
	for _, image := range imagestoDestroy {
		log.Printf("destroying image %s", image)
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
	for _, manifest := range imagestoCreate {
		ipam, ok := r.Ipam[manifest.Network.SubnetId]
		if !ok {
			oops.Err(fmt.Errorf("unkown subnet id %s for jails %s", manifest.Network.SubnetId, manifest.Name))
			break
		}

		ipAddr, err := ipam.AllocateIP(manifest.Name)
		if err != nil {
			oops.Err(err)
			break
		}

		randomId := make([]byte, 2)
		rand.Read(randomId)

		jailName := manifest.Name + "-image-" + hex.EncodeToString(randomId)

		jail, err := NewJail(&JailOptions{
			Name:     jailName,
			Manifest: manifest,
			Zfs:      r.Zfs,
			Config:   r.Config,
			ZfsSet:   "images",
			IpAddr:   *ipAddr,
			Hash:     "",
			Hints:    manifest.Hints,
			SubnetId: manifest.Network.SubnetId,
		})
		if err != nil {
			oops.Err(err)
			oops.Err(ipam.Free(*ipAddr))
			break
		}

		err = oops.Err(PrepareJailBeforeStart(jail, manifest.originalHostPath, manifest.Actions, manifest.Mounts, r.Config))
		if err != nil {
			oops.Err(jail.Shutdown())
			oops.Err(jail.Destroy())
			oops.Err(ipam.Free(*ipAddr))
			break
		}

		err = oops.Err(jail.Start())
		if err != nil {
			oops.Err(jail.Shutdown())
			oops.Err(jail.Destroy())
			oops.Err(ipam.Free(*ipAddr))
			break
		}

		err = oops.Err(PrepareJailAfterStart(jail, manifest.originalHostPath, manifest.Actions, manifest.Mounts, r.Config))

		oops.Err(jail.Shutdown())
		if err != nil {
			oops.Err(jail.Destroy())
		} else {
			r.State.Images[manifest.Name] = manifest.Name
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

	// reserve all static IPs
	for _, manifest := range jailstoCreate {
		ipam, ok := r.Ipam[manifest.Network.SubnetId]
		if !ok {
			oops.Err(fmt.Errorf("unknown subnet id %s for jails %s", manifest.Network.SubnetId, manifest.Name))
			break
		}

		if manifest.Network.StaticIp != "" {
			ip, err := netip.ParseAddr(manifest.Network.StaticIp)
			if err != nil {
				oops.Err(err)
				break
			}

			err = oops.Err(ipam.Reserve(manifest.Name, ip))
			if err != nil {
				break
			}
		}
	}

	// create jails
	for _, manifest := range jailstoCreate {
		log.Printf("jails will be created %v", manifest.Name)
		ipam, ok := r.Ipam[manifest.Network.SubnetId]
		if !ok {
			oops.Err(fmt.Errorf("unkown subnet id %s for jails %s", manifest.Network.SubnetId, manifest.Name))
			break
		}

		useDynamicIp := false
		var ipAddr netip.Addr

		if manifest.Network.StaticIp != "" {
			useDynamicIp = true
			ipAddr, err = netip.ParseAddr(manifest.Network.StaticIp)
			if err != nil {
				oops.Err(err)
				break
			}
		} else {
			ip, err := ipam.AllocateIP(manifest.Name)
			if err != nil {
				oops.Err(err)
				break
			}

			ipAddr = *ip
		}

		if err != nil {
			oops.Err(err)
			break
		}

		hash, err := manifest.Hash()
		if err != nil {
			oops.Err(err)
			break
		}

		jail, err := NewJail(&JailOptions{
			Manifest: manifest,
			Zfs:      r.Zfs,
			Config:   r.Config,
			ZfsSet:   "containers",
			IpAddr:   ipAddr,
			Hash:     hash,
			Hints:    manifest.Hints,
			SubnetId: manifest.Network.SubnetId,
		})
		if err != nil {
			oops.Err(err)
			if useDynamicIp {
				oops.Err(ipam.Free(ipAddr))
			}
			break
		}

		err = oops.Err(PrepareJailBeforeStart(jail, manifest.originalHostPath, manifest.Actions, manifest.Mounts, r.Config))
		if err != nil {
			oops.Err(err)
			oops.Err(jail.Shutdown())
			oops.Err(jail.Destroy())
			if useDynamicIp {
				oops.Err(ipam.Free(ipAddr))
			}
			break
		}

		if !manifest.EventSubscription.Empty() {
			err = jail.Copy(PUBKEY_PATH, PUBKEY_PATH_IN_JAIL, "root", "wheel", "644")
			if err != nil {
				oops.Err(err)
				oops.Err(jail.Shutdown())
				oops.Err(jail.Destroy())
				if useDynamicIp {
					oops.Err(ipam.Free(ipAddr))
				}
				break
			}
		}

		err = oops.Err(jail.Start())
		if err != nil {
			oops.Err(err)
			oops.Err(jail.Shutdown())
			oops.Err(jail.Destroy())
			if useDynamicIp {
				oops.Err(ipam.Free(ipAddr))
			}
			break
		}

		err = oops.Err(r.Rctl.Add(jail.Name, manifest.Rlimits))
		if err != nil {
			oops.Err(err)
			oops.Err(jail.Shutdown())
			oops.Err(jail.Destroy())
			if useDynamicIp {
				oops.Err(ipam.Free(ipAddr))
			}

			break
		}

		err = oops.Err(PrepareJailAfterStart(jail, manifest.originalHostPath, manifest.Actions, manifest.Mounts, r.Config))
		if err != nil {
			oops.Err(err)
			oops.Err(jail.Shutdown())
			oops.Err(jail.Destroy())
			if useDynamicIp {
				oops.Err(ipam.Free(ipAddr))
			}
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

	if len(jailstoCreate)+len(jailstoDestroy) > 0 || r.FirstRun {
		msg := make([]byte, 32)
		rand.Read(msg)

		signature := ed25519.Sign(r.Keypair.Priv, msg)

		jailsSync := EventSyncState{
			Signature:    hex.EncodeToString(signature),
			Verification: hex.EncodeToString(msg),
			Jails:        []EventJailSync{},
		}

		for _, jail := range r.State.Jails {
			hostname, ok := jail.Hostname()
			if !ok {
				log.Printf("somehow, jail does not have a hostname: %s", jail.Name)
				continue
			}

			jailsSync.Jails = append(jailsSync.Jails, EventJailSync{
				Name:     jail.Name,
				Hostname: hostname,
				IpAddr:   jail.IpAddr.String(),
				Hints:    jail.Hints,
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
	r.FirstRun = false
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

func InitLogging() {
	log.SetFlags(log.LstdFlags | log.Ldate | log.Lshortfile)
	// TODO: i dislike this but now it's too late?
	oops = NewErrAggregator()
}

func NewReconcilerOrFail(configPath string) *Reconciler {
	InitLogging()

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
	if len(config.AllowedJailParams) == 0 {
		config.AllowedJailParams = DEFAULT_ALLOWED_JAIL_PARAMS
	}

	if config.DefaultJailParams == nil {
		config.DefaultJailParams = DEFAULT_JAIL_PARAMS
	}

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

	ipam := map[string]*IPManager{}

	for _, subnet := range config.Subnets {
		manager, err := NewIPManager(subnet.Cidr, DEFAULT_IPAM_TTL*time.Minute)
		if err != nil {
			log.Fatal(err)
		}

		ipam[subnet.Id] = manager
	}

	_, ok := ipam["jails"]
	if !ok {
		ipam["jails"], err = NewIPManager(DEFAULT_JAIL_CIDR, DEFAULT_IPAM_TTL*time.Minute)
		if err != nil {
			log.Fatal(err)
		}
	}

	_, ok = ipam["images"]
	if !ok {
		ipam["images"], err = NewIPManager(DEFAULT_IMAGE_CIDR, DEFAULT_IPAM_TTL*time.Minute)
		if err != nil {
			log.Fatal(err)
		}
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

		_, _, err = RunCmd(&CmdOptions{
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

		_, _, err = RunCmd(&CmdOptions{
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

		_, _, err = RunCmd(&CmdOptions{
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
	existingJails, err := JailListAll()
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
				if result.Jail.SubnetId == "" {
					result.Jail.SubnetId = "jails"
				}

				ipam, ok := ipam[result.Jail.SubnetId]
				if !ok {
					log.Fatal(fmt.Errorf("unknown subnet id %s for imported jail %s", result.Jail.SubnetId, result.Jail.Name))
				}

				err = oops.Err(ipam.Reserve(name, result.Jail.IpAddr))
				if err == nil {
					log.Printf("imported jails %v", name)
					state.Jails[name] = result.Jail

					if !result.Meta.Events.Empty() {
						state.Subscribers[name] = Subscriber{
							Jail:         result.Jail,
							Subscription: result.Meta.Events,
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

	rctl := NewJailResourceManager()
	err = rctl.Import()
	if err != nil {
		log.Fatal(err)
	}

	reconciler := &Reconciler{
		State:    state,
		Config:   config,
		Ipam:     ipam,
		Repo:     repo,
		Zfs:      zfs,
		Notifier: NewEventNotifier(10, 5*time.Second),
		Rctl:     rctl,
		Keypair: Keypair{
			Priv: privKey,
			Pub:  pubKey,
		},
		FirstRun: true,
	}

	return reconciler
}
