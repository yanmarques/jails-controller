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
	"slices"
	"strings"
	"text/template"
	"time"

	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/transport/http"
	"github.com/pelletier/go-toml/v2"
)

const DEFAULT_CONFIG_PATH = "/usr/local/etc/jails-controllers.toml"
const DEFAULT_IMAGE_CIDR = "10.100.0.0/16"
const DEFAULT_JAIL_CIDR = "10.200.0.0/16"
const DEFAULT_CMD_TIMEOUT_SMALL = 60
const DEFAULT_CMD_TIMEOUT_LARGE = 600
const DEFAULT_IPAM_TTL = 10080 // 7 days

const RESERVED_LOGS_VOLUME = ":logs:"
const RESERVED_ROOT_CA_SECRET = ":rootCA:"
const PUBKEY_PATH_IN_JAIL = "/etc/jails-controller.pubkey"
const CONFIG_DIR = "/usr/local/etc/jails-controller"
const PRIVKEY_PATH = CONFIG_DIR + "/controller.key"
const PUBKEY_PATH = CONFIG_DIR + "/controller.pubkey"
const SECRETS_FILE = CONFIG_DIR + "/private_secrets.json"

var oops *ErrAggregator

type Reconciler struct {
	Repo     *git.Repository
	State    *State
	Ipam     map[string]*IPManager
	Config   Config
	Zfs      *Zfs
	Notifier *LazyEventNotifier
	Rctl     *JailResourceManager
	Scm      *SecretManager
	Pf       *Pf
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
	// Remote branch to clone
	RepoBranch string
	// Path inside repo where bastille stuff lives
	RepoPaths []string
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

	ExtIf string
}

type State struct {
	LastTag     string
	Images      map[string]string
	Jails       map[string]*Jail
	Volumes     map[string]*VolumeManifest
	Secrets     map[string]map[string]*SecretManifest
	Subscribers map[string]Subscriber
}

type DesiredState struct {
	BaseManifests map[string]*Manifest
	Jails         map[string]*Manifest
	Images        map[string]*Manifest
	Volumes       map[string]*VolumeManifest
	Secrets       map[string]map[string]*SecretManifest
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
	Secret     string
	SecretType string
	Src        string
	Dest       string
	Owner      string
	Group      string
	Mode       string
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
	ServerCertSecret  string
	ServerCertPath    string
	ServerPort        int
	ServerFingerprint string
}

func (e EventSubscription) Empty() bool {
	return e.ServerPort == 0 && (e.ServerCertPath == "" || e.ServerCertSecret == "")
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
	Firewall          []PfPolicy
	Hints             map[string]string
	FilesHash         string
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
	Firewall          []PfPolicy
	DependsOn         []string

	// metadata used internally to copy files
	searchPaths []string
}

type VolumeManifest struct {
	Name    string
	MaxSize string

	// metadata used internally
	quota int
}

type SecretManifest struct {
	Name         string
	SecretType   string
	Length       int64
	ExcludeChars bool
	SpecialChars string
	Bits         int
	DNSNames     []string
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

type JailAndManifest struct {
	Jail     *Jail
	Manifest *Manifest
}

func TopologicalSort(jails map[string]*Manifest) ([]*Manifest, error) {
	cycle := map[string]bool{}
	visited := map[string]bool{}
	sorted := []*Manifest{}

	var visit func(n string) error
	visit = func(n string) error {
		if cycle[n] {
			return nil
		}

		jail, ok := jails[n]
		if !ok {
			return nil
		}

		if !visited[n] {
			cycle[n] = true
			for _, dep := range jail.DependsOn {
				err := visit(dep)
				if err != nil {
					return err
				}
			}

			cycle[n] = false
			visited[n] = true
			sorted = append(sorted, jails[n])
		}

		return nil
	}

	for n := range jails {
		err := visit(n)
		if err != nil {
			return nil, err
		}
	}

	return sorted, nil
}

func (m *Manifest) Hash() (string, error) {
	params, err := m.Params.JailParams()
	if err != nil {
		return "", err
	}

	filesContent := []byte{}
	for _, action := range m.Actions {
		if action.Type != "copy" &&
			action.Type != "template" && action.Src == "" {
			continue
		}

		for _, searchPath := range m.searchPaths {
			path := filepath.Join(searchPath, action.Src)
			stat, err := os.Stat(path)
			if err != nil {
				if !os.IsNotExist(err) {
					oops.Err(err)
				}

				continue
			}

			if !stat.Mode().IsRegular() {
				continue
			}

			if stat.IsDir() {
				files, err := os.ReadDir(path)
				if err != nil {
					return "", err
				}

				for _, entry := range files {
					if entry.IsDir() || entry.Type().IsRegular() {
						continue
					}

					content, err := os.ReadFile(filepath.Join(path, entry.Name()))
					if err != nil {
						return "", err
					}

					filesContent = slices.Concat(filesContent, content)
				}
			} else {
				content, err := os.ReadFile(path)
				if err != nil {
					return "", err
				}

				filesContent = slices.Concat(filesContent, content)
			}

			break
		}
	}

	digest := sha256.Sum256(filesContent)

	manifest := HasheableManifest{
		Base:              m.Base,
		Network:           m.Network,
		Params:            params,
		EventSubscription: m.EventSubscription,
		Actions:           m.Actions,
		Mounts:            m.Mounts,
		Hints:             m.Hints,
		Firewall:          m.Firewall,
		FilesHash:         hex.EncodeToString(digest[:]),
	}

	out, err := json.Marshal(&manifest)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:]), nil
}

func NewState() *State {
	s := &State{
		Jails:       map[string]*Jail{},
		Images:      map[string]string{},
		Volumes:     map[string]*VolumeManifest{},
		Secrets:     map[string]map[string]*SecretManifest{},
		Subscribers: map[string]Subscriber{},
		LastTag:     "",
	}

	s.Secrets[SECRET_TYPE_PASSWORD] = map[string]*SecretManifest{}
	s.Secrets[SECRET_TYPE_TOKEN] = map[string]*SecretManifest{}
	s.Secrets[SECRET_TYPE_TLS_CERT] = map[string]*SecretManifest{}

	return s
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

func (r *Reconciler) PrepareJailBeforeStart(jail *Jail, searchPaths []string, actions []JailAction, mounts []JailMount) error {
	var err error
	// TODO: check for volume existence prior to this
	for _, mnt := range mounts {
		if mnt.Volume == RESERVED_LOGS_VOLUME {
			err = jail.Mount(r.Config.LogDir, mnt.Dest, "", "", "755", false, true)
			if err != nil {
				return err
			}

			continue
		}

		src := safePathJoin(r.Config.ZfsMountpoint, "volumes", mnt.Volume)
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

			err := r.CopyToJail(searchPaths, jail, &action)
			if err != nil {
				return err
			}
		case "template":
			if !action.BeforeStart {
				continue
			}

			err := r.TemplateToJail(searchPaths, jail, &action)
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

func (r *Reconciler) PrepareJailAfterStart(jail *Jail, searchPaths []string, actions []JailAction, mounts []JailMount) error {
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

			err := r.CopyToJail(searchPaths, jail, &action)
			if err != nil {
				return err
			}
		case "template":
			if action.BeforeStart {
				continue
			}

			err := r.TemplateToJail(searchPaths, jail, &action)
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

func (r *Reconciler) TemplateToJail(searchPaths []string, jail *Jail, action *JailAction) error {
	template := template.New("jail action")

	for _, searchPath := range searchPaths {
		path := safePathJoin(searchPath, action.Src)
		if len(path) == 0 {
			return fmt.Errorf("invalid copy src path: can not copy outside manifest path: %s", action.Src)
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		tmpl, err := template.Parse(string(content))
		if err != nil {
			return err
		}

		var buffer bytes.Buffer
		err = tmpl.Execute(&buffer, r.Scm.Inner)
		if err != nil {
			return err
		}

		err = oops.Err(jail.CopyContent(buffer.Bytes(), action.Dest, action.Owner, action.Group, action.Mode))
		if err == nil {
			return nil
		}
	}

	return fmt.Errorf("unable to find file for action src %s", action.Src)
}

func (r *Reconciler) CopyToJail(searchPaths []string, jail *Jail, action *JailAction) error {
	if action.Secret != "" && action.Src != "" {
		return fmt.Errorf("action src and secret defined, specify one not both, src=%s and secret=%s",
			action.Src, action.Secret)
	}

	if action.Secret != "" {
		if action.Secret == RESERVED_ROOT_CA_SECRET {
			return jail.CopyContent(r.Scm.Inner.RootCA.Cert, action.Dest,
				action.Owner, action.Group, action.Mode)
		}

		if action.SecretType == "" {
			return fmt.Errorf("action copy secret %s for jail %s is missing the secretType",
				action.Secret, jail.Name)
		}

		content, ok := r.Scm.Content(action.SecretType, action.Secret)
		if !ok {
			return fmt.Errorf("copy jail %s: unknown secret %s of type %s",
				jail.Name, action.Secret, action.SecretType)
		}

		return jail.CopyContent(content, action.Dest, action.Owner, action.Group, action.Mode)
	}

	for _, searchPath := range searchPaths {
		path := safePathJoin(searchPath, action.Src)
		if len(path) == 0 {
			return fmt.Errorf("invalid copy src path: can not copy outside manifest path: %s", action.Src)
		}

		err := oops.Err(jail.Copy(path, action.Dest, action.Owner, action.Group, action.Mode))
		if err == nil {
			return nil
		}
	}

	return fmt.Errorf("unable to find file for action src %s", action.Src)
}

func NewDesiredState() *DesiredState {
	d := &DesiredState{
		BaseManifests: map[string]*Manifest{},
		Jails:         map[string]*Manifest{},
		Images:        map[string]*Manifest{},
		Volumes:       map[string]*VolumeManifest{},
		Secrets:       map[string]map[string]*SecretManifest{},
	}

	d.Secrets[SECRET_TYPE_PASSWORD] = map[string]*SecretManifest{}
	d.Secrets[SECRET_TYPE_TOKEN] = map[string]*SecretManifest{}
	d.Secrets[SECRET_TYPE_TLS_CERT] = map[string]*SecretManifest{}

	return d
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

	for _, rule := range other.Firewall {
		m.Firewall = append(m.Firewall, rule)
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

	for _, searchPath := range other.searchPaths {
		m.searchPaths = append(m.searchPaths, searchPath)
	}
}

func (m *Manifest) ApplyMetadata(scm *SecretManager) error {
	if !m.EventSubscription.Empty() {
		if m.EventSubscription.ServerCertPath != "" && m.EventSubscription.ServerCertSecret != "" {
			return fmt.Errorf("event subscription in manifest %s contains both serverCertPath and serverCertSecret", m.Name)
		}

		var content []byte
		var ok bool
		var err error

		if m.EventSubscription.ServerCertPath != "" {
			var err error
			found := false

			for _, searchPath := range m.searchPaths {
				serverCertPath := safePathJoin(filepath.Dir(searchPath), m.EventSubscription.ServerCertPath)
				if serverCertPath == "" {
					return fmt.Errorf("invalid server cert path %s: can not copy outside m m: %s",
						m.EventSubscription.ServerCertPath, m.Name)
				}

				content, err = os.ReadFile(serverCertPath)
				if err == nil {
					found = true
					break
				}

				oops.Err(err)
			}

			if !found {
				if err == nil {
					err = fmt.Errorf("no such file or directory: %s", m.EventSubscription.ServerCertPath)
				}

				return err
			}
		} else {
			content, ok = scm.Content(SECRET_TYPE_TLS_CERT, m.EventSubscription.ServerCertSecret)
			if !ok {
				return fmt.Errorf("event subscription: unknown serverCertSecret %s", m.EventSubscription.ServerCertSecret)
			}
		}

		pemDecoded, _ := pem.Decode(content)
		fingerprint, err := sumFingerprint(pemDecoded.Bytes)
		if err != nil {
			return err
		}

		m.EventSubscription.ServerFingerprint = hex.EncodeToString(fingerprint[:])
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

func firewallDependentJails(jailName string, addresses []string, a map[string]*Jail, b map[string]*Manifest) ([]string, error) {
	jailsDeps := []string{}

	for _, addr := range addresses {
		_, err := netip.ParseAddr(addr)
		if err == nil {
			continue
		}

		_, err = netip.ParsePrefix(addr)
		if err == nil {
			continue
		}

		_, ok := a[addr]
		if !ok {
			_, ok = b[addr]
			if !ok {
				return nil, fmt.Errorf("figuring out dependencies: unknown ip address or jail name '%s' in firewall rule of jail %s", addr, jailName)
			}
		}

		jailsDeps = append(jailsDeps, addr)
	}

	return jailsDeps, nil
}

func firewallIpAddr(jailName string, addresses []string, a map[string]*Jail, b map[string]*Jail) ([]string, error) {
	ipAddresses := []string{}

	for _, addr := range addresses {
		ipAddr, err := netip.ParseAddr(addr)
		if err == nil {
			ipAddresses = append(ipAddresses, ipAddr.String())
			continue
		}

		ipPrefix, err := netip.ParsePrefix(addr)
		if err == nil {
			ipAddresses = append(ipAddresses, ipPrefix.String())
			continue
		}

		jail, ok := a[addr]
		if !ok {
			jail, ok = b[addr]
			if !ok {
				return nil, fmt.Errorf("unknown ip address or jail name '%s' in firewall rule of jail %s", addr, jailName)
			}
		}

		ipAddresses = append(ipAddresses, jail.IpAddr.String())
	}

	return ipAddresses, nil
}

func (m *Manifest) AppendFirewallPolicies(jail *Jail, a map[string]*Jail, b map[string]*Jail, policies *[]*PfPolicy) error {
	if len(m.Firewall) == 0 {
		*policies = append(*policies, &PfPolicy{
			Action:    "block",
			Direction: PF_INGRESS,
			Interface: jail.Interface.Host,
			From:      []string{jail.IpAddr.String()},
		})

		*policies = append(*policies, &PfPolicy{
			Action:    "block",
			Direction: PF_EGRESS,
			Interface: jail.Interface.Host,
			To:        []string{jail.IpAddr.String()},
		})
	} else {
		for _, pfPolicy := range m.Firewall {
			pfPolicy.Interface = jail.Interface.Host
			if pfPolicy.Direction == PF_INGRESS {
				addresses, err := firewallIpAddr(jail.Name, pfPolicy.From, a, b)
				if err != nil {
					return err
				}

				pfPolicy.From = addresses
				pfPolicy.To = []string{jail.IpAddr.String()}

				// forwarding has inverted direction semantics
				pfPolicy.Direction = PF_EGRESS
			} else {
				addresses, err := firewallIpAddr(jail.Name, pfPolicy.To, a, b)
				if err != nil {
					return err
				}

				pfPolicy.To = addresses
				pfPolicy.From = []string{jail.IpAddr.String()}
				pfPolicy.Direction = PF_INGRESS
			}

			*policies = append(*policies, &pfPolicy)
		}
	}

	return nil
}

func (m *Manifest) ValidateJailManifest(searchPaths []string) error {
	if m.Name == "" {
		return fmt.Errorf(
			"manifest with empty name, ignoring: %v",
			searchPaths)
	}

	if m.EventSubscription.ServerPort <= 0 && !m.EventSubscription.Empty() {
		return fmt.Errorf("invalid event port %d in jail manifest %s", m.EventSubscription.ServerPort, m.Name)
	}

	if !m.EventSubscription.Empty() {
		if m.EventSubscription.ServerCertPath != "" && m.EventSubscription.ServerCertSecret != "" {
			return fmt.Errorf("event subscription in manifest %s contains both serverCertPath and serverCertSecret", m.Name)
		}
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

	return nil
}

func (d *DesiredState) addBaseManifest(path string, manifest *Manifest) error {
	err := manifest.ValidateJailManifest([]string{path})
	if err != nil {
		return err
	}

	_, ok := d.BaseManifests[manifest.Name]
	if ok {
		return fmt.Errorf("duplicate base name definitions: %s", manifest.Name)
	}

	manifest.searchPaths = append(manifest.searchPaths, filepath.Dir(path))
	d.BaseManifests[manifest.Name] = manifest

	return nil
}

func (d *DesiredState) addJail(path string, jail *Manifest) error {
	err := jail.ValidateJailManifest([]string{path})
	if err != nil {
		return err
	}

	_, ok := d.Jails[jail.Name]
	if ok {
		return fmt.Errorf("duplicate jail name definitions: %s", jail.Name)
	}

	jail.searchPaths = append(jail.searchPaths, filepath.Dir(path))
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

	image.searchPaths = append(image.searchPaths, filepath.Dir(path))
	d.Images[image.Name] = image

	return nil
}

func (d *DesiredState) addVolume(path string, vol *VolumeManifest) error {
	if vol.Name == "" {
		return fmt.Errorf(
			"volume with empty name: %v",
			path)
	}

	if vol.Name == RESERVED_LOGS_VOLUME {
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

func (d *DesiredState) addSecret(path string, secret *SecretManifest) error {
	if secret.Name == "" {
		return fmt.Errorf(
			"manifest with empty secret name: %v",
			path)
	}

	if !(secret.SecretType == SECRET_TYPE_PASSWORD ||
		secret.SecretType == SECRET_TYPE_TOKEN ||
		secret.SecretType == SECRET_TYPE_TLS_CERT) {
		return fmt.Errorf("secret manifest has unknown secretType: %s", secret.SecretType)
	}

	_, ok := d.Secrets[secret.SecretType][secret.Name]
	if ok {
		return fmt.Errorf("duplicate secret name definitions: %s", secret.Name)
	}

	d.Secrets[secret.SecretType][secret.Name] = secret

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
	if volumeErr == nil {
		return desiredState.addVolume(path, &volume)
	}

	decoder = toml.NewDecoder(bytes.NewBuffer(content))
	decoder.DisallowUnknownFields()

	var secret SecretManifest
	secretErr := decoder.Decode(&secret)
	log.Printf("secret err: %v", secretErr)
	if secretErr != nil {
		var strictErr *toml.StrictMissingError

		if errors.As(secretErr, &strictErr) {
			return fmt.Errorf("file %s: %s", path, strictErr.String())
		}

		return fmt.Errorf("file %s does not seem to be a valid manifest for jail, image, volume, base or secret; check for typos: %v", path, secretErr)
	}

	return desiredState.addSecret(path, &secret)
}

func (r *Reconciler) NukeJail(jail *Jail) {
	log.Printf("destroying jail %s", jail.Name)
	oops.Err(jail.Shutdown())

	oops.Err(r.Rctl.DestroyAll(jail.Name))

	err := oops.Err(jail.Destroy(false))

	ipam, ok := r.Ipam[jail.SubnetId]
	if !ok {
		oops.Err(fmt.Errorf("unknown subnet id %s for jails %s", jail.SubnetId, jail.Name))
	} else {
		oops.Err(ipam.Free(jail.IpAddr))
	}

	if err == nil {
		delete(r.State.Jails, jail.Name)
		delete(r.State.Subscribers, jail.Name)
	}
}

func (r *Reconciler) Reconcile() {
	log.Println("reconciling...")

	w, err := r.Repo.Worktree()
	if err != nil {
		oops.Err(err)
		return
	}

	err = w.Pull(&git.PullOptions{
		Auth: &http.BasicAuth{
			Username: "token",
			Password: r.Config.RepoToken,
		},
	})
	if err != nil {
		if errors.Is(err, git.NoErrAlreadyUpToDate) {
			log.Printf("git: already up-to-date")
		} else {
			oops.Err(err)
			return
		}
	}

	desiredState := NewDesiredState()

	// for volume claims sanity check
	volumeClaims := map[string][]string{}

	for _, repoPath := range r.Config.RepoPaths {
		repoPath := filepath.Join(r.Config.Directory, repoPath)

		repoEntries, err := os.ReadDir(repoPath)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("repository path doesn't exist %s", repoPath)
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

		oops.Err(manifest.ValidateJailManifest(manifest.searchPaths))
	}

	for _, manifest := range desiredState.Jails {
		oops.Err(manifest.ApplyMetadata(r.Scm))
	}

	// TODO: count restarts
	existingJails, err := JailListAll()
	if err != nil {
		oops.Err(err)
	} else {
		for name, jail := range r.State.Jails {
			_, alive := existingJails[name]
			if !alive {
				log.Printf("jail %s died, removing from memory state so it can restart", name)
				r.NukeJail(jail)
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

	// image manifests that are missing and should be created
	imagestoCreate := []*Manifest{}

	// image names that exist and should be deleted
	imagestoDestroy := []string{}

	jailstoCreate := map[string]*Manifest{}
	jailstoDestroy := []*Jail{}
	jailsImageRefs := map[string]bool{}

	secretstoDestroy := []*SecretManifest{}
	secretstoCreate := []*SecretManifest{}

	// jails that exist but their manifest changed, and they should be recreated
	existingJailsToRecreate := map[string]bool{}
	existingJailsToRctl := []*Manifest{}

	// firewall rules to set
	firewall := []*PfPolicy{}

	// the steps to create a jail is split in initialization and kick-off (actual start)
	// so this holds all image jails initialized but not started yet
	imagestoStart := []*JailAndManifest{}
	jailstoStart := []*JailAndManifest{}

	// it's a helper struct to find implicit dependent jails from firewall rules
	jailstoStartB := map[string]*Jail{}

	// jails that failed initialization or start, and should be deleted
	// instead of immediately deleting the jail upon failure, it's scheduled
	// at the very end
	jailsPendingDeletion := []*Jail{}

	// allow existing jails to change their firewall rules
	jailsPendingFirewallRules := []*JailAndManifest{}

	for secretType := range desiredState.Secrets {
		for name, manifest := range desiredState.Secrets[secretType] {
			_, exists := r.State.Secrets[secretType][name]
			if exists {
				continue
			}

			secretstoCreate = append(secretstoCreate, manifest)
		}
	}

	for secretType := range r.State.Secrets {
		for name, manifest := range r.State.Secrets[secretType] {
			_, alive := desiredState.Secrets[secretType][name]
			if !alive {
				secretstoDestroy = append(secretstoDestroy, manifest)
			}
		}
	}

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
				jailsPendingFirewallRules = append(jailsPendingFirewallRules, &JailAndManifest{
					Jail:     existingJail,
					Manifest: manifest,
				})

				continue
			}

			jailstoDestroy = append(jailstoDestroy, existingJail)
			existingJailsToRecreate[manifest.Name] = true
		}

		jailstoCreate[manifest.Name] = manifest
		jailsImageRefs[manifest.Base] = true

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
		r.NukeJail(jail)
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

	// destroy secrets
	for _, secret := range secretstoDestroy {
		log.Printf("destroying secret %s/%s", secret.SecretType, secret.Name)
		err = oops.Err(r.Scm.Destroy(secret))
		if err == nil {
			delete(r.State.Secrets[secret.SecretType], secret.Name)
		}
	}

	// create images
	for _, manifest := range imagestoCreate {
		// skip if image is not referenced by any jail
		_, ok := jailsImageRefs["images/"+manifest.Name]
		if !ok {
			continue
		}

		ipam, ok := r.Ipam[manifest.Network.SubnetId]
		if !ok {
			oops.Err(fmt.Errorf("unknown subnet id %s for jails %s", manifest.Network.SubnetId, manifest.Name))
			continue
		}

		ipAddr, err := ipam.AllocateIP(manifest.Name)
		if err != nil {
			oops.Err(err)
			continue
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
			continue
		}

		// allow all egress
		firewall = append(firewall, &PfPolicy{
			Action:    "pass",
			Direction: PF_INGRESS,
			Interface: jail.Interface.Host,
			From:      []string{jail.IpAddr.String()},
			Protocol:  []string{"tcp", "udp"},
			State:     "keep state",
		})

		imagestoStart = append(imagestoStart, &JailAndManifest{
			Jail:     jail,
			Manifest: manifest,
		})
	}

	if len(imagestoStart)+len(imagestoDestroy) > 0 {
		oops.Err(r.Pf.SetRules(firewall))
	}

	for _, spec := range imagestoStart {
		jail := spec.Jail
		manifest := spec.Manifest

		ipam, ok := r.Ipam[manifest.Network.SubnetId]
		if !ok {
			oops.Err(fmt.Errorf("unknown subnet id %s for jails %s", manifest.Network.SubnetId, manifest.Name))
			jailsPendingDeletion = append(jailsPendingDeletion, jail)
			continue
		}

		err = oops.Err(r.PrepareJailBeforeStart(jail, manifest.searchPaths, manifest.Actions, manifest.Mounts))
		if err != nil {
			jailsPendingDeletion = append(jailsPendingDeletion, jail)
			continue
		}

		err = oops.Err(jail.Start())
		if err != nil {
			jailsPendingDeletion = append(jailsPendingDeletion, jail)
			continue
		}

		err = oops.Err(r.PrepareJailAfterStart(jail, manifest.searchPaths, manifest.Actions, manifest.Mounts))

		shutdownErr := oops.Err(jail.Shutdown())
		freeIpErr := oops.Err(ipam.Free(jail.IpAddr))

		if err == nil && shutdownErr == nil && freeIpErr == nil {
			err = oops.Err(jail.Destroy(true))
			if err == nil {
				r.State.Images[manifest.Name] = manifest.Name
			}
		} else {
			oops.Err(jail.Destroy(false))
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
				continue
			}

			if vol.quota < r.State.Volumes[volName].quota {
				oops.Err(fmt.Errorf(
					"volume %s max size %v can not be lower than current size %v",
					volName, vol.quota, r.State.Volumes[volName].quota))
				continue
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
			continue
		}
	}

	// reserve all static IPs
	for _, manifest := range jailstoCreate {
		ipam, ok := r.Ipam[manifest.Network.SubnetId]
		if !ok {
			oops.Err(fmt.Errorf("unknown subnet id %s for jails %s", manifest.Network.SubnetId, manifest.Name))
			continue
		}

		if manifest.Network.StaticIp != "" {
			ip, err := netip.ParseAddr(manifest.Network.StaticIp)
			if err != nil {
				oops.Err(err)
				continue
			}

			err = oops.Err(ipam.ReserveStatic(manifest.Name, ip))
			if err != nil {
				continue
			}
		}
	}

	// create secrets
	for _, secret := range secretstoCreate {
		log.Printf("creating secret %s/%s", secret.SecretType, secret.Name)
		err = oops.Err(r.Scm.Create(secret))
		if err == nil {
			r.State.Secrets[secret.SecretType][secret.Name] = secret
		}
	}

	oops.Err(r.Scm.Save())

	dependencyErrs := false
	for _, jail := range jailstoCreate {
		for _, rule := range jail.Firewall {
			jailsDepsFrom, err := firewallDependentJails(jail.Name, rule.From, r.State.Jails, jailstoCreate)
			if err != nil {
				dependencyErrs = true
				oops.Err(err)
				continue
			}

			jailsDepsTo, err := firewallDependentJails(jail.Name, rule.To, r.State.Jails, jailstoCreate)
			if err != nil {
				dependencyErrs = true
				oops.Err(err)
				continue
			}

			jail.DependsOn = append(jail.DependsOn, jailsDepsFrom...)
			jail.DependsOn = append(jail.DependsOn, jailsDepsTo...)
		}
	}

	if !dependencyErrs {
		sortedJailstoCreate, err := TopologicalSort(jailstoCreate)
		if err != nil {
			oops.Err(err)
		} else {
			// create jails
			for _, manifest := range sortedJailstoCreate {
				log.Printf("jails will be created %v", manifest.Name)
				ipam, ok := r.Ipam[manifest.Network.SubnetId]
				if !ok {
					oops.Err(fmt.Errorf("unknown subnet id %s for jails %s", manifest.Network.SubnetId, manifest.Name))
					continue
				}

				var ipAddr netip.Addr

				if manifest.Network.StaticIp != "" {
					ipAddr, err = netip.ParseAddr(manifest.Network.StaticIp)
					if err != nil {
						oops.Err(err)
						continue
					}
				} else {
					ip, err := ipam.AllocateIP(manifest.Name)
					if err != nil {
						oops.Err(err)
						continue
					}

					ipAddr = *ip
				}

				if err != nil {
					oops.Err(err)
					continue
				}

				hash, err := manifest.Hash()
				if err != nil {
					oops.Err(err)
					continue
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
					if jail != nil {
						jailsPendingDeletion = append(jailsPendingDeletion, jail)
					}
					continue
				}

				for _, j := range r.State.Jails {
					if j.Name != jail.Name && j.Interface.Host == jail.Interface.Host {
						log.Printf("[WARN] SRC %s CONFLICT EXISTING %s CREATED A DUPLICATE INTERFACE %s", jail.Name, j.Name, j.Interface.Host)
					}
				}

				for _, j := range jailstoStartB {
					if j.Name != jail.Name && j.Interface.Host == jail.Interface.Host {
						log.Printf("[WARN] SRC %s CONFLICT %s CREATED A DUPLICATE INTERFACE %s", jail.Name, j.Name, j.Interface.Host)
					}
				}

				jailstoStartB[jail.Name] = jail

				err = oops.Err(manifest.AppendFirewallPolicies(jail, r.State.Jails, jailstoStartB, &firewall))
				if err != nil {
					jailsPendingDeletion = append(jailsPendingDeletion, jail)
					continue
				}

				jailstoStart = append(jailstoStart, &JailAndManifest{
					Jail:     jail,
					Manifest: manifest,
				})
			}
		}
	}

	for _, spec := range jailsPendingFirewallRules {
		oops.Err(spec.Manifest.AppendFirewallPolicies(spec.Jail, r.State.Jails, jailstoStartB, &firewall))
	}

	if r.FirstRun || len(jailstoCreate)+len(jailstoDestroy) > 0 {
		oops.Err(r.Pf.SetRules(firewall))
	}

	for _, spec := range jailstoStart {
		jail := spec.Jail
		manifest := spec.Manifest

		err = oops.Err(r.PrepareJailBeforeStart(jail, manifest.searchPaths, manifest.Actions, manifest.Mounts))
		if err != nil {
			jailsPendingDeletion = append(jailsPendingDeletion, jail)
			continue
		}

		if !manifest.EventSubscription.Empty() {
			err = jail.Copy(PUBKEY_PATH, PUBKEY_PATH_IN_JAIL, "root", "wheel", "644")
			if err != nil {
				oops.Err(err)
				jailsPendingDeletion = append(jailsPendingDeletion, jail)
				continue
			}
		}

		err = oops.Err(jail.Start())
		if err != nil {
			jailsPendingDeletion = append(jailsPendingDeletion, jail)
			continue
		}

		err = oops.Err(r.Rctl.Add(jail.Name, manifest.Rlimits))
		if err != nil {
			jailsPendingDeletion = append(jailsPendingDeletion, jail)
			continue
		}

		err = oops.Err(r.PrepareJailAfterStart(jail, manifest.searchPaths, manifest.Actions, manifest.Mounts))
		if err != nil {
			jailsPendingDeletion = append(jailsPendingDeletion, jail)
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

	for _, jail := range jailsPendingDeletion {
		r.NukeJail(jail)
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

		config.Subnets = append(config.Subnets, Subnet{
			Id:   "jails",
			Cidr: DEFAULT_JAIL_CIDR,
		})
	}

	_, ok = ipam["images"]
	if !ok {
		ipam["images"], err = NewIPManager(DEFAULT_IMAGE_CIDR, DEFAULT_IPAM_TTL*time.Minute)
		if err != nil {
			log.Fatal(err)
		}

		config.Subnets = append(config.Subnets, Subnet{
			Id:   "images",
			Cidr: DEFAULT_IMAGE_CIDR,
		})
	}

	repo, err := git.PlainClone(config.Directory, &git.CloneOptions{
		URL: config.RepoUrl,
		Auth: &http.BasicAuth{
			Username: "token",
			Password: config.RepoToken,
		},
		ReferenceName: plumbing.ReferenceName(config.RepoBranch),
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
			Args:    []string{"--not-running-from-cron", "-b", releasePath, "fetch", "install"},
			Timeout: DEFAULT_CMD_TIMEOUT_LARGE,
		})
		if err != nil {
			log.Fatal(err)
		}

		zfs.CreateSnapshot("releases/15.0-RELEASE", "base", true)
	}

	var scm *SecretManager

	_, err = os.Stat(SECRETS_FILE)
	if err != nil {
		if os.IsNotExist(err) {
			scm, err = NewSecretManager(SECRETS_FILE)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			log.Fatal(err)
		}
	} else {
		scm, err = ImportSecretManager(SECRETS_FILE)
		if err != nil {
			log.Fatal(err)
		}
	}
	state := NewState()

	for name := range scm.Inner.Passwords {
		state.Secrets[SECRET_TYPE_PASSWORD][name] = &SecretManifest{
			Name:       name,
			SecretType: SECRET_TYPE_PASSWORD,
		}
	}

	for name := range scm.Inner.Tokens {
		state.Secrets[SECRET_TYPE_TOKEN][name] = &SecretManifest{
			Name:       name,
			SecretType: SECRET_TYPE_TOKEN,
		}
	}

	for name := range scm.Inner.TlsCerts {
		state.Secrets[SECRET_TYPE_TLS_CERT][name] = &SecretManifest{
			Name:       name,
			SecretType: SECRET_TYPE_TLS_CERT,
		}
	}

	existingJails, err := JailListAll()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("existing jails %v", len(existingJails))

	hadErrors := false
	for name := range existingJails {
		result, err := JailImport(name, zfs, config.ZfsMountpoint, "containers", config)
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

				err = oops.Err(ipam.Import(name, result.Jail.IpAddr))
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

	pf := NewPf(config, "/etc/jails-nat.conf", "/etc/jails-filter.conf")
	err = pf.Init()
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
		Scm:      scm,
		Keypair: Keypair{
			Priv: privKey,
			Pub:  pubKey,
		},
		Pf:       pf,
		FirstRun: true,
	}

	return reconciler
}
