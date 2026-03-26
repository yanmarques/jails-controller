package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/netip"
	"os"
	"os/exec"
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

const DEFAULT_PREFIX string = "/usr/local/jails"
const DEFAULT_CONFIG_PATH = "/usr/local/etc/bastille-poller.json"
const DEFAULT_TEMPLATE_ORG = "cluster"
const DEFAULT_JAIL_CONF = "jail.conf"
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
	Jails   map[string]*Jail
}

type JailUserConf map[string]any
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

type Manifest struct {
	Name    string
	Base    string
	Jail    JailUserConf
	Actions []JailAction
}

type IPSlot struct {
	IP    netip.Addr
	InUse bool
}

type IPManager struct {
	Slots   []IPSlot
	Network netip.Prefix
}

func NewState() *State {
	return &State{
		Jails:   map[string]*Jail{},
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

func (c JailUserConf) JailParams() (JailParams, error) {
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

func jailExists(name string) bool {
	cmd := exec.Command("/usr/sbin/jls", "-c", "-j", name)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError

		if errors.As(err, &exitErr) {
			return exitErr.ExitCode() == 0
		}

		return false
	}

	return true
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

func zfsCreate(filesystem string, mountpoint string) error {
	args := []string{
		"create",
	}
	if len(mountpoint) > 0 {
		args = append(args, "-o")
		args = append(args, fmt.Sprintf("mountpoint=%s", mountpoint))
	}

	args = append(args, filesystem)

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

func copyFile(src, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	baseDir := filepath.Dir(dest)
	if baseDir != "." && baseDir != string(os.PathSeparator) {
		err = os.MkdirAll(baseDir, 0755)
		if err != nil && !os.IsExist(err) {
			return err
		}
	}

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

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

func (m Manifest) PrepareJail(jail *Jail) error {
	for _, action := range m.Actions {
		switch action.Type {
		case "exec":
			err := jail.Exec(action.Command, action.Args...)
			if err != nil {
				return err
			}
		case "copy":
			err := jail.Copy(action.Src, action.Dest, action.Owner, action.Group, action.Mode)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown action type: %v", action.Type)
		}
	}

	return nil
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

	repoImgPath := filepath.Join(r.Config.Directory, r.Config.RepoPath, "images")

	_, err = os.Stat(repoImgPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("repository doesn't have images")
			// sPath := path.Join(DEFAULT_BASTILLE_PREFIX, "templates", DEFAULT_TEMPLATE_ORG)
			// log.Printf("removing templates symlink from %v", sPath)
			// err = os.Remove(sPath)
			// if !os.IsNotExist(err) {
			// 	oops.Err(err)
			// }
		} else {
			oops.Err(err)
		}
	} else {
		log.Println("creating images...")
		hostImgPath := filepath.Join(DEFAULT_PREFIX, "images")
		entries, err := os.ReadDir(hostImgPath)

		if err != nil {
			oops.Err(err)
		} else {
			images := map[string]Manifest{}

			for _, entry := range entries {
				if entry.IsDir() {
					images[entry.Name()] = Manifest{
						Name: entry.Name(),
					}
				}
			}

			log.Printf("existing images %v", len(images))

			entries, err = os.ReadDir(repoImgPath)
			if err != nil {
				oops.Err(err)
			} else {
				desiredImages := map[string]Manifest{}

				for _, entry := range entries {
					if entry.IsDir() {
						t := filepath.Join(repoImgPath, entry.Name(), "image.conf")
						_, err = os.Stat(t)
						if err != nil {
							if !os.IsNotExist(err) {
								oops.Err(err)
							}
						} else {
							content, err := os.ReadFile(t)
							if err != nil {
								oops.Err(err)
							} else {
								var m Manifest

								err = toml.Unmarshal(content, &m)
								if err != nil {
									oops.Err(err)
									break
								}

								if len(m.Name) == 0 {
									oops.Err(fmt.Errorf(
										"manifest with empty image name, ignoring: %v",
										filepath.Join(repoImgPath, entry.Name())))
									break
								}

								_, ok := desiredImages[m.Name]
								if ok {
									oops.Err(fmt.Errorf("duplicate image name definitions: %s, aborting", m.Name))
									return
								}

								desiredImages[m.Name] = m
							}
						}
					}
				}

				// create
				for name, manifest := range desiredImages {
					_, ok := images[name]
					if ok {
						continue
					}

					ipAddr, err := r.ImageIpam.AllocateIP()
					if err != nil {
						oops.Err(err)
						break
					}

					defer r.ImageIpam.Free(*ipAddr)

					jail, err := JailCreate("images", &manifest, *ipAddr)
					if err != nil {
						oops.Err(err)
						break
					}

					oops.Err(manifest.PrepareJail(jail))

					oops.Err(jail.Shutdown())
				}

				// destroy
				for _, image := range images {
					_, alive := desiredImages[image.Name]
					if alive {
						continue
					}

					oops.Err(zfsDestroy(fmt.Sprintf("zroot/jails/images/%s@base", image.Name)))
					oops.Err(zfsDestroy(fmt.Sprintf("zroot/jails/images/%s", image.Name)))
				}
			}
		}
	}

	// templates/base/v1/prometheus/Bastillefile
	// apps/production/v1/prometheus/Bastillefile

	repoJailsPath := filepath.Join(r.Config.Directory, r.Config.RepoPath, "jails")
	_, err = os.Stat(repoJailsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			oops.Err(err)
		}
	} else {
		desiredJails := map[string]Manifest{}

		err = filepath.WalkDir(repoJailsPath, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if entry.Type().IsRegular() && !entry.IsDir() && entry.Name() == DEFAULT_JAIL_CONF {
				content, err := os.ReadFile(path)
				if err != nil {
					oops.Err(err)
					return nil
				}

				var jail Manifest
				err = toml.Unmarshal(content, &jail)
				if err != nil {
					oops.Err(err)
					return nil
				}

				if len(jail.Name) == 0 {
					oops.Err(fmt.Errorf(
						"manifest with empty jail name, ignoring: %v",
						path))
					return nil
				}

				_, ok := desiredJails[jail.Name]
				if ok {
					return fmt.Errorf("duplicate jail name definitions: %s, aborting", jail.Name)
				}

				desiredJails[jail.Name] = jail
			}

			return nil
		})

		if err != nil {
			oops.Err(err)
			return
		}

		// create
		for _, manifest := range desiredJails {
			_, exists := r.State.Jails[manifest.Name]
			if exists {
				continue
			}

			ipAddr, err := r.JailIpam.AllocateIP()
			if err != nil {
				oops.Err(err)
				break
			}

			jail, err := JailCreate("containers", &manifest, *ipAddr)
			if err != nil {
				r.JailIpam.Free(*ipAddr)
				oops.Err(err)
				break
			}

			err = manifest.PrepareJail(jail)
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

		// destroy
		for _, jail := range r.State.Jails {
			_, alive := desiredJails[jail.Name]
			if alive {
				continue
			}

			oops.Err(jail.Shutdown())
			oops.Err(jail.Destroy())
			oops.Err(r.JailIpam.Free(jail.IpAddr))

			delete(r.State.Jails, jail.Name)
		}
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

	err = zfsCreate("zroot/jails", DEFAULT_PREFIX)
	if err != nil {
		log.Fatal(err)
	}
	err = zfsCreate("zroot/jails/media", "")
	if err != nil {
		log.Fatal(err)
	}
	err = zfsCreate("zroot/jails/releases", "")
	if err != nil {
		log.Fatal(err)
	}
	err = zfsCreate("zroot/jails/images", "")
	if err != nil {
		log.Fatal(err)
	}
	err = zfsCreate("zroot/jails/containers", "")
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

		err = zfsCreate("zroot/jails/releases/15.0-RELEASE", "")
		if err != nil {
			log.Fatal(err)
		}

		err = runCmd("/usr/bin/tar", "-xf", basetxz, "-C", releasePath, "--unlink")
		if err != nil {
			log.Fatal(err)
		}

		err := copyFile("/etc/resolv.conf", filepath.Join(releasePath, "etc/resolv.conf"))
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

	for {
		reconciler.Reconcile()

		time.Sleep(time.Duration(config.PollInterval * 1000_000_000))
	}
}
