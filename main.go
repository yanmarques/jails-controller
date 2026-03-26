package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
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
const DEFAULT_TEMPLATE_CIDR = "172.16.0.0/16"

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
}

type AppConf map[string]any
type JailConf map[string]string

type App struct {
	Path string
	Name string
	Conf AppConf
}

type Action struct {
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

type AppTemplate struct {
	Name    string
	Jail    AppConf
	Actions []Action
}

func (c AppConf) name() (string, error) {
	name, ok := c["name"]
	if !ok {
		return "", fmt.Errorf("missing name in jail config")
	}

	n, ok := name.(string)
	if !ok {
		return "", fmt.Errorf("name must be a string in jail config")
	}

	return n, nil
}

func (c JailConf) name() (string, error) {
	name, ok := c["name"]
	if !ok {
		return "", fmt.Errorf("missing name in jail config")
	}

	return name, nil
}

func runCmd(command string, args ...string) error {
	out, err := exec.Command(command, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %v: %v %v", err, strings.TrimSpace(string(out)), command, args)
	}

	return nil
}

func jailListAll() (map[string]JailConf, error) {
	out, err := exec.Command("/usr/sbin/jls", "--libxo", "json").Output()
	if err != nil {
		return nil, err
	}

	jailsOutput := map[string]any{}
	jails := []JailConf{}

	err = json.Unmarshal(out, &jailsOutput)
	if err != nil {
		return nil, err
	}

	info, ok := jailsOutput["jail-information"]
	if !ok {
		return nil, fmt.Errorf("missing jail-information from jls output: %v", string(out))
	}

	jails, ok = info.(map[string]any)["jails"].([]JailConf)
	if !ok {
		return nil, fmt.Errorf("missing jails from jls output: %v", string(out))
	}

	result := make(map[string]JailConf, len(jails))

	for _, jail := range jails {
		name, err := jail.name()
		if err != nil {
			return nil, err
		}

		result[name] = jail
	}

	return result, nil
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
				return nil
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
		args = append(args, fmt.Sprintf("mountpoint=%v", mountpoint))
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
		srcFile.Close()
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	return err
}

func reconcile(state *State, config *Config, repo *git.Repository, reconcile_errors *[]error) {
	log.Println("git fetch...")

	fakeGit := os.Getenv("FAKE_GIT") == "1"

	err := repo.Fetch(&git.FetchOptions{
		Auth: &http.BasicAuth{
			Username: "token",
			Password: config.RepoToken,
		},
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		*reconcile_errors = append(*reconcile_errors, err)
	}

	allTags := []object.Tag{}
	log.Println("git tags...")
	iter, err := repo.TagObjects()
	if err != nil {
		*reconcile_errors = append(*reconcile_errors, err)
	} else {
		err = iter.ForEach(func(tag *object.Tag) error {
			allTags = append(allTags, *tag)
			return nil
		})
		if err != nil {
			*reconcile_errors = append(*reconcile_errors, err)
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

	if state.LastTag == currentGitTag.Hash.String() && !fakeGit {
		log.Println("up to date")
		return
	}

	if !fakeGit {
		log.Printf("git checkout: %v\n", currentGitTag.Name)
		w, err := repo.Worktree()
		if err != nil {
			*reconcile_errors = append(*reconcile_errors, err)
			return
		}

		err = w.Checkout(&git.CheckoutOptions{
			Hash: currentGitTag.Hash,
		})
		if err != nil {
			*reconcile_errors = append(*reconcile_errors, err)
			return
		}
	}

	tPath := filepath.Join(config.Directory, config.RepoPath, "templates")

	_, err = os.Stat(tPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("repository doesn't have templates")
			// sPath := path.Join(DEFAULT_BASTILLE_PREFIX, "templates", DEFAULT_TEMPLATE_ORG)
			// log.Printf("removing templates symlink from %v", sPath)
			// err = os.Remove(sPath)
			// if !os.IsNotExist(err) {
			// 	*reconcile_errors = append(*reconcile_errors, err)
			// }
		} else {
			*reconcile_errors = append(*reconcile_errors, err)
		}
	} else {
		log.Println("creating templates...")
		templatesPath := filepath.Join(DEFAULT_PREFIX, "templates")
		entries, err := os.ReadDir(templatesPath)

		if err != nil {
			*reconcile_errors = append(*reconcile_errors, err)
		} else {
			appTemplates := map[string]AppTemplate{}

			for _, entry := range entries {
				if entry.IsDir() {
					appTemplates[entry.Name()] = AppTemplate{
						Name: entry.Name(),
					}
				}
			}

			log.Printf("existing templates %v", len(appTemplates))

			entries, err = os.ReadDir(tPath)
			if err != nil {
				*reconcile_errors = append(*reconcile_errors, err)
			} else {
				toCreate := []AppTemplate{}

				for _, entry := range entries {
					if entry.IsDir() {
						t := filepath.Join(tPath, entry.Name(), "template.conf")
						_, err = os.Stat(t)
						if err != nil {
							if !os.IsNotExist(err) {
								*reconcile_errors = append(*reconcile_errors, err)
							}
						} else {
							content, err := os.ReadFile(t)
							if err != nil {
								*reconcile_errors = append(*reconcile_errors, err)
							} else {
								var at AppTemplate

								err = toml.Unmarshal(content, &at)
								if err != nil {
									*reconcile_errors = append(*reconcile_errors, err)
								}

								_, ok := appTemplates[at.Name]
								if !ok {
									toCreate = append(toCreate, at)
								}
							}
						}
					}
				}

				log.Printf("templates to create %v", len(toCreate))

				ipAddr, network, err := net.ParseCIDR(DEFAULT_TEMPLATE_CIDR)
				if err != nil {
					*reconcile_errors = append(*reconcile_errors, err)
				} else {
					for _, at := range toCreate {
						for j := len(ipAddr) - 1; j >= 0; j-- {
							ipAddr[j]++
							if ipAddr[j] != 0 {
								break
							}
						}

						if !network.Contains(ipAddr) {
							*reconcile_errors = append(*reconcile_errors, fmt.Errorf("ipam failure: template network pool is full"))
							break
						}

						jail, err := JailCreate(&at, ipAddr)
						if err != nil {
							*reconcile_errors = append(*reconcile_errors, err)
							continue
						}

						for _, action := range at.Actions {
							switch action.Type {
							case "exec":
								err = jail.Exec(action.Command, action.Args...)
								if err != nil {
									*reconcile_errors = append(*reconcile_errors, err)
								}
							case "copy":
								err = jail.Copy(action.Src, action.Dest, action.Owner, action.Group, action.Mode)
								if err != nil {
									*reconcile_errors = append(*reconcile_errors, err)
								}
							default:
								*reconcile_errors = append(*reconcile_errors, fmt.Errorf("unknown action type: %v", action.Type))
							}
						}

						log.Printf("created template %s", at.Name)
						err = jail.Shutdown()
						if err != nil {
							*reconcile_errors = append(*reconcile_errors, err)
						}
					}
				}
			}
		}
	}

	// templates/base/v1/prometheus/Bastillefile
	// apps/production/v1/prometheus/Bastillefile

	// appsPath := filepath.Join(config.Directory, config.RepoPath, "apps")
	// _, err = os.Stat(appsPath)
	// if err != nil {
	// 	if !os.IsNotExist(err) {
	// 		*reconcile_errors = append(*reconcile_errors, err)
	// 	}
	// } else {
	// 	apps := []App{}
	//
	// 	err = filepath.WalkDir(appsPath, func(path string, entry fs.DirEntry, err error) error {
	// 		if entry.Type().IsRegular() && !entry.IsDir() && entry.Name() == DEFAULT_JAIL_CONF {
	// 			content, err := os.ReadFile(path)
	// 			if err != nil {
	// 				*reconcile_errors = append(*reconcile_errors, err)
	// 				return nil
	// 			}
	//
	// 			var conf AppConf
	// 			err = toml.Unmarshal(content, &conf)
	// 			if err != nil {
	// 				*reconcile_errors = append(*reconcile_errors, err)
	// 				return nil
	// 			}
	//
	// 			name, err := conf.name()
	// 			if err != nil {
	// 				*reconcile_errors = append(*reconcile_errors, err)
	// 				return nil
	// 			}
	//
	// 			app := App{
	// 				Path: path,
	// 				Name: name,
	// 				Conf: conf,
	// 			}
	//
	// 			apps = append(apps, app)
	// 		}
	//
	// 		return nil
	// 	})
	//
	// 	if err != nil {
	// 		*reconcile_errors = append(*reconcile_errors, err)
	// 	}
	//
	// 	jails, err := jailListAll()
	// 	if err != nil {
	// 		*reconcile_errors = append(*reconcile_errors, err)
	// 		return
	// 	}
	//
	// 	for _, app := range apps {
	// 		jail, exists := jails[app.Name]
	// 		if !exists {
	//
	// 		}
	// 	}
	// }

	state.LastTag = currentGitTag.Hash.String()
}

func main() {
	configPath := flag.String("config", DEFAULT_CONFIG_PATH, "Path to configuration")

	flag.Parse()

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
	err = zfsCreate("zroot/jails/templates", "")
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

	state := State{}

	errors := []error{}
	for {
		reconcile(&state, &config, repo, &errors)
		for _, err := range errors {
			log.Printf("[ERROR] %v\n", err)
		}

		clear(errors)
		errors = errors[:0]

		time.Sleep(time.Duration(config.PollInterval * 1000_000_000))
	}
}
