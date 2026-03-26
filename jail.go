package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const DEFAULT_GATEWAY_IP_ADDR string = "10.138.1.1"

type Jail struct {
	Name      string
	Root      string
	Interface *Epair
	IpAddr    net.IP
	Params    map[string]string
}

type Epair struct {
	Jail string
	Host string
}

func EpairCreate() (*Epair, error) {
	var stderr bytes.Buffer

	cmd := exec.Command("/sbin/ifconfig", "epair", "create")
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%v: %v", err, stderr.String())
	}

	north := strings.TrimSuffix(string(out), "\n")
	if len(north) == 0 {
		return nil, fmt.Errorf("failed to create epair")
	}

	// north is usually like 'epair0a'
	south := []rune(north)
	// so south becomes 'epair0b'
	south[len(south)-1] = 'b'

	return &Epair{
		Jail: north,
		Host: string(south),
	}, nil
}

func (e *Epair) Delete() error {
	return runCmd("/sbin/ifconfig", e.Host, "destroy")
}

func JailCreate(at *AppTemplate, ipAddr net.IP) (*Jail, error) {
	log.Printf("creating jail %v", at.Name)
	err := zfsCreateSnapshot("zroot/jails/releases/15.0-RELEASE", "base")
	if err != nil {
		return nil, err
	}

	// TODO: what if clone already exists?
	zfsSource := fmt.Sprintf("zroot/jails/templates/%s", at.Name)
	err = zfsClone("zroot/jails/releases/15.0-RELEASE@base", zfsSource)
	if err != nil {
		return nil, err
	}

	params := map[string]string{}
	for key, value := range at.Jail {
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
			return nil, fmt.Errorf("unsupported jail directive %v with that type. only string, integer, and list of strings are supported: %v", key, v)
		}
	}

	epair, err := EpairCreate()
	if err != nil {
		zfsDestroy(zfsSource)
		return nil, err
	}

	// remove potentially harmful parameters
	delete(params, "mount.fstab")

	_, ok := params["host.hostname"]
	if !ok {
		params["host.hostname"] = at.Name
	}

	root := filepath.Join(DEFAULT_PREFIX, "templates", at.Name)

	params["name"] = at.Name
	params["vnet"] = ""
	params["vnet.interface"] = epair.Jail
	params["path"] = root
	params["exec.consolelog"] = fmt.Sprintf("/var/log/bastille/%s_console.log", at.Name)

	paramStr := []string{"-c"}
	for key, value := range params {
		if len(value) > 0 {
			paramStr = append(paramStr, fmt.Sprintf("%s=%s", key, value))
		} else {
			paramStr = append(paramStr, key)
		}
	}

	err = runCmd("/usr/sbin/jail", paramStr...)
	if err != nil {
		zfsDestroy(zfsSource)
		epair.Delete()
		return nil, err
	}

	jail := Jail{
		Name:      at.Name,
		Root:      root,
		Interface: epair,
		IpAddr:    ipAddr,
		Params:    params,
	}

	err = jail.InitNetworking()
	if err != nil {
		// TODO: move this to shutdown?
		defer zfsDestroy(zfsSource)

		sErr := jail.Shutdown()
		if sErr != nil {
			return nil, fmt.Errorf("%v: %v", err, sErr)
		}

		return nil, err
	}

	return &jail, nil
}

func (j *Jail) InitNetworking() error {
	jailCidr := fmt.Sprintf("%s/32", j.IpAddr.To4().String())
	err := j.Exec("/sbin/ifconfig", j.Interface.Jail, jailCidr)
	if err != nil {
		return err
	}

	err = j.Exec("/sbin/route", "add", "-net", fmt.Sprintf("%s/32", DEFAULT_GATEWAY_IP_ADDR), "-interface", j.Interface.Jail)
	if err != nil {
		return err
	}

	err = j.Exec("/sbin/route", "add", "default", DEFAULT_GATEWAY_IP_ADDR)
	if err != nil {
		return err
	}

	err = runCmd("/sbin/ifconfig", j.Interface.Host, "inet", fmt.Sprintf("%s/32", DEFAULT_GATEWAY_IP_ADDR))
	if err != nil {
		return err
	}

	return runCmd("/sbin/route", "add", "-net", jailCidr, "-interface", j.Interface.Host)
}

// TODO: wait until the jails shuts down
// TODO: handle persistent jails
func (j *Jail) Shutdown() error {
	err := runCmd("/usr/sbin/jail", "-r", j.Name)

	_, ok := j.Params["mount.devfs"]
	if ok {
		umountErr := runCmd("/sbin/umount", filepath.Join(j.Root, "dev"))
		if umountErr != nil {
			err = fmt.Errorf("%v: %v", err, umountErr)
		}
	}

	epairErr := j.Interface.Delete()
	if epairErr != nil {
		err = fmt.Errorf("%v: %v", err, epairErr)
	}

	return err
}

func (j *Jail) Exec(command string, args ...string) error {
	a := []string{j.Name, command}
	for _, arg := range args {
		a = append(a, arg)
	}

	log.Printf("jexec: %v", a)
	return runCmd("/usr/sbin/jexec", a...)
}

func (j *Jail) Copy(src, dst, owner, group, mode string) error {
	srcStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	hostDestPath := filepath.Join(j.Root, dst)

	dstStat, err := os.Stat(hostDestPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}

	if !srcStat.IsDir() {
		if !srcStat.Mode().Type().IsRegular() {
			return fmt.Errorf("can not copy links: %v", src)
		}

		if dstStat != nil && dstStat.IsDir() {
			dst = filepath.Join(dst, filepath.Base(src))
			hostDestPath = filepath.Join(j.Root, dst)
		}

		err = copyFile(src, hostDestPath)
		if err != nil {
			return err
		}

		err = j.Exec("chown", fmt.Sprintf("%s:%s", owner, group), dst)
		if err != nil {
			return err
		}

		err = j.Exec("chmod", mode, dst)
		if err != nil {
			return err
		}
	}

	if dstStat != nil && !dstStat.IsDir() {
		return fmt.Errorf("copy destination must be a directory when src is also a directory")
	}

	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.Type().IsRegular() && !entry.IsDir() {
			destPath := filepath.Join(hostDestPath, path)

			err = copyFile(path, destPath)
			if err != nil {
				return err
			}

			err = j.Exec("chown", fmt.Sprintf("%s:%s", owner, group), filepath.Join(dst, path))
			if err != nil {
				return err
			}

			err = j.Exec("chmod", mode, filepath.Join(dst, path))
			if err != nil {
				return err
			}
		}

		return nil
	})
}
