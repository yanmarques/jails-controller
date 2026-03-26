package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/sys/mountinfo"
)

const SYS_ETHER_IFACE_FLAG = "0x8843"
const META_MARK string = "0xdeadbeef"
const DEFAULT_GATEWAY_IP_ADDR string = "10.138.1.1"

type Jail struct {
	Name          string
	Root          string
	ZfsDatasource string
	Interface     *Epair
	IpAddr        netip.Addr
}

type Epair struct {
	Jail string
	Host string
}

type NetstatIface struct {
	Name    string
	Address string
	Flags   string
}

type NetstatIfaces struct {
	Interface []NetstatIface
}

type NetstatStats struct {
	Statistics NetstatIfaces
}

func EpairCreate() (*Epair, error) {
	out, err := runCmdOutput("/sbin/ifconfig", "epair", "create")
	if err != nil {
		return nil, err
	}

	north := strings.TrimSpace(string(out))
	return ImportEpair(north)
}

func ImportEpair(iface string) (*Epair, error) {
	if len(iface) == 0 {
		return nil, fmt.Errorf("invalid epair %v", iface)
	}

	if !strings.HasPrefix(iface, "epair") {
		return nil, fmt.Errorf("interface is not epair %v", iface)
	}

	// north is usually like 'epair0a'
	south := []rune(iface)
	// so south becomes 'epair0b'
	south[len(south)-1] = 'b'

	return &Epair{
		Jail: iface,
		Host: string(south),
	}, nil
}

func (e *Epair) Delete() error {
	return runCmd("/sbin/ifconfig", e.Host, "destroy")
}

func netstatFirstEtherIface(jail string) (*NetstatIface, error) {
	out, err := runCmdOutput("/usr/bin/netstat", "-j", jail, "-i", "-4", "-n", "--libxo", "json")
	if err != nil {
		return nil, err
	}

	var stats NetstatStats
	err = json.Unmarshal(out, &stats)
	if err != nil {
		return nil, err
	}

	for _, iface := range stats.Statistics.Interface {
		if iface.Flags == SYS_ETHER_IFACE_FLAG {
			return &iface, nil
		}
	}

	return nil, nil
}

func JailImport(name string, zfsTree string) (*Jail, error) {
	zfsSource := fmt.Sprintf("zroot/jails/%s/%s", zfsTree, name)
	root := filepath.Join(DEFAULT_PREFIX, zfsTree, name)

	out, err := runCmdOutput("/usr/sbin/jls", "-j", name, "meta")
	if err != nil {
		return nil, err
	}

	// not managed by us
	if strings.TrimSpace(string(out)) != META_MARK {
		return nil, nil
	}

	iface, err := netstatFirstEtherIface(name)
	if err != nil {
		return nil, err
	}

	if iface == nil {
		return nil, fmt.Errorf("could not find ethernet interface of jail %s", name)
	}

	epair, err := ImportEpair(iface.Name)
	if err != nil {
		return nil, err
	}

	ipAddr, err := netip.ParseAddr(iface.Address)
	if err != nil {
		return nil, err
	}

	return &Jail{
		Name:          name,
		Root:          root,
		ZfsDatasource: zfsSource,
		Interface:     epair,
		IpAddr:        ipAddr,
	}, nil
}

func JailCreate(zfsTree string, manifest *Manifest, ipAddr netip.Addr) (*Jail, error) {
	log.Printf("creating jail %s/%s", zfsTree, manifest.Name)
	err := zfsCreateSnapshot(fmt.Sprintf("zroot/jails/%s", manifest.Base), "base")
	if err != nil {
		return nil, err
	}

	// TODO: what if clone already exists?
	zfsSource := fmt.Sprintf("zroot/jails/%s/%s", zfsTree, manifest.Name)
	err = zfsClone(fmt.Sprintf("zroot/jails/%s@base", manifest.Base), zfsSource)
	if err != nil {
		return nil, err
	}

	epair, err := EpairCreate()
	if err != nil {
		zfsDestroy(zfsSource)
		return nil, err
	}

	params, err := manifest.Jail.JailParams()
	if err != nil {
		return nil, err
	}

	// remove potentially harmful parameters
	delete(params, "mount.fstab")

	_, ok := params["host.hostname"]
	if !ok {
		params["host.hostname"] = manifest.Name
	}

	root := filepath.Join(DEFAULT_PREFIX, zfsTree, manifest.Name)

	params["name"] = manifest.Name
	params["vnet"] = ""
	params["vnet.interface"] = epair.Jail
	params["path"] = root
	params["meta"] = META_MARK
	params["exec.consolelog"] = fmt.Sprintf("/var/log/bastille/%s_console.log", manifest.Name)

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
		Name:          manifest.Name,
		Root:          root,
		ZfsDatasource: zfsSource,
		Interface:     epair,
		IpAddr:        ipAddr,
	}

	err = jail.initNetworking()
	if err != nil {
		defer jail.Destroy()

		sErr := jail.Shutdown()
		if sErr != nil {
			return nil, fmt.Errorf("%v: %v", err, sErr)
		}

		return nil, err
	}

	return &jail, nil
}

func (j *Jail) initNetworking() error {
	// jail side
	jailCidr := fmt.Sprintf("%s/32", j.IpAddr.String())
	err := runCmd("/sbin/ifconfig", "-j", j.Name, j.Interface.Jail, jailCidr)
	if err != nil {
		return err
	}

	err = runCmd("/sbin/route", "-j", j.Name, "add", "-net", fmt.Sprintf("%s/32", DEFAULT_GATEWAY_IP_ADDR), "-interface", j.Interface.Jail)
	if err != nil {
		return err
	}

	err = runCmd("/sbin/route", "-j", j.Name, "add", "default", DEFAULT_GATEWAY_IP_ADDR)
	if err != nil {
		return err
	}

	// host side
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

	mntPrefix := strings.TrimSuffix(j.Root, "/")
	mounts, mountsErr := mountinfo.GetMounts(mountinfo.PrefixFilter(mntPrefix))
	if mountsErr != nil {
		err = fmt.Errorf("%v: %v", err, mountsErr)
	} else {
		for _, mnt := range mounts {
			if strings.TrimSuffix(mnt.Mountpoint, "/") == mntPrefix {
				continue
			}

			log.Printf("shutdown: umounting %v", mnt.Mountpoint)
			umountErr := runCmd("/sbin/umount", mnt.Mountpoint)
			if umountErr != nil {
				err = fmt.Errorf("%v: %v", err, umountErr)
			}
		}
	}

	epairErr := j.Interface.Delete()
	if epairErr != nil {
		err = fmt.Errorf("%v: %v", err, epairErr)
	}

	return err
}

func (j *Jail) Destroy() error {
	err := zfsDestroy(j.ZfsDatasource)

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
