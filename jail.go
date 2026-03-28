package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moby/sys/mountinfo"
)

const SYS_ETHER_IFACE_FLAG = "0x8843"
const META_MARK = "0xdeadbeef"
const DEFAULT_GATEWAY_IP_ADDR string = "10.138.1.1"

type Jail struct {
	Name          string
	Root          string
	ZfsDatasource string
	Interface     *Epair
	Zfs           *Zfs
	IpAddr        netip.Addr
	Mounts        []string
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
	stdout, _, err := runCmdOutput("/sbin/ifconfig", "epair", "create")
	if err != nil {
		return nil, err
	}

	north := strings.TrimSpace(string(stdout))
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
	stdout, _, err := runCmdOutput("/usr/bin/netstat", "-j", jail, "-i", "-4", "-n", "--libxo", "json")
	if err != nil {
		return nil, err
	}

	var stats NetstatStats
	err = json.Unmarshal(stdout, &stats)
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

func JailImport(name string, zfs *Zfs, zfsMountpoint, zfsSet string) (*Jail, error) {
	zfsSource := zfsSet + "/" + name
	root := filepath.Join(zfsMountpoint, zfsSet, name)

	stdout, _, err := runCmdOutput("/usr/sbin/jls", "-j", name, "meta")
	if err != nil {
		return nil, err
	}

	// not managed by us
	if !bytes.Equal(bytes.TrimSpace(stdout), []byte(META_MARK)) {
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

	mntPrefix := strings.TrimSuffix(root, "/")
	jailMounts, err := mountinfo.GetMounts(mountinfo.PrefixFilter(mntPrefix))

	if err != nil {
		return nil, err
	}

	mounts := []string{}
	volumesPath := filepath.Join(zfsMountpoint, "volumes")
	for _, mnt := range jailMounts {
		if strings.TrimSuffix(mnt.Mountpoint, "/") == mntPrefix {
			continue
		}

		if strings.HasPrefix(mnt.Source, volumesPath) && mnt.FSType == "nullfs" {
			vol := strings.TrimPrefix(mnt.Source, fmt.Sprintf("%s/", volumesPath))
			mounts = append(mounts, vol)
		}
	}

	return &Jail{
		Name:          name,
		Root:          root,
		ZfsDatasource: zfsSource,
		Interface:     epair,
		IpAddr:        ipAddr,
		Mounts:        mounts,
		Zfs:           zfs,
	}, nil
}

func JailCreate(manifest *Manifest, zfs *Zfs, zfsMountpoint string, zfsSet string, ipAddr netip.Addr) (*Jail, error) {
	zfsSource := zfsSet + "/" + manifest.Name

	log.Printf("creating jail %s", zfsSource)

	err := zfs.CreateSnapshot(manifest.Base, "base", true)
	if err != nil {
		return nil, err
	}

	err = zfs.Clone(manifest.Base+"@base", zfsSource, false)
	if err != nil {
		return nil, err
	}

	epair, err := EpairCreate()
	if err != nil {
		zfs.Destroy(zfsSource, false)
		return nil, err
	}

	params, err := manifest.Params.JailParams()
	if err != nil {
		return nil, err
	}

	// remove potentially harmful parameters
	delete(params, "mount.fstab")

	_, ok := params["host.hostname"]
	if !ok {
		params["host.hostname"] = manifest.Name
	}

	root := filepath.Join(zfsMountpoint, zfsSource)

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
		zfs.Destroy(zfsSource, false)
		epair.Delete()
		return nil, err
	}

	mounts := []string{}

	for _, mnt := range manifest.Mounts {
		mounts = append(mounts, mnt.Volume)
	}

	jail := Jail{
		Name:          manifest.Name,
		Root:          root,
		ZfsDatasource: zfsSource,
		Interface:     epair,
		IpAddr:        ipAddr,
		Mounts:        mounts,
		Zfs:           zfs,
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
	err := j.Zfs.Destroy(j.ZfsDatasource, true)

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

// caller should verify whether [`src`] is "trusted"
// callee does verify whether [`dst`] are within jail bounds
func (j *Jail) Copy(src, dst, owner, group string, modeStr string) error {
	srcStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	hostDestPath := safePathJoin(j.Root, dst)
	if len(hostDestPath) == 0 {
		return fmt.Errorf("invalid copy dst path: can not copy outside jail root: %s", dst)
	}

	dstStat, err := os.Stat(hostDestPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}

	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return err
	}

	if !srcStat.IsDir() {
		if !srcStat.Mode().Type().IsRegular() {
			return fmt.Errorf("can not copy links: %v", src)
		}

		if dstStat != nil && dstStat.IsDir() {
			dst = filepath.Join(dst, filepath.Base(src))
			hostDestPath = safePathJoin(j.Root, dst)
			if len(hostDestPath) == 0 {
				return fmt.Errorf("invalid copy dst path: can not copy outside jail root: %s", dst)
			}
		}

		err = copyFile(src, hostDestPath, os.FileMode(mode))
		if err != nil {
			return err
		}

		err = j.Exec("chown", fmt.Sprintf("%s:%s", owner, group), dst)
		if err != nil {
			return err
		}

		return nil
	}

	if dstStat == nil {
		return fmt.Errorf("copy destination directory must exist in the jail: %v", dst)
	}

	if !dstStat.IsDir() {
		return fmt.Errorf("copy destination must be a directory when src is also a directory")
	}

	entries, err := os.ReadDir(src)

	for _, entry := range entries {
		path := filepath.Join(src, entry.Name())

		log.Printf("copy: walkdir path: %v", path)
		if !entry.Type().IsRegular() {
			continue
		}

		if entry.IsDir() {
			continue
		}

		destPath := filepath.Join(hostDestPath, entry.Name())
		// this shouldn't happen, but...
		if !strings.HasPrefix(destPath, j.Root) {
			return fmt.Errorf("invalid copy dst path: can not copy outside jail root: %s",
				destPath)
		}

		err = copyFile(path, destPath, os.FileMode(mode))
		if err != nil {
			return err
		}

		err = j.Exec("chown", fmt.Sprintf("%s:%s", owner, group), filepath.Join(dst, entry.Name()))
		if err != nil {
			return err
		}
	}

	return nil
}

// caller should verify whether [`src`] is "trusted"
// callee does verify whether [`dst`] are within jail bounds
func (j *Jail) Mount(src, dst, owner, group, modeStr string) error {
	hostDestPath := safePathJoin(j.Root, dst)
	if len(hostDestPath) == 0 {
		return fmt.Errorf("invalid mount dst path: can not mount outside jail root: %s", dst)
	}

	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return err
	}

	err = os.Mkdir(hostDestPath, os.FileMode(mode))
	if err != nil {
		if !os.IsExist(err) {
			return err
		}
	}

	err = runCmd("/sbin/mount", "-t", "nullfs", "-o", "nosuid,noexec,nodev", src, hostDestPath)
	if err != nil {
		return err
	}

	err = j.Exec("chmod", modeStr, dst)
	if err != nil {
		return err
	}

	err = j.Exec("chown", fmt.Sprintf("%s:%s", owner, group), dst)
	if err != nil {
		return err
	}

	return nil
}
