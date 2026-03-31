package controller

import (
	"bufio"
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
const DEFAULT_STOP_TIMEOUT = 60

type IdMap struct {
	Id   int
	Name string
}

type JailParams map[string]string

type JailMeta struct {
	Magic      string
	JailParams JailParams
	Events     EventSubscription
	ServerCert string
}

type Jail struct {
	Name          string
	Root          string
	ZfsDatasource string
	Interface     *Epair
	Zfs           *Zfs
	IpAddr        netip.Addr
	Mounts        []string
	ExecUser      IdMap
	UidMaps       map[string]IdMap
	GidMaps       map[string]IdMap
	// only populated for jails created by us, not imported
	Params JailParams
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

type JailImportResult struct {
	Jail   *Jail
	Events *EventSubscription
	ApiKey string
}

func EpairCreate() (*Epair, error) {
	stdout, _, err := runCmd(&CmdOptions{
		Path: "/sbin/ifconfig",
		Args: []string{"epair", "create"},
	})
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
	_, _, err := runCmd(&CmdOptions{
		Path: "/sbin/ifconfig",
		Args: []string{e.Host, "destroy"},
	})

	return err
}

func netstatFirstEtherIface(jail string) (*NetstatIface, error) {
	stdout, _, err := runCmd(&CmdOptions{
		Path: "/usr/bin/netstat",
		Args: []string{"-j", jail, "-i", "-4", "-n", "--libxo", "json"},
	})
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

func JailImport(name string, zfs *Zfs, zfsMountpoint, zfsSet string) (*JailImportResult, error) {
	zfsSource := zfsSet + "/" + name
	root := filepath.Join(zfsMountpoint, zfsSet, name)

	stdout, _, err := runCmd(&CmdOptions{
		Path: "/usr/sbin/jls",
		Args: []string{"-j", name, "meta"},
	})
	if err != nil {
		return nil, err
	}

	var jailMeta JailMeta
	err = json.Unmarshal(stdout, &jailMeta)
	if err != nil {
		log.Printf("invalid meta in jail %s", name)
		return nil, nil
	}

	if jailMeta.Magic != META_MARK {
		log.Printf("invalid meta magic %s in jail %s", jailMeta.Magic, name)
		return nil, nil
	}

	var uids map[string]IdMap
	var gids map[string]IdMap
	var uidMap IdMap

	err = parseIdentity(&uidMap, &uids, &gids, name, jailMeta.JailParams, zfsMountpoint, zfsSource)
	if err != nil {
		return nil, err
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
			vol := strings.TrimPrefix(mnt.Source, volumesPath+"/")
			mounts = append(mounts, vol)
		}
	}

	jail := Jail{
		Name:          name,
		Root:          root,
		ZfsDatasource: zfsSource,
		Interface:     epair,
		IpAddr:        ipAddr,
		Mounts:        mounts,
		Zfs:           zfs,
		ExecUser:      uidMap,
		UidMaps:       uids,
		GidMaps:       gids,
		Params:        jailMeta.JailParams,
	}

	return &JailImportResult{
		Jail:   &jail,
		Events: &jailMeta.Events,
	}, nil
}

func ImportUidMap(passwdPath string) (map[string]IdMap, error) {
	fd, err := os.Open(passwdPath)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)

	uids := map[string]IdMap{}

	lineNum := 0
	for scanner.Scan() {
		lineNum++

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.SplitN(line, ":", 7)
		if len(fields) != 7 {
			return nil, fmt.Errorf("invalid passwd format at line %d: %s", lineNum, line)
		}

		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("invalid passwd UID format at line %d: %s: %v", lineNum, line, err)
		}

		user := fields[0]
		if user == "" {
			return nil, fmt.Errorf("user is empty in passwd at line %d: %s", lineNum, line)
		}

		uids[user] = IdMap{
			Id:   uid,
			Name: user,
		}
	}

	return uids, nil
}

func ImportGidMap(groupPath string) (map[string]IdMap, error) {
	fd, err := os.Open(groupPath)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)

	gids := map[string]IdMap{}

	lineNum := 0
	for scanner.Scan() {
		lineNum++

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.SplitN(line, ":", 4)
		if len(fields) != 4 {
			return nil, fmt.Errorf("invalid group format at line %d: %s", lineNum, line)
		}

		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("invalid passwd GID format at line %d: %s: %v", lineNum, line, err)
		}

		group := fields[0]
		if group == "" {
			return nil, fmt.Errorf("group is empty in passwd at line %d: %s", lineNum, line)
		}

		gids[group] = IdMap{
			Id:   gid,
			Name: group,
		}
	}

	return gids, nil
}

func parseIdentity(uidMap *IdMap, uids *map[string]IdMap, gids *map[string]IdMap, name string, params JailParams, zfsMountpoint string, zfsSource string) error {
	var err error
	var ok bool

	*uids, err = ImportUidMap(filepath.Join(zfsMountpoint, zfsSource, "etc/passwd"))
	if err != nil {
		return err
	}

	*gids, err = ImportGidMap(filepath.Join(zfsMountpoint, zfsSource, "etc/group"))
	if err != nil {
		return err
	}

	jailUser := params["exec.jail_user"]
	if jailUser == "" {
		return fmt.Errorf("exec.jail_user params is required, jail %s", name)
	}

	*uidMap, ok = (*uids)[jailUser]
	if !ok {
		return fmt.Errorf("jail user %s was not found in jail %s /etc/passwd", jailUser, name)
	}

	if uidMap.Id == 0 {
		log.Printf("[WARN] running jail as root: %s", name)
	}

	return nil
}

func NewJail(manifest *Manifest, zfs *Zfs, config Config, zfsSet string, ipAddr netip.Addr) (*Jail, error) {
	zfsSource := zfsSet + "/" + manifest.Name

	log.Printf("creating jail %s", zfsSource)

	err := zfs.CreateSnapshot(manifest.Base, "base", true)
	if err != nil {
		return nil, err
	}

	err = zfs.Clone(manifest.Base+"@base", zfsSource, false)
	if err != nil {
		if os.IsExist(err) {
			err = zfs.Destroy(zfsSource, false)
			if err != nil {
				return nil, err
			}

			err = zfs.Clone(manifest.Base+"@base", zfsSource, false)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	epair, err := EpairCreate()
	if err != nil {
		zfs.Destroy(zfsSource, false)
		return nil, err
	}

	params, err := manifest.Params.JailParams()
	if err != nil {
		zfs.Destroy(zfsSource, false)
		return nil, err
	}

	var uids map[string]IdMap
	var gids map[string]IdMap
	var uidMap IdMap

	err = parseIdentity(&uidMap, &uids, &gids, manifest.Name, params, config.ZfsMountpoint, zfsSource)
	if err != nil {
		zfs.Destroy(zfsSource, false)
		return nil, err
	}

	// remove potentially harmful parameters
	delete(params, "mount.fstab")

	_, ok := params["host.hostname"]
	if !ok {
		params["host.hostname"] = manifest.Name
	}

	root := filepath.Join(config.ZfsMountpoint, zfsSource)

	params["name"] = manifest.Name
	params["vnet"] = ""
	params["vnet.interface"] = epair.Jail
	params["path"] = root
	params["exec.consolelog"] = filepath.Join(config.LogDir, manifest.Name+"_console.log")

	jailMeta := JailMeta{
		Magic:      META_MARK,
		JailParams: params,
		Events:     manifest.EventSubscription,
	}

	metadata, err := json.Marshal(jailMeta)
	if err != nil {
		return nil, fmt.Errorf("failed to create jail meta: %v", err)
	}

	// FIXME: check if meta can hold this, security.jail.meta_maxbufsize
	params["meta"] = string(metadata)

	mounts := []string{}

	for _, mnt := range manifest.Mounts {
		mounts = append(mounts, mnt.Volume)
	}

	return &Jail{
		Name:          manifest.Name,
		Root:          root,
		ZfsDatasource: zfsSource,
		Interface:     epair,
		IpAddr:        ipAddr,
		Mounts:        mounts,
		Zfs:           zfs,
		ExecUser:      uidMap,
		UidMaps:       uids,
		GidMaps:       gids,
		Params:        params,
	}, nil
}

func (j *Jail) Start() error {
	paramStr := []string{"-c"}
	for key, value := range j.Params {
		if len(value) > 0 {
			paramStr = append(paramStr, key+"="+value)
		} else {
			paramStr = append(paramStr, key)
		}
	}

	// using CloseFds here because unfortunately if the running
	// exec.start command holds the fds open, Go will keep trying
	// to read from it until it's either closed or times out
	_, _, err := runCmd(&CmdOptions{
		Path: "/usr/sbin/jail",
		Args: paramStr,
	})

	if err != nil {
		shutdownErr := j.Shutdown()
		destroyErr := j.Destroy()

		if shutdownErr != nil {
			err = fmt.Errorf("%v: %v", err, shutdownErr)
		}

		if destroyErr != nil {
			err = fmt.Errorf("%v: %v", err, destroyErr)
		}

		return err
	}

	err = j.initNetworking()
	if err != nil {
		defer j.Destroy()

		sErr := j.Shutdown()
		if sErr != nil {
			return fmt.Errorf("%v: %v", err, sErr)
		}

		return err
	}

	return nil
}

func (j *Jail) initNetworking() error {
	// jail side
	jailCidr := j.IpAddr.String() + "/32"
	_, _, err := runCmd(&CmdOptions{
		Path: "/sbin/ifconfig",
		Args: []string{
			"-j",
			j.Name,
			j.Interface.Jail,
			jailCidr},
	})
	if err != nil {
		return err
	}

	_, _, err = runCmd(&CmdOptions{
		Path: "/sbin/route",
		Args: []string{
			"-j", j.Name,
			"add",
			"-net", DEFAULT_GATEWAY_IP_ADDR + "/32",
			"-interface", j.Interface.Jail},
	})
	if err != nil {
		return err
	}

	_, _, err = runCmd(&CmdOptions{
		Path: "/sbin/route",
		Args: []string{"-j", j.Name, "add", "default", DEFAULT_GATEWAY_IP_ADDR},
	})
	if err != nil {
		return err
	}

	// host side
	_, _, err = runCmd(&CmdOptions{
		Path: "/sbin/ifconfig",
		Args: []string{j.Interface.Host, "inet", DEFAULT_GATEWAY_IP_ADDR + "/32"},
	})
	if err != nil {
		return err
	}

	_, _, err = runCmd(&CmdOptions{
		Path: "/sbin/route",
		Args: []string{"add", "-net", jailCidr, "-interface", j.Interface.Host},
	})

	return err
}

// TODO: tear down networking, but don't delete interface, move interface deletion to [`Destroy`]
// TODO: handle persistent jails
func (j *Jail) Shutdown() error {
	stopTimeout := DEFAULT_STOP_TIMEOUT

	jailStopTimeout := j.Params["stop.timeout"]
	if jailStopTimeout != "" {
		timeout, err := strconv.Atoi(jailStopTimeout)

		if err != nil {
			log.Printf("[WARN] invalid stop.timeout %s, using default %d", jailStopTimeout, stopTimeout)
		} else {
			stopTimeout = timeout
		}
	}

	_, _, err := runCmd(&CmdOptions{
		Path:    "/usr/sbin/jail",
		Args:    []string{"-r", j.Name},
		Timeout: stopTimeout + 10,
	})

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
			_, _, umountErr := runCmd(&CmdOptions{
				Path: "/sbin/umount",
				Args: []string{mnt.Mountpoint},
			})
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
	log.Printf("destroying jail %s %s", j.Name, j.ZfsDatasource)
	err := j.Zfs.Destroy(j.ZfsDatasource, true)

	return err
}

func (j *Jail) Exec(timeout int, command string, args ...string) error {
	a := []string{"-U", j.ExecUser.Name, j.Name, command}
	for _, arg := range args {
		a = append(a, arg)
	}

	log.Printf("jexec: %v", a)
	_, _, err := runCmd(&CmdOptions{
		Path: "/usr/sbin/jexec",
		Args: a,
	})

	return err
}

// caller should verify whether [`src`] is "trusted"
// callee does verify whether [`dst`] are within jail bounds
func (j *Jail) Copy(src, dst, owner, group string, modeStr string) error {
	uid, ok := j.UidMaps[owner]
	if !ok {
		return fmt.Errorf("unknown owner user %s in jail %s", owner, j.Name)
	}

	gid, ok := j.GidMaps[group]
	if !ok {
		return fmt.Errorf("unknown group %s in jail %s", group, j.Name)
	}

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

		err = os.Chown(hostDestPath, uid.Id, gid.Id)
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

		err = os.Chown(destPath, uid.Id, gid.Id)
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

	uid, ok := j.UidMaps[owner]
	if !ok {
		return fmt.Errorf("unknown owner user %s in jail %s", owner, j.Name)
	}

	gid, ok := j.GidMaps[group]
	if !ok {
		return fmt.Errorf("unknown group %s in jail %s", group, j.Name)
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

	_, _, err = runCmd(&CmdOptions{
		Path: "/sbin/mount",
		Args: []string{"-t", "nullfs", "-o", "nosuid,noexec,nodev", src, hostDestPath},
	})
	if err != nil {
		return err
	}

	err = os.Chmod(hostDestPath, os.FileMode(mode))
	if err != nil {
		return err
	}

	err = os.Chown(hostDestPath, uid.Id, gid.Id)
	if err != nil {
		return err
	}

	return nil
}
