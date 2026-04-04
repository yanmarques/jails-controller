package controller

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/moby/sys/mountinfo"
)

const SYS_ETHER_IFACE_FLAG = "0x8843"
const META_MARK = "0xdeadbeef"
const DEFAULT_GATEWAY_IP_ADDR string = "10.138.1.1"
const DEFAULT_STOP_TIMEOUT = 60

var DEFAULT_ALLOWED_JAIL_PARAMS = []string{
	"exec.clean",
	"mount.devfs",
	"exec.start",
	"exec.stop",
	"exec.jail_user",
	"stop.timeout",
	"host.hostname",
}

type IdMap struct {
	Id   int
	Name string
}

type JailParams map[string]string

type JailMeta struct {
	Magic      string
	JailParams JailParams
	Events     EventSubscription
	Hash       string
	Hints      map[string]string
	SubnetId   string
}

type Jail struct {
	Name          string
	Root          string
	ZfsDatasource string
	Interface     *Epair
	Zfs           *Zfs
	IpAddr        netip.Addr
	Mounts        []MountInfo
	ExecUser      IdMap
	UidMaps       map[string]IdMap
	GidMaps       map[string]IdMap
	Hash          string
	Params        JailParams
	Hints         map[string]string
	SubnetId      string
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
	Jail *Jail
	Meta *JailMeta
}

type JailOptions struct {
	Name     string
	Manifest *Manifest
	Zfs      *Zfs
	Config   Config
	ZfsSet   string
	IpAddr   netip.Addr
	Hash     string
	Hints    map[string]string
	SubnetId string
}

type MountInfo struct {
	Volume    string
	ReadWrite bool
}

func umountRecursively(root string) error {
	mntPrefix := strings.TrimSuffix(root, "/")
	mounts, err := mountinfo.GetMounts(mountinfo.PrefixFilter(mntPrefix))
	if err != nil {
		return err
	}

	for _, mnt := range mounts {
		if strings.TrimSuffix(mnt.Mountpoint, "/") == mntPrefix {
			continue
		}

		log.Printf("umounting %v", mnt.Mountpoint)
		_, _, umountErr := RunCmd(&CmdOptions{
			Path: "/sbin/umount",
			Args: []string{mnt.Mountpoint},
		})
		if umountErr != nil {
			err = fmt.Errorf("%v: %v", err, umountErr)
		}
	}

	return err
}

func EpairCreate() (*Epair, error) {
	stdout, _, err := RunCmd(&CmdOptions{
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
	_, stderr, err := RunCmd(&CmdOptions{
		Path: "/sbin/ifconfig",
		Args: []string{e.Host, "destroy"},
	})

	if err != nil {
		if bytes.Contains(stderr, []byte("does not exist")) {
			return nil
		}

		return err
	}

	return err
}

func netstatFirstEtherIface(jail string) (*NetstatIface, error) {
	stdout, _, err := RunCmd(&CmdOptions{
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

	stdout, _, err := RunCmd(&CmdOptions{
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

	mounts := []MountInfo{}
	volumesPath := filepath.Join(zfsMountpoint, "volumes")
	for _, mnt := range jailMounts {
		if strings.TrimSuffix(mnt.Mountpoint, "/") == mntPrefix {
			continue
		}

		if strings.HasPrefix(mnt.Source, volumesPath) && mnt.FSType == "nullfs" {
			vol := strings.TrimPrefix(mnt.Source, volumesPath+"/")
			options := strings.Split(mnt.Options, ",")
			rw := slices.Contains(options, "rw")
			mounts = append(mounts, MountInfo{
				Volume:    vol,
				ReadWrite: rw,
			})
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
		Hash:          jailMeta.Hash,
		Hints:         jailMeta.Hints,
		SubnetId:      jailMeta.SubnetId,
	}

	return &JailImportResult{
		Jail: &jail,
		Meta: &jailMeta,
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

func NewJail(options *JailOptions) (*Jail, error) {
	jailName := options.Name
	if jailName == "" {
		jailName = options.Manifest.Name
	}

	zfsSource := options.ZfsSet + "/" + options.Manifest.Name
	root := filepath.Join(options.Config.ZfsMountpoint, zfsSource)

	log.Printf("creating jail %s", zfsSource)

	err := options.Zfs.CreateSnapshot(options.Manifest.Base, "base", true)
	if err != nil {
		return nil, err
	}

	err = options.Zfs.Clone(options.Manifest.Base+"@base", zfsSource, false)
	if err != nil {
		if os.IsExist(err) {
			err = umountRecursively(root)
			if err != nil {
				return nil, err
			}

			err = options.Zfs.Destroy(zfsSource, false)
			if err != nil {
				return nil, err
			}

			err = options.Zfs.Clone(options.Manifest.Base+"@base", zfsSource, false)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	epair, err := EpairCreate()
	if err != nil {
		options.Zfs.Destroy(zfsSource, false)
		return nil, err
	}

	untrustedParams, err := options.Manifest.Params.JailParams()
	if err != nil {
		options.Zfs.Destroy(zfsSource, false)
		return nil, err
	}

	params := JailParams{}
	for _, key := range options.Config.AllowedJailParams {
		value, ok := untrustedParams[key]
		if ok {
			params[key] = value
		}
	}

	_, ok := params["host.hostname"]
	if !ok {
		params["host.hostname"] = jailName
	}

	if !ValidHostname(params["host.hostname"]) {
		options.Zfs.Destroy(zfsSource, false)
		return nil, fmt.Errorf("invalid jail hostname: %s", params["host.hostname"])
	}

	params["name"] = jailName
	params["vnet"] = ""
	params["vnet.interface"] = epair.Jail
	params["path"] = root
	params["exec.consolelog"] = filepath.Join(options.Config.LogDir, options.Manifest.Name+"_console.log")

	var uids map[string]IdMap
	var gids map[string]IdMap
	var uidMap IdMap

	err = parseIdentity(&uidMap, &uids, &gids, jailName, params, options.Config.ZfsMountpoint, zfsSource)
	if err != nil {
		options.Zfs.Destroy(zfsSource, false)
		return nil, err
	}

	jailMeta := JailMeta{
		Magic:      META_MARK,
		JailParams: params,
		Events:     options.Manifest.EventSubscription,
		Hash:       options.Hash,
		Hints:      options.Hints,
		SubnetId:   options.SubnetId,
	}

	metadata, err := json.Marshal(jailMeta)
	if err != nil {
		return nil, fmt.Errorf("failed to create jail meta: %v", err)
	}

	// FIXME: check if meta can hold this, security.jail.meta_maxbufsize
	params["meta"] = string(metadata)

	mounts := []MountInfo{}

	for _, mnt := range options.Manifest.Mounts {
		mounts = append(mounts, MountInfo{
			Volume:    mnt.Volume,
			ReadWrite: mnt.ReadWrite,
		})
	}

	return &Jail{
		Name:          jailName,
		Root:          root,
		ZfsDatasource: zfsSource,
		Interface:     epair,
		IpAddr:        options.IpAddr,
		Mounts:        mounts,
		Zfs:           options.Zfs,
		ExecUser:      uidMap,
		UidMaps:       uids,
		GidMaps:       gids,
		Params:        params,
		Hash:          options.Hash,
		Hints:         options.Hints,
		SubnetId:      options.SubnetId,
	}, nil
}

func (j *Jail) Hostname() (string, bool) {
	h, ok := j.Params["host.hostname"]
	return h, ok
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

	_, _, err := RunCmd(&CmdOptions{
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

	return nil
}

func routeDel(args []string, notExistOk bool) error {
	_, stderr, err := RunCmd(&CmdOptions{
		Path: "/sbin/route",
		Args: args,
	})

	if err != nil {
		if notExistOk && bytes.Contains(stderr, []byte("route has not been found")) {
			return nil
		}

		if notExistOk && bytes.Contains(stderr, []byte("does not exist")) {
			return nil
		}

		return err
	}

	return nil
}

func routeAdd(args []string, existOk bool) error {
	_, stderr, err := RunCmd(&CmdOptions{
		Path: "/sbin/route",
		Args: args,
	})

	if err != nil {
		if existOk && bytes.Contains(stderr, []byte("File exists")) {
			return nil
		}

		return err
	}

	return nil
}

func (j *Jail) initNetworking() error {
	// jail side
	_, _, err := RunCmd(&CmdOptions{
		Path: "/sbin/ifconfig",
		Args: []string{
			"-j",
			j.Name,
			"lo0",
			"inet",
			"127.0.0.1/8"},
	})
	if err != nil {
		return err
	}

	jailCidr := j.IpAddr.String() + "/32"
	_, _, err = RunCmd(&CmdOptions{
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

	err = routeAdd([]string{
		"-j", j.Name,
		"add",
		"-net", DEFAULT_GATEWAY_IP_ADDR + "/32",
		"-interface", j.Interface.Jail},
		true,
	)
	if err != nil {
		return err
	}

	err = routeAdd([]string{"-j", j.Name, "add", "default", DEFAULT_GATEWAY_IP_ADDR}, true)
	if err != nil {
		return err
	}

	// host side
	_, _, err = RunCmd(&CmdOptions{
		Path: "/sbin/ifconfig",
		Args: []string{j.Interface.Host, "inet", DEFAULT_GATEWAY_IP_ADDR + "/32"},
	})
	if err != nil {
		return err
	}

	err = routeAdd([]string{"add", "-net", jailCidr, "-interface", j.Interface.Host}, true)
	return err
}

func (j *Jail) teardownNetworking() error {
	// host side
	return routeDel([]string{"del", "-net", j.IpAddr.String(), "-interface", j.Interface.Host}, true)
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

	_, stderr, err := RunCmd(&CmdOptions{
		Path:    "/usr/sbin/jail",
		Args:    []string{"-r", j.Name},
		Timeout: stopTimeout + 10,
	})
	if err != nil && bytes.Contains(stderr, []byte("not found")) {
		err = nil
	}

	umountErr := umountRecursively(j.Root)
	if umountErr != nil {
		err = fmt.Errorf("%v: %v", err, umountErr)
	}

	netErr := j.teardownNetworking()
	if netErr != nil {
		err = fmt.Errorf("%v: %v", err, netErr)
	}

	return err
}

func (j *Jail) Destroy() error {
	log.Printf("destroying jail %s %s", j.Name, j.ZfsDatasource)
	err := j.Zfs.Destroy(j.ZfsDatasource, true)

	epairErr := j.Interface.Delete()
	if epairErr != nil {
		err = fmt.Errorf("%v: %v", err, epairErr)
	}

	return err
}

func (j *Jail) Exec(timeout int, command string, args ...string) error {
	a := []string{"-U", j.ExecUser.Name, j.Name, command}
	for _, arg := range args {
		a = append(a, arg)
	}

	log.Printf("jexec: %v", a)
	_, _, err := RunCmd(&CmdOptions{
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

	if !srcStat.Mode().IsRegular() {
		return fmt.Errorf("will not copy links: %v", src)
	}

	log.Printf("jail copy src %s dst %s", src, dst)

	hostDestPath := safePathJoin(j.Root, dst)
	if len(hostDestPath) == 0 {
		return fmt.Errorf("invalid copy dst path: can not copy outside jail root: %s", dst)
	}

	dstStat, dstStatErr := os.Stat(hostDestPath)
	if dstStatErr != nil {
		if !os.IsNotExist(dstStatErr) {
			return dstStatErr
		}
	}

	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return err
	}

	if !srcStat.IsDir() {
		if dstStatErr != nil && os.IsNotExist(dstStatErr) {
			parentDir := filepath.Dir(hostDestPath)
			if !strings.HasPrefix(parentDir, j.Root) {
				return fmt.Errorf("copy dest does not exist in jail: %s", dst)
			}

			_, err := os.Stat(parentDir)
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("copy dest does not exist in jail: %s", dst)
				}
				return err
			}
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
func (j *Jail) Mount(src, dst, owner, group, modeStr string, readWrite bool, dangerousAllowLinks bool) error {
	var ok bool
	var uid IdMap
	var gid IdMap

	if readWrite {
		uid, ok = j.UidMaps[owner]
		if !ok {
			return fmt.Errorf("unknown owner user %s in jail %s", owner, j.Name)
		}

		gid, ok = j.GidMaps[group]
		if !ok {
			return fmt.Errorf("unknown group %s in jail %s", group, j.Name)
		}
	}

	srcStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	src, err = filepath.Abs(src)
	if err != nil {
		return err
	}

	if !dangerousAllowLinks && !srcStat.Mode().IsRegular() {
		return fmt.Errorf("will not copy links: %v", src)
	}

	hostDestPath := safePathJoin(j.Root, dst)
	if len(hostDestPath) == 0 {
		return fmt.Errorf("invalid mount dst path: can not mount outside jail root: %s", dst)
	}

	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return err
	}

	var mntOptions string

	if srcStat.IsDir() {
		err = os.Mkdir(hostDestPath, os.FileMode(mode))
		if err != nil {
			if !os.IsExist(err) {
				return err
			}
		}

		mntOptions = "nosuid,noexec,nodev,"
	} else {
		mntOptions = ""
	}

	mask := "ro"
	if readWrite {
		mask = "rw"
	}

	_, _, err = RunCmd(&CmdOptions{
		Path: "/sbin/mount",
		Args: []string{"-t", "nullfs", "-o", mntOptions + mask, src, hostDestPath},
	})
	if err != nil {
		return err
	}

	if readWrite {
		err = os.Chmod(hostDestPath, os.FileMode(mode))
		if err != nil {
			return err
		}

		err = os.Chown(hostDestPath, uid.Id, gid.Id)
		if err != nil {
			return err
		}
	}

	return nil
}
