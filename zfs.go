package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

type Zfs struct {
	Root string
}

type ZfsCreateOptions struct {
	Filesystem string
	Mountpoint string
	QuotaSize  int
	ExistOk    bool
}

func NewZfs(root string) *Zfs {
	return &Zfs{
		Root: strings.TrimSuffix(root, "/"),
	}
}

func (z *Zfs) Clone(src, dst string, existOk bool) error {
	srcSet := z.ToDataset(src)
	dstSet := z.ToDataset(dst)
	err := runCmd(DEFAULT_CMD_TIMEOUT_SMALL, "/sbin/zfs", "list", "-t", "snapshot", srcSet)
	if err != nil {
		return fmt.Errorf("no such snapshot: %s: %v", srcSet, err)
	}

	_, stderr, err := runCmdOutput("/sbin/zfs", "clone", srcSet, dstSet)
	if err != nil {
		if bytes.Contains(stderr, []byte("dataset already exists")) {
			if existOk {
				return nil
			}

			return &os.PathError{
				Op:   "clone",
				Path: dstSet,
				Err:  os.ErrExist,
			}
		}

		return err
	}

	return nil
}

func (z *Zfs) CreateSnapshot(dataset, snapName string, existOk bool) error {
	snapshot := z.ToDataset(dataset + "@" + snapName)
	_, stderr, err := runCmdOutput("/sbin/zfs", "snapshot", snapshot)
	if err != nil {
		if bytes.Contains(stderr, []byte("dataset already exists")) {
			if existOk {
				return nil
			}

			return &os.PathError{
				Op:   "clone",
				Path: snapshot,
				Err:  os.ErrExist,
			}
		}

		return err
	}

	return nil
}

func (z *Zfs) Destroy(filesystem string, notExistsOk bool) error {
	_, stderr, err := runCmdOutput("/sbin/zfs", "destroy", z.ToDataset(filesystem))
	if err != nil {
		if bytes.Contains(stderr, []byte("dataset does not exist")) {
			if notExistsOk {
				return nil
			}

			return err
		}
	}

	return nil
}

func (z *Zfs) ListFilesystems(root string) (map[string]*VolumeManifest, error) {
	rootSet := z.ToDataset(root)
	stdout, _, err := runCmdOutput("/sbin/zfs", "list", "-o", "name,quota",
		"-t", "filesystem", "-H", "-d", "1", "-r", rootSet)
	if err != nil {
		return nil, err
	}

	volumes := map[string]*VolumeManifest{}
	rootSlash := strings.TrimSuffix(rootSet, "/") + "/"

	out := strings.TrimSpace(string(stdout))
	for line := range strings.SplitSeq(out, "\n") {
		elements := strings.SplitN(line, "\t", 2)
		if elements[0] != rootSet {
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

func (z *Zfs) Set(options *ZfsCreateOptions) error {
	args := []string{
		"set",
	}
	if options.QuotaSize > 0 {
		args = append(args, fmt.Sprintf("quota=%dG", options.QuotaSize))
	}

	args = append(args, z.ToDataset(options.Filesystem))

	return runCmd(DEFAULT_CMD_TIMEOUT_SMALL, "/sbin/zfs", args...)
}

func (z *Zfs) Create(options *ZfsCreateOptions) error {
	args := []string{
		"create",
	}
	if len(options.Mountpoint) > 0 {
		args = append(args, "-o")
		args = append(args, "mountpoint="+options.Mountpoint)
	}

	if options.QuotaSize > 0 {
		args = append(args, "-o")
		args = append(args, fmt.Sprintf("quota=%dG", options.QuotaSize))
	}

	args = append(args, z.ToDataset(options.Filesystem))

	_, stderr, err := runCmdOutput("/sbin/zfs", args...)
	if err != nil {
		if bytes.Contains(stderr, []byte("dataset already exists")) {
			if options.ExistOk {
				return nil
			}

			return &os.PathError{
				Op:   "clone",
				Path: z.ToDataset(options.Filesystem),
				Err:  os.ErrExist,
			}
		}

		return err
	}

	return nil
}

func (z *Zfs) ToDataset(root string) string {
	if root == "/" {
		return z.Root
	}

	return z.Root + "/" + root
}
