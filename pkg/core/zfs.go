package controller

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"
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
	_, _, err := RunCmd(&CmdOptions{
		Path: "/sbin/zfs",
		Args: []string{"list", "-t", "snapshot", srcSet},
	})
	if err != nil {
		return fmt.Errorf("no such snapshot: %s: %v", srcSet, err)
	}

	_, stderr, err := RunCmd(&CmdOptions{
		Path: "/sbin/zfs",
		Args: []string{"clone", srcSet, dstSet},
	})
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
	_, stderr, err := RunCmd(&CmdOptions{
		Path: "/sbin/zfs",
		Args: []string{"snapshot", snapshot},
	})
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

// Try to destroy the filesystem, with automatic retry.
// It will retry up to 10 seconds to destroy.
func (z *Zfs) Destroy(filesystem string, notExistsOk bool) error {
	var retries int
	var err error
	var stderr []byte

	for {
		if retries >= 20 {
			return err
		}

		_, stderr, err = RunCmd(&CmdOptions{
			Path: "/sbin/zfs",
			Args: []string{"destroy", z.ToDataset(filesystem)},
		})
		if err != nil {
			if notExistsOk && bytes.Contains(stderr, []byte("dataset does not exist")) {
				return nil

			}

			if !bytes.Contains(stderr, []byte("pool or dataset is busy")) {
				return err
			}
		} else {
			return nil
		}

		retries++
		time.Sleep(500 * time.Millisecond)
	}
}

func (z *Zfs) ListFilesystems(root string) (map[string]*VolumeManifest, error) {
	rootSet := z.ToDataset(root)
	stdout, _, err := RunCmd(&CmdOptions{
		Path: "/sbin/zfs",
		Args: []string{"list", "-o", "name,quota",
			"-t", "filesystem", "-H", "-d", "1", "-r", rootSet},
	})
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

	_, _, err := RunCmd(&CmdOptions{
		Path: "/sbin/zfs",
		Args: args,
	})

	return err
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

	_, stderr, err := RunCmd(&CmdOptions{
		Path: "/sbin/zfs",
		Args: args,
	})
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
