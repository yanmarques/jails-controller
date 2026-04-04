package controller

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func copyFile(src, dest string, perm os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	err = os.Chmod(dest, perm)
	if err != nil {
		return err
	}

	_, err = io.Copy(destFile, srcFile)
	return err
}

func safePathJoin(base string, untrusted ...string) string {
	base = filepath.Clean(base)
	u := []string{base}
	for _, p := range untrusted {
		u = append(u, p)
	}
	path := filepath.Join(u...)
	if !strings.HasPrefix(path, base) {
		return ""
	}

	return path
}

func ValidHostname(hostname string) bool {
	if hostname == "" {
		return false
	}

	if strings.TrimSpace(hostname) == "" {
		return false
	}

	if len(hostname) > 512 {
		return false
	}

	parsedUrl, err := url.Parse("https://" + hostname + "/")
	if err != nil {
		return false
	}

	if parsedUrl.Host != hostname {
		return false
	}

	if !((hostname[0] >= 'a' && hostname[0] <= 'z') ||
		(hostname[0] >= 'A' && hostname[0] <= 'Z') ||
		(hostname[0] >= '0' && hostname[0] <= '9')) {
		return false
	}

	for _, char := range hostname {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-') {
			return false
		}
	}

	return true
}

func RunCmd(options *CmdOptions) ([]byte, []byte, error) {
	if options.Timeout <= 0 {
		options.Timeout = DEFAULT_CMD_TIMEOUT_SMALL
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(options.Timeout)*time.Second)
	defer cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.CommandContext(ctx, options.Path, options.Args...)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if options.CloseFds {
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
	} else {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		cmd.Stdin = options.Stdin
	}

	// this WaitDelay addresses a bug on Go command execution,
	// maybe on FreeBSD only, when an open file descriptor is not
	// closed by the callee process (identified here by [`options.Path`]),
	// causing Go I/O coroutines to wait forever.
	cmd.WaitDelay = time.Duration(DEFAULT_CMD_TIMEOUT_SMALL) * time.Second

	err := cmd.Run()

	stdoutB := stdout.Bytes()
	stderrB := stderr.Bytes()

	if ctx.Err() == context.DeadlineExceeded {
		return stdoutB, stderrB, fmt.Errorf("command timed out: stdout=%s stderr=%s: %v %v",
			strings.TrimSpace(string(stdoutB)), strings.TrimSpace(string(stderrB)),
			options.Path, options.Args)
	}

	if err != nil {
		return stdoutB, stderrB, fmt.Errorf("%v: stdout=%s stderr=%s: %v %v",
			err, strings.TrimSpace(string(stdoutB)), strings.TrimSpace(string(stderrB)),
			options.Path, options.Args)
	}

	return stdoutB, stderrB, nil
}

func VolumeSize(size string) (int, error) {
	if size == "none" {
		return -1, nil
	}

	idx := len(size)
	if strings.HasSuffix(size, "G") {
		idx--
	}

	log.Printf("volume size: %s", size[:idx])
	n, err := strconv.Atoi(size[:idx])
	if err != nil {
		return 0, err
	}

	if n < 1 {
		return 0, fmt.Errorf("volume size can not be lower than 1 GB")
	}

	return n, nil
}
