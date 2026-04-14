// fetch-lib downloads the prebuilt wispers-connect static library and header
// for the current platform from GitHub Releases.
//
// Usage:
//
//	go run github.com/s-te-ch/wispers-client/wrappers/go/cmd/fetch-lib@v0.8.0
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
)

func main() {
	version := moduleVersion()
	platform := runtime.GOOS + "_" + runtime.GOARCH
	asset := fmt.Sprintf("libwispers_connect-%s.a", platform)

	modDir := wispersModDir(version)
	libDir := filepath.Join(modDir, "lib", platform)
	libPath := filepath.Join(libDir, "libwispers_connect.a")
	headerPath := filepath.Join(modDir, "lib", "wispers_connect.h")

	if fileExists(libPath) && fileExists(headerPath) {
		fmt.Printf("Already fetched: %s\n", libPath)
		return
	}

	repo := "s-te-ch/wispers-client"

	if err := os.MkdirAll(libDir, 0o755); err != nil {
		fatal("creating lib dir: %v", err)
	}

	if !fileExists(libPath) {
		fmt.Printf("Downloading %s from release %s...\n", asset, version)
		url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, version, asset)
		if err := download(url, libPath); err != nil {
			fatal("downloading library: %v", err)
		}
	}

	if !fileExists(headerPath) {
		fmt.Println("Downloading header...")
		url := fmt.Sprintf("https://github.com/%s/releases/download/%s/wispers_connect.h", repo, version)
		if err := download(url, headerPath); err != nil {
			fatal("downloading header: %v", err)
		}
	}

	fmt.Printf("Done: %s\n", libPath)
}

func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, dep := range info.Deps {
			if strings.HasSuffix(dep.Path, "wrappers/go") {
				return dep.Version
			}
		}
		// We are the main module being run via go run
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}

	// Fallback: check args
	if len(os.Args) > 1 {
		return os.Args[1]
	}

	fatal("could not determine version. Pass it as an argument: fetch-lib v0.8.0")
	return ""
}

func wispersModDir(version string) string {
	// Find the module cache directory
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		fatal("go env GOMODCACHE: %v", err)
	}
	modCache := strings.TrimSpace(string(out))
	modDir := filepath.Join(modCache, "github.com", "s-te-ch", "wispers-client", "wrappers", "go@"+version)

	if !fileExists(modDir) {
		fatal("module directory not found: %s\nRun: go get github.com/s-te-ch/wispers-client/wrappers/go@%s", modDir, version)
	}

	// The module cache is read-only; make lib dir writable
	libDir := filepath.Join(modDir, "lib")
	if !fileExists(libDir) {
		// Need to make the parent writable temporarily
		os.Chmod(modDir, 0o755)
	}

	return modDir
}

func download(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return fmt.Errorf("not found: %s (platform may not be supported yet)", url)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "fetch-lib: "+format+"\n", args...)
	os.Exit(1)
}
