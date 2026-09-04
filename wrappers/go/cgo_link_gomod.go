package wispersgo

// Link directives for the Go-module build only: `go build` finds the
// prebuilt static library where fetch-lib put it, under lib/<platform>/
// next to this file. The Bazel build (wrappers/go/BUILD.bazel) excludes
// this file and supplies the library through cdeps instead; the system
// libraries every platform needs stay in wispers.go, which both builds
// compile.

/*
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/lib/darwin_arm64 -lwispers_connect
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin_amd64 -lwispers_connect
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib/linux_arm64 -lwispers_connect
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux_amd64 -lwispers_connect
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/lib/windows_amd64 -lwispers_connect
*/
import "C"
