// APIARY #3179: the test for dimse_status_patch itself.
//
// The behavioural proof lives in testdata/ax_status_3179_test.go, a file in
// package dicompot that this test writes into a throwaway copy of the pinned
// nsmfoo/dicompot module -- once as pinned, once patched -- and then runs
// with `go test`. The identical suite is therefore executed against the
// unpatched dependency and against the patched one, and this test asserts
// that the first fails and the second passes. That is the whole point of
// running the unpatched copy at all: a suite that only ever ran green could
// be satisfied by a patch that changed nothing, and #3179's asks are stated
// as wire behaviour, not as "the patcher's strings are present".
//
// This mirrors how the repo's other dependency patches are tested --
// arcane/home/honeypot-cowrie/cowrie/tests/test_txtcmds_priority_patch.py
// applies its patcher to a fixture and then execs the result -- with the
// fixture upgraded from a text excerpt to the real pinned module, because
// the two tells under test are decided inside unexported functions of that
// module and no in-tree shim could reach them.
package main

import (
	"bytes"
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const dependencyPath = "github.com/nsmfoo/dicompot"

// suiteSource is the behavioural suite, written into each copy of the pinned
// module. It has to be a real file in package dicompot rather than a string
// because it calls onAssociateRequest, handleCFind, handleCMove and
// handleCGet, none of which this repository can reach from outside the
// dependency. testdata keeps it out of `go build ./...` and `go vet` while
// leaving it gofmt-checked, since quality.yml's gofmt gate walks every *.go
// in the tree.
//
//go:embed testdata/ax_status_3179_test.go
var suiteSource []byte

// suiteRunPattern selects the behavioural suite inside the copied module. The
// copied module has no tests of its own, so it only narrows the run.
const suiteRunPattern = "TestAssociation|TestCFind|TestCMove|TestCGet|TestARefusedQuery"

// suiteFile is the testdata file written into each copy of the dependency.
const suiteFile = "ax_status_3179_test.go"

// pinnedModuleDir resolves the dependency's source directory the way the
// build does, from the module graph rather than by guessing at a GOMODCACHE
// layout -- the same `go list -m -f {{.Dir}}` the Dockerfile's build step
// uses, so the copy under test is the one the image would patch.
func pinnedModuleDir(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Version}} {{.Dir}}", dependencyPath)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -m %s: %v\n%s", dependencyPath, err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) != 2 {
		t.Fatalf("go list -m %s returned %q, want <version> <dir>", dependencyPath, out)
	}
	if version := fields[0]; version != PinnedRevision {
		t.Fatalf("go.mod pins %s at %s but this patch's anchors were taken from %s; "+
			"re-derive every anchor against the new revision and bump PinnedRevision "+
			"(the build would fail the same way, one layer later)", dependencyPath, version, PinnedRevision)
	}
	return fields[1]
}

// copyTree copies src to dst, making both writable: a module cache stores
// every file mode 0555, and the patcher writes in place.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copying %s: %v", src, err)
	}
}

var (
	warmOnce sync.Once
	warmedOK bool
)

// warmDependencyDeps puts the pinned module's *own* dependency set into the
// module cache, once per test process.
//
// This is not a convenience. The copy is built under its own go.mod, so
// minimal version selection there resolves the dependency's requirements --
// e.g. golang.org/x/sys v0.1.0 and golang.org/x/text v0.3.8 -- rather than
// the higher versions this module's own build list upgraded them to. A clean
// runner has only the outer, higher versions in its cache, so the copy's
// build cannot resolve anything the outer build never downloaded.
//
// Warming here, with the ambient proxy, keeps the nested test runs themselves
// hermetic (GOPROXY=off below), so a module that is genuinely unavailable
// still fails as a clear resolution error instead of a mid-test fetch.
//
// It is deliberately best-effort and never fatal. A developer running offline
// with an already-warm cache cannot fetch anything, but does not need to: the
// nested runs will resolve from that same cache. Only the combination of a
// cold cache and no proxy is actually fatal, and that is reported by the
// nested run itself, with a message aimed at the cache rather than the patch.
func warmDependencyDeps(t *testing.T) {
	t.Helper()
	warmOnce.Do(func() {
		// Any directory carrying the pinned module's go.mod/go.sum will do; the
		// download populates the shared module cache, not this directory.
		dir := t.TempDir()
		copyTree(t, pinnedModuleDir(t), dir)
		cmd := exec.Command("go", "mod", "download", "all")
		cmd.Dir = dir
		// No GOPROXY override: the point is to use whatever proxy the caller
		// has, and an inherited GOPROXY=off simply reports warmedOK = false.
		cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Logf("could not pre-fetch the pinned module's own dependency set (%v); "+
				"continuing on the assumption the module cache already has it. If a nested "+
				"run then fails to resolve a module, that is the cause:\n%s", err, out)
			return
		}
		warmedOK = true
	})
	if !warmedOK {
		t.Log("the pinned module's own dependencies were not pre-fetched; the module cache must " +
			"already contain them for the nested runs to resolve offline")
	}
}

// moduleResolutionFailureIn returns the portion of a nested `go test` run that
// shows the go command could not resolve a module from the cache, or "" if
// that is not what went wrong.
func moduleResolutionFailureIn(out string) string {
	for _, marker := range []string{
		"module lookup disabled by GOPROXY=off",
		"missing go.sum entry",
		"cannot find module",
		"module lookup disabled by GOPROXY",
	} {
		if i := strings.Index(out, marker); i >= 0 {
			start := strings.LastIndex(out[:i], "\n") + 1
			return strings.TrimSpace(out[start:])
		}
	}
	return ""
}

// requireNoCacheMiss fails the current test when a nested run failed to
// resolve a module rather than to fail an assertion. The two look alike from
// outside -- both are a non-zero exit -- but only one of them says anything
// about tells 2 and 5, and reporting a module-cache problem as a behavioural
// RED (or GREEN) would be actively misleading.
func requireNoCacheMiss(t *testing.T, what, out string) {
	t.Helper()
	if miss := moduleResolutionFailureIn(out); miss != "" {
		t.Fatalf("%s could not resolve a module from the cache, so it exercised nothing. "+
			"The copy is built under the pinned module's own go.mod, whose build list "+
			"(golang.org/x/sys v0.1.0, golang.org/x/text v0.3.8) differs from this "+
			"module's (v0.47.0, v0.41.0), so the outer build never downloaded them:\n%s",
			what, miss)
	}
}

// nestedGoTest runs `go test` inside a copy of the dependency module. The
// environment is pinned so the nested run cannot silently reach the network
// or pick up an unrelated go.work: warmDependencyDeps has already put
// everything the copy needs in the module cache.
func nestedGoTest(t *testing.T, dir string) (string, error) {
	t.Helper()
	cmd := exec.Command("go", "test", "-count=1", "-run", suiteRunPattern, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOPROXY=off", // cache only; a missing module must fail here, not hang on a fetch
		"GOFLAGS=",    // neutralise an inherited -mod flag against the copy's own go.mod
		"GOWORK=off",  // a stray go.work above the temp dir would change resolution
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// prepareModule copies the pinned module into t.TempDir() with the
// behavioural suite written in, and returns the copy's path. It warms the
// module cache first, since every caller here builds the copy under the
// dependency's own go.mod.
func prepareModule(t *testing.T) string {
	t.Helper()
	warmDependencyDeps(t)
	dir := filepath.Join(t.TempDir(), "dicompot")
	copyTree(t, pinnedModuleDir(t), dir)
	if err := os.WriteFile(filepath.Join(dir, suiteFile), suiteSource, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// buildFailureIn returns the portion of a nested `go test` run that reports a
// build or vet failure rather than a failed test, or "" if the run got as far
// as executing tests. The markers are the ones the go tool prints on its own;
// the suite's own messages never contain them.
func buildFailureIn(out string) string {
	for _, marker := range []string{
		"[build failed]",
		"build constraints exclude all Go files",
		"vet: ",
		"undefined: ",
		"cannot use",
		"syntax error",
	} {
		if i := strings.Index(out, marker); i >= 0 {
			start := strings.LastIndex(out[:i], "\n") + 1
			return strings.TrimSpace(out[start:])
		}
	}
	return ""
}

// TestSuiteIsRedAgainstThePinnedDependencyAndGreenWithThePatch is #3179's
// proof obligation: the same suite, run twice, once against the dependency
// exactly as go.mod resolves it and once with the patch applied.
func TestSuiteIsRedAgainstThePinnedDependencyAndGreenWithThePatch(t *testing.T) {
	t.Run("red against the unpatched dependency", func(t *testing.T) {
		unpatched := prepareModule(t)
		out, err := nestedGoTest(t, unpatched)
		if err == nil {
			t.Fatalf("the behavioural suite passed against the UNPATCHED pinned dependency, so it "+
				"proves nothing about the patch. Either nsmfoo/dicompot has fixed tells 2 and 5 "+
				"upstream (retire the patch) or the suite lost its assertions.\n\n%s", out)
		}
		// A non-zero exit is not by itself proof of RED: a suite that could
		// not resolve a module, or that no longer *compiles* against the
		// pinned dependency, also exits non-zero, and would leave this
		// subtest green while saying nothing about tells 2 and 5. Require an
		// assertion failure, and name the real cause loudly if it was not.
		requireNoCacheMiss(t, "the behavioural suite against the unpatched dependency", out)
		if buildErr := buildFailureIn(out); buildErr != "" {
			t.Fatalf("the behavioural suite did not compile against the UNPATCHED pinned dependency, "+
				"so this RED run proves nothing about the patch (a build break, not a failed "+
				"assertion). The suite must compile unpatched and fail on behaviour:\n%s", buildErr)
		}
		if !strings.Contains(out, "--- FAIL: Test") {
			t.Fatalf("the behavioural suite exited non-zero against the unpatched dependency but no "+
				"test reported a failed assertion:\n%s", out)
		}
		t.Logf("unpatched %s fails as it must:\n%s", PinnedRevision, out)
	})

	t.Run("green with the patch applied", func(t *testing.T) {
		patched := prepareModule(t)
		status, err := applyPatch(patched)
		if err != nil {
			t.Fatalf("applyPatch: %v", err)
		}
		t.Logf("applyPatch: %s", status)
		out, err := nestedGoTest(t, patched)
		if err != nil {
			requireNoCacheMiss(t, "the behavioural suite with the patch applied", out)
			t.Fatalf("the behavioural suite still fails with the patch applied:\n%s", out)
		}
		t.Logf("patched dependency passes:\n%s", out)
	})
}

// TestPatchedDependencyCompiles is separate from the suite so a plain build
// break is reported as one, rather than as a wall of failed assertions.
func TestPatchedDependencyCompiles(t *testing.T) {
	patched := prepareModule(t)
	if _, err := applyPatch(patched); err != nil {
		t.Fatalf("applyPatch: %v", err)
	}
	cmd := exec.Command("go", "build", ".")
	cmd.Dir = patched
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		requireNoCacheMiss(t, "the patched dependency's build", string(out))
		t.Fatalf("the patched dependency does not build: %v\n%s", err, out)
	}
}

// TestPatchedDependencyIsGofmtClean keeps the repository's own gofmt gate
// honest for code that does not live in the repository: a patch that lands
// unformatted Go inside the dependency would otherwise only be caught by a
// hand-run gofmt, never by CI.
func TestPatchedDependencyIsGofmtClean(t *testing.T) {
	patched := prepareModule(t)
	if _, err := applyPatch(patched); err != nil {
		t.Fatalf("applyPatch: %v", err)
	}
	out, err := exec.Command("gofmt", "-l", patched).CombinedOutput()
	if err != nil {
		t.Fatalf("gofmt -l: %v\n%s", err, out)
	}
	// The behavioural suite is testdata, not part of the image build; it is
	// gofmt-checked in its own right by this repository's gate instead.
	var unformatted []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" || filepath.Base(strings.TrimSpace(line)) == suiteFile {
			continue
		}
		unformatted = append(unformatted, strings.TrimSpace(line))
	}
	if len(unformatted) > 0 {
		t.Errorf("the patch lands unformatted Go in the dependency:\n%s", strings.Join(unformatted, "\n"))
	}
}

// TestApplyIsIdempotent: the build runs on every image rebuild, and a second
// apply must be a no-op rather than the "expected exactly 1 match" failure.
func TestApplyIsIdempotent(t *testing.T) {
	dir := prepareModule(t)
	first, err := applyPatch(dir)
	if err != nil {
		t.Fatalf("first applyPatch: %v", err)
	}
	if !strings.Contains(first, PinnedRevision) {
		t.Errorf("applyPatch status %q does not name the pinned revision it patched", first)
	}
	after, err := os.ReadFile(filepath.Join(dir, contextManagerFile))
	if err != nil {
		t.Fatal(err)
	}
	second, err := applyPatch(dir)
	if err != nil {
		t.Fatalf("second applyPatch: %v", err)
	}
	if !strings.Contains(second, "already patched") {
		t.Errorf("second applyPatch said %q, want it to short-circuit", second)
	}
	again, err := os.ReadFile(filepath.Join(dir, contextManagerFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, again) {
		t.Error("the second apply changed contextmanager.go; it must be a no-op")
	}
}

// TestApplyFailsWhenThePinnedTextHasDrifted is the build-time drift guard,
// exercised where a failure is cheap. Bumping the go.mod pin past this
// revision must fail loudly rather than ship an unpatched decoy.
func TestApplyFailsWhenThePinnedTextHasDrifted(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		anchor  anchor
		rewrite func(string) string
	}{
		{
			name:   "contextmanager.go's accept block moved",
			file:   contextManagerFile,
			anchor: contextManagerAnchors[0],
			rewrite: func(text string) string {
				return strings.Replace(text, "\t\t\t\tResult:    0, // accepted\n", "", 1)
			},
		},
		{
			name:   "serviceprovider.go's C-FIND callback moved",
			file:   serviceProviderFile,
			anchor: serviceProviderAnchors[1],
			rewrite: func(text string) string {
				return strings.Replace(text, "params.CFind(connState", "params.CFind2(connState", 1)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := prepareModule(t)
			path := filepath.Join(dir, tc.file)
			text, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.rewrite(string(text))), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err = applyPatch(dir)
			if err == nil {
				t.Fatalf("applyPatch succeeded even though %s no longer contains %q verbatim",
					tc.file, firstLine(tc.anchor.old))
			}
			if !strings.Contains(err.Error(), tc.anchor.name) {
				t.Errorf("error %q does not name the anchor that drifted (%q)", err, tc.anchor.name)
			}
			if !strings.Contains(err.Error(), PinnedRevision) {
				t.Errorf("error %q does not name the pinned revision", err)
			}
		})
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// TestApplyRefusesToOverwriteAnUnmarkedInjectedFile: the idempotency check is
// "the marker is present", so a file that exists without it is somebody's
// code, not our patch's output. Overwriting it would be a silent data loss on
// the next image rebuild.
func TestApplyRefusesToOverwriteAnUnmarkedInjectedFile(t *testing.T) {
	dir := prepareModule(t)
	foreign := []byte("package dicompot\n\n// hand-written, not ours\n")
	if err := os.WriteFile(filepath.Join(dir, InjectedFile), foreign, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := applyPatch(dir)
	if err == nil {
		t.Fatal("applyPatch overwrote an existing apistatus3179.go that does not carry the marker")
	}
	if !strings.Contains(err.Error(), InjectedFile) {
		t.Errorf("error %q does not name the file it refused to overwrite", err)
	}
	got, readErr := os.ReadFile(filepath.Join(dir, InjectedFile))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, foreign) {
		t.Error("applyPatch modified the pre-existing file it refused to overwrite")
	}
}

// TestInjectedSourceDeserializesNothing is the standing constraint from
// #3179: these are status codes on response paths that already exist, not new
// parsing. The guarantee is structural rather than a promise -- the file this
// patch injects takes no byte slice, imports no decoder, and calls no
// reader, so there is no code path in it that could decode an attacker's
// DICOM object even if a future edit tried to.
func TestInjectedSourceDeserializesNothing(t *testing.T) {
	source := string(injectedSource)
	forbidden := []string{
		"[]byte",
		"dicomio",
		"dicom.ReadElement",
		"dicom.Read",
		"ReadMessage",
		"ReadPDU",
		"DecodeMessage",
		"bufio",
		"regexp",
	}
	for _, needle := range forbidden {
		if strings.Contains(source, needle) {
			t.Errorf("the injected file references %q; it must not gain a deserialization path "+
				"(it decides status codes from the already-parsed Affected SOP Class UID and the "+
				"negotiated abstract syntax, nothing else)", needle)
		}
	}
	// The decisions must be reachable from string inputs only.
	for _, signature := range []string{
		"func apiary3179RefuseAbstractSyntax(uid string)",
		"func apiary3179RefuseQuery(",
		"sopClassUID string",
		"contextAbstractSyntaxUID string",
	} {
		if !strings.Contains(source, signature) {
			t.Errorf("the injected file no longer contains %q; the patch's entry points moved", signature)
		}
	}
}
