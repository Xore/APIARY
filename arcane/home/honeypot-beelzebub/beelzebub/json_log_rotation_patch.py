#!/usr/bin/env python3
"""Give beelzebub's JSON log writer self-rotation (#2892).

beelzebub.json is written by internal/builder/builder.go's buildLogger(),
which os.OpenFile()s core.yaml's logsPath once with O_APPEND|O_CREATE|O_RDWR
and hands the raw *os.File to logrus via io.MultiWriter(os.Stdout, logsFile)
-- confirmed directly against the vendored source at the pinned
BEELZEBUB_REF commit (github.com/mariocandela/beelzebub,
internal/builder/builder.go). There is no size check, no rotation knob in
core.yaml's Logging block (internal/parser/configurations_parser.go has
only logsPath/logDisableTimestamp/debug/debugReportCaller), and no external
rotation of this file anywhere in this stack -- same gap
dionaea/log_rotation_patch.py (#1389), mailoney/json_log_patch.py (#2196),
conpot/json_log_rotation_patch.py (#2892) and galah/json_log_rotation_patch.py
(#2892) already closed for their own sinks.

Same shape as those four, modelled directly on galah's (the other Go
target): an exact-match source patch applied at Docker build time,
close/rename/reopen at BEELZEBUB_JSON_LOG_MAX_BYTES (0 disables, matching
the "0 means unbounded" contract every other self-rotating writer in this
repo uses). The patch inserts a small io.Writer wrapper (rotatingWriter)
between os.OpenFile()'s handle and the io.MultiWriter rather than editing
an existing method body -- buildLogger() is the only place the file is
opened (confirmed: `grep -rn OpenFile internal/` finds exactly one hit) and
it already stores the handle on the *Builder, which Builder.Close() closes
at shutdown, so the wrapper keeps b.logsFile pointed at whichever
generation is currently open (Close()'ing that one is enough; a superseded,
already-renamed generation left as-is on process exit is not a leak, it's
simply done). logrus serialises every Out.Write() under Logger.mu, so the
wrapper needs no lock of its own.

The 64 MiB default is the same one the other four patches use; it was NOT
tuned against beelzebub's real traffic (81 MB in roughly three weeks on the
homeserver when #2892 was filed), only chosen so all five sinks share one
number. Override with BEELZEBUB_JSON_LOG_MAX_BYTES in compose if it turns
out wrong.

Applied at Docker build time to the git-cloned copy -- see this directory's
Dockerfile for the RUN order (before `go build`).
"""
from pathlib import Path

MARKER = "honeypot-stack: JSON log self-rotation patch (#2892)"
TARGET = Path("/build/internal/builder/builder.go")

OLD_IMPORTS = '''import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/MCP"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TELNET"
'''

NEW_IMPORTS = '''import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv" // --- __MARKER__ ---
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/MCP"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TELNET"
'''.replace("__MARKER__", MARKER)

OLD_BUILD_LOGGER = '''func (b *Builder) buildLogger(configurations parser.Logging) error {
	output := io.Writer(os.Stdout)

	if configurations.LogsPath != "" {
		logsFile, err := os.OpenFile(configurations.LogsPath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
		if err != nil {
			return err
		}
		output = io.MultiWriter(os.Stdout, logsFile)
		b.logsFile = logsFile
	}
'''

NEW_BUILD_LOGGER = '''// --- __MARKER__ ---
// rotatingWriter closes, renames aside with a timestamp suffix, and
// reopens fresh at path once size would exceed max -- same pattern
// dionaea/log_rotation_patch.py, mailoney/json_log_patch.py,
// conpot/json_log_rotation_patch.py and galah/json_log_rotation_patch.py
// already use for their own sinks (#1389, #2196, #2892). max <= 0 disables
// rotation entirely. logrus holds Logger.mu around every Out.Write(), so
// Write() here is never entered concurrently.
type rotatingWriter struct {
	path  string
	max   int64
	size  int64
	file  *os.File
	owner *Builder
}

func newRotatingWriter(path string, f *os.File, owner *Builder) *rotatingWriter {
	max := int64(67108864)
	if v := os.Getenv("BEELZEBUB_JSON_LOG_MAX_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			max = n
		}
	}
	size := int64(0)
	if fi, err := f.Stat(); err == nil {
		size = fi.Size()
	}
	return &rotatingWriter{path: path, max: max, size: size, file: f, owner: owner}
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	if w.max > 0 && w.size+int64(len(p)) > w.max {
		w.rotate()
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingWriter) rotate() {
	_ = w.file.Close()
	stamp := time.Now().UTC().Format("20060102-150405")
	target := w.path + "." + stamp
	for i := 2; fileExists(target); i++ {
		target = w.path + "." + stamp + "." + strconv.Itoa(i)
	}
	_ = os.Rename(w.path, target)
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		// Best effort: keep writing to the old (renamed) descriptor rather
		// than losing events -- the next successful rotation attempt will
		// still try to reopen at path.
		return
	}
	w.file = f
	w.size = 0
	if w.owner != nil {
		w.owner.logsFile = f
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (b *Builder) buildLogger(configurations parser.Logging) error {
	output := io.Writer(os.Stdout)

	if configurations.LogsPath != "" {
		logsFile, err := os.OpenFile(configurations.LogsPath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
		if err != nil {
			return err
		}
		b.logsFile = logsFile
		output = io.MultiWriter(os.Stdout, newRotatingWriter(configurations.LogsPath, logsFile, b))
	}
'''.replace("__MARKER__", MARKER)


def apply_patch(target: Path = TARGET) -> str:
    text = target.read_text()
    if MARKER in text:
        return "json_log_rotation_patch.py: already patched"

    if text.count(OLD_IMPORTS) != 1:
        raise SystemExit(
            "json_log_rotation_patch.py: expected exactly 1 match for the "
            "import block, found {}".format(text.count(OLD_IMPORTS))
        )
    if text.count(OLD_BUILD_LOGGER) != 1:
        raise SystemExit(
            "json_log_rotation_patch.py: expected exactly 1 match for "
            "buildLogger(), found {}".format(text.count(OLD_BUILD_LOGGER))
        )

    text = text.replace(OLD_IMPORTS, NEW_IMPORTS, 1)
    text = text.replace(OLD_BUILD_LOGGER, NEW_BUILD_LOGGER, 1)
    target.write_text(text)
    return "json_log_rotation_patch.py: added self-rotation to buildLogger()"


def main():
    print(apply_patch())


if __name__ == "__main__":
    main()
