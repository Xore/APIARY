#!/usr/bin/env python3
"""Give galah's event log writer self-rotation (#2892).

event_log.json is written by internal/logger/logger.go's New(), which
os.OpenFile()s the path once with O_APPEND|O_CREATE|O_WRONLY and hands the
raw *os.File straight to cblog's EventLogger.SetOutput() -- confirmed
directly against the vendored source at the pinned GALAH_REF commit
(github.com/0x4d31/galah, internal/logger/logger.go). There is no size
check, no rotation flag on galah's CLI (internal/app/args.go has no such
flag), and no external rotation of this file anywhere in this stack --
same shape as the gap dionaea/log_rotation_patch.py (#1389),
mailoney/json_log_patch.py (#2196) and conpot/json_log_rotation_patch.py
(#2892) already closed for their own sinks.

Same shape as those three: an exact-match source patch applied at Docker
build time, close/rename/reopen at GALAH_JSON_LOG_MAX_BYTES (0 disables,
matching the "0 means unbounded" contract every other self-rotating writer
in this repo uses). Unlike the Python sinks above, galah is Go, so the
patch inserts a small io.Writer wrapper (rotatingWriter) between
os.OpenFile()'s handle and eventLogger.SetOutput() rather than editing an
existing method body -- New() is the only call site (confirmed: `grep -rn
SetOutput internal/logger` finds exactly one hit) and it already returns
the *Logger this needs to keep EventFile in sync with the file the wrapper
is currently writing to (galah/service.go's Close() calls
EventLogger.EventFile.Close() at shutdown, and Close()'ing whichever
generation is currently open is enough -- a superseded, already-renamed
generation being left as-is on process exit is not a leak, it's simply
done).

Applied at Docker build time to the git-cloned copy the same way
timeout_patch.py already patches this repo's server.go -- see this
directory's Dockerfile for the RUN order.
"""
from pathlib import Path

MARKER = "honeypot-stack: event log self-rotation patch (#2892)"
TARGET = Path("/build/internal/logger/logger.go")

OLD_IMPORTS = '''import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/0x4d31/galah/pkg/enrich"
	"github.com/0x4d31/galah/pkg/llm"
	"github.com/0x4d31/galah/pkg/suricata"
	cblog "github.com/charmbracelet/log"
	"github.com/google/uuid"
)'''

NEW_IMPORTS = '''import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"  // --- __MARKER__ ---
	"strings"
	"time"

	"github.com/0x4d31/galah/pkg/enrich"
	"github.com/0x4d31/galah/pkg/llm"
	"github.com/0x4d31/galah/pkg/suricata"
	cblog "github.com/charmbracelet/log"
	"github.com/google/uuid"
)'''.replace("__MARKER__", MARKER)

OLD_NEW_FUNC = '''// New creates a new Logger instance with the specified configuration.
func New(eventLogFile string, modelConfig llm.Config, eCache *enrich.Enricher, sessionizer *Sessionizer, l *cblog.Logger) (*Logger, error) {
	eventLogger := cblog.NewWithOptions(nil, cblog.Options{Formatter: cblog.JSONFormatter, TimeFormat: time.RFC3339Nano})
	evFile, err := os.OpenFile(eventLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	eventLogger.SetOutput(evFile)

	return &Logger{
		EnrichCache: eCache,
		Sessionizer: sessionizer,
		EventLogger: eventLogger,
		EventFile:   evFile,
		LLMConfig:   modelConfig,
		Logger:      l,
	}, nil
}'''

NEW_NEW_FUNC = '''// --- __MARKER__ ---
// rotatingWriter closes, renames aside with a timestamp suffix, and
// reopens fresh at path once size would exceed max -- same pattern
// dionaea/log_rotation_patch.py, mailoney/json_log_patch.py and
// conpot/json_log_rotation_patch.py already use for their own sinks
// (#1389, #2196, #2892). max <= 0 disables rotation entirely.
type rotatingWriter struct {
	path  string
	max   int64
	size  int64
	file  *os.File
	owner *Logger
}

func newRotatingWriter(path string, f *os.File, owner *Logger) *rotatingWriter {
	max := int64(67108864)
	if v := os.Getenv("GALAH_JSON_LOG_MAX_BYTES"); v != "" {
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
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Best effort: keep writing to the old (renamed) descriptor rather
		// than losing events -- the next successful rotation attempt will
		// still try to reopen at path.
		return
	}
	w.file = f
	w.size = 0
	if w.owner != nil {
		w.owner.EventFile = f
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// New creates a new Logger instance with the specified configuration.
func New(eventLogFile string, modelConfig llm.Config, eCache *enrich.Enricher, sessionizer *Sessionizer, l *cblog.Logger) (*Logger, error) {
	eventLogger := cblog.NewWithOptions(nil, cblog.Options{Formatter: cblog.JSONFormatter, TimeFormat: time.RFC3339Nano})
	evFile, err := os.OpenFile(eventLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	logger := &Logger{
		EnrichCache: eCache,
		Sessionizer: sessionizer,
		EventLogger: eventLogger,
		EventFile:   evFile,
		LLMConfig:   modelConfig,
		Logger:      l,
	}
	eventLogger.SetOutput(newRotatingWriter(eventLogFile, evFile, logger))
	return logger, nil
}'''.replace("__MARKER__", MARKER)


def apply_patch(target: Path = TARGET) -> str:
    text = target.read_text()
    if MARKER in text:
        return "json_log_rotation_patch.py: already patched"

    if text.count(OLD_IMPORTS) != 1:
        raise SystemExit(
            "json_log_rotation_patch.py: expected exactly 1 match for the "
            "import block, found {}".format(text.count(OLD_IMPORTS))
        )
    if text.count(OLD_NEW_FUNC) != 1:
        raise SystemExit(
            "json_log_rotation_patch.py: expected exactly 1 match for "
            "New(), found {}".format(text.count(OLD_NEW_FUNC))
        )

    text = text.replace(OLD_IMPORTS, NEW_IMPORTS, 1)
    text = text.replace(OLD_NEW_FUNC, NEW_NEW_FUNC, 1)
    target.write_text(text)
    return "json_log_rotation_patch.py: added self-rotation to New()"


def main():
    print(apply_patch())


if __name__ == "__main__":
    main()
