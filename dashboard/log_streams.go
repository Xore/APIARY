package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultLogStreamMaxBytes     int64 = 67108864
	defaultLogStreamAlertPercent       = 90
)

type logStreamStat struct {
	Name    string
	Size    int64
	ModTime time.Time
}

type logStreamAlert struct {
	Key     string
	Message string
}

// configuredLogStreamMaxBytes mirrors the self-rotation limit used by
// Dionaea and ip-enrichment-worker. Zero deliberately means unbounded and
// disables the size alert, matching both writers' existing contract.
func configuredLogStreamMaxBytes(raw string) int64 {
	if raw == "" {
		return defaultLogStreamMaxBytes
	}
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || n < 0 {
		return defaultLogStreamMaxBytes
	}
	return n
}

func configuredLogStreamAlertPercent(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 1 || n > 99 {
		return defaultLogStreamAlertPercent
	}
	return n
}

// scanLogStreams returns only the active files covered by #1389's
// self-rotation. Rotated generations are intentionally excluded: their age
// and retention are owned by log-maintenance, while these current paths are
// the ones that reveal a writer which has stopped rotating before it grows
// unbounded again.
func scanLogStreams(root string) []logStreamStat {
	patterns := []string{
		filepath.Join(root, "enriched", "*.json"),
		filepath.Join(root, "dionaea", "dionaea.json"),
		filepath.Join(root, "dionaea", "dionaea_incident.json"),
	}
	seen := map[string]bool{}
	var streams []logStreamStat
	for _, pattern := range patterns {
		paths, _ := filepath.Glob(pattern)
		for _, path := range paths {
			if seen[path] {
				continue
			}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				continue
			}
			seen[path] = true
			streams = append(streams, logStreamStat{
				Name:    filepath.ToSlash(rel),
				Size:    info.Size(),
				ModTime: info.ModTime(),
			})
		}
	}
	sort.Slice(streams, func(i, j int) bool { return streams[i].Name < streams[j].Name })
	return streams
}

func logStreamAgeSeconds(stream logStreamStat, now time.Time) int64 {
	age := now.Sub(stream.ModTime)
	if age < 0 {
		return 0
	}
	return int64(age / time.Second)
}

func logStreamAlerts(streams []logStreamStat, maxBytes int64, alertPercent int, now time.Time) []logStreamAlert {
	if maxBytes <= 0 || alertPercent < 1 || alertPercent > 99 {
		return nil
	}
	threshold := (maxBytes*int64(alertPercent) + 99) / 100
	var alerts []logStreamAlert
	for _, stream := range streams {
		if stream.Size < threshold {
			continue
		}
		alerts = append(alerts, logStreamAlert{
			Key: "log-stream-size:" + stream.Name,
			Message: fmt.Sprintf(
				"honeypot JSON stream approaching rotation limit: %s size=%s limit=%s age=%s",
				stream.Name,
				humanBytes(stream.Size),
				humanBytes(maxBytes),
				(time.Duration(logStreamAgeSeconds(stream, now)) * time.Second).String(),
			),
		})
	}
	return alerts
}
