package main

import (
	"log"
	"runtime/debug"
	"time"
)

// #1980: wrap each polling cycle so an unexpected panic costs one cycle,
// not the process. These workers parse attacker-controlled data (NUL and
// control bytes in credentials, hostile filenames, raw base64) against ES
// response shapes that can drift; before this helper one index-out-of-range
// killed the worker mid-cycle and everything downstream -- attackers-v1,
// the verdict join, abuse reporting -- silently froze at its last successful
// cycle until Docker's restart policy happened to notice, while the
// dashboard kept rendering stale data with no signal anything was dead.
//
// The cadence also counts from cycle START rather than completion: sleeping
// a fixed interval after the cycle made the effective period
// interval + cycleDuration, which silently stretches on slow cycles.
//
// Duplication note: this helper is intentionally near-identical in
// correlator-worker, payload-inventory-worker and reporter -- they are
// separate Go modules by stack boundary, not one workspace.
func runLoop(name string, interval time.Duration, cycle func()) {
	for {
		started := time.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("%s: cycle panicked: %v\n%s", name, r, debug.Stack())
				}
			}()
			cycle()
		}()
		if rest := interval - time.Since(started); rest > 0 {
			time.Sleep(rest)
		}
	}
}
