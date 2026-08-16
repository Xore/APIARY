package main

import (
	"context"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// tarpit.go implements a HellPot-style tarpit (#246): for a request already
// classified as scanner/exploit-probe noise -- not a bait path with its own
// crafted response, see classify()'s "scan"/"rce-probe" buckets -- stream an
// endless, slowly-drip-fed page of Markov-chain-generated garbage text
// instead of a normal reply. Costs the requester bandwidth/time for
// near-zero effort on our side; a real browser/tool sees what looks like an
// HTML page that never finishes loading.
//
// HellPot's own README is explicit that this technique is meant to sit
// behind specific, already-identified trap paths, not be the default
// response for everything -- an unqualified real visitor (or an
// uptime/health checker that doesn't know this path is bait) hitting a
// tarpitted route would hang instead of getting a normal 404. tarpitCategory
// keeps that scoped to classify()'s "scan" bucket by default (paths this
// sensor doesn't otherwise recognize, precisely where nothing legitimate is
// expected to matter).

// markovSeedCorpus is a small, fixed, self-contained corpus (classic filler
// text) the word-chain below trains on at startup. Doesn't need to be
// realistic-sounding prose -- an attacker's scanner is looking for a normal
// HTTP response shape, not proofreading the body -- just varied enough that
// the chain doesn't degenerate into repeating the same two words forever.
const markovSeedCorpus = `Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod
tempor incididunt ut labore et dolore magna aliqua Ut enim ad minim veniam
quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
consequat Duis aute irure dolor in reprehenderit in voluptate velit esse
cillum dolore eu fugiat nulla pariatur Excepteur sint occaecat cupidatat non
proident sunt in culpa qui officia deserunt mollit anim id est laborum
Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium
doloremque laudantium totam rem aperiam eaque ipsa quae ab illo inventore
veritatis et quasi architecto beatae vitae dicta sunt explicabo Nemo enim
ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit sed quia
consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt`

// markovChain is an order-1 word chain: each key maps to every word observed
// immediately after it anywhere in the corpus (duplicates kept deliberately,
// so a more common transition is more likely to be picked again -- a real
// weighted Markov chain, not a uniform shuffle).
type markovChain map[string][]string

func newMarkovChain(corpus string) markovChain {
	words := strings.Fields(corpus)
	chain := make(markovChain, len(words))
	for i := 0; i < len(words)-1; i++ {
		w := words[i]
		chain[w] = append(chain[w], words[i+1])
	}
	return chain
}

// generate returns n space-joined words starting from a random seed word.
// A dead end (a word with no observed follower -- the corpus's last word)
// restarts from a fresh random seed rather than stopping early, so the
// output is always exactly n words regardless of where the walk began.
func (c markovChain) generate(n int) string {
	if len(c) == 0 {
		return ""
	}
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	word := keys[rand.Intn(len(keys))]
	out := make([]string, 0, n)
	for len(out) < n {
		out = append(out, word)
		next := c[word]
		if len(next) == 0 {
			word = keys[rand.Intn(len(keys))]
			continue
		}
		word = next[rand.Intn(len(next))]
	}
	return strings.Join(out, " ")
}

var defaultMarkovChain = newMarkovChain(markovSeedCorpus)

// tarpitCategory reports whether classify(path)'s category is one this
// sensor tarpits rather than answers normally: "scan" (nothing this sensor
// recognizes -- the safest bucket to stall, since no real health check or
// bait-response consumer expects a fast reply from an unrecognized path)
// and "rce-probe" (an active exploit attempt, e.g. cgi-bin/shell paths --
// worth wasting the requester's time on deliberately, not just recon).
func tarpitCategory(category string) bool {
	return category == "scan" || category == "rce-probe"
}

// tarpitChunkDelay is the pause between each drip-fed write. tarpitTest.go
// (or a future test) may lower this via tarpitDelayOverride to keep tests
// fast without changing production timing.
var tarpitChunkDelay = 500 * time.Millisecond

// tarpitMaxDuration bounds how long a single connection is held open --
// long enough to cost a scanner real time, short enough that a flood of
// scanner traffic can't pin down an unbounded number of goroutines/sockets
// on this side indefinitely.
const tarpitMaxDuration = 90 * time.Second

// tarpit streams an endless HTML page of Markov-generated garbage text to
// w, a few words at a time, until the client disconnects, tarpitMaxDuration
// elapses, or the request context is otherwise cancelled. Returns the
// number of bytes written and how long the connection was held, both
// folded into the logged event so a tarpitted request is distinguishable
// from a normally-answered one.
func tarpit(ctx context.Context, w http.ResponseWriter) (bytesWritten int, held time.Duration) {
	flusher, canFlush := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if n, err := writeString(w, "<!doctype html>\n<html><head><title>Loading…</title></head><body>\n"); err == nil {
		bytesWritten += n
	}
	if canFlush {
		flusher.Flush()
	}

	deadline := time.NewTimer(tarpitMaxDuration)
	defer deadline.Stop()
	ticker := time.NewTicker(tarpitChunkDelay)
	defer ticker.Stop()
	start := time.Now()

	for {
		select {
		case <-ctx.Done():
			return bytesWritten, time.Since(start)
		case <-deadline.C:
			return bytesWritten, time.Since(start)
		case <-ticker.C:
			chunk := "<p>" + defaultMarkovChain.generate(12+rand.Intn(12)) + "</p>\n"
			n, err := writeString(w, chunk)
			bytesWritten += n
			if err != nil {
				// The client gave up reading (connection reset, etc.) --
				// same outcome as ctx.Done() for logging purposes.
				return bytesWritten, time.Since(start)
			}
			if canFlush {
				flusher.Flush()
			}
		}
	}
}

func writeString(w http.ResponseWriter, s string) (int, error) {
	return w.Write([]byte(s))
}
