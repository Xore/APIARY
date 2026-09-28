package main

// #3394's class and its helpers. ollamaAPIPath belongs here too: it is
// Ollure's emulated surface, and classify() in main.go -- the path-side
// classifier, a different function -- is its only other caller.

import "strings"

// ollamaModelTarget reports whether an Ollama model name names a network
// target instead of a model.
//
// #3394, OllamaDrama/Ollure (arXiv 2609.29757): the model *name* on an Ollama
// management call used as a network target rather than a model reference. The
// paper's Table 2 measures it as two categories -- 17 pull + 14 push naming an
// out-of-band-interaction host, and 10 pull naming an internal one -- and
// every name in both is unique, so this is a shape and not a list. It is the
// same SSRF primitive the issue proposed, and the issue's own regex cannot
// reach it: its alternation is anchored with ^, and an Ollama body is JSON,
// so `^(https?://)` and `^127.` never see the value. Measured, that regex
// matches 5 of the paper's 34 request shapes; this case reaches the 9 the
// anchored branches were aimed at, and 0 of the 27 real-corpus entries in
// payload_test.go.
//
// The three shapes are the ones Ollure measured across 84 days and four
// deployments, and none of them can be a model reference:
//
//   - a URL, for the external-URL category (17 pull + 14 push) and the
//     internal-URL category (10 pull): out-of-band-interaction hosts, the
//     link-local metadata address, loopback API recursion, port probes;
//   - an out-of-band-interaction hostname anywhere in the name, which is
//     unambiguous -- there is no benign reason for one in a model reference;
//   - a bare `host:port/model`, which is the insecure-registry form and
//     carries no scheme at all, so the issue's `^(https?://)` branch is
//     blind to it by construction.
//
// Anchoring matters more than reach here. A name is not disqualified by
// containing a slash: `meta-llama/llama3.1:70b-instruct` and
// `huihui_ai/gemma-4-abliterated:12b` are ordinary references, and the
// abliterated one is a deliberate guardrail-bypass intent the sensor
// should record as a model name rather than as an SSRF. The host part has
// to be an address, which is what separates `127.0.0.1:37987/cve-12886`
// from `llama3.1:70b`.
//
// Its place in the dispatch is below path-traversal and secret-read, on
// purpose: a name that is both a traversal and a target is a traversal,
// which is the more specific of the two. Moving it above them relabels that
// overlap, so the precedence is asserted in classify_order_3464_test.go.
func ollamaModelTarget(body string) bool {
	v := strings.ToLower(ollamaModelName(body))
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		return true
	}
	if strings.Contains(v, ".oast.") {
		return true
	}

	var host, port string
	if strings.HasPrefix(v, "[") {
		// The bracketed form the paper records for internal targets.
		end := strings.IndexByte(v, ']')
		if end < 0 || !strings.HasPrefix(v[end+1:], ":") {
			return false
		}
		host, port = v[1:end], v[end+2:]
	} else {
		i := strings.IndexByte(v, ':')
		if i <= 0 {
			return false
		}
		host, port = v[:i], v[i+1:]
	}
	if k := strings.IndexByte(port, '/'); k >= 0 {
		port = port[:k]
	}
	if host == "" || port == "" {
		return false
	}
	address := true
	for _, r := range host {
		if r != '.' && r != ':' && !(r >= '0' && r <= '9') {
			address = false
			break
		}
	}
	if !address {
		return false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ollamaModelTargetCase is the dispatch's entry for ollamaModelTarget. The
// helper keeps its plain-string signature because
// ollure_coverage_3394_test.go calls it directly, and the dispatch hands it
// the lowercased body -- the form it was written against, and the one the
// case read before the split.
func ollamaModelTargetCase(c classifyInput) bool {
	return ollamaModelTarget(c.B)
}

// ollamaModelName returns the value of the first JSON string field called
// "name" or "model" in body, which is where the Ollama management API
// carries the model reference: "name" on the registry calls (pull, push,
// create, copy, delete, show) and "model" on the inference calls (generate,
// chat, embed).
//
// It scans the text rather than parsing it, and that is the point rather
// than a shortcut. Everything this file matches arrived from the network,
// and none of it is deserialized here; the field's value is delimited in the
// bytes that arrived, and ServeHTTP has already capped the body at 64 KiB.
// A value carrying an escaped quote truncates early, which under-matches;
// the raw body is stored on the event regardless, so nothing is lost.
func ollamaModelName(body string) string {
	for _, key := range []string{`"name"`, `"model"`} {
		rest := body
		for {
			i := strings.Index(rest, key)
			if i < 0 {
				break
			}
			rest = rest[i+len(key):]
			// A field only carries a value if one follows the colon.
			// Without this, the word "name" inside some other string is a
			// hit and the value it is handed is the rest of the request.
			j := 0
			for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t' || rest[j] == ':') {
				j++
			}
			if j >= len(rest) || rest[j] != '"' {
				continue
			}
			rest = rest[j+1:]
			k := strings.IndexByte(rest, '"')
			if k < 0 {
				// Unterminated: this was the tail of a string, not a
				// field, and there is nothing left to look at.
				break
			}
			return rest[:k]
		}
	}
	return ""
}

// ollamaAPIPath reports whether p is one of the Ollama management API's
// documented routes, and nothing else. The list is the whole of the REST
// surface Ollure emulated, and every entry is compared whole -- a prefix
// match on "/api/" would take /api/v1/namespaces with it.
func ollamaAPIPath(p string) bool {
	switch p {
	case "/api/tags", "/api/version", "/api/ps", "/api/show",
		"/api/generate", "/api/chat", "/api/embed",
		"/api/pull", "/api/push", "/api/create", "/api/copy", "/api/delete":
		return true
	}
	return false
}
