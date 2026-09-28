package main

// The classes that are not one CVE: the long-standing ones, plus the generic
// fallbacks. They live together because they do not churn the way a new CVE
// does -- what matters is that each is a named function the dispatch can
// point at, so a CVE branch never has to touch this file.
//
// The count on each one is events over the pinned 30-day window the note on
// classifyPayload describes. They are kept because they are the only record
// of how much traffic each class actually claims, and because a class that
// fires on ordinary traffic is worse than no pattern at all.

import (
	"strings"
	"unicode/utf8"
)

// phpCGIArgumentInjection: 390 events. CVE-2012-1823 / CVE-2024-4577: turns
// php-cgi's argument handling into "execute the request body as PHP".
func phpCGIArgumentInjection(c classifyInput) bool {
	return strings.Contains(c.Q, "allow_url_include") && strings.Contains(c.Q, "auto_prepend_file")
}

// thinkphpInvokefunction: 162 events. ThinkPHP's invokefunction routing
// gadget: the callable and its arguments are both in the query.
func thinkphpInvokefunction(c classifyInput) bool {
	return strings.Contains(c.Q, "invokefunction") && strings.Contains(c.Q, "call_user_func_array")
}

// pearcmdConfigCreate: 81 events. Traversal to PEAR's CLI, which is then told
// to write a PHP file -- local file inclusion escalated to code execution.
func pearcmdConfigCreate(c classifyInput) bool {
	return strings.Contains(c.Q, "pearcmd") && strings.Contains(c.Q, "config-create")
}

// jndiLookup: Log4Shell and its JNDI relatives; the lookup syntax is
// unambiguous.
func jndiLookup(c classifyInput) bool {
	return strings.Contains(c.Both, "${jndi:")
}

// phpBase64Shell: 390 events across two variants, both wrapping a base64 blob
// in a shell call. Checked before the bare phpCode case, which would
// otherwise swallow it.
func phpBase64Shell(c classifyInput) bool {
	return containsAny(c.B, "shell_exec", "system(", "passthru", "popen(", "proc_open") &&
		strings.Contains(c.B, "base64_decode")
}

// phpCode: 2,918 events -- CVE-2017-9841's eval-stdin.php probe is a quarter
// of the whole corpus on its own, and it is simply PHP source in a body.
func phpCode(c classifyInput) bool {
	return strings.Contains(c.B, "<?php") || strings.Contains(c.B, "<?=")
}

// downloaderChain: 58 events. Fetch a stage-two script and pipe it straight to
// a shell.
func downloaderChain(c classifyInput) bool {
	return containsAny(c.Both, "wget ", "curl ") &&
		containsAny(c.Both, "|sh", "| sh", "|bash", "| bash", "-qo-", "-so-")
}

// commandInjection: 45 events. A shell command reachable from the request,
// which needs both a way to start one and something to run -- see
// shellCommand.
func commandInjection(c classifyInput) bool {
	return shellCommand(c.Both)
}

// secretRead: 26 events. Straight to the credential files, no execution
// needed.
func secretRead(c classifyInput) bool {
	return containsAny(c.Both, "/root/.aws/credentials", "/etc/passwd", "/etc/shadow", ".ssh/id_rsa", "/.env")
}

// pathTraversal: 81 events. Traversal on its own, once the escalations
// earlier in the dispatch have had their turn.
func pathTraversal(c classifyInput) bool {
	return strings.Contains(c.Both, "../../") || strings.Contains(c.Both, "..%2f") ||
		strings.Contains(c.Both, `..\..\`)
}

// adminAccountCreate: 171 events. Creating an administrator through an API
// that should not allow it -- persistence rather than a smash-and-grab.
func adminAccountCreate(c classifyInput) bool {
	return strings.Contains(c.B, "roleid") && strings.Contains(c.B, "administrator")
}

// sqliInjection: the generic injection class. A name it cannot put is a
// request a scanner sent, and naming it wrongly is worse than not naming it:
// the six tokens here are the ones with no ordinary use in a request body.
func sqliInjection(c classifyInput) bool {
	return containsAny(c.B, "union select", "or 1=1", "' or '", "sleep(", "benchmark(", "waitfor delay")
}

// prototypePollution: 19 events. React/Next.js server actions reached through
// a multipart body; the marker is the polluted key, not the transport.
func prototypePollution(c classifyInput) bool {
	return containsAny(c.B, "__proto__", "constructor.prototype")
}

// xxeInjection: an external entity declared in a DTD and referenced, with
// something to resolve it against. The declaration alone is a DTD.
func xxeInjection(c classifyInput) bool {
	return strings.Contains(c.B, "<!entity") && strings.Contains(c.B, "system")
}

// templateInjection: template expression syntax paired with something worth
// evaluating. Deliberately narrow: braces alone are ordinary in JSON, and
// "{{name}}" in a template field is not an attack.
func templateInjection(c classifyInput) bool {
	return containsAny(c.B, "{{", "${", "#{") &&
		containsAny(c.B, "7*7", "runtime.", "getruntime", "class.forname", "__import__", "self.__", "process.env")
}

// soapProbe: 50 events. ONVIF device discovery -- cameras and recorders.
func soapProbe(c classifyInput) bool {
	return strings.Contains(c.B, "soap-envelope") || strings.Contains(c.B, "onvif.org")
}

// vpnHandshake: 19 events. Cisco AnyConnect's initial exchange, aimed at a
// web port to find VPN concentrators.
func vpnHandshake(c classifyInput) bool {
	return strings.Contains(c.B, "<config-auth")
}

// mcpProbe: 38 events. JSON-RPC "initialize" carrying a protocolVersion is the
// Model Context Protocol handshake -- scanners looking for exposed MCP
// servers, which is new traffic rather than a legacy exploit.
func mcpProbe(c classifyInput) bool {
	return strings.Contains(c.B, `"jsonrpc"`) && strings.Contains(c.B, `"initialize"`) &&
		strings.Contains(c.B, "protocolversion")
}

// miningRPCProbe: 38 events. getwork / eth_getWork -- looking for an
// unauthenticated miner or pool to hijack.
func miningRPCProbe(c classifyInput) bool {
	return strings.Contains(c.B, `"method"`) && containsAny(c.B, `"getwork"`, `"eth_getwork"`, `"eth_submitwork"`)
}

// batchRequestProbe: 137 events. WordPress's /batch/v1 multiplexer: one
// request that asks the server to make several more, including to itself.
func batchRequestProbe(c classifyInput) bool {
	return strings.Contains(c.B, `"requests"`) && strings.Contains(c.B, "[")
}

// dnsVersionProbe: 178 events. version.bind is a DNS CHAOS query, aimed at a
// web port by scanners that fan the same probe across every protocol. It is
// also a bare hostname, so it sits above openResolverProbe and says what it
// is rather than what it looks like.
func dnsVersionProbe(c classifyInput) bool {
	return c.Q == "version.bind"
}

// openResolverProbe: ~200 events. A query that is nothing but a hostname --
// the shape of an open-resolver or open-proxy test, where the value names the
// thing the server is being asked to fetch or resolve on the caller's behalf.
func openResolverProbe(c classifyInput) bool {
	return bareHostname(c.Q)
}

// androxgh0stMarker: 35 events, and the name is the payload.
func androxgh0stMarker(c classifyInput) bool {
	return strings.Contains(c.Both, "androxgh0st")
}

// wordpressRESTProbe: 372 events. WordPress's REST surface, enumerated for
// something exploitable rather than exploited yet.
func wordpressRESTProbe(c classifyInput) bool {
	return strings.Contains(c.Q, "rest_route=")
}

// infoDisclosure: phpinfo, asked for directly.
func infoDisclosure(c classifyInput) bool {
	return strings.Contains(c.Q, "phpinfo")
}

// multipartPadding: 401 events. Kilobytes of "A" behind a random boundary: a
// size or parser limit being tested, not an exploit. This is also why the
// distinct-body count reads higher than the number of real payloads.
func multipartPadding(c classifyInput) bool {
	return strings.Contains(c.B, "webkitformboundary") && strings.Contains(c.Body, strings.Repeat("A", 64))
}

// serializedObject: Java and PHP serialised objects, by their headers rather
// than their contents. rO0AB is base64 for the Java stream magic. Unchanged by
// #3212 and deliberately so: this is one ordered class shared by two
// languages, and the Java-specific evidence it lacked now lives in its own
// java_marker field (see javaMarker) rather than in a split of this value,
// which existing queries already mean and the PHP case would lose.
//
// It is also the generic object case, which is why it sits so low. Anything
// with an object header in it lands here unless a more specific class earlier
// in the dispatch claims it first, so a new class that is more specific than
// this one belongs ABOVE this line. That is the ordering the issue is about,
// and TestPayloadClassOrderIsPinned is what makes a wrong side of it fail.
func serializedObject(c classifyInput) bool {
	return strings.HasPrefix(c.Body, "rO0AB") || strings.Contains(c.Body, "\xac\xed\x00\x05") ||
		phpSerializedObject(c.B)
}

// binaryProtocol: 38 events. Anything speaking a binary protocol at an HTTP
// port. Checked last in the dispatch: it is a statement about the bytes
// rather than about intent, and any earlier pattern is more informative.
func binaryProtocol(c classifyInput) bool {
	return binaryPayload(c.Body)
}

// phpSerializedObject matches PHP's serialize() object header -- O:<len>:"
// -- without matching the O: that shows up in ordinary prose.
func phpSerializedObject(s string) bool {
	i := strings.Index(s, "o:")
	if i < 0 {
		return false
	}
	rest := s[i+2:]
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	return digits > 0 && strings.HasPrefix(rest[digits:], `:"`)
}

// binaryPayload reports whether a body is something other than text.
//
// utf8.ValidString alone is not the test: the 38-event probe that prompted
// this ("\x00\x00\x00\x00\x03:\x01*") is perfectly valid UTF-8, because C0
// control characters encode as themselves. A NUL byte, or control
// characters beyond the ones text actually uses, is the real signal.
func binaryPayload(body string) bool {
	if body == "" {
		return false
	}
	if !utf8.ValidString(body) || strings.ContainsRune(body, 0) {
		return true
	}
	control := 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			control++
		}
	}
	return control*10 > len(body)
}

// shellCommand reports whether s looks like it is trying to start a shell
// command, rather than merely containing characters a shell would use.
//
// The distinction matters because both halves are ordinary on their own:
// "$(" is everyday JavaScript, ";" is everyday in a header, and "uname"
// sits inside "username". So the binary has to appear *at* a command
// position -- immediately after a separator or a substitution opener, and
// followed by a boundary rather than more letters.
//
// The payloads this actually catches in the live window are Node
// child_process calls smuggled into multipart bodies, where the command is
// `id; hostname; pwd` and the rest is padding.
func shellCommand(s string) bool {
	binaries := []string{
		"cat ", "ls ", "id;", "id ", "id\n", "pwd", "whoami", "uname ", "uname -",
		"wget ", "curl ", "nc ", "sh ", "bash ", "chmod ", "busybox", "python", "perl ",
	}
	starters := []string{"$(", "`", ";", "|", "&&", "\n", "%0a"}

	for _, start := range starters {
		rest := s
		for {
			i := strings.Index(rest, start)
			if i < 0 {
				break
			}
			rest = rest[i+len(start):]
			trimmed := strings.TrimLeft(rest, " \t'\"")
			for _, bin := range binaries {
				if strings.HasPrefix(trimmed, bin) {
					return true
				}
			}
		}
	}
	// cmd= and exec= style parameters name the command directly, with no
	// separator in front of it.
	for _, param := range []string{"cmd=", "exec=", "command=", "execute="} {
		if i := strings.Index(s, param); i >= 0 {
			rest := strings.TrimLeft(s[i+len(param):], " '\"")
			for _, bin := range binaries {
				if strings.HasPrefix(rest, bin) {
					return true
				}
			}
			// A bare `cmd=pwd` has nothing after the binary to match a
			// trailing space, so those are checked whole.
			for _, bare := range []string{"pwd", "id", "whoami", "ls", "uname"} {
				if rest == bare || strings.HasPrefix(rest, bare+"&") {
					return true
				}
			}
		}
	}
	return false
}

// bareHostname reports whether a query string is nothing but a hostname --
// no key, no value, just a name. Scanners testing for an open resolver or
// open proxy send exactly that, and it cannot be confused with a normal
// query, which has an "=" in it.
func bareHostname(q string) bool {
	if q == "" || len(q) > 253 || strings.ContainsAny(q, "=&/ ") {
		return false
	}
	if !strings.Contains(q, ".") || strings.HasPrefix(q, ".") || strings.HasSuffix(q, ".") {
		return false
	}
	for _, r := range q {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '.' && r != '-' {
			return false
		}
	}
	// A trailing label of letters is what separates a hostname from a
	// version string or a filename.
	last := q[strings.LastIndex(q, ".")+1:]
	if len(last) < 2 {
		return false
	}
	for _, r := range last {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}
