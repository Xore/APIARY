package main

// #3189's class, CVE-2026-63077, and every helper it needs. It is first in
// the dispatch, above the generic serialized-object case, which is the one
// ordering decision #3444 had to make by hand and the one this file's own
// tests now pin from both sides.

import (
	"net/url"
	"strings"
)

// teamcityAgentDeserialization reports a request aimed at a Java
// deserialization sink through TeamCity's build-agent polling protocol
// (CVE-2026-63077), as a conjunction of two things seen on the wire.
//
// Half one is the product's own agent protocol: a call name from TeamCity's
// polling channel, or one of its qualified DTO/package names. Half two is a
// serialization container: the Java stream header, raw or base64, or a gadget
// class name -- see javaSerializationContainer.
//
// Both are required, and neither alone is worth anything. Every TeamCity
// server on earth has agents polling it, so the product half on its own is
// the fleet's background traffic, and a classified agent poll would be worse
// than no classification at all. A serialized object on an HTTP port is
// somebody else's finding: this sensor serves a WordPress XML-RPC bait of
// its own (#238) and buckets xmlrpc paths as "wordpress", so containers on
// that transport are expected to arrive here, and they are not TeamCity's.
// The conjunction is the CVE, which is why this takes the product AND the
// container and cannot be reduced to a single substring.
//
// The raw and lowered forms of each channel are both passed in, and the
// distinction is load-bearing rather than tidiness. The container has to be
// read from the RAW bytes: strings.ToLower replaces every byte that is not
// valid UTF-8 with U+FFFD, so the lowered form of a raw AC ED 00 05 header
// is replacement characters and the signature is gone. That is the same
// reason the generic serialized-object case reads `body` rather than this
// function's `b`. The product names are ASCII and are read from the lowered
// copies, which the caller has already built for its own cases -- so this
// function allocates nothing.
//
// What it does not do: deserialize. No decoder, no parser, no object
// reader, no evaluation of anything received. The class reports that a
// request carried the marks of a deserialization attempt on a named
// product's protocol, and nothing more: not that the object graph was
// well-formed, not that the sink existed, and emphatically not that anything
// was executed. Those are different claims, and only this one is available
// from the bytes a sensor receives.
func teamcityAgentDeserialization(c classifyInput) bool {
	if !javaSerializationContainer(c) {
		return false
	}
	return teamcityAgentProtocol(c.Q, c.B)
}

const (
	// javaStreamHeader is the four bytes every java.io ObjectOutputStream
	// begins with: STREAM_MAGIC (0xAC 0xED) followed by the serialization
	// protocol version (0x00 0x05). It is the only place in a Java stream
	// that says "this is a Java object stream", which is what makes it worth
	// matching on its own -- a payload whose class descriptor has been
	// mangled to slip a filter still starts with these four bytes.
	//
	// Read as bytes and compared. Never handed to a deserializer: that
	// would be the vulnerability, not the detection.
	javaStreamHeader = "\xac\xed\x00\x05"
	// javaStreamHeaderBase64 is base64(javaStreamHeader), truncated to the
	// five characters that are fixed whatever follows it. The first three
	// bytes fill one base64 group exactly, and the fifth character is the
	// first six bits of the version byte, so it is 'B' in every stream. An
	// attacker who rewrites the tail of their blob cannot move the header
	// without rewriting the transport that carries it.
	//
	// This is how the XML-RPC string/base64 types and TeamCity's own JSP
	// entry point actually put a serialized object on the wire, so it is
	// the form this class is most likely to meet in the clear.
	javaStreamHeaderBase64 = "rO0AB"
)

// javaGadgetClasses are the class names a published Java gadget chain needs,
// lowercased for the case-insensitive comparison
// javaSerializationContainer makes against the caller's lowered copies.
//
// A Java stream carries its class descriptor in cleartext -- the descriptor
// names the class before any of it has been read -- which makes a gadget
// class name in the request two things at once: the reason a container on
// the wire is an attack rather than an accident, and the signal that
// survives an attempt whose header bytes were tampered with. The list is the
// gadget families that are actually published, not a guess at what might
// work: the commons-collections chains that are the ysoserial default, the
// JNDI datasource rowset, BeanComparator, the annotation proxy that wraps
// it, the Xalan TemplatesImpl bytecode sink that nearly every chain ends
// in, the xbean JNDI converter, and the ysoserial marker itself.
//
// Only ever matched in company with TeamCity's protocol shape, so ordinary
// traffic that happens to contain one of these words is unaffected.
var javaGadgetClasses = []string{
	// commons-collections 3 and 4: InvokerTransformer, ChainedTransformer
	// and the rest of the default chain.
	"org.apache.commons.collections.functors",
	"org.apache.commons.collections4.functors",
	// The JNDI route: a rowset that will be told where to look up.
	"com.sun.rowset.jdbcrowsetimpl",
	// BeanComparator, and the annotation proxy that carries it.
	"org.apache.commons.beanutils.beancomparator",
	"sun.reflect.annotation.annotationinvocationhandler",
	// The bytecode sink.
	"com.sun.org.apache.xalan.internal.xsltc.trax.templatesimpl",
	// The xbean converter, for the chains that need a different entry.
	"org.apache.xbean.propertyeditor.jndiconverter",
	// A scanner naming its own toolchain, which is the clearest possible
	// statement of intent and costs nothing to recognise.
	"com.ysoserial",
}

// javaSerializationContainer reports whether either channel carries the
// marks of an object stream that something might deserialize.
//
// Three marks, in the order they are worth matching: the stream header
// itself, the same header in the base64 form the transports use, and a
// gadget class name. The first two are byte comparisons over the raw
// strings and the third is a substring search over copies the caller
// already holds, so the common case -- ordinary traffic with no container
// anywhere -- costs two linear scans and no allocation.
//
// There is no decoder anywhere in this function, and that is the point
// rather than an accident of implementation. Decoding in order to "confirm"
// the object is the sink reimplemented inside the thing meant to observe it:
// a second place to get parsing wrong, on attacker-chosen bytes, for no
// extra signal, since every container worth naming is already caught by its
// header. One consequence is worth stating, because it reads like a
// limitation and is not -- a payload whose bytes would not survive a
// decoder still matches here, and one that would is caught by the same four
// bytes the decoder would have needed.
func javaSerializationContainer(c classifyInput) bool {
	// The header, raw. Containment rather than a prefix test, because the
	// raw transport is not always a body on its own: the same four bytes
	// arrive inside a form field, inside an XML element, and on a JSP entry
	// point's query string.
	if strings.Contains(c.Query, javaStreamHeader) || strings.Contains(c.Body, javaStreamHeader) {
		return true
	}
	// The header, base64'd, anchored to the start of a base64 token, and
	// case-sensitively -- because base64 is. Lowercasing this token would
	// match attempts that cannot work and reject ones that can.
	if base64TokenHasPrefix(c.Query, javaStreamHeaderBase64) ||
		base64TokenHasPrefix(c.Body, javaStreamHeaderBase64) {
		return true
	}
	// A gadget class name, in either channel.
	return containsAny(c.Q, javaGadgetClasses...) ||
		containsAny(c.B, javaGadgetClasses...)
}

// base64TokenHasPrefix reports whether a base64 token in s begins with
// prefix -- that is, whether prefix sits at a position where a base64 blob
// could begin rather than somewhere inside one.
//
// Deep inside a long blob any five characters turn up by chance; at the
// start of one they are the header. Every character a base64 value travels
// inside -- the XML element's angle brackets, a URL's own separators,
// whitespace -- is outside the base64 alphabet, which is what lets a
// five-byte comparison stand in for "the start of the blob" without parsing
// the surrounding transport, let alone decoding anything.
func base64TokenHasPrefix(s, prefix string) bool {
	if len(prefix) == 0 || len(s) < len(prefix) {
		return false
	}
	for i := 0; i+len(prefix) <= len(s); i++ {
		if s[i:i+len(prefix)] != prefix {
			continue
		}
		if i == 0 || !isBase64Char(s[i-1]) {
			return true
		}
	}
	return false
}

// isBase64Char reports whether c can appear inside a base64 token.
//
// Padding is deliberately excluded: '=' ends a token, so a '=' immediately
// before a match is a delimiter, and in a query string it is the very
// separator that introduces the parameter. data=rO0AB... has to match.
func isBase64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/'
}

// teamcityAgentCallNames are the call names TeamCity's own build agents use
// on the polling channel, lowercased.
//
// Matched as WHOLE values, because the transport is not TeamCity's alone:
// xmlrpc/remote in particular is an XML-RPC convention, and a product a
// request merely mentions is not a product a request is aimed at. The
// registration family is the part of this channel that needs no credential,
// which is the shape the CVE actually takes.
var teamcityAgentCallNames = []string{
	"xmlrpc/allowregistration",
	"xmlrpc/canregisteragent",
	"xmlrpc/registeragent",
	"xmlrpc/getunregisteredagents",
	"xmlrpc/unregisteragent",
	// The generic envelope the rest of the protocol travels inside, and the
	// two work-download calls by which an agent is handed a build.
	"xmlrpc/remote",
	"agentunload",
	"agentunload2",
}

// teamcityProtocolMarkers are TeamCity's own qualified names: a DTO the
// agent protocol exchanges, the product's Java packages, and the JSP entry
// point's file name.
//
// A substring match is right here, unlike for the call names: these are
// package-qualified identifiers rather than words, and
// "org.jetbrains.teamcity" is not something ordinary traffic carries. The
// teamcity.* namespace at large is deliberately NOT in this list -- an
// agent's own property bag is full of teamcity.agent.jvm.os.name and
// neighbours, and that bag is what a normal poll looks like. The namespace
// is the product's; these are its internals.
var teamcityProtocolMarkers = []string{
	"teamcity.server.message",
	"org.jetbrains.teamcity",
	"jetbrains.buildserver",
	"buildserver.action",
}

// teamcityAgentProtocol reports whether a request names TeamCity's own
// build-agent protocol, on the lowered copies of the two channels.
//
// Two ways, and the cheap one comes first: a product-qualified marker
// anywhere, or a call name as a whole value. The call name is extracted
// rather than substring-matched -- from the parameters a caller addressed it
// with, and from the XML-RPC <methodName> element it arrives in -- so that
// xmlrpc/allowRegistrationAndPing, and a call name sitting inside somebody
// else's parameter value, both keep their own answers.
//
// Nothing is parsed in order to answer this. url.ParseQuery splits a string
// into key/value pairs and the element extractor is two index searches;
// neither is told what to do with what it found, and neither can fail in a
// way that changes the answer. Parsing a request to learn what it asked for
// is a different job from noticing what it carried, and the second one is
// this sensor's.
func teamcityAgentProtocol(lowerQuery, lowerBody string) bool {
	if containsAny(lowerQuery, teamcityProtocolMarkers...) ||
		containsAny(lowerBody, teamcityProtocolMarkers...) {
		return true
	}
	for _, channel := range []string{lowerQuery, lowerBody} {
		// A body that is not a parameter list at all parses into junk keys
		// and values, which is harmless: the key test below rejects them.
		// An error alongside real values is tolerated for the same reason
		// wordpressPagenameTraversal tolerates it.
		values, err := url.ParseQuery(channel)
		if err != nil && len(values) == 0 {
			continue
		}
		for key, vals := range values {
			if key != "methodname" && key != "method" {
				continue
			}
			for _, v := range vals {
				if teamcityAgentCall(v) {
					return true
				}
			}
		}
	}
	return teamcityAgentCall(xmlrpcMethodName(lowerBody))
}

// teamcityAgentCall reports whether a lowercased call name is one of
// TeamCity's.
func teamcityAgentCall(lowerName string) bool {
	if lowerName == "" {
		return false
	}
	for _, name := range teamcityAgentCallNames {
		if lowerName == name {
			return true
		}
	}
	return false
}

// xmlrpcMethodName returns the text of an XML-RPC <methodName> element from
// an already-lowercased body, or "" when there is none.
//
// Two index searches over the same string, and deliberately consistent about
// which string they search: lowercasing can change a body's length, so
// indices taken from one copy must never be used to slice another. Working
// throughout on the lowered copy sidesteps that instead of measuring around
// it, and the result is only ever compared as a name, never acted on.
func xmlrpcMethodName(lowerBody string) string {
	const open, closing = "<methodname>", "</methodname>"
	i := strings.Index(lowerBody, open)
	if i < 0 {
		return ""
	}
	rest := lowerBody[i+len(open):]
	j := strings.Index(rest, closing)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
