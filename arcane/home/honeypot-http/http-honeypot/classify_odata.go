package main

// #3430's class, layer C: the part of the scanner-laundering rule this binary
// can actually implement. The other two layers are in laundering.go, and the
// case here is the query/body half -- the half that has to be seen before any
// state exists, which is why it is a case in the dispatch and not a hook
// behind it.

import "strings"

// odataDoubleEncode reports an OData system query option -- $select, $filter,
// $top and the rest -- whose key or value still carries a percent-escape
// after one decode. That residue is the whole signature: a client that
// encodes its query once has nothing left to encode, so %2520 (a literal
// %20, or a space one decode too late) is a request that was assembled to
// survive a second decode, which is what #3430's double-encoding bypass is.
//
// Both halves are required and the ordering is the design. The escape alone
// is not this class's business: measured against the pinned 30-day corpus,
// a bare residual escape claims the PHP-CGI probe arriving as %25ADd and
// both WordPress pagename double-encodings, and all three are already
// correctly labelled by the more specific classes earlier in the dispatch. An
// OData option alone is worse, because a legitimate OData client sends
// exactly those keys and would be indistinguishable from a scanner. Together
// they are a shape neither produces: a field-selection endpoint probed with a
// filter that only comes out of the filter after the second decode.
//
// Keys are parsed rather than substring-matched, and the alias form
// (`northwind.$filter`) is allowed because OData defines one -- which also
// means "$filter" inside some other value cannot trigger this.
//
// Matched on the option's own bytes rather than on a path, for the reason
// #2919, #3309 and #3364 each give: a real probe goes to whatever endpoint
// the target's own dispatch resolves, and a bait path would never match.
//
// odataDoubleEncode keeps its (query, body) signature because
// odata_double_encode_test.go calls it directly; the entry point into the
// dispatch is below. residualEscape, the other half of the rule, is shared
// with laundering.go and so lives in classify.go.
func odataDoubleEncode(query, body string) bool {
	options := map[string]bool{
		"$select": true, "$filter": true, "$expand": true, "$orderby": true,
		"$top": true, "$skip": true, "$count": true, "$apply": true,
		"$format": true, "$search": true, "$skiptoken": true, "$index": true,
	}
	for _, raw := range []string{query, body} {
		// formValues, not url.ParseQuery, for the reason
		// roundcubeVirtuserSQLi gives at its own call site: a `;` inside
		// a pair makes url.ParseQuery drop that pair, so an option whose
		// own value carries one was invisible to this gate while the
		// target parsed it. `;` is also what a Java/ASP.NET-style
		// client sends when it is being careless, and a request nobody
		// sends is not evidence.
		values := formValues(raw)
		for key, vals := range values {
			// OData allows a namespace alias prefix, so compare the last
			// dotted part: `northwind.$filter` is the same option.
			name := strings.ToLower(key)
			if i := strings.LastIndex(name, "."); i >= 0 {
				name = name[i+1:]
			}
			if !options[name] {
				continue
			}
			if residualEscape(key) {
				return true
			}
			for _, v := range vals {
				if residualEscape(v) {
					return true
				}
			}
		}
	}
	return false
}

// odataDoubleEncodeCase is the dispatch's entry for odataDoubleEncode. The
// raw query and body go in, not the lowercased pair: formValues does its own
// decoding, and the residue this class is looking for is destroyed by a
// decode that happens before it.
func odataDoubleEncodeCase(c classifyInput) bool {
	return odataDoubleEncode(c.Query, c.Body)
}
