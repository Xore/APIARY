// dicompot build-time dependency patch (#3179) -- close DICOM tells 2 and 5.
//
// Same shape as this repo's other dependency patches (cowrie's
// txtcmds_priority_patch.py and service_request_log_patch.py, hellpot's
// router_patch.py, mailoney's json_log_patch.py, dionaea's six, conpot's
// seven): a program that performs exact-match string replacement against the
// real upstream source, with a marker for idempotency, applied at image build
// time -- not a vendored copy of the dependency, and not a monkeypatch
// injected through an importable module. It is written in Go rather than
// Python only because the target is a Go module and the anchors have to be
// byte-exact Go source; everything else is the same contract:
//
//   - every anchor is verbatim from the pinned dependency, and the pinned
//     revision is named in the comment above it, so a reviewer can diff this
//     file against the upstream source it claims to match;
//   - a match count other than 1 is a hard error, so a bump of the go.mod pin
//     that moves the anchored text fails the image build instead of silently
//     shipping an unpatched decoy;
//   - a second apply is a no-op, so the build is re-runnable.
//
// WHY A PATCH AND NOT A VENDORED COPY (#3179's decision, 2026-09-27):
// this repo has never committed a vendored copy of a patched dependency --
// all ~25 existing patches are build-time rewrites of a source tree fetched
// at the pinned SHA -- and dicompot in particular is a `go get` dependency
// whose whole point is that go.mod/go.sum is the committed pin. A committed
// copy would turn a one-commit pin bump into a manual merge against upstream
// for files this repo does not otherwise own, and would make it invisible to
// `go mod` that the source has drifted from the pin. So the patch is applied
// to a writable copy of the pinned module at build time and the build is
// pointed at that copy; go.mod stays exactly as committed, so CI's `go test`
// keeps resolving the same pinned revision (and therefore runs this patch's
// suite RED against the unpatched dependency, which is the point -- see
// ax_status_test.go).
//
// WHAT IT CHANGES, and why the wrapper could not:
// #3155's sensor-fidelity audit found five DICOM fingerprint tells. Tells 1, 3
// and 4 were closed in arcane/home/honeypot-dicompot/dicompot/aetitle.go, on
// the raw A-ASSOCIATE byte stream between the socket and
// dicompot.RunProviderForConn. The remaining two are decided below that
// boundary, inside the dependency, with no exported hook, callback or config
// knob to override them -- so closing them means editing the dependency:
//
//   - Tell 2: contextmanager.go's onAssociateRequest answered result 0
//     (acceptance) in the A-ASSOCIATE-AC for *every* abstract syntax it
//     could parse, including UIDs no SCP serves and strings that are not UIDs
//     at all. A real SCP answers 0x03, "abstract syntax not supported", in
//     that presentation context's response item (PS3.8 9.3.3.2, Table 9-9),
//     with no transfer-syntax sub-item attached.
//   - Tell 5: serviceprovider.go's handleCFind / handleCMove / handleCGet
//     always ended on 0x0000, claiming success for a C-MOVE that moved
//     nothing and a C-FIND for a patient the archive has never heard of. A
//     real SCP refuses from the 0xA7xx family (PS3.4 Table C.4-8).
//
// Both are status codes on paths that already exist, computed from state the
// DIMSE command layer has already parsed -- the command's own Affected SOP
// Class UID and the abstract syntax of the presentation context it arrived
// on. No received DICOM object is deserialized by anything this patch adds,
// and no new decoder is introduced. The new helper file is verbatim in
// testdata/apistatus3179.go rather than an inline string, so the repository's
// gofmt gate (quality.yml) formats the code that actually lands in the
// dependency instead of trusting a hand-escaped literal.
package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PinnedRevision is the github.com/nsmfoo/dicompot revision every anchor
// below was taken from. It is asserted against the module's own go.mod path
// at build time by the Dockerfile's `go list -m`; keep the three in step.
const PinnedRevision = "v0.0.0-20260511142612-7351dbec0d3a"

// Marker makes the patch idempotent. Every anchor's replacement text carries
// it, and it also heads the injected file, so a second apply short-circuits
// per file instead of failing the "expected exactly 1 match" drift guard.
const Marker = "APIARY #3179"

// InjectedFile is the new file this patch adds to the dependency; the shared
// refusal logic for tells 2 and 5 lives here rather than inline in three
// anchors, so there is one definition of "what this SCP serves".
const InjectedFile = "apistatus3179.go"

//go:embed testdata/apistatus3179.go
var injectedSource []byte

// anchor is one exact-match replacement: old must occur exactly once in the
// target file, and is replaced by replacement.
type anchor struct {
	name        string
	old         string
	replacement string
}

const contextManagerFile = "contextmanager.go"
const serviceProviderFile = "serviceprovider.go"

// contextManagerAnchors: tell 2.
//
// Verbatim from nsmfoo/dicompot at PinnedRevision, contextmanager.go's
// onAssociateRequest -- the only place in the package that builds the
// A-ASSOCIATE-AC presentation context responses (statemachine.go's AE-6/AC
// action only forwards whatever onAssociateRequest returns).
var contextManagerAnchors = []anchor{{
	name: "onAssociateRequest's presentation-context accept block",
	old: `			if sopUID == "" || pickedTransferSyntaxUID == "" {
				return nil, fmt.Errorf("dicom.onAssociateRequest: SOP or transfersyntax not found in PresentationContext: %v",
					ri.String())
			}
			responses = append(responses, &pdu.PresentationContextItem{
				Type:      pdu.ItemTypePresentationContextResponse,
				ContextID: ri.ContextID,
				Result:    0, // accepted
				Items:     []pdu.SubItem{&pdu.TransferSyntaxSubItem{Name: pickedTransferSyntaxUID}}})
			addContextMapping(m, sopUID, pickedTransferSyntaxUID, ri.ContextID, pdu.PresentationContextAccepted)
`,
	replacement: `			if sopUID == "" || pickedTransferSyntaxUID == "" {
				return nil, fmt.Errorf("dicom.onAssociateRequest: SOP or transfersyntax not found in PresentationContext: %v",
					ri.String())
			}
			// ` + Marker + ` (tell 2): a real SCP accepts only the abstract
			// syntaxes it serves and answers 0x03 -- "abstract syntax not
			// supported" -- in the response item for the rest, with no
			// transfer-syntax sub-item attached (PS3.8 9.3.3.2, Table 9-9).
			// Upstream appended an acceptance for every UID it could parse,
			// which is the fingerprint: propose a private-root UID, read the
			// result byte back. The context is deliberately not registered
			// with addContextMapping, so a P_DATA_TF that arrives on it hits
			// the existing "Unknown context ID" path and is answered with an
			// A-ABORT, which is what a real SCP does with a rejected
			// context. See apistatus3179.go.
			if result, comment, refused := apiary3179RefuseAbstractSyntax(sopUID); refused {
				logrus.WithFields(logrus.Fields{
					"AbstractSyntax": sopUID,
					"ContextID":      ri.ContextID,
					"Result":         result.String(),
					"Reason":         comment,
					"ID":             m.label,
				}).Warn("Presentation context refused")
				responses = append(responses, &pdu.PresentationContextItem{
					Type:      pdu.ItemTypePresentationContextResponse,
					ContextID: ri.ContextID,
					Result:    result,
					Items:     nil})
				continue
			}
			responses = append(responses, &pdu.PresentationContextItem{
				Type:      pdu.ItemTypePresentationContextResponse,
				ContextID: ri.ContextID,
				Result:    0, // accepted
				Items:     []pdu.SubItem{&pdu.TransferSyntaxSubItem{Name: pickedTransferSyntaxUID}}})
			addContextMapping(m, sopUID, pickedTransferSyntaxUID, ri.ContextID, pdu.PresentationContextAccepted)
`,
}}

// serviceProviderAnchors: tell 5, plus the import the new calls need.
//
// Verbatim from nsmfoo/dicompot at PinnedRevision, serviceprovider.go.
var serviceProviderAnchors = []anchor{{
	name: "import block",
	old: `	dicom "github.com/grailbio/go-dicom"
	"github.com/grailbio/go-dicom/dicomio"
	"github.com/nsmfoo/dicompot/dimse"
	"github.com/sirupsen/logrus"
`,
	replacement: `	dicom "github.com/grailbio/go-dicom"
	"github.com/grailbio/go-dicom/dicomio"
	"github.com/nsmfoo/dicompot/dimse"
	"github.com/nsmfoo/dicompot/sopclass"
	"github.com/sirupsen/logrus"
`,
}, {
	name: "handleCFind's callback launch",
	old: `	status := dimse.Status{Status: dimse.StatusSuccess}
	responseCh := make(chan CFindResult, 128)
	var sessionID string = cs.cm.label

	go func() {
		params.CFind(connState, cs.context.transferSyntaxUID, c.AffectedSOPClassUID, elems, sessionID, responseCh)
	}()
	for resp := range responseCh {
`,
	replacement: `	status := dimse.Status{Status: dimse.StatusSuccess}
	responseCh := make(chan CFindResult, 128)
	var sessionID string = cs.cm.label

	// ` + Marker + ` (tell 5): decide the final status from the command's
	// own Affected SOP Class UID and the negotiated abstract syntax, both
	// already parsed by the DIMSE command layer -- no received data set is
	// read to get here. The callback still runs either way, because it is
	// what logs the attempt: a refused query is captured exactly as an
	// accepted one is. A FIND whose SOP class this SCP serves falls through
	// to upstream's code unchanged and still answers 0x0000. See
	// apistatus3179.go.
	refusal, refuse := apiary3179RefuseQuery(
		c.AffectedSOPClassUID, cs.context.abstractSyntaxUID, sopclass.QRFindClasses, false)

	go func() {
		params.CFind(connState, cs.context.transferSyntaxUID, c.AffectedSOPClassUID, elems, sessionID, responseCh)
	}()
	if refuse {
		for range responseCh {
		}
		cs.sendMessage(&dimse.CFindRsp{
			AffectedSOPClassUID:       c.AffectedSOPClassUID,
			MessageIDBeingRespondedTo: c.MessageID,
			CommandDataSetType:        dimse.CommandDataSetTypeNull,
			Status:                    refusal}, nil)
		return
	}
	for resp := range responseCh {
`,
}, {
	name: "handleCMove's callback launch",
	old: `	var sessionID string = cs.cm.label
	responseCh := make(chan CMoveResult, 128)
	go func() {
		params.CMove(connState, cs.context.transferSyntaxUID, c.AffectedSOPClassUID, elems, sessionID, responseCh)
	}()
	status := dimse.Status{Status: dimse.StatusSuccess}
`,
	replacement: `	var sessionID string = cs.cm.label
	responseCh := make(chan CMoveResult, 128)
	// ` + Marker + ` (tell 5): as for C-FIND above, decided from the
	// already-parsed Affected SOP Class UID and negotiated abstract syntax
	// only. len(params.RemoteAEs) is the second half: this decoy configures
	// no destination AE and holds no instance data, so a move it understood
	// but cannot perform is refused with PS3.4's 0xA701 rather than answered
	// 0x0000. The Move Destination (0008,0100) that would decide it more
	// precisely is inside the query data set, which this patch deliberately
	// does not deserialize. See apistatus3179.go.
	refusal, refuse := apiary3179RefuseQuery(
		c.AffectedSOPClassUID, cs.context.abstractSyntaxUID, sopclass.QRMoveClasses, len(params.RemoteAEs) == 0)
	go func() {
		params.CMove(connState, cs.context.transferSyntaxUID, c.AffectedSOPClassUID, elems, sessionID, responseCh)
	}()
	if refuse {
		for range responseCh {
		}
		cs.sendMessage(&dimse.CMoveRsp{
			AffectedSOPClassUID:       c.AffectedSOPClassUID,
			MessageIDBeingRespondedTo: c.MessageID,
			CommandDataSetType:        dimse.CommandDataSetTypeNull,
			Status:                    refusal}, nil)
		return
	}
	status := dimse.Status{Status: dimse.StatusSuccess}
`,
}, {
	name: "handleCGet's callback launch",
	old: `	var sessionID string = cs.cm.label
	responseCh := make(chan CMoveResult, 128)
	go func() {
		params.CGet(connState, cs.context.transferSyntaxUID, c.AffectedSOPClassUID, elems, sessionID, responseCh)
	}()
	status := dimse.Status{Status: dimse.StatusSuccess}
`,
	replacement: `	var sessionID string = cs.cm.label
	responseCh := make(chan CMoveResult, 128)
	// ` + Marker + ` (tell 5): as for C-MOVE above. A C-GET for instances
	// this decoy does not hold is refused with 0xA701 instead of claiming a
	// retrieval that streamed nothing.
	refusal, refuse := apiary3179RefuseQuery(
		c.AffectedSOPClassUID, cs.context.abstractSyntaxUID, sopclass.QRGetClasses, len(params.RemoteAEs) == 0)
	go func() {
		params.CGet(connState, cs.context.transferSyntaxUID, c.AffectedSOPClassUID, elems, sessionID, responseCh)
	}()
	if refuse {
		for range responseCh {
		}
		cs.sendMessage(&dimse.CGetRsp{
			AffectedSOPClassUID:       c.AffectedSOPClassUID,
			MessageIDBeingRespondedTo: c.MessageID,
			CommandDataSetType:        dimse.CommandDataSetTypeNull,
			Status:                    refusal}, nil)
		return
	}
	status := dimse.Status{Status: dimse.StatusSuccess}
`,
}}

// files maps a file in the dependency's tree to the anchors that apply to it.
var files = map[string][]anchor{
	contextManagerFile:  contextManagerAnchors,
	serviceProviderFile: serviceProviderAnchors,
}

// applyPatch rewrites the dependency rooted at root in place and returns a
// one-line status. Deliberately free of package-level side effects, so
// ax_status_test.go can drive it over a throwaway copy of the pinned module
// without a real dicompot install anywhere.
func applyPatch(root string) (string, error) {
	// The injected file is what makes both tells work; if it is already
	// there, the whole tree is already patched.
	injected := filepath.Join(root, InjectedFile)
	if existing, err := os.ReadFile(injected); err == nil {
		if bytes.Contains(existing, []byte(Marker)) {
			return fmt.Sprintf("dimse_status_patch: %s already patched, skipping", root), nil
		}
		return "", fmt.Errorf("dimse_status_patch: %s exists but does not carry %q; refusing to overwrite it",
			injected, Marker)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("dimse_status_patch: reading %s: %w", injected, err)
	}

	for _, name := range []string{contextManagerFile, serviceProviderFile} {
		path := filepath.Join(root, name)
		text, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("dimse_status_patch: reading %s: %w", path, err)
		}
		anchors, ok := files[name]
		if !ok {
			return "", fmt.Errorf("dimse_status_patch: no anchors registered for %s", name)
		}
		for _, a := range anchors {
			if count := strings.Count(string(text), a.old); count != 1 {
				return "", fmt.Errorf("dimse_status_patch: expected exactly 1 match for %s in %s, found %d "+
					"(pinned revision %s no longer matches this anchor; re-derive it before bumping the pin)",
					a.name, path, count, PinnedRevision)
			}
			text = []byte(strings.Replace(string(text), a.old, a.replacement, 1))
		}
		if err := os.WriteFile(path, text, 0o644); err != nil {
			return "", fmt.Errorf("dimse_status_patch: writing %s: %w", path, err)
		}
	}

	if err := os.WriteFile(injected, injectedSource, 0o644); err != nil {
		return "", fmt.Errorf("dimse_status_patch: writing %s: %w", injected, err)
	}
	return fmt.Sprintf("dimse_status_patch: refused unsupported abstract syntax (0x03) and added 0xA701/0xA702 "+
		"DIMSE refusals in %s (pinned %s)", root, PinnedRevision), nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: dimse_status_patch <path-to-dicompot-module-root>")
		os.Exit(2)
	}
	status, err := applyPatch(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(status)
}
