package dicompot

// APIARY #3179: presentation-context and DIMSE failure-path fidelity for the
// DICOM decoy, written verbatim into this package by this repo's
// dimse_status_patch at image build time. See that program for why these two
// tells are not reachable from the wrapper's aetitle.go.
//
// #3155's sensor-fidelity audit reported five DICOM fingerprint tells. Tells
// 1, 3 and 4 are closed in the wrapper, on the raw A-ASSOCIATE byte stream
// between the socket and RunProviderForConn. The two closed here are deeper,
// inside this package:
//
//   - Tell 2: onAssociateRequest accepted every abstract syntax it could
//     parse, answering result 0 (acceptance) in the A-ASSOCIATE-AC even for a
//     UID no SCP serves, or for one that is not a UID at all. A real SCP
//     answers 0x03, "abstract syntax not supported", in that presentation
//     context's response item (PS3.8 9.3.3.2, Table 9-9) and drops the
//     transfer-syntax sub-item. Accepting everything is a one-shot
//     fingerprint: propose a private-root UID and read the result byte.
//   - Tell 5: the C-FIND/C-MOVE/C-GET handlers always ended on 0x0000.
//     Whatever the command asked for, the response claimed the operation
//     succeeded -- including a C-MOVE that moved nothing. A real SCP refuses
//     from the 0xA7xx family (PS3.4 Table C.4-8) when it cannot serve the
//     request.
//
// Both decisions read only state the DIMSE command layer has already parsed
// by the time these functions run: the command's own Affected SOP Class UID
// (0000,0002, a required element of every C-FIND/C-MOVE/C-GET command) and
// the abstract syntax of the presentation context the message arrived on.
// Nothing here decodes a received data set, and no new decoder is
// introduced. That is deliberate: the query data set is attacker-controlled,
// these handlers are exactly where a new parser would be a new attack
// surface, and the tell is the status code on an existing response path, not
// a failure to read the request. Move Destination (0008,0100) -- the one
// field that would let a C-MOVE be refused more precisely -- lives inside
// that data set and is therefore deliberately not read; an SCP with no
// destination AE configured refuses the sub-operation instead.

import (
	"strings"

	"github.com/nsmfoo/dicompot/dimse"
	"github.com/nsmfoo/dicompot/pdu"
	"github.com/nsmfoo/dicompot/sopclass"
)

// apiary3179Marker identifies these additions in a patched tree, which is
// what makes the patch idempotent.
const apiary3179Marker = "APIARY #3179"

// apiary3179MaxUIDLength is PS3.5 9.1's ceiling on a UID's encoded length.
const apiary3179MaxUIDLength = 64

// apiary3179UIDWellFormed reports whether uid satisfies PS3.5 9.1: at most 64
// characters, dot-separated components of at most 10 digits each, no leading
// zero in a component longer than one digit, and no empty component. Checked
// before the supported-sopclass lookup so that a syntactically invalid
// abstract syntax and a merely unsupported one stay distinguishable in the
// Error Comment the attacker reads back.
func apiary3179UIDWellFormed(uid string) bool {
	if uid == "" || len(uid) > apiary3179MaxUIDLength {
		return false
	}
	if strings.HasPrefix(uid, ".") || strings.HasSuffix(uid, ".") {
		return false
	}
	for _, component := range strings.Split(uid, ".") {
		if component == "" || len(component) > 10 {
			return false
		}
		if len(component) > 1 && component[0] == '0' {
			return false
		}
		for i := 0; i < len(component); i++ {
			if component[i] < '0' || component[i] > '9' {
				return false
			}
		}
	}
	return true
}

func apiary3179Union(sets ...[]string) []string {
	var out []string
	for _, set := range sets {
		out = append(out, set...)
	}
	return out
}

func apiary3179Contains(haystack []string, needle string) bool {
	for _, candidate := range haystack {
		if candidate == needle {
			return true
		}
	}
	return false
}

// apiary3179SupportedAbstractSyntaxes is every abstract syntax this decoy can
// serve: Verification (C-ECHO), Storage (C-STORE, plus the contexts C-GET
// needs in order to push instances back over the same association), and the
// Query/Retrieve FIND, MOVE and GET classes. It is exactly the union that
// github.com/nsmfoo/dicompot/sopclass already publishes for the client side
// -- the same list read as the server side's answer to "what do you
// accept?", which upstream never asked.
var apiary3179SupportedAbstractSyntaxes = apiary3179Union(
	sopclass.VerificationClasses,
	sopclass.StorageClasses,
	sopclass.QRFindClasses,
	sopclass.QRMoveClasses,
	sopclass.QRGetClasses,
)

// apiary3179RefuseAbstractSyntax decides the A-ASSOCIATE-AC presentation
// context result for one proposed abstract syntax, and whether to refuse at
// all. A supported abstract syntax is never refused, so an honest client's
// association negotiates exactly as it did before.
//
// Note on the Error Comment: it is carried in the DIMSE status the client
// reads back, not in the AC -- PS3.8 Table 9-9's rejected presentation
// context response item has no field for a reason, which is why upstream's
// own PresentationContextResult.String() is the only trace a real SCP leaves
// either. The comment returned here therefore reaches the attacker only via
// apiary3179RefuseQuery's ErrorComment below, and the refused context is
// logged rather than answered with a reason.
func apiary3179RefuseAbstractSyntax(uid string) (pdu.PresentationContextResult, string, bool) {
	if !apiary3179UIDWellFormed(uid) {
		return pdu.PresentationContextProviderRejectionAbstractSyntaxNotSupported,
			"Abstract syntax is not a well-formed UID (PS3.5 9.1)", true
	}
	if !apiary3179Contains(apiary3179SupportedAbstractSyntaxes, uid) {
		return pdu.PresentationContextProviderRejectionAbstractSyntaxNotSupported,
			"Abstract syntax is not served by this application entity", true
	}
	return pdu.PresentationContextAccepted, "", false
}

// apiary3179RefuseQuery decides the final status of a C-FIND/C-MOVE/C-GET.
//
//   - sopClassUID is the command's own Affected SOP Class UID (0000,0002),
//     already parsed by dimse.CommandAssembler into the command struct.
//   - contextAbstractSyntaxUID is the abstract syntax of the presentation
//     context the command arrived on. PS3.7 7.1 requires the Affected SOP
//     Class UID to be one for which a presentation context was accepted;
//     when the two disagree, the SCP cannot know which service was asked
//     for, so it refuses rather than guessing.
//   - supported is the SOP Class list for this DIMSE service
//     (sopclass.QRFindClasses, sopclass.QRMoveClasses or sopclass.QRGetClasses).
//   - noSubOperations is true when this SCP has no destination AE and no
//     instance data behind any storage SOP Class -- the decoy's standing
//     configuration for C-MOVE and C-GET. It has nothing to send, so
//     PS3.4's 0xA701 ("out of resources, unable to calculate number of
//     matches") is the truthful answer, where upstream claimed 0x0000 for a
//     move that moved nothing.
//
// The returned dimse.Status is only meaningful when refuse is true. The 0xA702
// constant is named for C-MOVE in upstream's dimse package, but 0xA702 is the
// shared PS3.4 "refused: cannot understand" code and is what every DIMSE
// service answers with; the constant is reused rather than a literal, so
// there is one number in the wire and one in the source.
func apiary3179RefuseQuery(
	sopClassUID string,
	contextAbstractSyntaxUID string,
	supported []string,
	noSubOperations bool,
) (dimse.Status, bool) {
	if !apiary3179UIDWellFormed(sopClassUID) {
		return dimse.Status{
			Status:       dimse.CMoveOutOfResourcesUnableToPerformSubOperations,
			ErrorComment: "Refused: cannot understand -- Affected SOP Class UID is not a well-formed UID (PS3.5 9.1)",
		}, true
	}
	if contextAbstractSyntaxUID != "" && sopClassUID != contextAbstractSyntaxUID {
		return dimse.Status{
			Status:       dimse.CMoveOutOfResourcesUnableToPerformSubOperations,
			ErrorComment: "Refused: cannot understand -- Affected SOP Class UID does not match the abstract syntax of the negotiated presentation context (PS3.7 7.1)",
		}, true
	}
	if !apiary3179Contains(supported, sopClassUID) {
		return dimse.Status{
			Status:       dimse.CMoveOutOfResourcesUnableToPerformSubOperations,
			ErrorComment: "Refused: cannot understand -- this application entity does not serve Affected SOP Class UID " + sopClassUID,
		}, true
	}
	if noSubOperations {
		return dimse.Status{
			Status:       dimse.CMoveOutOfResourcesUnableToCalculateNumberOfMatches,
			ErrorComment: "Refused: out of resources, unable to calculate number of matches -- no destination application entity is configured for this move",
		}, true
	}
	return dimse.Status{}, false
}
