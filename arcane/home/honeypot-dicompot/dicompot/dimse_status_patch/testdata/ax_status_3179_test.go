package dicompot

// APIARY #3179: the RED/GREEN suite for the two DICOM fingerprint tells that
// live inside this package. It is written verbatim into a throwaway copy of
// the pinned nsmfoo/dicompot module by ../../ax_status_test.go, which runs
// the identical file twice -- once against the pinned source as `go mod`
// resolves it, and once against the same source with dimse_status_patch
// applied. Against the pinned source these tests fail (upstream accepts every
// abstract syntax and answers 0x0000 for every query); against the patched
// source they pass. Nothing here asserts on the patch's own text, so the
// suite cannot be satisfied by a patch that changes the wrong thing.
//
// No test in this file decodes a received DICOM object. The queries are
// driven through the real handlers with an empty data set, because what is
// under test is the status code those handlers put on an existing response
// path, not a parser.

import (
	"testing"

	dicom "github.com/grailbio/go-dicom"
	"github.com/nsmfoo/dicompot/dimse"
	"github.com/nsmfoo/dicompot/pdu"
	"github.com/nsmfoo/dicompot/sopclass"
)

// implicitVRLittleEndian is the transfer syntax every proposal below offers;
// it is the one default every real SCU proposes and the one this decoy already
// picked unconditionally before the patch.
const implicitVRLittleEndian = "1.2.840.10008.1.2"

// ---------------------------------------------------------------------------
// Tell 2: unsupported / invalid abstract syntax must be refused with 0x03.
// ---------------------------------------------------------------------------

// proposeContext builds one A-ASSOCIATE-RQ presentation context request item.
func proposeContext(contextID byte, abstractSyntax string, transferSyntaxes ...string) pdu.SubItem {
	items := []pdu.SubItem{&pdu.AbstractSyntaxSubItem{Name: abstractSyntax}}
	for _, syntax := range transferSyntaxes {
		items = append(items, &pdu.TransferSyntaxSubItem{Name: syntax})
	}
	return &pdu.PresentationContextItem{
		Type:      pdu.ItemTypePresentationContextRequest,
		ContextID: contextID,
		Items:     items,
	}
}

// negotiate runs onAssociateRequest over a single proposed presentation
// context and reports the result byte the A-ASSOCIATE-AC will carry for it,
// how many sub-items were attached to the response item, and whether the
// context ended up usable for data transfer.
func negotiate(t *testing.T, abstractSyntax string) (result byte, subItems int, usable bool) {
	t.Helper()
	m := newContextManager("ax3179")
	responses, err := m.onAssociateRequest([]pdu.SubItem{
		proposeContext(1, abstractSyntax, implicitVRLittleEndian),
	})
	if err != nil {
		t.Fatalf("onAssociateRequest(%q): %v", abstractSyntax, err)
	}
	for _, item := range responses {
		pc, ok := item.(*pdu.PresentationContextItem)
		if !ok || pc.Type != pdu.ItemTypePresentationContextResponse {
			continue
		}
		_, lookupErr := m.lookupByContextID(pc.ContextID)
		return byte(pc.Result), len(pc.Items), lookupErr == nil
	}
	t.Fatalf("A-ASSOCIATE-AC for %q carried no presentation context response item", abstractSyntax)
	return 0, 0, false
}

// TestAssociationRefusesUnsupportedAbstractSyntaxWith0x03 is tell 2. A
// private-root UID is syntactically perfect and is served by nobody: PS3.8
// Table 9-9's answer is result 3, "abstract syntax not supported", with no
// transfer-syntax sub-item on the response item. Upstream answered 0 for it.
func TestAssociationRefusesUnsupportedAbstractSyntaxWith0x03(t *testing.T) {
	const privateRoot = "1.3.6.1.4.1.99999.1.2.1"
	result, subItems, usable := negotiate(t, privateRoot)
	if result != 3 {
		t.Errorf("presentation context result = %d, want 3 (abstract syntax not supported) for %s",
			result, privateRoot)
	}
	if subItems != 0 {
		t.Errorf("refused presentation context carried %d sub-item(s), want 0: "+
			"PS3.8 Table 9-9 attaches the transfer syntax only on acceptance", subItems)
	}
	if usable {
		t.Error("a refused presentation context is still registered and usable for data transfer, " +
			"so a rejected SOP Class could still carry a C-FIND (upstream's addContextMapping)")
	}
}

// TestAssociationRefusesSyntacticallyInvalidAbstractSyntaxWith0x03 is tell 2's
// other half: tell 2 was reported as "any SOP Class UID is accepted,
// including syntactically invalid ones", and PS3.5 9.1's UID syntax is what
// makes the two halves distinguishable to a scanner.
func TestAssociationRefusesSyntacticallyInvalidAbstractSyntaxWith0x03(t *testing.T) {
	cases := []struct {
		name string
		uid  string
	}{
		{"trailing separator", sopclass.QRFindClasses[0] + "."},
		{"leading separator", "." + sopclass.QRFindClasses[0]},
		{"not a UID at all", "definitely not a uid"},
		{"empty component", "1.2.840..10008"},
		{"leading zero in a component", "1.2.0840.10008.5.1.4.1.2.2.1"},
		{"non-numeric component", "1.2.840.10008.5.1.4.1.2.2.x"},
		{"over PS3.5's 64-character ceiling", "1.2.840.10008.5.1.4.1.2.2.1.1111111111.1111111111.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, subItems, usable := negotiate(t, tc.uid)
			if result != 3 {
				t.Errorf("presentation context result = %d, want 3 for %q", result, tc.uid)
			}
			if subItems != 0 {
				t.Errorf("refused presentation context carried %d sub-item(s), want 0 for %q", subItems, tc.uid)
			}
			if usable {
				t.Errorf("presentation context for %q is registered despite being refused", tc.uid)
			}
		})
	}
}

// TestAssociationStillAcceptsEverySupportedAbstractSyntax is tell 2's
// mandatory negative subtest: 0x03 is only for abstract syntaxes this SCP
// does not serve. Every class in the dependency's own published lists --
// Verification, Storage, and the Query/Retrieve FIND, MOVE and GET classes --
// must still negotiate, and still negotiate exactly as it did before the
// patch: result 0, the client's first proposed transfer syntax echoed back,
// and a context that is usable for data transfer.
func TestAssociationStillAcceptsEverySupportedAbstractSyntax(t *testing.T) {
	groups := []struct {
		name    string
		classes []string
	}{
		{"Verification (C-ECHO)", sopclass.VerificationClasses},
		{"Storage (C-STORE, and C-GET's sub-operation contexts)", sopclass.StorageClasses},
		{"Query/Retrieve FIND (C-FIND)", sopclass.QRFindClasses},
		{"Query/Retrieve MOVE (C-MOVE)", sopclass.QRMoveClasses},
		{"Query/Retrieve GET (C-GET)", sopclass.QRGetClasses},
	}
	proposed := 0
	for _, group := range groups {
		for _, uid := range group.classes {
			proposed++
			// Reported in one line per failure rather than as a subtest each:
			// the whole point is that every one of these ~120 classes still
			// negotiates, and a wall of PASS lines would bury the two that
			// stop doing so.
			result, subItems, usable := negotiate(t, uid)
			if result != 0 {
				t.Errorf("%s %s: presentation context result = %d, want 0 (accepted)",
					group.name, uid, result)
				continue
			}
			if subItems != 1 {
				t.Errorf("%s %s: accepted presentation context carried %d sub-item(s), want 1 (the transfer syntax)",
					group.name, uid, subItems)
			}
			if !usable {
				t.Errorf("%s %s: accepted presentation context is not usable for data transfer", group.name, uid)
			}
		}
	}
	if proposed < 100 {
		t.Fatalf("only %d supported SOP Classes were exercised; the dependency's lists shrank, "+
			"so this test is no longer covering the acceptance path broadly", proposed)
	}
}

// TestAssociationAcceptsABlanketListOfSupportedClassesInOneProposal covers the
// shape a real SCU actually sends -- every SOP Class it supports in a single
// A-ASSOCIATE-RQ, one context each -- so the 0x03 rejection cannot be
// implemented in a way that costs the association its accepted contexts.
func TestAssociationAcceptsABlanketListOfSupportedClassesInOneProposal(t *testing.T) {
	var proposals []pdu.SubItem
	var wantResults []byte
	var refusedContextID byte
	// PS3.8 9.3.2.2: a presentation context ID is an odd byte, which
	// addContextMapping asserts on.
	contextID := byte(1)
	for i, uid := range append(append([]string{}, sopclass.VerificationClasses...), sopclass.QRFindClasses...) {
		if i == len(sopclass.VerificationClasses) {
			// One unsupported context wedged between the two groups, so the
			// refusal cannot be implemented as "give up on the association".
			refusedContextID = contextID
			proposals = append(proposals, proposeContext(contextID, "9.9.9.9.9", implicitVRLittleEndian))
			wantResults = append(wantResults, 3)
			contextID += 2
		}
		proposals = append(proposals, proposeContext(contextID, uid, implicitVRLittleEndian))
		wantResults = append(wantResults, 0)
		contextID += 2
	}

	m := newContextManager("ax3179")
	responses, err := m.onAssociateRequest(proposals)
	if err != nil {
		t.Fatalf("onAssociateRequest: %v", err)
	}
	var got []byte
	for _, item := range responses {
		if pc, ok := item.(*pdu.PresentationContextItem); ok && pc.Type == pdu.ItemTypePresentationContextResponse {
			got = append(got, byte(pc.Result))
		}
	}
	if len(got) != len(wantResults) {
		t.Fatalf("A-ASSOCIATE-AC carried %d presentation context responses, want %d",
			len(got), len(wantResults))
	}
	for i := range wantResults {
		if got[i] != wantResults[i] {
			t.Errorf("presentation context %d result = %d, want %d", i, got[i], wantResults[i])
		}
	}
	// The rejected one must be the only context that cannot carry a command.
	if _, err := m.lookupByContextID(refusedContextID); err == nil {
		t.Errorf("the refused context %d is still usable, so a C-FIND could run on a SOP Class that was rejected",
			refusedContextID)
	}
	if _, err := m.lookupByContextID(1); err != nil {
		t.Errorf("accepted context 1 is not usable: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tell 5: C-FIND/C-MOVE/C-GET must stop claiming unconditional success.
// ---------------------------------------------------------------------------

// silentParams are the decoy's own callbacks: each records that it ran (which
// is what emits the honeypot event) and then reports no matches, exactly as
// main.go's paramsFor does. A refusal must not skip them.
func silentParams(calls *int) ServiceProviderParams {
	return ServiceProviderParams{
		AETitle: "RADIANT",
		CFind: func(_ ConnectionState, _ string, _ string, _ []*dicom.Element, _ string, ch chan CFindResult) {
			*calls = *calls + 1
			close(ch)
		},
		CMove: func(_ ConnectionState, _ string, _ string, _ []*dicom.Element, _ string, ch chan CMoveResult) {
			*calls = *calls + 1
			close(ch)
		},
		CGet: func(_ ConnectionState, _ string, _ string, _ []*dicom.Element, _ string, ch chan CMoveResult) {
			*calls = *calls + 1
			close(ch)
		},
	}
}

// newProviderCommand builds a command state for a message arriving on a
// presentation context already negotiated for abstractSyntaxUID.
func newProviderCommand(t *testing.T, disp *serviceDispatcher, abstractSyntaxUID string) *serviceCommandState {
	t.Helper()
	cs, err := disp.newCommand(newContextManager("ax3179"), contextManagerEntry{
		contextID:         1,
		abstractSyntaxUID: abstractSyntaxUID,
		transferSyntaxUID: implicitVRLittleEndian,
		result:            pdu.PresentationContextAccepted,
	})
	if err != nil {
		t.Fatalf("newCommand: %v", err)
	}
	return cs
}

// collectStatuses drains the dispatcher's downcall channel and returns the
// DIMSE status of every response the handler queued, in order.
func collectStatuses(t *testing.T, disp *serviceDispatcher) []dimse.Status {
	t.Helper()
	var out []dimse.Status
	for ev := range disp.downcallCh {
		if ev.dimsePayload == nil || ev.dimsePayload.command == nil {
			t.Fatalf("handler queued a downcall with no DIMSE payload: %+v", ev)
		}
		status := ev.dimsePayload.command.GetStatus()
		if status == nil {
			t.Fatalf("handler queued a %T, which is a request, not a response", ev.dimsePayload.command)
		}
		out = append(out, *status)
	}
	return out
}

func findStatuses(t *testing.T, params ServiceProviderParams, requestSOPClass, contextSOPClass string) []dimse.Status {
	t.Helper()
	disp := newServiceDispatcher("ax3179")
	cs := newProviderCommand(t, disp, contextSOPClass)
	handleCFind(params, ConnectionState{}, &dimse.CFindRq{
		AffectedSOPClassUID: requestSOPClass,
		MessageID:           1,
	}, nil, cs)
	disp.deleteCommand(cs)
	close(disp.downcallCh)
	return collectStatuses(t, disp)
}

func moveStatuses(t *testing.T, params ServiceProviderParams, requestSOPClass, contextSOPClass string) []dimse.Status {
	t.Helper()
	disp := newServiceDispatcher("ax3179")
	cs := newProviderCommand(t, disp, contextSOPClass)
	handleCMove(params, ConnectionState{}, &dimse.CMoveRq{
		AffectedSOPClassUID: requestSOPClass,
		MessageID:           1,
	}, nil, cs)
	disp.deleteCommand(cs)
	close(disp.downcallCh)
	return collectStatuses(t, disp)
}

func getStatuses(t *testing.T, params ServiceProviderParams, requestSOPClass, contextSOPClass string) []dimse.Status {
	t.Helper()
	disp := newServiceDispatcher("ax3179")
	cs := newProviderCommand(t, disp, contextSOPClass)
	handleCGet(params, ConnectionState{}, &dimse.CGetRq{
		AffectedSOPClassUID: requestSOPClass,
		MessageID:           1,
	}, nil, cs)
	disp.deleteCommand(cs)
	close(disp.downcallCh)
	return collectStatuses(t, disp)
}

func requireSingle(t *testing.T, which string, got []dimse.Status, want dimse.StatusCode) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("%s produced %d DIMSE responses, want exactly 1 (a refusal sends no pending 0xFF00 first)",
			which, len(got))
	}
	if got[0].Status != want {
		t.Errorf("%s status = %#04x (%v), want %#04x (%v)", which, uint16(got[0].Status), got[0].Status,
			uint16(want), want)
	}
}

// TestCFindRefusesAnUnsupportedSOPClassWithA702 is tell 5 for C-FIND: a query
// for a SOP Class this SCP does not serve cannot be understood, so PS3.4
// Table C.4-8's 0xA702 is the answer. Upstream answered 0x0000.
func TestCFindRefusesAnUnsupportedSOPClassWithA702(t *testing.T) {
	calls := 0
	got := findStatuses(t, silentParams(&calls), "1.3.6.1.4.1.99999.1.2.1", implicitVRLittleEndian)
	requireSingle(t, "C-FIND", got, dimse.CMoveOutOfResourcesUnableToPerformSubOperations)
	if got[0].ErrorComment == "" {
		t.Error("0xA702 carried no Error Comment; PS3.8 has no field for one in a presentation context, " +
			"but a DIMSE status does (0000,0902) and a real SCP fills it")
	}
}

// TestCFindRefusesAMismatchedAbstractSyntaxWithA702 is the other half of tell
// 5: PS3.7 7.1 requires the Affected SOP Class UID to be one for which a
// presentation context was accepted, so a command whose Affected SOP Class UID
// disagrees with the context it arrived on is not a request this SCP can
// interpret. Nothing about the query data set is read to reach that verdict.
func TestCFindRefusesAMismatchedAbstractSyntaxWithA702(t *testing.T) {
	calls := 0
	// Arrives on a context negotiated for C-FIND, but claims to be a C-MOVE.
	got := findStatuses(t, silentParams(&calls), sopclass.QRMoveClasses[0], sopclass.QRFindClasses[0])
	requireSingle(t, "C-FIND", got, dimse.CMoveOutOfResourcesUnableToPerformSubOperations)
}

// TestCFindStillAnswersSuccessForASupportedQuery is tell 5's mandatory
// negative subtest. A well-formed query for a SOP Class the SCP serves, on a
// presentation context negotiated for that same SOP Class, is the case a real
// archive answers 0x0000 (no pending matches, then success) and is the case
// the honeypot must keep answering 0x0000 -- it is the overwhelmingly common
// probe, and turning it into a refusal would make the decoy look broken
// rather than real.
func TestCFindStillAnswersSuccessForASupportedQuery(t *testing.T) {
	for _, uid := range sopclass.QRFindClasses {
		calls := 0
		got := findStatuses(t, silentParams(&calls), uid, uid)
		requireSingle(t, "C-FIND for "+uid, got, dimse.StatusSuccess)
		if got[0].ErrorComment != "" {
			t.Errorf("successful C-FIND for %s carried Error Comment %q", uid, got[0].ErrorComment)
		}
	}
}

// TestCMoveRefusesWithA701WhenNoDestinationIsConfigured is tell 5 for C-MOVE.
// This decoy configures no RemoteAEs and holds no instance data, so a move it
// understood but cannot perform is refused with 0xA701, "out of resources,
// unable to calculate number of matches" (PS3.4 Table C.4-8), rather than
// answered 0x0000 for a move that moved nothing.
func TestCMoveRefusesWithA701WhenNoDestinationIsConfigured(t *testing.T) {
	calls := 0
	for _, uid := range sopclass.QRMoveClasses {
		got := moveStatuses(t, silentParams(&calls), uid, uid)
		requireSingle(t, "C-MOVE for "+uid, got, dimse.CMoveOutOfResourcesUnableToCalculateNumberOfMatches)
	}
}

// TestCMoveStillAnswersSuccessWhenADestinationIsConfigured is tell 5's second
// mandatory negative subtest for C-MOVE: the 0xA701 is a statement about this
// decoy's configuration, not a blanket refusal of C-MOVE. Configure a
// destination AE and the handler must fall through to upstream's code
// unchanged and answer 0x0000.
func TestCMoveStillAnswersSuccessWhenADestinationIsConfigured(t *testing.T) {
	calls := 0
	params := silentParams(&calls)
	params.RemoteAEs = map[string]string{"DEST": "10.8.0.9:104"}
	uid := sopclass.QRMoveClasses[0]
	got := moveStatuses(t, params, uid, uid)
	requireSingle(t, "C-MOVE for "+uid+" with a destination configured", got, dimse.StatusSuccess)
}

// TestCGetRefusesWithA701WhenNoDestinationIsConfigured is tell 5 for C-GET,
// including the storage SOP Classes it proposes so instances can come back
// over the same association: there is nothing to stream, so 0xA701. Only the
// first few storage classes are walked -- sopclass.QRGetClasses already
// contains all ~120 of them, and listing each failure separately would bury
// the one that matters.
func TestCGetRefusesWithA701WhenNoDestinationIsConfigured(t *testing.T) {
	calls := 0
	getClasses := sopclass.QRGetClasses[:len(sopclass.QRGetClasses)-len(sopclass.StorageClasses)]
	subjects := append(append([]string{}, getClasses...), sopclass.StorageClasses[:3]...)
	for _, uid := range subjects {
		got := getStatuses(t, silentParams(&calls), uid, uid)
		requireSingle(t, "C-GET for "+uid, got, dimse.CMoveOutOfResourcesUnableToCalculateNumberOfMatches)
	}
}

// TestCGetRefusesAnUnsupportedSOPClassWithA702 keeps the 0xA702 half of tell 5
// on C-GET as well: a C-GET naming a SOP Class that is not a GET class is not
// something this SCP can interpret.
func TestCGetRefusesAnUnsupportedSOPClassWithA702(t *testing.T) {
	calls := 0
	got := getStatuses(t, silentParams(&calls), sopclass.QRFindClasses[0], sopclass.QRFindClasses[0])
	requireSingle(t, "C-GET", got, dimse.CMoveOutOfResourcesUnableToPerformSubOperations)
}

// TestCMoveRefusesAnUnsupportedSOPClassWithA702 completes tell 5's coverage of
// the three handlers.
func TestCMoveRefusesAnUnsupportedSOPClassWithA702(t *testing.T) {
	calls := 0
	got := moveStatuses(t, silentParams(&calls), "1.3.6.1.4.1.99999.1.2.1", implicitVRLittleEndian)
	requireSingle(t, "C-MOVE", got, dimse.CMoveOutOfResourcesUnableToPerformSubOperations)
}

// TestARefusedQueryStillRunsTheCallback is the honeypot's own contract, and
// the reason the refusal sits *after* the callback launch rather than before
// it: the decoy's C-FIND/C-MOVE/C-GET callbacks are what emit the JSON event
// that records the attempt. Refusing before invoking them would close tell 5
// by making the sensor blind to the probe that closed it.
func TestARefusedQueryStillRunsTheCallback(t *testing.T) {
	calls := 0
	params := silentParams(&calls)
	findStatuses(t, params, "1.3.6.1.4.1.99999.1.2.1", implicitVRLittleEndian)
	moveStatuses(t, params, "1.3.6.1.4.1.99999.1.2.1", implicitVRLittleEndian)
	getStatuses(t, params, "1.3.6.1.4.1.99999.1.2.1", implicitVRLittleEndian)
	if calls != 3 {
		t.Errorf("the C-FIND/C-MOVE/C-GET callbacks ran %d times, want 3: a refused query must still be logged", calls)
	}
}
