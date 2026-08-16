package main

import (
	_ "embed"
	"fmt"
)

// pdfHeaderMarkData is the compact APIARY emblem encoded as a 64x64,
// one-bit image mask. The copper fill is supplied by the report theme at
// draw time, so the same source remains correct for both PDF color modes.
//
//go:embed assets_pdf/apiary-header-mark.maskdata
var pdfHeaderMarkData []byte

const (
	pdfHeaderMarkWidth        = 64
	pdfHeaderMarkHeight       = 64
	pdfHeaderMarkSize         = 22.0
	pdfHeaderMarkObjectNumber = 8
)

func pdfHeaderMarkImageObject() []byte {
	return []byte(fmt.Sprintf(
		"<< /Type /XObject /Subtype /Image /Width %d /Height %d /ImageMask true /BitsPerComponent 1 /Decode [1 0] /Filter /FlateDecode /Length %d >>\nstream\n",
		pdfHeaderMarkWidth, pdfHeaderMarkHeight, len(pdfHeaderMarkData)))
}

func (w *pdfReportWriter) drawHeaderMark() {
	t := w.theme()
	fmt.Fprintf(&w.page.content, "q %.3f %.3f %.3f rg %.2f 0 0 %.2f 32 %.2f cm /HMark Do Q\n",
		t.Accent.r, t.Accent.g, t.Accent.b,
		pdfHeaderMarkSize, pdfHeaderMarkSize, pdfPageHeight-35)
}
