package main

import (
	_ "embed"
	"fmt"
)

// watermarkGrayData is a 360x360 8-bit DeviceGray bitmap of the APIARY
// emblem (docs/assets/apiary-logo.png, recolored to Xore/theme's palette),
// zlib-compressed (compress/zlib-compatible /FlateDecode) so it can be
// embedded directly as a PDF Image XObject stream without re-encoding at
// request time. Regenerate via the same luminance-to-grayscale step
// documented in the logo's own source, not by hand-editing this file.
//
//go:embed assets_pdf/watermark.graydata
var watermarkGrayData []byte

const (
	watermarkImageWidth  = 360
	watermarkImageHeight = 360
	// watermarkOpacity is intentionally very low -- this sits behind every
	// other element on the page (drawn first in newPage(), before the
	// background band, header, and all body content that follows), so it
	// must never compete with the report's own text for attention.
	watermarkOpacity = 0.05
	// watermarkSize is the on-page footprint in points, centered, larger
	// than the printable column so it reads as a background mark rather
	// than a bounded illustration.
	watermarkSize = 380.0
)

// pdfImageXObject is the one shared Image XObject every page's content
// stream references -- object numbers are fixed by pdfDocument.bytes()'s
// own layout (see its comment), not computed here.
const pdfWatermarkObjectNumber = 6
const pdfWatermarkGStateObjectNumber = 7

func pdfWatermarkImageObject() []byte {
	return []byte(fmt.Sprintf(
		"<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length %d >>\nstream\n",
		watermarkImageWidth, watermarkImageHeight, len(watermarkGrayData)))
}

func pdfWatermarkGStateObject() []byte {
	return []byte(fmt.Sprintf("<< /Type /ExtGState /ca %.3f >>", watermarkOpacity))
}

// drawWatermark paints the shared image XObject once per page, before
// anything else in that page's content stream -- PDF content streams
// paint in the order they're written, so this is what makes the mark sit
// behind the page background band, every heading, table, and paragraph
// the rest of pdfReportWriter draws afterward, without needing real PDF
// layer/z-order support this minimal writer doesn't otherwise have.
func (w *pdfReportWriter) drawWatermark() {
	x := (pdfPageWidth - watermarkSize) / 2
	y := (pdfPageHeight - watermarkSize) / 2
	fmt.Fprintf(&w.page.content, "q /GS1 gs %.2f 0 0 %.2f %.2f %.2f cm /Wm Do Q\n",
		watermarkSize, watermarkSize, x, y)
}
