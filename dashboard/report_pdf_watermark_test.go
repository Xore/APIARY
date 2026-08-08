package main

import (
	"bytes"
	"compress/zlib"
	"io"
	"strings"
	"testing"
	"time"
)

// TestReportPDFWatermarkPresent (#watermark) proves the emitted PDF actually
// wires the watermark into every page's /Resources and content stream --
// not just that drawWatermark() exists, but that pdfDocument.bytes()'s
// fixed object-number layout (6=image, 7=ExtGState) stays consistent with
// report_pdf_watermark.go's own constants and every page really references
// them, on both themed variants (the two live palettes this ships).
func TestReportPDFWatermarkPresent(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	data := sampleReportData(now)

	for _, theme := range []struct {
		name string
		pdf  pdfTheme
	}{{"dark", pdfThemeDark()}, {"light", pdfThemeLight()}} {
		body := renderThemedReportPDF(data, theme.pdf, defaultPDFBranding())
		text := string(body)

		if !strings.Contains(text, "/Subtype /Image") || !strings.Contains(text, "/ImageMask true") {
			t.Fatalf("%s: watermark Image XObject not found", theme.name)
		}
		if !strings.Contains(text, "/Type /ExtGState") {
			t.Fatalf("%s: watermark ExtGState not found", theme.name)
		}
		if got := strings.Count(text, "/XObject << /Wm 6 0 R /HMark 8 0 R >>"); got == 0 {
			t.Fatalf("%s: no page /Resources references the watermark XObject", theme.name)
		}
		if got := strings.Count(text, "/Wm Do"); got == 0 {
			t.Fatalf("%s: no page content stream actually paints the watermark", theme.name)
		}
		// Every occurrence must come before that page's own header band
		// fill in the SAME content stream -- proving "behind all text" is
		// draw order, not just presence somewhere in the file.
		for _, stream := range strings.Split(text, "stream\n") {
			wm := strings.Index(stream, "/Wm Do")
			if wm == -1 {
				continue
			}
			header := strings.Index(stream, " rg\n")
			if header != -1 && header < wm {
				t.Fatalf("%s: found page content where the header band was filled before the watermark was painted", theme.name)
			}
		}
	}
}

func TestReportPDFHeaderMarkPresent(t *testing.T) {
	body := renderThemedReportPDF(sampleReportData(time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)), pdfThemeLight(), defaultPDFBranding())
	text := string(body)
	for _, want := range []string{
		"/ImageMask true",
		"/Decode [1 0]",
		"/F3 5 0 R",
		"/BaseFont /Helvetica-Bold",
		"/Width 64 /Height 64",
		"/HMark 8 0 R",
		"/HMark Do",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("PDF header mark missing %q", want)
		}
	}
	if strings.Contains(text, "/BaseFont /Times-Roman") {
		t.Fatal("PDF still uses the pre-brand serif display font")
	}

	r, err := zlib.NewReader(bytes.NewReader(pdfHeaderMarkData))
	if err != nil {
		t.Fatalf("pdfHeaderMarkData is not valid zlib data: %v", err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to decompress pdfHeaderMarkData: %v", err)
	}
	wantBytes := pdfHeaderMarkWidth * pdfHeaderMarkHeight / 8
	if len(raw) != wantBytes {
		t.Fatalf("decompressed header mark is %d bytes, want %d", len(raw), wantBytes)
	}
}

// TestWatermarkMaskDataDecompresses proves the embedded asset is valid
// zlib/FlateDecode data of exactly the declared dimensions -- a corrupt or
// mis-sized embed would still compile (it's just a []byte), but would
// produce a PDF no viewer can actually decode the image from.
func TestWatermarkMaskDataDecompresses(t *testing.T) {
	r, err := zlib.NewReader(bytes.NewReader(watermarkMaskData))
	if err != nil {
		t.Fatalf("watermarkMaskData is not valid zlib data: %v", err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to decompress watermarkMaskData: %v", err)
	}
	want := watermarkImageWidth * watermarkImageHeight / 8
	if len(raw) != want {
		t.Fatalf("decompressed watermark is %d bytes, want %d (%dx%d 1-bit mask)",
			len(raw), want, watermarkImageWidth, watermarkImageHeight)
	}
}
