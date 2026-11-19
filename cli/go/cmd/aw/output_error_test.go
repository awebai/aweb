package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestWriteOutputReturnsJSONEncodingFailureBeforeWriting(t *testing.T) {
	prior := jsonFlag
	jsonFlag = true
	t.Cleanup(func() { jsonFlag = prior })
	var output bytes.Buffer
	err := writeOutput(&output, map[string]any{"unencodable": make(chan int)}, nil)
	if err == nil || output.Len() != 0 {
		t.Fatalf("encoding failure reported output success: error=%v output=%q", err, output.String())
	}
}

type commandOutputRefusingWriter struct{ failure error }

func (writer commandOutputRefusingWriter) Write([]byte) (int, error) { return 0, writer.failure }

func TestCommandOutputReturnsWriterFailureForBothFormats(t *testing.T) {
	failure := errors.New("output unavailable")
	for _, format := range []commandOutputFormat{commandOutputText, commandOutputJSON} {
		err := writeCommandOutput(commandOutputRequest{Writer: commandOutputRefusingWriter{failure: failure}, Value: map[string]string{"status": "connected"}, Format: format, Text: func(any) string { return "connected\n" }})
		if !errors.Is(err, failure) {
			t.Fatalf("format=%v lost writer failure: %v", format, err)
		}
	}
}
