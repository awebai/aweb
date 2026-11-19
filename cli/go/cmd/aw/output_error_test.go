package main

import (
	"bytes"
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
