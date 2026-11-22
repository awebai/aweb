package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIntegrationValidationReturnsClosedOutputAndItsOriginalRefusal(t *testing.T) {
	for _, input := range []struct {
		Name string
		Code string
	}{{Name: "one:example.test"}, {Name: "invalid", Code: "invalid_team_id"}} {
		for _, format := range []struct {
			Name string
			JSON bool
		}{{Name: "text"}, {Name: "json", JSON: true}} {
			t.Run(input.Name+"/"+format.Name, func(t *testing.T) {
				file, err := os.Create(filepath.Join(t.TempDir(), "output"))
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				previousStdout, previousJSON, previousWritten := os.Stdout, jsonFlag, commandStdout.written
				os.Stdout, jsonFlag = file, format.JSON
				t.Cleanup(func() {
					os.Stdout, jsonFlag, commandStdout.written = previousStdout, previousJSON, previousWritten
				})
				err = runValidateTeamID(validateTeamIDCmd, []string{input.Name})
				if !errors.Is(err, os.ErrClosed) || errorCodeOf(err) != input.Code {
					t.Fatalf("closed output lost its error or original validation refusal: %v", err)
				}
			})
		}
	}
}
