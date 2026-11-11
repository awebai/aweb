package logschain

import "io"

// Witnesses are receipts and checkpoints a verifier holds independently of the
// exporter, each kind in the order given.
type Witnesses struct {
	Receipts    []Artefact
	Checkpoints []Artefact
}

// Read appends the witnesses of one file: lines in a bundle's own artefact
// shape, {"receipt": artefact} or {"checkpoint": artefact}, under a bundle's
// line rules. A line that is not one is refused with a *BundleMalformed.
func (w *Witnesses) Read(r io.Reader) error {
	_, err := readLines(r, func(number int, record map[string]any) error {
		name, value, err := bundleRecord(record, number)
		if err != nil {
			return err
		}
		if name != "receipt" && name != "checkpoint" {
			return &BundleMalformed{number, "not a receipt or checkpoint record"}
		}
		artefact, err := bundleArtefact(value, number)
		if err != nil {
			return err
		}
		if name == "receipt" {
			w.Receipts = append(w.Receipts, artefact)
		} else {
			w.Checkpoints = append(w.Checkpoints, artefact)
		}
		return nil
	})
	return err
}
