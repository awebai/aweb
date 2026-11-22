package awconfig

import (
	"errors"
	"io/fs"
	"os"

	"github.com/awebai/aw/awid"
)

type issuanceRequestIndex struct {
	store IDIssuanceFileStore
	files fs.FS
}

func (index issuanceRequestIndex) fileIndex() requestFileIndex {
	return requestFileIndex{directory: index.store.Dir, files: index.files, bindings: func() ([]requestFileBinding, error) {
		entries, err := index.store.ResignEntries()
		if err != nil {
			return nil, err
		}
		bindings := make([]requestFileBinding, 0, len(entries))
		for _, entry := range entries {
			if binding := issuanceBinding(entry); binding != nil {
				bindings = append(bindings, *binding)
			}
		}
		return bindings, nil
	}}
}

func issuanceBinding(entry *awid.IDIssuanceEntry) *requestFileBinding {
	if entry == nil || entry.Resign == nil {
		return nil
	}
	return &requestFileBinding{RequestID: entry.Resign.RequestID, RecordID: entry.CertificateID}
}

func (index issuanceRequestIndex) lookup(requestID string) (*awid.IDIssuanceEntry, error) {
	if exists, err := index.store.directory(false); err != nil || !exists {
		return nil, err
	}
	binding, err := index.fileIndex().lookup(requestID)
	if err != nil || binding == nil {
		return nil, err
	}
	entry, err := index.store.readEntry(index.files, binding.RecordID)
	if err != nil {
		return nil, err
	}
	if entry == nil || entry.Resign == nil || entry.Resign.RequestID != requestID {
		return nil, errors.New("issuance request index differs from its record")
	}
	return entry, nil
}

func (index issuanceRequestIndex) put(entry *awid.IDIssuanceEntry) error {
	if entry == nil {
		return errors.New("missing ID issuance entry")
	}
	if _, err := index.store.path(entry.CertificateID); err != nil {
		return err
	}
	fileIndex := index.fileIndex()
	exists, err := fileIndex.exists()
	if err != nil {
		return err
	}
	if entry.Resign == nil && !exists {
		return index.store.writeEntry(entry)
	}
	if _, err := index.store.directory(true); err != nil {
		return err
	}
	if err := fileIndex.ensure(); err != nil {
		return err
	}
	previous, err := index.store.Entry(entry.CertificateID)
	if err != nil {
		return err
	}
	if entry.Resign != nil {
		bound, err := index.lookup(entry.Resign.RequestID)
		if err != nil {
			return err
		}
		if bound != nil && bound.CertificateID != entry.CertificateID {
			return errors.New("issuance request is already bound to another certificate")
		}
	}
	if err := index.store.writeEntry(entry); err != nil {
		return err
	}
	return fileIndex.commit(requestFileBindingChange{Previous: issuanceBinding(previous), Current: issuanceBinding(entry)})
}

// EntryForRequest finds only the named re-sign record. The common derived
// request index detects released atomic writers, preserving older store bytes.
func (store IDIssuanceFileStore) EntryForRequest(requestID string) (*awid.IDIssuanceEntry, error) {
	return (issuanceRequestIndex{store: store, files: os.DirFS(store.Dir)}).lookup(requestID)
}
