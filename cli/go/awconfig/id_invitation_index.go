package awconfig

import (
	"errors"
	"io/fs"
	"os"

	"github.com/awebai/aw/awid"
)

type invitationRequestIndex struct {
	store IDInvitationFileStore
	files fs.FS
}

// InvitationForRequest uses a derived request index; the invitation remains the
// authoritative record. Callers hold the issuer transaction lock. Released
// writers atomically replace invitation files and invalidate the index's saved
// directory timestamp, causing one rebuild rather than hiding their requests.
func (store IDInvitationFileStore) InvitationForRequest(requestID string) (*awid.IDInvitation, error) {
	return (invitationRequestIndex{store: store, files: os.DirFS(store.Dir)}).lookup(requestID)
}

func (index invitationRequestIndex) fileIndex() requestFileIndex {
	return requestFileIndex{directory: index.store.Dir, files: index.files, bindings: func() ([]requestFileBinding, error) {
		invitations, err := index.store.Invitations()
		if err != nil {
			return nil, err
		}
		bindings := []requestFileBinding{}
		for _, inv := range invitations {
			if binding := invitationBinding(inv); binding != nil {
				bindings = append(bindings, *binding)
			}
		}
		return bindings, nil
	}}
}

func invitationBinding(inv *awid.IDInvitation) *requestFileBinding {
	if inv == nil || inv.Request == nil {
		return nil
	}
	return &requestFileBinding{RequestID: inv.Request.RequestID, RecordID: inv.InvitationID}
}

func (index invitationRequestIndex) lookup(requestID string) (*awid.IDInvitation, error) {
	binding, err := index.fileIndex().lookup(requestID)
	if err != nil || binding == nil {
		return nil, err
	}
	inv, err := index.store.readInvitation(index.files, binding.RecordID)
	if err != nil {
		return nil, err
	}
	if inv == nil || inv.Request == nil || inv.Request.RequestID != requestID {
		return nil, errors.New("invitation request index differs from its invitation")
	}
	return inv, nil
}

func (index invitationRequestIndex) put(inv *awid.IDInvitation) error {
	if inv == nil {
		return errors.New("missing ID invitation")
	}
	if _, err := index.store.path(inv.InvitationID); err != nil {
		return err
	}
	fileIndex := index.fileIndex()
	exists, err := fileIndex.exists()
	if err != nil {
		return err
	}
	if inv.Request == nil && !exists {
		return index.store.writeInvitation(inv)
	}
	if err := os.MkdirAll(index.store.Dir, 0700); err != nil {
		return err
	}
	if err := fileIndex.ensure(); err != nil {
		return err
	}
	previous, err := index.store.Invitation(inv.InvitationID)
	if err != nil {
		return err
	}
	if inv.Request != nil {
		bound, err := index.lookup(inv.Request.RequestID)
		if err != nil {
			return err
		}
		if bound != nil && bound.InvitationID != inv.InvitationID {
			return errors.New("invitation request is already bound to another invitation")
		}
	}
	if err := index.store.writeInvitation(inv); err != nil {
		return err
	}
	return fileIndex.commit(requestFileBindingChange{Previous: invitationBinding(previous), Current: invitationBinding(inv)})
}
