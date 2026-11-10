// Exercise the released continuation client and trace writer without containers.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/awebai/aw/awid"
)

func main() {
	if len(os.Args) != 4 {
		panic("usage: mail-continuation-trace URL ALIAS CONVERSATION_ID")
	}
	pub, key, err := awid.GenerateKeypair()
	must(err)
	_, controller, err := awid.GenerateKeypair()
	must(err)
	id, err := awid.GenerateUUID4()
	must(err)
	stableID := "did:aw:" + id
	address := "test.local/" + os.Args[2]
	cert, err := awid.SignTeamCertificate(controller, awid.TeamCertificateFields{
		Team: "devteam:test.local", MemberDIDKey: awid.ComputeDIDKey(pub),
		MemberDIDAW: stableID, MemberAddress: address, Alias: os.Args[2],
		IdentityScope: awid.IdentityModeGlobal,
	})
	must(err)
	client, err := awid.NewWithCertificate(os.Args[1], key, cert)
	must(err)
	client.SetStableID(stableID)
	client.SetAddress(address)
	must(os.Setenv("AW_TRACE", "1"))
	// The CLI's --conversation-id --plaintext path calls this same method.
	_, err = client.SendMessageByIdentity(context.Background(), &awid.SendMessageRequest{
		ConversationID: os.Args[3], Body: "Continuation must refuse",
	})
	if err == nil {
		panic("continuation unexpectedly succeeded")
	}
	fmt.Fprintln(os.Stderr, err)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
