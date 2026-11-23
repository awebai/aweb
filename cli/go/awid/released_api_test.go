package awid

import "context"

// aw-v1.36.58 exposed a comparable spawn request and this client signature.
var (
	_ map[SpawnAcceptInviteRequest]struct{}
	_ func(*Client, context.Context, *SpawnAcceptInviteRequest) (*SpawnAcceptInviteResponse, error) = (*Client).AcceptSpawnInvite
)
