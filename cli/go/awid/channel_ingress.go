package awid

// ChannelIngress is delivery-server metadata for one message. It is separate
// from author content, signature status, custody and read authorization.
type ChannelIngress struct {
	Platform        string `json:"platform"`
	PresenceKind    string `json:"presence_kind"`
	InputOrigin     string `json:"input_origin"`
	Confidentiality string `json:"confidentiality"`
}
