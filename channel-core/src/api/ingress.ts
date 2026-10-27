/** One message's delivery-server assertion, independent of author verification. */
export interface ChannelIngress {
  platform: string;
  presence_kind: "shared" | "dedicated" | "native";
  input_origin: "external_human";
  confidentiality: "end_to_end" | "hosted_readable" | "bridge_readable" | "server_readable";
}
