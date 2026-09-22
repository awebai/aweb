# Lessons

* [Delivery receipts and stream health in channel adapters](delivery-receipts-and-stream-health.md) - A transport send is not a delivery receipt; acknowledge only at a real host acceptance boundary, keep event lanes independent, and declare a stream healthy only after live evidence.
* [tmux isolation for agent runtimes](tmux-isolation-for-agent-runtimes.md) - Per-team sockets and a guarded tmux on the path are the runtime-agnostic protections; an inherited tmux variable can hide the server that holds the whole fleet.
