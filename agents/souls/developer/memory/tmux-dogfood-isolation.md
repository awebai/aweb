# Tmux dogfood isolation

When dogfooding or testing `aw team up` / tmux launcher behavior, never use the default tmux server for destructive or recreate flows. Use a dedicated socket for direct tmux commands (`tmux -L awdogfood ...`) and, when dogfooding the `aw` CLI itself, put a wrapper `tmux` earlier on `PATH` that execs the real tmux with `-L <throwaway-socket>`. Also use throwaway session names and repos. This prevents tests from killing live agent sessions on the default tmux server.
