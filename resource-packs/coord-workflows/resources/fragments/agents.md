# Agent operating fragment

- Coordinate through `aw`; do not rely on private TODO files for shared state.
- Treat `.aw` and private keys as identity state. Never overwrite or delete them automatically.
- Prefer primitives and skills over monolithic bootstrap commands.
