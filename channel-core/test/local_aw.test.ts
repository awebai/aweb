import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

import { createLocalAWDecryptProvider } from "../src/index.js";

describe("createLocalAWDecryptProvider", () => {
  test("reads decrypted mail from aw mail show JSON", async () => {
    const dir = await mkdtemp(join(tmpdir(), "aweb-local-aw-"));
    const script = join(dir, "aw");
    await writeFile(script, `#!/bin/sh
if [ "$1 $2 $3 $4" != "mail show --message-id mail-1" ]; then
  echo "unexpected args: $*" >&2
  exit 7
fi
printf '{"messages":[{"message_id":"mail-1","subject":"hello","body":"decrypted mail"}]}\\n'
`);
    await chmod(script, 0o755);

    const provider = createLocalAWDecryptProvider({ workdir: dir, awCommand: script });
    await expect(provider.mailMessage?.("mail-1")).resolves.toMatchObject({
      message_id: "mail-1",
      subject: "hello",
      body: "decrypted mail",
    });
  });

  test("reads decrypted chat from exact aw chat history JSON", async () => {
    const dir = await mkdtemp(join(tmpdir(), "aweb-local-aw-"));
    const script = join(dir, "aw");
    await writeFile(script, `#!/bin/sh
if [ "$1 $2 $3 $4 $5 $6" != "chat history --session-id sess-1 --message-id chat-1" ]; then
  echo "unexpected args: $*" >&2
  exit 7
fi
printf '{"session_id":"sess-1","messages":[{"message_id":"chat-1","body":"decrypted chat"}]}\\n'
`);
    await chmod(script, 0o755);

    const provider = createLocalAWDecryptProvider({ workdir: dir, awCommand: script });
    await expect(provider.chatMessage?.("sess-1", "chat-1")).resolves.toMatchObject({
      message_id: "chat-1",
      body: "decrypted chat",
    });
  });
});
