import test from "node:test";
import assert from "node:assert/strict";
import { createDocumentModel } from "../src/folio/assets/document-model.mjs";

const raw =
  ':::widget\r\n{"id":"research","type":"table","bind":{"collection":"notes"}}\r\n:::';
function segments() {
  return [
    { kind: "prose", text: "Before\r\n" },
    {
      kind: "widget",
      id: "research",
      raw,
      definition: { id: "research", type: "table" },
    },
    { kind: "prose", text: "\r\nAfter" },
  ];
}

test("initial serialization retains CRLFs and widget source byte for byte", () => {
  const model = createDocumentModel(segments());
  assert.equal(model.serialize(), "Before\r\n" + raw + "\r\nAfter");
  assert.deepEqual(
    model.parts.map((p) => p.kind),
    ["prose", "widget", "prose"],
  );
});

test("the prose view never exposes widget source as editable text", () => {
  const model = createDocumentModel(segments());
  assert.deepEqual(
    model.parts.filter((p) => p.kind === "prose").map((p) => p.text),
    ["Before\r\n", "\r\nAfter"],
  );
  assert.equal(model.parts[1].raw, undefined);
  model.setProse(0, "");
  model.setProse(1, "");
  assert.equal(model.serialize(), raw);
  assert.equal(model.parts[1].id, "research");
});

test("typing next to an atomic block inserts only prose boundary newlines", () => {
  const model = createDocumentModel(segments());
  model.setProse(0, "Café before");
  model.setProse(1, "After");
  assert.equal(model.serialize(), "Café before\r\n" + raw + "\r\nAfter");
});

test("callers cannot alter source blocks through exposed parts or input aliases", () => {
  const input = segments();
  const model = createDocumentModel(input);
  input[1].raw = "corrupted";
  input[0].text = "also changed";
  const view = model.parts;
  view.splice(1, 1);
  model.parts[1].definition.id = "changed";
  assert.equal(model.serialize(), "Before\r\n" + raw + "\r\nAfter");
  assert.equal(model.parts[1].definition.id, "research");
});

test("ordinary prose stays a single editable value", () => {
  const model = createDocumentModel([{ kind: "prose", text: "Ordinary text" }]);
  model.setProse(0, "Changed\ntext");
  assert.equal(model.serialize(), "Changed\ntext");
  assert.throws(() => model.setProse(1, "unknown slot"));
  assert.throws(() => model.setProse(0, null));
});

test("ambiguous segment lists refuse rather than showing source as prose", () => {
  for (const parts of [
    [],
    [{ kind: "widget", id: "research", raw }],
    [segments()[0], segments()[1]],
    [segments()[0], { ...segments()[1], raw: undefined }, segments()[2]],
  ]) {
    assert.throws(() => createDocumentModel(parts));
  }
});

test("a save snapshot restores only prose while leaving widget bytes intact", () => {
  const model = createDocumentModel(segments());
  model.setProse(0, "Saved prose\n\n");
  const saved = model.prose;
  model.setProse(0, "Discard this prose\n\n");
  model.restoreProse(saved);
  assert.equal(model.prose[0], "Saved prose\n\n");
  assert.equal(model.serialize().includes(raw), true);
  saved[0] = "tampered caller copy";
  assert.equal(model.prose[0], "Saved prose\n\n");
});
