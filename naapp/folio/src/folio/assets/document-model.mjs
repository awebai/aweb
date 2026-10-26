// The checked host supplies ordered segments. Only prose is editable; widget
// source stays in this closure and is never exposed to a prose input.
export function createDocumentModel(segments) {
  if (!Array.isArray(segments) || !segments.length || segments.length % 2 !== 1)
    throw new TypeError("Invalid document segments");
  const parts = structuredClone(segments);
  const ids = new Set();
  parts.forEach((part, index) => {
    if (index % 2 === 0) {
      if (part?.kind !== "prose" || typeof part.text !== "string")
        throw new TypeError("Invalid prose segment");
    } else {
      if (
        part?.kind !== "widget" ||
        typeof part.id !== "string" ||
        typeof part.raw !== "string" ||
        part.definition?.id !== part.id ||
        ids.has(part.id)
      )
        throw new TypeError("Invalid widget segment");
      ids.add(part.id);
    }
  });
  return {
    get prose() {
      return parts
        .filter((part) => part.kind === "prose")
        .map((part) => part.text);
    },
    restoreProse(texts) {
      if (
        !Array.isArray(texts) ||
        texts.length !== (parts.length + 1) / 2 ||
        texts.some((text) => typeof text !== "string")
      )
        throw new TypeError("Invalid prose snapshot");
      texts.forEach((text, index) => {
        parts[index * 2].text = text;
      });
    },
    get parts() {
      let proseIndex = 0;
      return parts.map((part) =>
        part.kind === "prose"
          ? { kind: "prose", index: proseIndex++, text: part.text }
          : {
              kind: "widget",
              id: part.id,
              definition: structuredClone(part.definition),
            },
      );
    },
    setProse(index, text) {
      if (
        !Number.isInteger(index) ||
        index < 0 ||
        index * 2 >= parts.length ||
        typeof text !== "string"
      )
        throw new TypeError("Invalid prose edit");
      parts[index * 2].text = text;
    },
    serialize() {
      if (parts.length === 1) return parts[0].text;
      let result = "";
      let newline = "\n";
      for (const [index, part] of parts.entries()) {
        if (part.kind === "widget") {
          newline = part.raw.includes("\r\n") ? "\r\n" : "\n";
          if (result && !/[\r\n]$/.test(result)) result += newline;
          result += part.raw;
        } else {
          if (index && part.text && !/^[\r\n]/.test(part.text))
            result += newline;
          result += part.text;
        }
      }
      return result;
    },
  };
}
