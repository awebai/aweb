// A JSON reader for signed protocol records. JSON.parse silently keeps the last
// of duplicate keys, reads 1.0 and 1e0 as the integer 1, and accepts lone
// surrogate escapes, so it cannot tell a strict record from a lenient one.
//
// Values are objects, arrays, strings, booleans, null and safe integers.
// "syntax" covers anything that is not strict JSON (including duplicate keys
// and lone surrogates); "number" is a well-formed number that is not a safe
// integer; "depth" is nesting deeper than the caller allows.

export type StrictJSONFailure = "syntax" | "number" | "depth";

export class StrictJSONError extends Error {
  constructor(readonly failure: StrictJSONFailure, message: string) {
    super(message);
  }
}

export function parseStrictJSON(text: string, maxDepth: number): unknown {
  const reader = new Reader(text, maxDepth);
  reader.skipWhitespace();
  const value = reader.value(0);
  reader.skipWhitespace();
  if (reader.position !== text.length) reader.fail("syntax", "trailing data");
  return value;
}

class Reader {
  position = 0;

  constructor(private readonly text: string, private readonly maxDepth: number) {}

  fail(failure: StrictJSONFailure, message: string): never {
    throw new StrictJSONError(failure, `${message} at offset ${this.position}`);
  }

  skipWhitespace(): void {
    while (this.position < this.text.length && " \t\n\r".includes(this.text[this.position])) this.position += 1;
  }

  value(depth: number): unknown {
    const ch = this.text[this.position];
    if (ch === "{") return this.object(depth + 1);
    if (ch === "[") return this.array(depth + 1);
    if (ch === '"') return this.string();
    if (ch === "-" || (ch >= "0" && ch <= "9")) return this.number();
    for (const [literal, result] of [["true", true], ["false", false], ["null", null]] as const) {
      if (this.text.startsWith(literal, this.position)) {
        this.position += literal.length;
        return result;
      }
    }
    return this.fail("syntax", "unexpected character");
  }

  object(depth: number): Record<string, unknown> {
    if (depth > this.maxDepth) this.fail("depth", "nesting too deep");
    this.position += 1;
    const result: Record<string, unknown> = Object.create(null);
    this.skipWhitespace();
    if (this.text[this.position] === "}") {
      this.position += 1;
      return { ...result };
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.position] !== '"') this.fail("syntax", "expected object key");
      const key = this.string();
      if (Object.prototype.hasOwnProperty.call(result, key)) this.fail("syntax", `duplicate key ${JSON.stringify(key)}`);
      this.skipWhitespace();
      if (this.text[this.position] !== ":") this.fail("syntax", "expected ':'");
      this.position += 1;
      this.skipWhitespace();
      result[key] = this.value(depth);
      this.skipWhitespace();
      const ch = this.text[this.position];
      this.position += 1;
      if (ch === "}") return { ...result };
      if (ch !== ",") this.fail("syntax", "expected ',' or '}'");
    }
  }

  array(depth: number): unknown[] {
    if (depth > this.maxDepth) this.fail("depth", "nesting too deep");
    this.position += 1;
    const result: unknown[] = [];
    this.skipWhitespace();
    if (this.text[this.position] === "]") {
      this.position += 1;
      return result;
    }
    for (;;) {
      this.skipWhitespace();
      result.push(this.value(depth));
      this.skipWhitespace();
      const ch = this.text[this.position];
      this.position += 1;
      if (ch === "]") return result;
      if (ch !== ",") this.fail("syntax", "expected ',' or ']'");
    }
  }

  string(): string {
    this.position += 1;
    let result = "";
    for (;;) {
      if (this.position >= this.text.length) this.fail("syntax", "unterminated string");
      const ch = this.text[this.position];
      const code = ch.charCodeAt(0);
      if (ch === '"') {
        this.position += 1;
        return result;
      }
      if (code < 0x20) this.fail("syntax", "control character in string");
      if (code >= 0xd800 && code <= 0xdfff) {
        // Raw surrogates only reach here as a valid pair from decoded UTF-8.
        const next = this.text.charCodeAt(this.position + 1);
        if (code > 0xdbff || !(next >= 0xdc00 && next <= 0xdfff)) this.fail("syntax", "lone surrogate");
        result += this.text.slice(this.position, this.position + 2);
        this.position += 2;
        continue;
      }
      if (ch !== "\\") {
        result += ch;
        this.position += 1;
        continue;
      }
      const escape = this.text[this.position + 1];
      this.position += 2;
      const simple: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (escape in simple) {
        result += simple[escape];
        continue;
      }
      if (escape !== "u") this.fail("syntax", "invalid escape");
      const unit = this.hexUnit();
      if (unit >= 0xdc00 && unit <= 0xdfff) this.fail("syntax", "lone surrogate");
      if (unit >= 0xd800 && unit <= 0xdbff) {
        if (this.text.slice(this.position, this.position + 2) !== "\\u") this.fail("syntax", "lone surrogate");
        this.position += 2;
        const low = this.hexUnit();
        if (!(low >= 0xdc00 && low <= 0xdfff)) this.fail("syntax", "lone surrogate");
        result += String.fromCharCode(unit, low);
        continue;
      }
      result += String.fromCharCode(unit);
    }
  }

  hexUnit(): number {
    const digits = this.text.slice(this.position, this.position + 4);
    if (!/^[0-9A-Fa-f]{4}$/.test(digits)) this.fail("syntax", "invalid \\u escape");
    this.position += 4;
    return parseInt(digits, 16);
  }

  number(): number {
    const match = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(this.text.slice(this.position));
    if (!match) return this.fail("syntax", "invalid number");
    this.position += match[0].length;
    if (match[2] !== undefined || match[3] !== undefined) this.fail("number", "number is not an integer");
    const value = Number(match[0]);
    if (!Number.isSafeInteger(value)) this.fail("number", "integer out of safe range");
    return value;
  }
}
