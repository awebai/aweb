// C1 permits a bounded, reference-free JSON Schema subset. This evaluator has
// no expression engine, regex compilation, eval, remote reads or coercion.
export function inputErrors(value, schema, pointer = "") {
  if (schema === false) return [pointer];
  if (schema === true || !schema) return [];
  const errors = [];
  const types = Array.isArray(schema.type)
    ? schema.type
    : schema.type
      ? [schema.type]
      : [];
  const isType = (type) =>
    ({
      null: value === null,
      array: Array.isArray(value),
      object:
        value !== null && typeof value === "object" && !Array.isArray(value),
      string: typeof value === "string",
      boolean: typeof value === "boolean",
      integer: Number.isSafeInteger(value),
    })[type];
  if (types.length && !types.some(isType)) return [pointer];
  if (schema.enum && !schema.enum.some((entry) => entry === value))
    errors.push(pointer);
  if (Object.hasOwn(schema, "const") && schema.const !== value)
    errors.push(pointer);
  if (typeof value === "string") {
    const length = [...value].length;
    if (
      length < (schema.minLength ?? 0) ||
      length > (schema.maxLength ?? Infinity)
    )
      errors.push(pointer);
  }
  if (
    typeof value === "number" &&
    (!Number.isSafeInteger(value) ||
      value < (schema.minimum ?? -Infinity) ||
      value > (schema.maximum ?? Infinity))
  )
    errors.push(pointer);
  if (Array.isArray(value)) {
    if (
      value.length < (schema.minItems ?? 0) ||
      value.length > (schema.maxItems ?? Infinity)
    )
      errors.push(pointer);
    value.forEach((item, index) =>
      errors.push(...inputErrors(item, schema.items, `${pointer}/${index}`)),
    );
  } else if (value !== null && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length > (schema.maxProperties ?? Infinity)) errors.push(pointer);
    for (const name of schema.required || [])
      if (!Object.hasOwn(value, name))
        errors.push(`${pointer}/${escapePointer(name)}`);
    for (const name of keys) {
      const child = schema.properties?.[name];
      const path = `${pointer}/${escapePointer(name)}`;
      if (child !== undefined)
        errors.push(...inputErrors(value[name], child, path));
      else if (schema.additionalProperties === false) errors.push(path);
      else if (typeof schema.additionalProperties === "object")
        errors.push(
          ...inputErrors(value[name], schema.additionalProperties, path),
        );
    }
  }
  return [...new Set(errors)];
}
function escapePointer(value) {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

export function typedValue(text, schema) {
  const types = Array.isArray(schema?.type) ? schema.type : [schema?.type];
  if (types.includes("integer")) {
    if (!/^-?(0|[1-9][0-9]*)$/.test(text)) return undefined;
    const integer = Number(text);
    return Number.isSafeInteger(integer) ? integer : undefined;
  }
  // Decimal strings remain strings; no locale-dependent binary float is signed.
  return text;
}
export function acceptableFile(file, accept, maxBytes) {
  if (!file || file.size > maxBytes)
    return "Choose a file within the size limit.";
  if (
    !accept.some((mime) =>
      mime.endsWith("/*")
        ? file.type.startsWith(mime.slice(0, -1))
        : file.type === mime,
    )
  )
    return "Choose an allowed file type.";
  return null;
}
