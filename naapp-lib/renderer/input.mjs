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
export function fileTypes(accept) {
  return accept
    .map(
      (mime) =>
        ({
          "text/plain": "Text files",
          "application/pdf": "PDF files",
          "image/*": "Images",
          "image/png": "PNG images",
          "image/jpeg": "JPEG images",
        })[mime] || `${mime} files`,
    )
    .join(" or ");
}
export function fileSize(bytes) {
  return bytes >= 1024
    ? `${new Intl.NumberFormat("en", { maximumFractionDigits: 1 }).format(bytes / 1024)} KB`
    : `${bytes} bytes`;
}
export function acceptableFile(file, accept, maxBytes) {
  if (!file) return "Choose a file.";
  if (file.size > maxBytes)
    return `${file.name} is ${fileSize(file.size)}. The limit is ${fileSize(maxBytes)}.`;
  if (
    !accept.some((mime) =>
      mime.endsWith("/*")
        ? file.type.startsWith(mime.slice(0, -1))
        : file.type === mime,
    )
  )
    return accept.length === 1 && accept[0] === "text/plain"
      ? `${file.name} isn't a text file.`
      : `${file.name} isn't an allowed type. Choose ${fileTypes(accept).toLowerCase()}.`;
  return null;
}
export function fieldError(value, schema, required, kind) {
  if (value === "" && required) return "Complete this field.";
  if (inputErrors(value, schema).length === 0) return null;
  if (kind === "number" && schema?.type === "integer") {
    if (schema.minimum !== undefined && schema.maximum !== undefined)
      return `Enter a whole number from ${schema.minimum} to ${schema.maximum}.`;
    if (schema.minimum !== undefined)
      return `Enter a whole number of at least ${schema.minimum}.`;
    if (schema.maximum !== undefined)
      return `Enter a whole number no greater than ${schema.maximum}.`;
    return "Enter a whole number.";
  }
  if (
    typeof value === "string" &&
    [...value].length > (schema?.maxLength ?? Infinity)
  )
    return `Use at most ${schema.maxLength} characters.`;
  if (
    schema?.minLength !== undefined &&
    typeof value === "string" &&
    [...value].length < schema.minLength
  )
    return `Use at least ${schema.minLength} characters.`;
  return "Enter a valid value for this field.";
}
