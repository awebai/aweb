export function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}
export function valueText(value, format = "text", locale = "en", timeZone) {
  if (value === null || value === undefined) return "—";
  if (format === "date") {
    const date = new Date(value);
    return Number.isFinite(date.valueOf())
      ? new Intl.DateTimeFormat(locale, {
          dateStyle: "medium",
          timeZone,
        }).format(date)
      : String(value);
  }
  if (format === "number" || format === "money_minor") {
    const decimal = String(value).match(/^(-?)([0-9]+)(?:\.([0-9]+))?$/);
    if (!decimal || !["number", "string"].includes(typeof value)) return "—";
    const [, sign, whole, fraction] = decimal;
    let integer = BigInt(whole),
      tail = fraction;
    if (format === "money_minor") {
      if (fraction !== undefined) return "—";
      tail = (integer % 100n).toString().padStart(2, "0");
      integer /= 100n;
    }
    return (
      sign +
      new Intl.NumberFormat(locale).format(integer) +
      (tail !== undefined ? "." + tail : "")
    );
  }
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}
