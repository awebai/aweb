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
    const number = Number(value);
    if (!Number.isFinite(number)) return "—";
    return new Intl.NumberFormat(
      locale,
      format === "money_minor"
        ? { minimumFractionDigits: 2, maximumFractionDigits: 2 }
        : {},
    ).format(format === "money_minor" ? number / 100 : number);
  }
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}
