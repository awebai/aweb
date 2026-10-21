export function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}
// Only renderer-authored words use English. Authored labels and record text
// continue to inherit the page container's language.
export function chrome(tag, text, className) {
  const node = element(tag, text, className);
  node.lang = "en";
  return node;
}
export function formattedValue(value, format, ...options) {
  const node = element("bdi", valueText(value, format, ...options));
  if (["date", "date-time", "number", "money_minor"].includes(format))
    node.lang = "en";
  return node;
}
export function valueText(
  value,
  format = "text",
  locale = "en",
  timeZone,
  currency,
) {
  if (value === null || value === undefined) return "—";
  if (format === "date" || format === "date-time") {
    const date = new Date(value);
    return Number.isFinite(date.valueOf())
      ? new Intl.DateTimeFormat(locale, {
          dateStyle: "medium",
          ...(format === "date-time" ? { timeStyle: "short" } : {}),
          timeZone: /^\d{4}-\d{2}-\d{2}$/.test(String(value))
            ? "UTC"
            : timeZone,
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
      const validCurrency =
        typeof currency === "string" &&
        Intl.supportedValuesOf("currency").includes(currency);
      const formatter = new Intl.NumberFormat(
        "en",
        validCurrency
          ? { style: "currency", currency }
          : { minimumFractionDigits: 2, maximumFractionDigits: 2 },
      );
      const scale = validCurrency
        ? formatter.resolvedOptions().maximumFractionDigits
        : 2;
      const divisor = 10n ** BigInt(scale);
      tail = (integer % divisor).toString().padStart(scale, "0");
      integer /= divisor;
      // Format the integer with Intl and replace only its fractional part. This
      // avoids rounding large signed minor-unit integers through Number.
      const parts = formatter.formatToParts(sign === "-" ? -integer : integer);
      // Preserve a negative amount smaller than one major unit.
      if (sign === "-" && integer === 0n)
        parts.unshift({ type: "minusSign", value: "-" });
      return parts
        .map((part) => (part.type === "fraction" ? tail : part.value))
        .join("");
    }
    return (
      sign +
      new Intl.NumberFormat(locale).format(integer) +
      (tail !== undefined ? "." + tail : "")
    );
  }
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}
