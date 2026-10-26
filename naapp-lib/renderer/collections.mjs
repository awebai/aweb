import { element, chrome, formattedValue, valueText } from "./dom.mjs";
import { safeLink } from "./sanitize.mjs";

export function selectRecords(records, bind) {
  const compare = (a, b) =>
    a === b ? 0 : a == null ? -1 : b == null ? 1 : a < b ? -1 : 1;
  const predicates = {
    eq: (a, b) => a === b,
    ne: (a, b) => a !== b,
    lt: (a, b) => a < b,
    lte: (a, b) => a <= b,
    gt: (a, b) => a > b,
    gte: (a, b) => a >= b,
    in: (a, b) => Array.isArray(b) && b.includes(a),
  };
  return records
    .filter((record) =>
      (bind.all || []).every((p) =>
        predicates[p.op]?.(record.value[p.field], p.value),
      ),
    )
    .toSorted((a, b) => {
      for (const sort of bind.sort || []) {
        const difference = compare(a.value[sort.field], b.value[sort.field]);
        if (difference)
          return sort.direction === "desc" ? -difference : difference;
      }
      return 0;
    });
}

function dataTable(records, columns, label, locale, timeZone, pageLink) {
  const table = element("table");
  table.append(element("caption", label, "sr-only"));
  const head = element("thead");
  const header = element("tr");
  for (const column of columns) {
    const th = element("th", column.label);
    th.scope = "col";
    header.append(th);
  }
  head.append(header);
  table.append(head);
  const body = element("tbody");
  for (const record of records) {
    const row = element("tr");
    row.dataset.record = record.id;
    for (const column of columns) {
      const cell = element(
        "td",
        null,
        ["date", "number", "money_minor", "status"].includes(column.format)
          ? "cell-compact"
          : "cell-text",
      );
      const value = record.value[column.field];
      const url =
        column.format === "url" && typeof value === "string"
          ? safeLink(value)
          : null;
      if (url && pageLink) {
        const link = element("a");
        const domain = element("bdi", url.host);
        domain.setAttribute("aria-hidden", "true");
        // Keep the full destination accessible without a URL attribute.
        link.append(domain, element("span", url.href, "sr-only"));
        pageLink(link, url);
        cell.append(link);
      } else {
        cell.append(
          formattedValue(
            value,
            column.format,
            locale,
            timeZone,
            record.value.currency,
          ),
        );
      }
      row.append(cell);
    }
    body.append(row);
  }
  table.append(body);
  return table;
}
const svg = (tag, attrs) => {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [name, value] of Object.entries(attrs))
    node.setAttribute(name, String(value));
  return node;
};
function chartGraphic(records, p, seriesIndex) {
  const field = p.series[seriesIndex];
  const chart = svg("svg", {
    viewBox: "0 0 640 240",
    "aria-hidden": "true",
    focusable: "false",
    class: `chart-graphic series-${seriesIndex}`,
  });
  const values = records.map((r) => {
    const value = r.value[field];
    return (typeof value === "number" || typeof value === "string") &&
      /^-?[0-9]+(?:\.[0-9]+)?$/.test(String(value))
      ? Number(value)
      : NaN;
  });
  const maximum = Math.max(1, ...values.filter(Number.isFinite).map(Math.abs));
  const points = values.map((v, i) => [
    30 + (i * 580) / Math.max(1, values.length - 1),
    120 - (Number.isFinite(v) ? v / maximum : 0) * 100,
  ]);
  if (p.kind === "bar") {
    const width = 580 / Math.max(1, values.length);
    values.forEach((v, i) => {
      const height = Number.isFinite(v) ? (v / maximum) * 100 : 0;
      chart.append(
        svg("rect", {
          x: 30 + i * width,
          y: height >= 0 ? 120 - height : 120,
          width: Math.max(1, width - 4),
          height: Math.abs(height),
          rx: 2,
        }),
      );
    });
  } else if (p.kind === "line") {
    chart.append(
      svg("polyline", {
        points: points.map((point) => point.join(",")).join(" "),
        fill: "none",
        "stroke-width": 3,
      }),
    );
    for (const [cx, cy] of points)
      chart.append(svg("circle", { cx, cy, r: 4 }));
  } else {
    const positive = values.map((v) =>
      Number.isFinite(v) ? Math.max(0, v) / maximum : 0,
    );
    const total = positive.reduce((a, b) => a + b, 0);
    let offset = 0;
    positive.forEach((value, i) => {
      if (!value || !total) return;
      const fraction = value / total;
      chart.append(
        svg("circle", {
          cx: 320,
          cy: 120,
          r: 85,
          fill: "none",
          "stroke-width": 45,
          "stroke-dasharray": `${Math.max(0, fraction * 534.071 - 6)} 534.071`,
          "stroke-dashoffset": -offset * 534.071,
          class: `series-${i % 8}`,
        }),
      );
      const angle = (offset + fraction / 2) * Math.PI * 2;
      const label = svg("text", {
        x: Math.cos(angle) < 0 ? 200 : 440,
        y: 120 + Math.sin(angle) * 100,
        "text-anchor": Math.cos(angle) < 0 ? "end" : "start",
        class: "pie-direct-label",
      });
      const category = svg("tspan", { x: Math.cos(angle) < 0 ? 200 : 440 });
      category.textContent = valueText(records[i].value[p.x]);
      const amount = svg("tspan", {
        x: Math.cos(angle) < 0 ? 200 : 440,
        dy: 25,
      });
      amount.textContent = valueText(records[i].value[field], "number");
      amount.setAttribute("lang", "en");
      label.append(category, amount);
      chart.append(label);
      offset += fraction;
    });
  }
  return chart;
}

export function renderCollection({
  box,
  w,
  initialRecords,
  initialProjection,
  schema,
  locale,
  timeZone,
  t,
  query,
  onRead,
  actionButton,
  pageLink,
  announce,
  sortEnabled = true,
  rowControls,
}) {
  const p = w.props;
  const region = element("div", null, "collection-content");
  let offset = 0,
    nextCursor = initialProjection?.next_cursor,
    remote = !!initialProjection,
    records =
      initialProjection?.records || selectRecords(initialRecords, query),
    count = initialProjection?.count ?? records.length;
  const cursors = [query.cursor];
  let cursorIndex = 0;
  const limit = query.limit || 20;
  const status = chrome("p", "", "collection-count");
  let requestSerial = 0;
  async function change(bind, reset = true) {
    const request = ++requestSerial;
    if (reset) {
      offset = 0;
      cursorIndex = 0;
      cursors.splice(0, cursors.length, bind.cursor);
    }
    Object.assign(query, bind);
    try {
      const result = await onRead?.(structuredClone(query));
      if (request !== requestSerial) return;
      if (result) {
        records = result.records;
        count = result.count ?? records.length;
        nextCursor = result.next_cursor;
        remote = true;
      } else {
        records = selectRecords(initialRecords, query);
        count = records.length;
        remote = false;
      }
      draw(true);
    } catch (error) {
      status.textContent =
        error?.code === "revision_conflict" ? t.conflict : t.unavailable;
    }
  }
  let projectionFocusKey;
  function draw(shouldAnnounce = false) {
    const active = document.activeElement;
    const focusKey = region.contains(document.activeElement)
      ? document.activeElement.dataset.focusKey
      : document.activeElement === document.body
        ? projectionFocusKey
        : undefined;
    projectionFocusKey = undefined;
    region.replaceChildren();
    const visible = remote ? records : records.slice(offset, offset + limit);
    const start = cursorIndex * limit + offset + 1;
    const range = count
      ? `Showing ${start === Math.min(start + visible.length - 1, count) ? start : `${start}–${Math.min(start + visible.length - 1, count)}`} of ${count}`
      : "0 records";
    status.textContent = range;
    if (!visible.length)
      region.append(chrome("p", "Nothing here yet.", "field-description"));
    else if (w.type === "table") {
      const table = dataTable(
        visible,
        p.columns,
        t.records,
        locale,
        timeZone,
        pageLink,
      );
      table.caption.lang = "en";
      table.caption.id = `records-${w.id}`;
      [...table.tHead.rows[0].cells].forEach((th, i) => {
        if (!sortEnabled) return;
        const column = p.columns[i];
        const button = element("button", column.label, "sort-button");
        const order = query.sort?.find(
          (s) => s.field === column.field,
        )?.direction;
        if (order)
          th.setAttribute(
            "aria-sort",
            order === "asc" ? "ascending" : "descending",
          );
        button.dataset.focusKey = `sort:${column.field}`;
        button.type = "button";
        button.onclick = () =>
          change({
            sort: [
              {
                field: column.field,
                direction: order === "asc" ? "desc" : "asc",
              },
            ],
            cursor: undefined,
          });
        th.replaceChildren(button);
      });
      if (p.row_actions?.length || rowControls) {
        const th = chrome("th", t.actions);
        th.scope = "col";
        table.tHead.rows[0].append(th);
        [...table.tBodies[0].rows].forEach((row, i) => {
          const td = element("td");
          for (const id of p.row_actions || [])
            if (actionButton) td.append(actionButton(id, visible[i]));
          if (rowControls) td.append(rowControls(visible[i]));
          row.append(td);
        });
      }
      const scroll = element("div", null, "table-scroll");
      scroll.tabIndex = 0;
      scroll.setAttribute("role", "region");
      scroll.setAttribute("aria-labelledby", table.caption.id);
      scroll.append(table);
      region.append(scroll);
    } else if (w.type === "chart") {
      const figure = element("figure");
      figure.append(element("figcaption", p.alternative));
      if (
        visible.some((record) =>
          p.series.some((field) => {
            const value = record.value[field];
            return (
              value === null ||
              value === "" ||
              !Number.isFinite(Number(value)) ||
              (p.kind === "pie" && Number(value) < 0)
            );
          }),
        )
      )
        figure.append(
          chrome(
            "p",
            "Some values cannot be charted. Refer to the data table.",
            "field-description",
          ),
        );
      for (let i = 0; i < p.series.length; i++) {
        figure.append(
          element(
            "p",
            schema?.properties?.[p.series[i]]?.title || p.series[i],
            "widget-label",
          ),
          chartGraphic(visible, p, i),
        );
        const labels = element("ul", null, "chart-labels");
        visible.forEach((record, category) => {
          const item = element("li");
          const swatch = element(
            "span",
            null,
            `chart-swatch series-${p.kind === "pie" ? category % 8 : i}`,
          );
          swatch.setAttribute("aria-hidden", "true");
          item.append(
            swatch,
            element("bdi", valueText(record.value[p.x])),
            ": ",
            formattedValue(record.value[p.series[i]], "number", locale),
          );
          labels.append(item);
        });
        figure.append(labels);
      }
      figure.append(
        dataTable(
          visible,
          [
            {
              field: p.x,
              label: schema?.properties?.[p.x]?.title || p.x,
              format: "text",
            },
            ...p.series.map((field) => ({
              field,
              label: schema?.properties?.[field]?.title || field,
              format: "number",
            })),
          ],
          p.alternative,
          locale,
          timeZone,
        ),
      );
      region.append(figure);
    } else {
      const list = element(
        w.type === "activity_timeline" ? "ol" : "ul",
        null,
        w.type === "cards"
          ? "record-cards"
          : w.type === "activity_timeline"
            ? "record-list activity-timeline"
            : "record-list",
      );
      for (const record of visible) {
        const item = element("li");
        item.dataset.record = record.id;
        const fields = element("dl");
        const timeField =
          w.type === "activity_timeline" &&
          Object.values(p.fields).find(
            (field) => schema?.properties?.[field]?.format === "date-time",
          );
        if (timeField) {
          const time = chrome(
            "time",
            valueText(record.value[timeField], "date-time", locale, timeZone),
            "timeline-time",
          );
          time.dateTime = record.value[timeField];
          item.append(time);
        }
        for (const [slot, field] of Object.entries(p.fields)) {
          if (field === timeField) continue;
          fields.append(element("dt", slot));
          const dd = element("dd");
          dd.append(
            formattedValue(
              record.value[field],
              ["date", "date-time"].includes(
                schema?.properties?.[field]?.format,
              )
                ? schema.properties[field].format
                : "text",
              locale,
              timeZone,
            ),
          );
          fields.append(dd);
        }
        item.append(fields);
        for (const id of p.actions || []) item.append(actionButton(id, record));
        list.append(item);
      }
      region.append(list);
    }
    if (focusKey)
      region
        .querySelector(`[data-focus-key="${CSS.escape(focusKey)}"]`)
        ?.focus({ preventScroll: true });
    previous.disabled = remote ? cursorIndex === 0 : offset === 0;
    next.disabled = remote ? !nextCursor : offset + limit >= records.length;
    navigation.hidden = !visible.length || (previous.disabled && next.disabled);
    if (
      (active === previous && previous.disabled) ||
      (active === next && next.disabled) ||
      (navigation.contains(active) && navigation.hidden)
    ) {
      (navigation.hidden ? region : previous.disabled ? next : previous).focus({
        preventScroll: true,
      });
    }
    if (shouldAnnounce) announce?.(range);
  }
  const previous = element("button", t.previous);
  previous.type = "button";
  previous.onclick = () => {
    if (remote) {
      cursorIndex--;
      change({ cursor: cursors[cursorIndex] }, false);
    } else {
      offset = Math.max(0, offset - limit);
      draw();
    }
  };
  const next = element("button", t.next);
  next.type = "button";
  next.onclick = () => {
    if (remote) {
      cursorIndex++;
      cursors[cursorIndex] = nextCursor;
      change({ cursor: nextCursor }, false);
    } else {
      offset += limit;
      draw();
    }
  };
  box.append(region);
  const navigation = chrome("nav", null, "pagination");
  navigation.setAttribute("aria-label", `${t.pagination}: ${w.id}`);
  navigation.append(status, previous, next);
  box.append(navigation);
  region.tabIndex = -1;
  draw();
  return {
    clear() {
      ++requestSerial;
      box.replaceChildren();
    },
    beginRefresh() {
      projectionFocusKey = region.contains(document.activeElement)
        ? document.activeElement.dataset.focusKey
        : undefined;
      region.setAttribute("aria-busy", "true");
      cursorIndex = 0;
      cursors.splice(0, cursors.length, query.cursor);
    },
    updateProjection(projection) {
      records = projection.records;
      count = projection.count ?? records.length;
      nextCursor = projection.next_cursor;
      remote = true;
      region.setAttribute("aria-busy", "false");
      draw();
    },
    showError(message) {
      region.setAttribute("aria-busy", "false");
      region.replaceChildren(chrome("p", message));
    },
  };
}
