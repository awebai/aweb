import { element, valueText } from "./dom.mjs";

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

function dataTable(records, columns, label, locale, timeZone) {
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
      const cell = element("td");
      cell.append(
        element(
          "bdi",
          valueText(
            record.value[column.field],
            column.format,
            locale,
            timeZone,
          ),
        ),
      );
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
  const values = records.map((r) => Number(r.value[field]));
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
          "stroke-dasharray": `${fraction * 534.071} 534.071`,
          "stroke-dashoffset": -offset * 534.071,
          class: `series-${i % 8}`,
        }),
      );
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
  const toolbar = element("div", null, "collection-toolbar");
  const status = element("p", "", "collection-count");
  status.setAttribute("role", "status");
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
      draw();
    } catch (error) {
      status.textContent =
        error?.code === "revision_conflict" ? t.conflict : t.unavailable;
    }
  }
  function draw() {
    const focusKey = region.contains(document.activeElement)
      ? document.activeElement.dataset.focusKey
      : undefined;
    region.replaceChildren();
    const visible = remote ? records : records.slice(offset, offset + limit);
    status.textContent = `${count} ${t.records}`;
    if (!visible.length) region.append(element("p", t.empty));
    else if (w.type === "table") {
      const table = dataTable(visible, p.columns, t.records, locale, timeZone);
      [...table.tHead.rows[0].cells].forEach((th, i) => {
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
      if (p.row_actions?.length) {
        const th = element("th", t.actions);
        th.scope = "col";
        table.tHead.rows[0].append(th);
        [...table.tBodies[0].rows].forEach((row, i) => {
          const td = element("td");
          for (const id of p.row_actions)
            td.append(actionButton(id, visible[i]));
          row.append(td);
        });
      }
      const scroll = element("div", null, "table-scroll");
      scroll.tabIndex = 0;
      scroll.setAttribute("role", "region");
      scroll.setAttribute("aria-label", t.records);
      scroll.append(table);
      region.append(scroll);
    } else if (w.type === "chart") {
      const figure = element("figure");
      figure.append(element("figcaption", p.alternative));
      for (let i = 0; i < p.series.length; i++) {
        figure.append(
          element("p", p.series[i], "widget-label"),
          chartGraphic(visible, p, i),
        );
      }
      figure.append(
        dataTable(
          visible,
          [
            { field: p.x, label: p.x, format: "text" },
            ...p.series.map((field) => ({
              field,
              label: field,
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
        w.type === "cards" ? "record-cards" : "record-list",
      );
      for (const record of visible) {
        const item = element("li");
        item.dataset.record = record.id;
        const fields = element("dl");
        for (const [slot, field] of Object.entries(p.fields)) {
          fields.append(element("dt", slot));
          const dd = element("dd");
          dd.append(
            element(
              "bdi",
              valueText(
                record.value[field],
                schema?.properties?.[field]?.format === "date-time"
                  ? "date"
                  : "text",
                locale,
                timeZone,
              ),
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
  if (w.type === "table") {
    const filter = element("form", null, "filter-controls");
    const fields = element("select");
    fields.setAttribute("aria-label", t.filterField);
    for (const column of p.columns) {
      const option = element("option", column.label);
      option.value = column.field;
      fields.append(option);
    }
    const value = element("input");
    value.setAttribute("aria-label", t.filterValue);
    const submit = element("button", t.applyFilter);
    submit.type = "submit";
    const clear = element("button", t.clearFilter);
    clear.type = "button";
    clear.onclick = () => {
      value.value = "";
      change({ all: w.bind.all || [], cursor: undefined });
    };
    filter.append(fields, value, submit, clear);
    filter.onsubmit = (event) => {
      event.preventDefault();
      const type = schema?.properties?.[fields.value]?.type;
      let typed = value.value;
      if (type === "integer") typed = Number(value.value);
      if (type === "boolean") typed = value.value === "true";
      change({
        all: [
          ...(w.bind.all || []),
          { field: fields.value, op: "eq", value: typed },
        ],
        cursor: undefined,
      });
    };
    toolbar.append(filter);
  }
  toolbar.append(status);
  box.append(toolbar, region);
  const navigation = element("nav", null, "pagination");
  navigation.setAttribute("aria-label", `${t.pagination}: ${w.id}`);
  navigation.append(previous, next);
  box.append(navigation);
  draw();
}
