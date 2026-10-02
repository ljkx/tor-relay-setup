// tor-relay-setup fleet web UI: renders GET api/fleet every 15 seconds.
// Read-only; every value goes into the page through textContent or DOM
// attributes, never as HTML.
(function () {
  "use strict";

  const meta = (name) => (document.querySelector('meta[name="' + name + '"]') || {}).content || "";
  const BASE = meta("trs-base") || "/";
  const PRIVACY = meta("trs-privacy") === "1";
  const REFRESH_MS = 15000;
  const $ = (id) => document.getElementById(id);

  // ---- DOM helper -------------------------------------------------------
  function el(tag, attrs, ...children) {
    const svg = tag.startsWith("svg:");
    const node = svg ? document.createElementNS("http://www.w3.org/2000/svg", tag.slice(4)) : document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") node.setAttribute("class", v);
      else if (k === "text") node.textContent = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat(Infinity)) {
      if (c === undefined || c === null || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  // ---- formatting -------------------------------------------------------
  function rate(bytesPerSecond) {
    const bits = (bytesPerSecond || 0) * 8;
    if (bits >= 1e9) return (bits / 1e9).toFixed(2) + " Gbit/s";
    if (bits >= 1e6) return (bits / 1e6).toFixed(1) + " Mbit/s";
    if (bits >= 1e3) return (bits / 1e3).toFixed(0) + " kbit/s";
    return bits.toFixed(0) + " bit/s";
  }
  function bytes(n) {
    const units = [[1e15, "PB"], [1e12, "TB"], [1e9, "GB"], [1e6, "MB"], [1e3, "kB"]];
    for (const [d, u] of units) if (n >= d) return (n / d).toFixed(1) + " " + u;
    return Math.round(n || 0) + " B";
  }
  function binBytes(n) {
    const units = [[2 ** 40, "TiB"], [2 ** 30, "GiB"], [2 ** 20, "MiB"], [2 ** 10, "KiB"]];
    for (const [d, u] of units) if (n >= d) return (n / d).toFixed(2) + " " + u;
    return Math.round(n || 0) + " B";
  }
  function percent(f) {
    const p = (f || 0) * 100;
    if (p === 0) return "0%";
    if (p < 0.01) return p.toFixed(4) + "%";
    if (p < 1) return p.toFixed(3) + "%";
    return p.toFixed(2) + "%";
  }
  function count(n) { return (n || 0).toLocaleString("en-US"); }
  function ago(iso) {
    if (!iso) return "never";
    const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
    if (s < 60) return Math.round(s) + " s ago";
    if (s < 3600) return Math.round(s / 60) + " min ago";
    if (s < 172800) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " days ago";
  }
  function until(iso) {
    const s = (Date.parse(iso) - Date.now()) / 1000;
    if (s <= 0) return "expired";
    if (s < 3600) return "in " + Math.round(s / 60) + " min";
    if (s < 172800) return "in " + Math.round(s / 3600) + " h";
    return "in " + Math.round(s / 86400) + " days";
  }
  function date(iso) {
    if (!iso) return "–";
    const d = new Date(iso);
    return d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
  }
  const FLAG_ORDER = ["Guard", "Stable", "Fast", "Exit", "HSDir", "Valid", "Running", "V2Dir", "BadExit", "MiddleOnly", "Authority", "StaleDesc"];
  const FLAG_LETTER = { Guard: "G", Stable: "S", Fast: "F", Exit: "E", HSDir: "H", Valid: "V", Running: "R", V2Dir: "D", BadExit: "B", MiddleOnly: "M", Authority: "A", StaleDesc: "s" };
  function abbrevFlags(flags) {
    return FLAG_ORDER.filter((f) => (flags || []).includes(f)).map((f) => FLAG_LETTER[f]).join("");
  }
  const STATE_CLASS = { running: "", stopped: "bad", missing: "bad", unconfigured: "bad", unreachable: "bad", failed: "bad", "too-old": "warn", "not-installed": "warn", pending: "idle" };

  // ---- state ------------------------------------------------------------
  let data = null;
  let lastOK = 0;
  let sortKey = "status";
  let sortDir = 1;
  let roleFilter = "";
  let textFilter = "";
  let openID = null;
  let timer = null;

  function live(r) { return (r.live_read || 0) + (r.live_written || 0); }
  function weight(r) { return (r.directory && r.directory.consensus_weight) || 0; }
  function rank(r) {
    if (r.state !== "running") return STATE_CLASS[r.state] === "bad" ? 0 : 1;
    if ((r.warnings || []).length || (r.directory && r.directory.overloaded)) return 2;
    return 3;
  }
  const SORTS = {
    nickname: (a, b) => a.nickname.localeCompare(b.nickname, "en", { sensitivity: "base" }),
    role: (a, b) => a.role.localeCompare(b.role),
    state: (a, b) => rank(a) - rank(b),
    status: (a, b) => rank(a) - rank(b),
    flags: (a, b) => abbrevFlags(b.directory && b.directory.flags).length - abbrevFlags(a.directory && a.directory.flags).length,
    live: (a, b) => live(b) - live(a),
    weight: (a, b) => weight(b) - weight(a),
    country: (a, b) => ((a.directory && a.directory.country) || "~").localeCompare((b.directory && b.directory.country) || "~"),
    tor: (a, b) => (a.tor_version || "").localeCompare(b.tor_version || ""),
    warnings: (a, b) => (b.warnings || []).length - (a.warnings || []).length,
  };

  // ---- fetching ---------------------------------------------------------
  async function load() {
    clearTimeout(timer);
    try {
      const res = await fetch(BASE + "api/fleet", { credentials: "same-origin", headers: { Accept: "application/json" }, cache: "no-store" });
      if (res.status === 401) { window.location.assign(BASE); return; }
      if (!res.ok) throw new Error("HTTP " + res.status);
      data = await res.json();
      lastOK = Date.now();
      render();
    } catch (e) {
      status(String(e.message || e), true);
    } finally {
      timer = setTimeout(load, REFRESH_MS);
    }
  }

  function status(error, failed) {
    const s = $("status");
    s.replaceChildren();
    s.className = "topbar-status" + (failed ? " error" : "");
    if (!data) { s.append(el("span", { class: "dot" }), failed ? "Cannot reach the server: " + error : "Loading…"); return; }
    const stale = data.last_probe && Date.now() - Date.parse(data.last_probe) > 5 * 60 * 1000;
    if (stale) s.classList.add("stale");
    s.append(el("span", { class: "dot" }));
    const parts = [];
    parts.push(data.last_probe ? "Probed " + ago(data.last_probe) + " (" + (data.probe_seconds || 0).toFixed(1) + " s)" : "First probe running…");
    parts.push(data.directory_updated ? "Tor Metrics " + ago(data.directory_updated) : "Tor Metrics pending");
    if (failed) parts.unshift("Update failed: " + error);
    s.append(parts.join(" · "));
  }

  // ---- rendering --------------------------------------------------------
  function render() {
    status();
    renderBanner();
    renderCards();
    renderSpark();
    renderAttention();
    renderRelays();
    renderHosts();
    if (openID) {
      const r = data.relays.find((x) => x.id === openID);
      if (r) fillDrawer(r); else closeDrawer();
    }
  }

  function renderBanner() {
    const b = $("banner");
    if (data.directory_error) {
      b.textContent = "Tor Metrics could not be reached; its numbers may be out of date (" + data.directory_error + ").";
      b.hidden = false;
    } else {
      b.hidden = true;
    }
  }

  function card(label, value, sub, tone) {
    return el("div", { class: "card " + (tone || "") }, el("span", { class: "label", text: label }), value, sub ? el("span", { class: "sub" }, sub) : null);
  }
  function big(main, small) { return el("span", { class: "value" }, main, small ? el("small", {}, " " + small) : null); }

  function renderCards() {
    const t = data.totals;
    const cards = [];
    const down = t.relays - t.running;
    cards.push(card("Relays running", big(String(t.running), "/ " + t.relays), down ? down + " not running" : "all running", down ? "bad" : "good"));
    const hostTone = t.hosts_unreachable ? "bad" : t.hosts_without_probe ? "warn" : "good";
    const hostSub = [t.hosts_unreachable ? t.hosts_unreachable + " unreachable" : "", t.hosts_without_probe ? t.hosts_without_probe + " without probe" : ""].filter(Boolean).join(" · ") || "all answering";
    cards.push(card("Servers up", big(String(t.hosts_up), "/ " + t.hosts), hostSub, hostTone));
    cards.push(card("Live traffic", big(rate(t.live_read + t.live_written)),
      [el("span", { class: "r", text: "↓ " + rate(t.live_read) }), "  ", el("span", { class: "w", text: "↑ " + rate(t.live_written) })]));
    cards.push(card("Consensus weight", big(count(t.consensus_weight)), percent(t.consensus_weight_fraction) + " of the network"));
    cards.push(card("Selection", big(percent(t.guard_probability), "guard"), "middle " + percent(t.middle_probability) + " · exit " + percent(t.exit_probability)));
    cards.push(card("Advertised", big(rate(t.advertised_bandwidth)), "observed " + rate(t.observed_bandwidth)));
    cards.push(card("OR connections", big(count(t.or_connections)), t.published + " of " + t.relays + " published"));
    const att = t.attention;
    const bad = data.attention.some((a) => a.level === "bad");
    cards.push(card("Needs attention", big(String(att)), att ? "see the list" : "nothing to do", att ? (bad ? "bad" : "warn") : "good"));
    $("cards").replaceChildren(...cards);
  }

  // Sparkline of the fleet's daily traffic from Tor Metrics.
  function renderSpark() {
    const svg = $("spark-svg");
    const foot = $("spark-foot");
    const h = data.history;
    svg.replaceChildren();
    foot.replaceChildren();
    if (!h || !h.daily || !h.daily.length) {
      svg.append(el("svg:text", { x: 300, y: 75, "text-anchor": "middle", fill: "currentColor", class: "muted", text: "Waiting for Tor Metrics…" }));
      return;
    }
    const vals = h.daily.slice(-30);
    const first = new Date(Date.parse(h.first_day + "T00:00:00Z") + (h.daily.length - vals.length) * 86400000);
    const max = Math.max(1, ...vals.filter((v) => v !== null));
    const W = 600, H = 140, pad = 6;
    const x = (i) => vals.length === 1 ? W / 2 : (i / (vals.length - 1)) * W;
    const y = (v) => H - pad - (v / max) * (H - 2 * pad);
    for (const f of [0.25, 0.5, 0.75]) svg.append(el("svg:line", { class: "grid", x1: 0, x2: W, y1: y(max * f), y2: y(max * f) }));
    // Runs of days with data become separate line segments.
    let line = "", area = "", run = [];
    const flush = () => {
      if (!run.length) return;
      line += run.map(([i, v], k) => (k ? "L" : "M") + x(i).toFixed(1) + " " + y(v).toFixed(1)).join(" ") + " ";
      area += "M" + x(run[0][0]).toFixed(1) + " " + (H - pad) + " " + run.map(([i, v]) => "L" + x(i).toFixed(1) + " " + y(v).toFixed(1)).join(" ") +
        " L" + x(run[run.length - 1][0]).toFixed(1) + " " + (H - pad) + " Z ";
      run = [];
    };
    vals.forEach((v, i) => { if (v === null) { flush(); svg.append(el("svg:rect", { class: "gap", x: x(i) - 4, y: 0, width: 8, height: H })); } else run.push([i, v]); });
    flush();
    svg.append(el("svg:path", { class: "area", d: area }), el("svg:path", { class: "line", d: line }));
    const marker = el("svg:line", { class: "marker", x1: 0, x2: 0, y1: 0, y2: H, visibility: "hidden" });
    svg.append(marker);

    const known = vals.filter((v) => v !== null);
    const avg = known.reduce((a, b) => a + b, 0) / Math.max(1, known.length);
    foot.append(
      el("span", {}, "Average " + rate(avg)),
      el("span", {}, "Peak " + rate(max)),
      el("span", {}, "In " + bytes(h.read_bytes) + " · out " + bytes(h.written_bytes)),
    );
    $("spark-caption").textContent = vals.length + " days · Tor Metrics";

    const tip = $("spark-tip");
    const box = $("spark");
    box.onmousemove = (ev) => {
      const r = box.getBoundingClientRect();
      const i = Math.round(((ev.clientX - r.left) / r.width) * (vals.length - 1));
      if (i < 0 || i >= vals.length) return;
      const day = new Date(first.getTime() + i * 86400000).toISOString().slice(0, 10);
      tip.textContent = day + " · " + (vals[i] === null ? "no data" : rate(vals[i]));
      tip.style.left = ((x(i) / W) * r.width) + "px";
      tip.hidden = false;
      marker.setAttribute("x1", x(i)); marker.setAttribute("x2", x(i)); marker.setAttribute("visibility", "visible");
    };
    box.onmouseleave = () => { tip.hidden = true; marker.setAttribute("visibility", "hidden"); };
  }

  function renderAttention() {
    const list = $("attention");
    const c = $("attention-count");
    const items = data.attention || [];
    c.textContent = String(items.length);
    c.className = "count" + (items.some((a) => a.level === "bad") ? " bad" : items.length ? " warn" : "");
    if (!items.length) { list.replaceChildren(el("li", { class: "ok", text: "All relays look healthy." })); return; }
    const sorted = items.slice().sort((a, b) => (a.level === b.level ? 0 : a.level === "bad" ? -1 : 1));
    list.replaceChildren(...sorted.map((a) => el("li", { class: a.level, title: a.kind, text: a.text })));
  }

  function matches(r) {
    if (roleFilter && r.role !== roleFilter) return false;
    if (!textFilter) return true;
    const d = r.directory || {};
    const hay = [r.nickname, r.host, r.instance, r.fingerprint, r.state, r.role, r.tor_version, d.country, d.as, d.as_name, (d.flags || []).join(" "),
      r.bridge && r.bridge.transport].join(" ").toLowerCase();
    return textFilter.split(/\s+/).every((w) => hay.includes(w));
  }

  function renderRelays() {
    const rows = data.relays.filter(matches);
    const cmp = SORTS[sortKey] || SORTS.status;
    const order = new Map(data.relays.map((r, i) => [r.id, i]));
    rows.sort((a, b) => (cmp(a, b) * sortDir) || (order.get(a.id) - order.get(b.id)));
    $("relay-count").textContent = rows.length === data.relays.length ? String(rows.length) : rows.length + " of " + data.relays.length;
    $("relay-empty").hidden = rows.length > 0;
    for (const th of document.querySelectorAll("#relays th")) {
      th.setAttribute("aria-sort", th.dataset.sort === sortKey ? (sortDir > 0 ? "ascending" : "descending") : "none");
    }
    $("relay-rows").replaceChildren(...rows.map(row));
  }

  function row(r) {
    const d = r.directory || {};
    const warns = (r.warnings || []).length;
    const stateCell = el("td", {}, el("span", { class: "state " + (STATE_CLASS[r.state] || ""), text: r.state }));
    if (d.overloaded) stateCell.append(el("span", { class: "pill", text: "overloaded" }));
    if (r.accounting && r.accounting.max_bytes && r.accounting.used_bytes / r.accounting.max_bytes >= 0.85) stateCell.append(el("span", { class: "pill warn", text: "quota" }));
    let liveCell;
    if (PRIVACY) liveCell = el("td", { class: "num muted", text: "hidden" });
    else if (r.live_read !== undefined) liveCell = el("td", { class: "num" }, el("span", { class: "dir", text: "↓" }), " " + rate(r.live_read), el("br"), el("span", { class: "dirw", text: "↑" }), " " + rate(r.live_written));
    else liveCell = el("td", { class: "num zero", text: "–" });
    const tr = el("tr", { tabindex: 0, "data-id": r.id, onclick: () => openDrawer(r.id), onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(r.id); } } },
      el("td", {}, el("span", { class: "nick", text: r.nickname || "(unnamed)" }), el("span", { class: "where", text: r.host + (r.instance !== "default" ? " / " + r.instance : "") })),
      el("td", { class: "opt-sm" }, el("span", { class: "role " + r.role, text: r.role })),
      stateCell,
      el("td", { class: "flags opt", title: (d.flags || []).join(", "), text: abbrevFlags(d.flags) || "–" }),
      liveCell,
      el("td", { class: "num opt", text: d.consensus_weight ? count(d.consensus_weight) : "–" }),
      el("td", { class: "opt", title: d.as_name || "", text: d.country ? d.country.toUpperCase() + (d.as ? " · " + d.as : "") : "–" }),
      el("td", { class: "opt mono", text: r.tor_version || "–" }),
      el("td", { class: "num" }, warns ? el("span", { class: "warncount", text: String(warns) }) : el("span", { class: "zero", text: "0" })),
    );
    return tr;
  }

  function renderHosts() {
    $("host-count").textContent = data.totals.hosts_up + " of " + data.totals.hosts + " up";
    $("hosts").replaceChildren(...data.hosts.map((h) => {
      const cls = h.state === "ok" ? "" : STATE_CLASS[h.state] || "bad";
      const label = h.state === "ok" ? "ok" : h.state;
      const detail = [h.relays + (h.relays === 1 ? " relay" : " relays"), h.version ? "tor-relay-setup " + h.version : "",
        h.probed_at ? "probed " + ago(h.probed_at) + (h.probe_seconds ? " in " + h.probe_seconds.toFixed(1) + " s" : "") : ""].filter(Boolean).join(" · ");
      return el("li", {},
        el("span", { class: "h", title: h.host, text: h.host }),
        el("span", {}, el("span", { class: "state " + cls, text: label })),
        el("span", { class: "d", text: detail }),
        h.detail ? el("span", { class: "d", title: h.detail, text: h.detail }) : null,
        h.state !== "ok" && h.last_ok ? el("span", { class: "d", text: "last answered " + ago(h.last_ok) }) : null);
    }));
  }

  // ---- drawer -----------------------------------------------------------
  let lastFocus = null;
  function openDrawer(id) {
    const r = data.relays.find((x) => x.id === id);
    if (!r) return;
    if (!openID) lastFocus = document.activeElement;
    openID = id;
    fillDrawer(r);
    $("drawer").hidden = false;
    $("scrim").hidden = false;
    $("drawer-close").focus();
  }
  function closeDrawer() {
    openID = null;
    $("drawer").hidden = true;
    $("scrim").hidden = true;
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  function kv(pairs) {
    const dl = el("dl", { class: "kv" });
    for (const [k, v] of pairs) {
      if (v === undefined || v === null || v === "") continue;
      dl.append(el("dt", { text: k }), el("dd", {}, v));
    }
    return dl;
  }
  function section(title, ...body) { return el("section", {}, el("h3", { text: title }), ...body); }
  function yesno(ok, yes, no) { return el("span", { class: "state " + (ok ? "" : "bad"), text: ok ? yes : no }); }
  function bar(fraction) {
    const tone = fraction >= 0.95 ? "bad" : fraction >= 0.8 ? "warn" : "";
    const fill = el("span");
    fill.style.width = Math.min(100, Math.max(0, fraction * 100)).toFixed(1) + "%";
    return el("div", { class: "bar " + tone }, fill);
  }

  function fillDrawer(r) {
    const d = r.directory;
    $("drawer-title").textContent = r.nickname || "(unnamed)";
    $("drawer-sub").textContent = r.role + " on " + r.host + (r.instance !== "default" ? " / " + r.instance : "") + (r.fresh ? "" : " · last known state");
    const body = [];

    const fpRow = r.fingerprint ? el("span", { class: "fp" }, el("code", { text: r.fingerprint.replace(/(.{4})(?=.)/g, "$1 ") }),
      navigator.clipboard ? el("button", { type: "button", class: "ghost copy", onclick: (e) => { navigator.clipboard.writeText(r.fingerprint); e.target.textContent = "copied"; } }, "copy") : null) : "unknown";
    body.push(section("Relay", kv([
      ["Status", el("span", { class: "state " + (STATE_CLASS[r.state] || ""), text: r.state })],
      [r.role === "bridge" ? "Hashed fingerprint" : "Fingerprint", fpRow],
      ["Tor", r.tor_version || "unknown"],
      ["Service", r.fresh ? yesno(r.service_active, "active", "not running") : "unknown (host not answering)"],
      ["ORPort", r.or_port ? String(r.or_port) + (r.ipv6 ? " (IPv4 + IPv6)" : " (IPv4)") : null],
      ["Listening", r.or_port ? [yesno(r.listening.ipv4, "IPv4", "IPv4 no"), r.ipv6 ? [" ", yesno(r.listening.ipv6, "IPv6", "IPv6 no")] : null] : null],
      ["Reachable", r.or_port ? [yesno(r.reachable.ipv4, "IPv4", "IPv4 not confirmed"), r.ipv6 ? [" ", yesno(r.reachable.ipv6, "IPv6", "IPv6 not confirmed")] : null] : null],
      ["In inventory", r.in_inventory ? "yes" : "no — found on the host"],
    ])));

    if ((r.warnings || []).length || (r.lost_flags || []).length) {
      const items = (r.warnings || []).map((w) => el("li", { text: w }));
      if ((r.lost_flags || []).length) items.push(el("li", { text: "lost " + r.lost_flags.join(", ") + " since the cached run" }));
      body.push(section("Warnings", el("ul", { class: "warnlist" }, items)));
    }

    if (d && d.published) {
      const link = el("a", { href: "https://metrics.torproject.org/rs.html#details/" + encodeURIComponent(r.fingerprint), target: "_blank", rel: "noopener noreferrer", text: "Relay Search ↗" });
      body.push(section("Tor Metrics", kv([
        ["Running", yesno(d.running, "yes", "no")],
        ["Flags", el("span", { class: "flaglist" }, (d.flags || []).map((f) => el("span", { text: f })))],
        ["Location", d.country ? d.country.toUpperCase() + (d.as ? " · " + d.as : "") + (d.as_name ? " · " + d.as_name : "") : null],
        ["Consensus weight", r.role === "bridge" ? null : count(d.consensus_weight) + " (" + percent(d.consensus_weight_fraction) + ")"],
        ["Selection", r.role === "bridge" ? null : "guard " + percent(d.guard_probability) + " · middle " + percent(d.middle_probability) + " · exit " + percent(d.exit_probability)],
        ["Advertised", rate(d.advertised_bandwidth) + (d.observed_bandwidth ? " · observed " + rate(d.observed_bandwidth) : "")],
        ["First seen", d.first_seen ? date(d.first_seen) : null],
        ["Restarted", d.last_restarted ? date(d.last_restarted) + " (" + ago(d.last_restarted) + ")" : null],
        ["Overload", d.overloaded ? el("span", { class: "state bad", text: "overloaded since " + date(d.overload_general) }) : d.overload_general ? "last " + date(d.overload_general) : "none reported"],
      ]), link));
    } else if (d) {
      body.push(section("Tor Metrics", el("p", { class: "muted", text: "Not listed yet (new relays appear after about 3 hours)." })));
    }

    if (!PRIVACY && (r.live_read !== undefined || r.or_connections !== undefined)) {
      body.push(section("Traffic", kv([
        ["Live", r.live_read !== undefined ? "↓ " + rate(r.live_read) + "  ↑ " + rate(r.live_written) : "after the next probe"],
        ["OR connections", r.or_connections !== undefined ? count(r.or_connections) : null],
      ])));
    }

    if (r.load) {
      const l = r.load;
      const dropShare = l.onionskins_processed ? l.onionskins_dropped / (l.onionskins_processed + l.onionskins_dropped) : 0;
      body.push(section("Load since tor started", kv([
        ["Onionskins", count(l.onionskins_processed) + " processed · " + count(l.onionskins_dropped) + " dropped (" + percent(dropShare) + ")"],
        ["Memory pressure", l.oom_bytes ? binBytes(l.oom_bytes) + " freed by the OOM handler" : "none"],
        ["TCP port exhaustion", count(l.tcp_exhaustion)],
        ["Rate limit reached", count(l.rate_limit_reached) + " times"],
        ["Sockets", count(l.sockets_open) + (l.sockets_limit ? " of " + count(l.sockets_limit) + " (" + Math.round((l.sockets_open / l.sockets_limit) * 100) + "%)" : "")],
      ])));
    }

    if (r.accounting) {
      const a = r.accounting;
      const f = a.max_bytes ? a.used_bytes / a.max_bytes : 0;
      body.push(section("Accounting", bar(f), kv([
        ["Used", binBytes(a.used_bytes) + " of " + binBytes(a.max_bytes) + " (" + (f * 100).toFixed(1) + "%, rule " + a.rule + ")"],
        ["Projected", binBytes(a.projected_bytes) + " by " + date(a.period_end)],
        ["Runs out", a.exhausts_at ? date(a.exhausts_at) + " (" + until(a.exhausts_at) + ")" : "not before the period ends"],
      ])));
    }

    if (r.keys) {
      const k = r.keys;
      body.push(section("Identity keys", kv([
        ["Master key", k.offline_master_key ? "offline" : "on the server"],
        ["Signing certificate", k.signing_cert_expires ? date(k.signing_cert_expires) + " (" + until(k.signing_cert_expires) + ")" : "unknown"],
        ["Problem", k.problem || null],
      ])));
    }

    if (r.family) {
      const f = r.family;
      body.push(section("Family", kv([
        ["FamilyIds", String(f.ids)],
        ["Missing keys", f.missing_keys ? el("span", { class: "state bad", text: String(f.missing_keys) }) : "none"],
        ["Matches the fleet", f.consistent === undefined ? null : yesno(f.consistent, "yes", "no")],
      ])));
    }

    if (r.bridge) {
      const b = r.bridge;
      body.push(section("Bridge", kv([
        ["Transport", b.transport],
        ["Listening", yesno(b.listening, "yes", "no")],
        ["Distribution", b.distribution || null],
        ["Distributor", b.distributor || (d && d.published ? "not assigned yet" : null)],
        ["Blocked in", (b.blocklist || []).length ? b.blocklist.join(", ").toUpperCase() : null],
      ]), el("p", { class: "muted", text: "The bridge line never leaves the bridge: use tor-relay-setup status on it." })));
    }

    $("drawer-body").replaceChildren(...body);
  }

  // ---- events -----------------------------------------------------------
  function init() {
    for (const th of document.querySelectorAll("#relays th")) {
      th.tabIndex = 0;
      const sort = () => {
        const k = th.dataset.sort;
        if (sortKey === k) sortDir = -sortDir; else { sortKey = k; sortDir = 1; }
        if (data) renderRelays();
      };
      th.addEventListener("click", sort);
      th.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sort(); } });
    }
    for (const chip of document.querySelectorAll("#roles .chip")) {
      chip.addEventListener("click", () => {
        roleFilter = chip.dataset.role;
        for (const c of document.querySelectorAll("#roles .chip")) c.classList.toggle("active", c === chip);
        if (data) renderRelays();
      });
    }
    $("filter").addEventListener("input", (e) => {
      textFilter = e.target.value.trim().toLowerCase();
      if (data) renderRelays();
    });
    $("drawer-close").addEventListener("click", closeDrawer);
    $("scrim").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && openID) closeDrawer();
      if (e.key === "/" && document.activeElement !== $("filter")) { e.preventDefault(); $("filter").focus(); }
    });
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && Date.now() - lastOK > REFRESH_MS) load();
    });
    setInterval(() => { if (data) status(); }, 5000);
    load();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
