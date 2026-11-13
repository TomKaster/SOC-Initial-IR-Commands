# IRTRIAGE-COMPONENT shared/IRReport.ps1
# HTML report renderer, shared by the collector (report.html inside every collection) and
# analyst\ConvertTo-TriageReport.ps1 (adds baseline diff / IOC hits). Output is one self-contained file:
# no external fonts, scripts or images, so it opens offline in an isolated analysis VM.
# Keep this file PS 5.1 + ASCII. CSS/JS live in single-quoted here-strings so '$' is never interpolated.

$script:IRReportCss = @'
/* Layout: masthead (host identity) -> summary tiles -> sticky section nav -> full-width data sections.
   Palette: Meadow (matches the team's dashboards). */
:root {
  --ground: #f2f5ec; --card: #ffffff; --head: #f6f8f1; --text: #1e2a1f; --muted: #66735f; --border: #dde4d2;
  --accent: #2d6a4f; --accent-soft: #e2eee4; --accent-2: #52b788;
  --good: #006300; --good-soft: #e3efe0; --warning: #734500; --warning-soft: #f6ecd6; --bad: #8e2626; --bad-soft: #f7e3e1;
  --row-alt: #fafbf7; --focus: #52b788;
  --font-body: "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  --font-display: "Bahnschrift", "Segoe UI Variable Display", "Segoe UI", system-ui, sans-serif;
  --font-mono: "Cascadia Mono", "Cascadia Code", Consolas, "SFMono-Regular", Menlo, monospace;
  --radius: 10px;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ground: #0e130e; --card: #192019; --head: #141b14; --text: #f0efec; --muted: #9a9890; --border: #2c332b;
    --accent: #72d0a2; --accent-soft: #1d3127; --accent-2: #488166;
    --good: #3fbf3f; --good-soft: #15291a; --warning: #db9300; --warning-soft: #33280f; --bad: #ec7e7e; --bad-soft: #3a1d1d;
    --row-alt: #1c241c; --focus: #72d0a2;
    color-scheme: dark;
  }
}
* { box-sizing: border-box; }
html { scroll-padding-top: 64px; }
body { margin: 0; background: var(--ground); color: var(--text); font: 15px/1.55 var(--font-body); -webkit-font-smoothing: antialiased; }
a { color: var(--accent); }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
.wrap { max-width: 1440px; margin: 0 auto; padding-inline: max(16px, 3vw); }

.masthead { background: var(--card); border-bottom: 1px solid var(--border); padding-block: 28px 24px; }
.masthead .wrap { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 20px 32px; align-items: start; }
.eyebrow { font: 600 12px/1.2 var(--font-body); letter-spacing: .08em; text-transform: uppercase; color: var(--muted); margin: 0 0 6px; }
.host { font: 600 34px/1.1 var(--font-display); margin: 0; letter-spacing: .01em; text-wrap: balance; overflow-wrap: anywhere; }
.ip { margin: 8px 0 0; display: flex; flex-wrap: wrap; gap: 6px 14px; align-items: baseline; font: 500 16px/1.4 var(--font-mono); }
.ip .primary { color: var(--accent); font-weight: 600; }
.ip .other { color: var(--muted); font-size: 13.5px; }
.ip .label { font: 600 11px/1 var(--font-body); letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
.facts { grid-column: 1 / -1; display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 12px 28px; margin: 6px 0 0; }
.facts div { min-width: 0; }
.facts dt { font: 600 11.5px/1.3 var(--font-body); letter-spacing: .07em; text-transform: uppercase; color: var(--muted); }
.facts dd { margin: 3px 0 0; overflow-wrap: anywhere; }
.facts dd.mono { font: 13px/1.45 var(--font-mono); }
.pill { display: inline-flex; align-items: center; gap: 8px; padding: 6px 14px; border-radius: 999px; font-weight: 600; font-size: 14px; white-space: nowrap; }
.pill::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
.pill.ok { color: var(--good); background: var(--good-soft); }
.pill.fail { color: var(--bad); background: var(--bad-soft); }
.integrity-note { margin: 8px 0 0; color: var(--muted); font-size: 13px; text-align: right; max-width: 320px; }

.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; padding-block: 22px 6px; }
.tile { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 16px; text-align: left; font: inherit; color: inherit; }
button.tile { cursor: pointer; }
button.tile:hover { border-color: var(--accent-2); }
.tile .n { display: block; font: 600 30px/1.1 var(--font-display); font-variant-numeric: tabular-nums; }
.tile .k { display: block; margin-top: 4px; color: var(--muted); font-size: 13px; }
.tile.high .n { color: var(--bad); } .tile.review .n { color: var(--warning); } .tile.info .n { color: var(--accent); }

nav.sections { position: sticky; top: 0; z-index: 5; background: var(--ground); border-bottom: 1px solid var(--border); margin-top: 18px; }
nav.sections .wrap { display: flex; gap: 4px; overflow-x: auto; padding-block: 8px; scrollbar-width: thin; }
nav.sections a { white-space: nowrap; text-decoration: none; color: var(--muted); font-weight: 600; font-size: 14px; padding: 6px 12px; border-radius: 8px; }
nav.sections a:hover { color: var(--text); background: var(--accent-soft); }

main { padding-block: 8px 48px; }
section { padding-top: 30px; }
section > header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px 14px; margin-bottom: 10px; }
h2 { font: 600 21px/1.25 var(--font-display); margin: 0; letter-spacing: .01em; }
h3 { font: 600 16px/1.3 var(--font-display); margin: 22px 0 8px; }
.count { color: var(--muted); font-size: 14px; font-variant-numeric: tabular-nums; }
.lede { color: var(--muted); margin: 0 0 12px; max-width: 75ch; }
.empty { color: var(--muted); background: var(--card); border: 1px dashed var(--border); border-radius: var(--radius); padding: 14px 16px; margin: 0; }

.toolbar { display: flex; flex-wrap: wrap; gap: 8px 10px; align-items: center; margin: 0 0 10px; }
.seg { display: inline-flex; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; background: var(--card); }
.seg button { font: 600 13.5px/1 var(--font-body); color: var(--muted); background: none; border: 0; padding: 9px 14px; cursor: pointer; }
.seg button + button { border-left: 1px solid var(--border); }
.seg button[aria-pressed="true"] { background: var(--accent-soft); color: var(--accent); }
.search { font: 14px var(--font-body); color: var(--text); background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; min-width: 0; width: 280px; max-width: 100%; }
.hint { color: var(--muted); font-size: 12.5px; margin-left: auto; }

.table-wrap { overflow-x: auto; background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); }
table { border-collapse: separate; border-spacing: 0; width: 100%; font-size: 14px; line-height: 1.45; }
table.fixed { table-layout: fixed; min-width: 100%; }
th, td { text-align: left; vertical-align: top; padding: 9px 12px; border-bottom: 1px solid var(--border); overflow-wrap: anywhere; }
table.fixed th, table.fixed td { overflow: hidden; }
th { position: relative; background: var(--head); font-weight: 600; font-size: 12.5px; letter-spacing: .04em; text-transform: uppercase; color: var(--muted); white-space: nowrap; text-overflow: ellipsis; }
thead th { position: sticky; top: 0; z-index: 1; }
th + th, td + td { border-left: 1px solid var(--border); }
tbody tr:nth-child(even) td { background: var(--row-alt); }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: var(--accent-soft); }
td.mono { font: 13px/1.45 var(--font-mono); }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
table.measuring { width: auto; table-layout: auto; }
table.measuring th, table.measuring td { white-space: nowrap; overflow-wrap: normal; }
.one-line { white-space: nowrap !important; overflow-wrap: normal !important; text-overflow: ellipsis; }
tr.sev-high td:first-child { box-shadow: inset 4px 0 0 var(--bad); }
tr.sev-review td:first-child { box-shadow: inset 4px 0 0 var(--warning); }
tr.sev-info td:first-child { box-shadow: inset 4px 0 0 var(--accent-2); }

.grip { position: absolute; top: 0; right: -5px; width: 10px; height: 100%; cursor: col-resize; z-index: 2; touch-action: none; }
.grip::after { content: ""; position: absolute; top: 20%; bottom: 20%; left: 4px; width: 2px; border-radius: 1px; background: transparent; }
th:hover .grip::after, .grip:focus-visible::after, table.resizing .grip::after { background: var(--accent-2); }
table.resizing { cursor: col-resize; user-select: none; }

.chip { display: inline-block; padding: 2px 9px; border-radius: 999px; font: 600 12px/1.5 var(--font-body); white-space: nowrap; }
.chip.high, .chip.error, .chip.added { color: var(--bad); background: var(--bad-soft); }
.chip.review, .chip.modified, .chip.skipped { color: var(--warning); background: var(--warning-soft); }
.chip.info, .chip.removed { color: var(--accent); background: var(--accent-soft); }
.chip.ok { color: var(--good); background: var(--good-soft); }

/* Collapsible sections and sub-tables. The fold buttons are added by the script, so without it everything stays open. */
button.fold { font: inherit; color: inherit; letter-spacing: inherit; background: none; border: 0; padding: 0; margin: 0; cursor: pointer;
  display: inline-flex; align-items: baseline; gap: 10px; text-align: left; }
button.fold::before { content: ""; flex: none; width: 0; height: 0; border-inline: 5px solid transparent; border-top: 7px solid var(--muted);
  transform: translateY(-2px); transition: transform .15s ease; }
button.fold[aria-expanded="false"]::before { transform: translateY(-2px) rotate(-90deg); }
button.fold:hover { color: var(--accent); }
button.fold:hover::before { border-top-color: var(--accent); }
.nav-tools { display: inline-flex; gap: 4px; margin-left: auto; padding-left: 12px; }
.nav-tools button { white-space: nowrap; font: 600 13px/1 var(--font-body); color: var(--muted); background: var(--card); border: 1px solid var(--border);
  border-radius: 8px; padding: 7px 11px; cursor: pointer; }
.nav-tools button:hover { color: var(--accent); border-color: var(--accent-2); }

footer { color: var(--muted); font-size: 13px; padding-block: 0 32px; }
@media (max-width: 720px) {
  .masthead .wrap { grid-template-columns: 1fr; }
  .integrity-note { text-align: left; }
  .host { font-size: 27px; }
  .hint { margin-left: 0; }
}
@media (prefers-reduced-motion: no-preference) { html { scroll-behavior: smooth; } }
@media print {
  nav.sections, .toolbar, .grip { display: none; } .table-wrap { overflow: visible; }
  .fold-body[hidden] { display: block !important; } button.fold::before { display: none; }
}
'@

$script:IRReportJs = @'
(function () {
  "use strict";
  var MIN = 56;

  // Excel-style columns: drag a header edge to resize; double-click it (or focus it and press Enter)
  // to fit the column to its longest value on one line; double-click again to go back to wrapped text.
  function setupTable(table) {
    if (!table.tHead) return;
    var ths = Array.prototype.slice.call(table.tHead.rows[0].cells);
    var cap = function (th) { return th.hasAttribute("data-wide") ? 560 : 300; };
    // Start every column at its one-line width (capped), then hand any spare room to the columns that were capped.
    table.classList.add("measuring");
    var natural = ths.map(function (th) { return Math.ceil(th.getBoundingClientRect().width); });
    table.classList.remove("measuring");
    var widths = natural.map(function (w, i) { return Math.max(MIN, Math.min(w, cap(ths[i]))); });
    var avail = table.parentNode.clientWidth - 2;
    var spare = avail - widths.reduce(function (s, w) { return s + w; }, 0);
    if (spare > 0) {
      var want = natural.map(function (w, i) { return Math.max(0, w - widths[i]); });
      var totalWant = want.reduce(function (s, w) { return s + w; }, 0);
      if (totalWant > 0) {
        var give = Math.min(spare, totalWant);
        widths = widths.map(function (w, i) { return w + Math.floor(give * want[i] / totalWant); });
      }
    }
    widths = widths.map(Math.round);
    // Any room still left goes to the last wide column (or the last column) so the table fills its card.
    var left = avail - widths.reduce(function (s, w) { return s + w; }, 0);
    if (left > 0) {
      var target = widths.length - 1;
      for (var k = ths.length - 1; k >= 0; k--) { if (ths[k].hasAttribute("data-wide")) { target = k; break; } }
      widths[target] += left;
    }
    var cg = document.createElement("colgroup");
    var cols = widths.map(function (w) { var c = document.createElement("col"); c.style.width = w + "px"; cg.appendChild(c); return c; });
    table.insertBefore(cg, table.firstChild);
    table.classList.add("fixed");
    function sync() {
      var total = cols.reduce(function (s, c) { return s + parseFloat(c.style.width); }, 0);
      table.style.width = total + "px";
    }
    function setWidth(i, w) { cols[i].style.width = Math.max(MIN, Math.round(w)) + "px"; sync(); }
    function cellsOf(i) {
      var out = [];
      for (var r = 0; r < table.rows.length; r++) { var c = table.rows[r].cells[i]; if (c) out.push(c); }
      return out;
    }
    function fit(i) {
      var th = ths[i], cells = cellsOf(i);
      if (th.classList.contains("one-line")) {
        cells.forEach(function (c) { c.classList.remove("one-line"); });
        setWidth(i, parseFloat(th.getAttribute("data-prev-width")) || 160);
        return;
      }
      th.setAttribute("data-prev-width", cols[i].style.width);
      cells.forEach(function (c) { c.classList.add("one-line"); });
      setWidth(i, MIN);
      var max = MIN;
      cells.forEach(function (c) { if (!c.parentNode.hidden) max = Math.max(max, c.scrollWidth); });
      setWidth(i, Math.min(max + 2, 8000));
    }
    ths.forEach(function (th, i) {
      var g = document.createElement("span");
      g.className = "grip";
      g.tabIndex = 0;
      g.setAttribute("role", "separator");
      g.setAttribute("aria-orientation", "vertical");
      g.setAttribute("aria-label", "Resize " + th.textContent.trim() + " column. Drag, use arrow keys, or double-click to fit on one line.");
      g.title = "Drag to resize. Double-click to fit on one line.";
      th.appendChild(g);
      g.addEventListener("pointerdown", function (e) {
        if (e.button !== 0) return;
        e.preventDefault();
        g.setPointerCapture(e.pointerId);
        var x0 = e.clientX, w0 = parseFloat(cols[i].style.width);
        table.classList.add("resizing");
        function move(ev) { setWidth(i, w0 + ev.clientX - x0); }
        function up() {
          g.removeEventListener("pointermove", move);
          g.removeEventListener("pointerup", up);
          g.removeEventListener("pointercancel", up);
          table.classList.remove("resizing");
        }
        g.addEventListener("pointermove", move);
        g.addEventListener("pointerup", up);
        g.addEventListener("pointercancel", up);
      });
      g.addEventListener("dblclick", function (e) { e.preventDefault(); fit(i); });
      g.addEventListener("keydown", function (e) {
        if (e.key === "ArrowLeft" || e.key === "ArrowRight") { e.preventDefault(); setWidth(i, parseFloat(cols[i].style.width) + (e.key === "ArrowRight" ? 24 : -24)); }
        else if (e.key === "Enter") { e.preventDefault(); fit(i); }
      });
    });
    sync();
  }
  Array.prototype.forEach.call(document.querySelectorAll("table[data-resizable]"), setupTable);

  // Plain text search for other tables: <input data-filter-table="table-id">.
  Array.prototype.forEach.call(document.querySelectorAll("input[data-filter-table]"), function (inp) {
    var t = document.getElementById(inp.getAttribute("data-filter-table"));
    if (!t || !t.tBodies[0]) return;
    var trs = Array.prototype.slice.call(t.tBodies[0].rows);
    inp.addEventListener("input", function () {
      var q = (inp.value || "").toLowerCase();
      trs.forEach(function (r) { r.hidden = !!q && r.textContent.toLowerCase().indexOf(q) === -1; });
    });
  });

  // Collapsible sections (h2) and sub-tables (h3). Everything after a heading, up to the next heading of the
  // same level, moves into a .fold-body; the heading text becomes a button that toggles it.
  var folds = [], foldById = {};
  function makeFold(heading, nodes) {
    if (!nodes.length) return null;
    var body = document.createElement("div");
    body.className = "fold-body";
    nodes[0].parentNode.insertBefore(body, nodes[0]);
    nodes.forEach(function (n) { body.appendChild(n); });
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "fold";
    btn.setAttribute("aria-expanded", "true");
    while (heading.firstChild) btn.appendChild(heading.firstChild);
    heading.appendChild(btn);
    var f = { body: body, set: function (open) { btn.setAttribute("aria-expanded", String(open)); body.hidden = !open; } };
    btn.addEventListener("click", function () { f.set(btn.getAttribute("aria-expanded") !== "true"); });
    folds.push(f);
    return f;
  }
  function following(el, stop) {
    var out = [], n = el.nextSibling;
    while (n && !(n.nodeType === 1 && stop(n))) { out.push(n); n = n.nextSibling; }
    return out;
  }
  // Folding is a convenience: if it fails, leave the report fully open and keep the rest of the script running.
  try {
    Array.prototype.forEach.call(document.querySelectorAll("main > section"), function (sec) {
      var header = sec.querySelector(":scope > header"), h2 = header && header.querySelector("h2");
      if (!h2) return;
      var f = makeFold(h2, following(header, function () { return false; }));
      if (!f) return;
      foldById[sec.id] = f;
      Array.prototype.forEach.call(f.body.querySelectorAll(":scope > h3"), function (h3) {
        makeFold(h3, following(h3, function (n) { return n.tagName === "H3"; }));
      });
    });
  } catch (e) {
    folds.forEach(function (f) { f.set(true); });
    folds = [];
  }
  function openSection(id) { if (foldById[id]) foldById[id].set(true); }
  Array.prototype.forEach.call(document.querySelectorAll("nav.sections a[href^='#']"), function (a) {
    a.addEventListener("click", function () { openSection(a.getAttribute("href").slice(1)); });
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-fold-all]"), function (b) {
    if (!folds.length) return;
    b.hidden = false;
    b.addEventListener("click", function () {
      var open = b.getAttribute("data-fold-all") === "expand";
      folds.forEach(function (f) { f.set(open); });
    });
  });
  if (location.hash) openSection(location.hash.slice(1));

  // Leads: severity filter + text search.
  var leads = document.getElementById("leads-table");
  if (leads) {
    var rows = Array.prototype.slice.call(leads.tBodies[0].rows);
    var buttons = Array.prototype.slice.call(document.querySelectorAll("[data-sev-filter]"));
    var search = document.getElementById("lead-search");
    var count = document.getElementById("lead-count");
    var sev = "all";
    function apply() {
      var q = (search.value || "").toLowerCase(), shown = 0;
      rows.forEach(function (r) {
        var ok = (sev === "all" || r.getAttribute("data-sev") === sev) && (!q || r.textContent.toLowerCase().indexOf(q) !== -1);
        r.hidden = !ok;
        if (ok) shown++;
      });
      buttons.forEach(function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-sev-filter") === sev)); });
      count.textContent = shown === rows.length ? rows.length + " leads" : shown + " of " + rows.length + " leads";
    }
    buttons.forEach(function (b) { b.addEventListener("click", function () { sev = b.getAttribute("data-sev-filter"); apply(); }); });
    search.addEventListener("input", apply);
    Array.prototype.forEach.call(document.querySelectorAll("[data-jump-sev]"), function (t) {
      t.addEventListener("click", function () {
        sev = t.getAttribute("data-jump-sev");
        search.value = "";
        apply();
        openSection("leads");
        document.getElementById("leads").scrollIntoView();
      });
    });
    apply();
  }
})();
'@

function ConvertTo-IRHtmlText {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-IRHostAddresses {
    <#
      Returns @{ Primary = '10.0.0.5'; Others = @('fe80::..', ...) } for the report header.
      Uses manifest.host (collector 2.1+), falling back to the network_config collector for older collections.
    #>
    param($Triage)
    $h = $Triage.Manifest.host
    $primary = $null; $all = @()
    if ($h.PSObject.Properties['primaryIPv4'] -and $h.primaryIPv4) { $primary = [string]$h.primaryIPv4 }
    if ($h.PSObject.Properties['ipAddresses']) { $all = @($h.ipAddresses | ForEach-Object { [string]$_ }) }
    if (-not $primary -and $all.Count -eq 0) {
        $cfg = @(Get-IRRecords $Triage 'network_config') | Select-Object -First 1
        if ($cfg) {
            $addrs = @($cfg.IPAddresses | Where-Object { $_.IPAddress -and $_.IPAddress -notmatch '^(127\.|169\.254\.|::1$|fe80:)' })
            $all = @($addrs | ForEach-Object { [string]$_.IPAddress })
            $gwIfs = @($cfg.DefaultRoutes | ForEach-Object { $_.InterfaceAlias })
            $p = $addrs | Where-Object { $_.AddressFamily -eq 'IPv4' -and $gwIfs -contains $_.InterfaceAlias } | Select-Object -First 1
            if (-not $p) { $p = $addrs | Where-Object { $_.AddressFamily -eq 'IPv4' } | Select-Object -First 1 }
            if ($p) { $primary = [string]$p.IPAddress }
        }
    }
    if (-not $primary) { $primary = $all | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1 }
    $others = @($all | Where-Object { $_ -and $_ -ne $primary } | Select-Object -Unique)
    return [pscustomobject]@{ Primary = $primary; Others = $others }
}

function ConvertTo-IRReportTable {
    <#
      Columns: array of hashtables @{ Name = 'Prop'; Label = 'Header'; Kind = 'text'|'mono'|'num'|'chip'; Wide = $bool }
      or plain strings (Kind inferred from the name).
    #>
    param([object[]]$Rows, [object[]]$Columns, [string]$Empty = 'Nothing collected.', [string]$Id, [string]$SeverityProperty)
    if (-not $Rows -or $Rows.Count -eq 0) { return "<p class=""empty"">$(ConvertTo-IRHtmlText $Empty)</p>" }
    $cols = foreach ($c in $Columns) {
        if ($c -is [string]) {
            $kind = 'text'
            if ($c -match '(?i)(sha256|hash|address$|^ip|path$|^sid$|^key$|^indicator$)') { $kind = 'mono' }
            if ($c -match '(?i)^(records|ms|bytes|count|localport|remoteport|owningprocess|processid|sessionid|numopens)$') { $kind = 'num' }
            if ($c -match '(?i)^(severity|status|change)$') { $kind = 'chip' }
            @{ Name = $c; Label = $c; Kind = $kind; Wide = ($c -match '(?i)^(detail|title|commandline|actions|value|suspect|baseline)$') }
        } else { $c }
    }
    $sb = New-Object System.Text.StringBuilder
    $idAttr = ''
    if ($Id) { $idAttr = " id=""$Id""" }
    [void]$sb.Append("<div class=""table-wrap""><table data-resizable$idAttr><thead><tr>")
    foreach ($c in $cols) {
        $wide = ''
        if ($c.Wide) { $wide = ' data-wide' }
        [void]$sb.Append("<th scope=""col""$wide>$(ConvertTo-IRHtmlText $c.Label)</th>")
    }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $Rows) {
        $trAttr = ''
        if ($SeverityProperty -and $r.PSObject.Properties[$SeverityProperty]) {
            $s = ([string]$r.$SeverityProperty).ToLowerInvariant()
            $trAttr = " class=""sev-$s"" data-sev=""$s"""
        }
        [void]$sb.Append("<tr$trAttr>")
        foreach ($c in $cols) {
            $v = $r.($c.Name)
            if ($v -is [array]) { $v = ($v | ForEach-Object { [string]$_ }) -join ', ' }
            $enc = ConvertTo-IRHtmlText $v
            switch ($c.Kind) {
                'mono' { [void]$sb.Append("<td class=""mono"">$enc</td>") }
                'num'  { [void]$sb.Append("<td class=""num"">$enc</td>") }
                'chip' {
                    $cls = ([string]$v).ToLowerInvariant() -replace '^skipped.*', 'skipped' -replace '[^a-z]', ''
                    $label = [string]$v
                    if ($label.Length -gt 0) { $label = $label.Substring(0, 1).ToUpperInvariant() + $label.Substring(1) }
                    [void]$sb.Append("<td><span class=""chip $cls"">$(ConvertTo-IRHtmlText ($label -replace '_', ' '))</span></td>")
                }
                default { [void]$sb.Append("<td>$enc</td>") }
            }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function Get-IRProcessTreeRows {
    <#
      Orders processes depth-first under their parents and adds TreeName (name indented by depth).
      A parent only counts if the collector resolved ParentName (it rejects reused PIDs), so orphans become roots.
    #>
    param([object[]]$Processes)
    $byPid = @{}
    foreach ($p in $Processes) { if ($null -ne $p.ProcessId) { $byPid[[int]$p.ProcessId] = $p } }
    $children = @{}
    $roots = New-Object System.Collections.ArrayList
    foreach ($p in $Processes) {
        $ppid = [int]$p.ParentProcessId
        if ($p.ParentName -and $byPid.ContainsKey($ppid) -and $ppid -ne [int]$p.ProcessId) {
            if (-not $children.ContainsKey($ppid)) { $children[$ppid] = New-Object System.Collections.ArrayList }
            [void]$children[$ppid].Add($p)
        } else { [void]$roots.Add($p) }
    }
    $out = New-Object System.Collections.ArrayList
    $seen = @{}
    $stack = New-Object System.Collections.Stack
    foreach ($r in @($roots | Sort-Object { [int]$_.ProcessId } -Descending)) { $stack.Push(@($r, 0)) }
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $p = $item[0]; $depth = $item[1]
        $id = [int]$p.ProcessId
        if ($seen.ContainsKey($id)) { continue }
        $seen[$id] = $true
        $row = $p | Select-Object *
        $prefix = ''
        if ($depth -gt 0) { $prefix = ('. ' * ($depth - 1)) + '\_ ' }
        $row | Add-Member -NotePropertyName TreeName -NotePropertyValue ($prefix + $p.Name) -Force
        [void]$out.Add($row)
        if ($children.ContainsKey($id)) {
            foreach ($c in @($children[$id] | Sort-Object { [int]$_.ProcessId } -Descending)) { $stack.Push(@($c, ($depth + 1))) }
        }
        if ($stack.Count -eq 0 -and $seen.Count -lt $byPid.Count) {
            # Parent links that form a loop (equal timestamps on reused PIDs) have no root; list them flat.
            $left = @($Processes | Where-Object { -not $seen.ContainsKey([int]$_.ProcessId) } | Sort-Object { [int]$_.ProcessId } -Descending)
            foreach ($l in $left) { $stack.Push(@($l, 0)) }
        }
    }
    return $out.ToArray()
}

function New-IRReportSection {
    param([string]$Id, [string]$Title, [string]$Count, [string]$Lede, [string]$Body, [string]$CountId)
    $c = ''
    $cid = ''
    if ($CountId) { $cid = " id=""$CountId""" }
    if ($Count -or $CountId) { $c = "<span class=""count""$cid>$(ConvertTo-IRHtmlText $Count)</span>" }
    $l = ''
    if ($Lede) { $l = "<p class=""lede"">$(ConvertTo-IRHtmlText $Lede)</p>" }
    return "<section id=""$Id""><header><h2>$(ConvertTo-IRHtmlText $Title)</h2>$c</header>$l$Body</section>"
}

function New-IRTriageReport {
    <#
    .SYNOPSIS
        Writes the self-contained HTML report for a triage collection loaded with Import-IRTriage.
    .OUTPUTS
        The report path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Triage,
        [Parameter(Mandatory)][string]$OutFile,
        [object[]]$Diff,
        [string]$BaselineName,
        [object[]]$IocHits,
        [switch]$IncludeIocSection,
        [ValidateSet('high', 'review', 'info')][string]$MinimumSeverity = 'info',
        [string]$GeneratedBy = 'IRTriage'
    )
    $m = $Triage.Manifest
    $sevRank = @{ high = 0; review = 1; info = 2 }
    $leads = @(Get-IRTriageLeads -Triage $Triage | Where-Object { $sevRank[$_.Severity] -le $sevRank[$MinimumSeverity] })
    $counts = @{
        high   = @($leads | Where-Object { $_.Severity -eq 'high' }).Count
        review = @($leads | Where-Object { $_.Severity -eq 'review' }).Count
        info   = @($leads | Where-Object { $_.Severity -eq 'info' }).Count
    }
    $colls = @($m.collectors)
    $okCount = @($colls | Where-Object { $_.status -eq 'ok' }).Count
    $skipCount = @($colls | Where-Object { $_.status -like 'skipped*' }).Count
    $errCount = @($colls | Where-Object { $_.status -eq 'error' }).Count

    $conns = Get-IRRecords $Triage 'network_connections'
    $external = @($conns | Where-Object { $_.Protocol -eq 'TCP' -and $_.State -eq 'Established' -and $_.IsExternal } | Sort-Object ProcessName, RemoteAddress)
    $listen = @($conns | Where-Object { $_.State -eq 'Listen' -and $_.LocalAddress -notmatch '^(127\.|::1$)' } | Sort-Object Protocol, LocalPort)
    $addr = Get-IRHostAddresses $Triage

    # ---- Masthead ------------------------------------------------------------------------------
    $hostName = ConvertTo-IRHtmlText $m.host.computerName
    $ipHtml = '<p class="ip"><span class="label">IP address</span><span class="other">not recorded</span></p>'
    if ($addr.Primary -or $addr.Others.Count) {
        $primaryHtml = ''
        if ($addr.Primary) { $primaryHtml = "<span class=""primary"">$(ConvertTo-IRHtmlText $addr.Primary)</span>" }
        $otherHtml = ($addr.Others | Select-Object -First 6 | ForEach-Object { "<span class=""other"">$(ConvertTo-IRHtmlText $_)</span>" }) -join ''
        $ipHtml = "<p class=""ip""><span class=""label"">IP address</span>$primaryHtml$otherHtml</p>"
    }
    $integrityOk = [bool]$Triage.Integrity.Valid
    if ($integrityOk) {
        $note = "All $(@($m.files).Count) evidence files match their SHA-256 in the manifest"
        if ($Triage.Integrity.Zip -and $Triage.Integrity.Zip.Match) { $note += ', and the zip matches its .sha256' }
        $integrityHtml = "<span class=""pill ok"">Integrity verified</span><p class=""integrity-note"">$(ConvertTo-IRHtmlText $note).</p>"
    } else {
        $probs = @($Triage.Integrity.Problems | ForEach-Object { "$($_.File): $($_.Problem)" })
        if ($Triage.Integrity.Zip -and -not $Triage.Integrity.Zip.Match) { $probs += 'zip does not match its .sha256' }
        $integrityHtml = "<span class=""pill fail"">Integrity check failed</span><p class=""integrity-note"">$(ConvertTo-IRHtmlText ($probs -join '; ')). Treat this collection as unverified and re-collect.</p>"
    }
    $domain = $m.host.domain
    $facts = @(
        @('Domain', $domain, $false),
        @('Operating system', ("{0} ({1})" -f $m.host.osCaption, $m.host.osVersion), $false),
        @('Collected (UTC)', ("{0}  ->  {1}" -f ($m.run.startUtc -replace 'T', ' ' -replace '\.\d+Z$', 'Z'), ($m.run.endUtc -replace '^.*T', '' -replace '\.\d+Z$', 'Z')), $true),
        @('Profile', ("{0}, {1}s" -f $m.run.profile, $m.run.durationSeconds), $false),
        @('Requested by', $m.case.analyst, $false),
        @('Ran as', ("{0}{1}" -f $m.case.executedAs, $(if ($m.case.elevated) { ' (elevated)' } else { ' (NOT elevated)' })), $false),
        @('Tool', ("IRTriage {0}  {1}" -f $m.tool.version, $m.tool.build), $true),
        @('Script SHA-256', $m.tool.scriptSha256, $true)
    )
    $factsHtml = ($facts | Where-Object { $_[1] } | ForEach-Object {
        $cls = ''
        if ($_[2]) { $cls = ' class="mono"' }
        "<div><dt>$(ConvertTo-IRHtmlText $_[0])</dt><dd$cls>$(ConvertTo-IRHtmlText $_[1])</dd></div>"
    }) -join ''
    $caseId = ConvertTo-IRHtmlText $m.case.caseId

    # ---- Sections ------------------------------------------------------------------------------
    $nav = New-Object System.Collections.ArrayList
    $body = New-Object System.Text.StringBuilder

    $leadToolbar = @"
<div class="toolbar">
  <div class="seg" role="group" aria-label="Filter leads by severity">
    <button type="button" data-sev-filter="all" aria-pressed="true">All</button>
    <button type="button" data-sev-filter="high" aria-pressed="false">High $($counts.high)</button>
    <button type="button" data-sev-filter="review" aria-pressed="false">Review $($counts.review)</button>
    <button type="button" data-sev-filter="info" aria-pressed="false">Info $($counts.info)</button>
  </div>
  <input id="lead-search" class="search" type="search" placeholder="Search leads" aria-label="Search leads">
  <span class="hint">Drag a column edge to resize. Double-click it to fit the column on one line.</span>
</div>
"@
    $leadTable = ConvertTo-IRReportTable -Rows $leads -Id 'leads-table' -SeverityProperty 'Severity' -Empty 'No leads. Nothing matched the heuristics.' -Columns @(
        @{ Name = 'Severity'; Label = 'Severity'; Kind = 'chip' }, 'Category', @{ Name = 'Title'; Label = 'Lead'; Kind = 'text'; Wide = $true },
        @{ Name = 'Detail'; Label = 'Detail'; Kind = 'text'; Wide = $true }, @{ Name = 'Collector'; Label = 'Source'; Kind = 'mono' })
    [void]$nav.Add(@('leads', 'Leads'))
    [void]$body.Append((New-IRReportSection -Id 'leads' -Title 'Leads' -CountId 'lead-count' -Count "$($leads.Count) leads" -Lede 'Heuristic leads for analyst review, not verdicts. Confirm each against the raw JSON, EDR telemetry, the baseline and the ticket context.' -Body ($leadToolbar + $leadTable)))

    if ($IncludeIocSection -or ($IocHits -and $IocHits.Count)) {
        [void]$nav.Add(@('iocs', 'IOC hits'))
        [void]$body.Append((New-IRReportSection -Id 'iocs' -Title 'IOC hits' -Count "$(@($IocHits).Count) hits" -Body (ConvertTo-IRReportTable -Rows $IocHits -Empty 'No indicator matched this collection.' -Columns @(
            @{ Name = 'IndicatorType'; Label = 'Type'; Kind = 'text' }, 'Indicator', 'Collector', @{ Name = 'Field'; Label = 'Field'; Kind = 'mono' }, @{ Name = 'Value'; Label = 'Value'; Kind = 'mono'; Wide = $true }, 'Description'))))
    }
    if ($null -ne $Diff) {
        $added = @($Diff | Where-Object { $_.Change -eq 'Added' }).Count
        $modified = @($Diff | Where-Object { $_.Change -eq 'Modified' }).Count
        $removed = @($Diff | Where-Object { $_.Change -eq 'Removed' }).Count
        $order = @{ Added = 0; Modified = 1; Removed = 2 }
        $sorted = @($Diff | Sort-Object @{ Expression = { $order[$_.Change] } }, Category, Key)
        [void]$nav.Add(@('baseline', 'Baseline diff'))
        [void]$body.Append((New-IRReportSection -Id 'baseline' -Title 'Baseline diff' -Count "$added added, $modified modified, $removed removed" -Lede "Compared with $BaselineName. Items added on this host are where persistence usually shows up." -Body (ConvertTo-IRReportTable -Rows $sorted -Empty 'No differences from the baseline.' -Columns @(
            @{ Name = 'Change'; Label = 'Change'; Kind = 'chip' }, 'Category', @{ Name = 'Key'; Label = 'Item'; Kind = 'mono'; Wide = $true }, @{ Name = 'Suspect'; Label = 'This host'; Kind = 'mono'; Wide = $true }, @{ Name = 'Baseline'; Label = 'Baseline'; Kind = 'mono'; Wide = $true }))))
    }

    [void]$nav.Add(@('network', 'Network'))
    $netBody = '<h3>External TCP connections <span class="count">' + $external.Count + '</span></h3>' +
        (ConvertTo-IRReportTable -Rows $external -Empty 'No established connections to public addresses.' -Columns @(
            @{ Name = 'RemoteAddress'; Label = 'Remote address'; Kind = 'mono' }, @{ Name = 'RemotePort'; Label = 'Port'; Kind = 'num' },
            @{ Name = 'ProcessName'; Label = 'Process'; Kind = 'text' }, @{ Name = 'OwningProcess'; Label = 'PID'; Kind = 'num' },
            @{ Name = 'ProcessPath'; Label = 'Image path'; Kind = 'mono'; Wide = $true }, @{ Name = 'ProcessSha256'; Label = 'SHA-256'; Kind = 'mono' })) +
        '<h3>Listening ports <span class="count">' + $listen.Count + '</span></h3>' +
        (ConvertTo-IRReportTable -Rows $listen -Empty 'No listeners outside loopback.' -Columns @(
            'Protocol', @{ Name = 'LocalAddress'; Label = 'Local address'; Kind = 'mono' }, @{ Name = 'LocalPort'; Label = 'Port'; Kind = 'num' },
            @{ Name = 'ProcessName'; Label = 'Process'; Kind = 'text' }, @{ Name = 'OwningProcess'; Label = 'PID'; Kind = 'num' },
            @{ Name = 'ProcessPath'; Label = 'Image path'; Kind = 'mono'; Wide = $true }))
    [void]$body.Append((New-IRReportSection -Id 'network' -Title 'Network' -Body $netBody))

    $procRows = @(Get-IRProcessTreeRows @(Get-IRRecords $Triage 'processes'))
    [void]$nav.Add(@('processes', 'Processes'))
    $procBody = '<div class="toolbar"><input id="proc-search" class="search" type="search" placeholder="Search processes" aria-label="Search processes" data-filter-table="proc-table"></div>' +
        (ConvertTo-IRReportTable -Rows $procRows -Id 'proc-table' -Empty 'No processes collected.' -Columns @(
            @{ Name = 'ProcessId'; Label = 'PID'; Kind = 'num' }, @{ Name = 'ParentProcessId'; Label = 'PPID'; Kind = 'num' },
            @{ Name = 'TreeName'; Label = 'Process (tree)'; Kind = 'mono' }, @{ Name = 'Owner'; Label = 'Owner'; Kind = 'text' },
            @{ Name = 'SessionId'; Label = 'Session'; Kind = 'num' }, @{ Name = 'CreationDate'; Label = 'Started (UTC)'; Kind = 'mono' },
            @{ Name = 'CommandLine'; Label = 'Command line'; Kind = 'mono'; Wide = $true }, @{ Name = 'ExecutablePath'; Label = 'Image path'; Kind = 'mono'; Wide = $true },
            @{ Name = 'Sha256'; Label = 'SHA-256'; Kind = 'mono' }, @{ Name = 'Signer'; Label = 'Signer'; Kind = 'text' }))
    $appRows = @(Get-IRRecords $Triage 'installed_software' | Sort-Object @{ Expression = { [string]$_.DisplayName } }, Scope)
    $storeCount = @($appRows | Where-Object { $_.Type -eq 'Store' }).Count
    $appsSection = New-IRReportSection -Id 'apps' -Title 'Installed applications' -Count "$($appRows.Count - $storeCount) desktop, $storeCount Store" -Lede 'Desktop programs from the machine and per-user Uninstall keys, and Microsoft Store/MSIX packages per user (frameworks and inbox Windows apps omitted). Remote access tools and sideloaded packages are also raised as leads.' -Body (
        '<div class="toolbar"><input id="apps-search" class="search" type="search" placeholder="Search applications" aria-label="Search installed applications" data-filter-table="apps-table"></div>' +
        (ConvertTo-IRReportTable -Rows $appRows -Id 'apps-table' -Empty 'Installed applications were not collected (installed_software collector not run).' -Columns @(
            @{ Name = 'DisplayName'; Label = 'Application'; Kind = 'text' }, @{ Name = 'DisplayVersion'; Label = 'Version'; Kind = 'mono' },
            @{ Name = 'Publisher'; Label = 'Publisher'; Kind = 'text' }, @{ Name = 'Type'; Label = 'Type'; Kind = 'text' },
            @{ Name = 'Scope'; Label = 'Scope'; Kind = 'text' }, @{ Name = 'InstallDate'; Label = 'Installed'; Kind = 'mono' },
            @{ Name = 'SignatureKind'; Label = 'Package signature'; Kind = 'text' }, @{ Name = 'InstallLocation'; Label = 'Location'; Kind = 'mono'; Wide = $true })))
    [void]$body.Append((New-IRReportSection -Id 'processes' -Title 'Processes' -Count "$($procRows.Count) processes" -Lede 'Running processes in parent-child order, as of collection time. Suspicious command lines, Office children and images in user-writable or unsigned paths are also raised as leads.' -Body $procBody))
    [void]$nav.Add(@('apps', 'Installed applications'))
    [void]$body.Append($appsSection)

    [void]$nav.Add(@('accounts', 'Users and sessions'))
    $acctBody = '<h3>Logged-on users</h3>' +
        (ConvertTo-IRReportTable -Rows @(Get-IRRecords $Triage 'logged_on_users') -Columns @(
            'Source', @{ Name = 'UserName'; Label = 'User'; Kind = 'text' }, @{ Name = 'SessionName'; Label = 'Session'; Kind = 'text' },
            @{ Name = 'SessionId'; Label = 'ID'; Kind = 'num' }, 'State', @{ Name = 'LogonTime'; Label = 'Logon time'; Kind = 'mono' })) +
        '<h3>Local administrators</h3>' +
        (ConvertTo-IRReportTable -Rows @(Get-IRRecords $Triage 'local_admins') -Columns @(
            'Name', @{ Name = 'ObjectClass'; Label = 'Type'; Kind = 'text' }, @{ Name = 'PrincipalSource'; Label = 'Source'; Kind = 'text' }, @{ Name = 'SID'; Label = 'SID'; Kind = 'mono' })) +
        '<h3>Inbound SMB sessions</h3>' +
        (ConvertTo-IRReportTable -Rows @(Get-IRRecords $Triage 'smb_sessions') -Empty 'No inbound SMB sessions, or the collection was not elevated.' -Columns @(
            @{ Name = 'ClientComputerName'; Label = 'Client'; Kind = 'mono' }, @{ Name = 'ClientUserName'; Label = 'User'; Kind = 'text' },
            @{ Name = 'NumOpens'; Label = 'Open files'; Kind = 'num' }, @{ Name = 'SecondsExists'; Label = 'Seconds connected'; Kind = 'num' })) +
        '<h3>PowerShell history <span class="count">' + @(Get-IRRecords $Triage 'powershell_history').Count + '</span></h3>' +
        '<div class="toolbar"><input id="pshist-search" class="search" type="search" placeholder="Search history" aria-label="Search PowerShell history" data-filter-table="pshist-table"></div>' +
        (ConvertTo-IRReportTable -Rows @(Get-IRRecords $Triage 'powershell_history') -Id 'pshist-table' -Empty 'No PSReadLine history files found.' -Columns @(
            @{ Name = 'User'; Label = 'User'; Kind = 'text' }, @{ Name = 'LineNumber'; Label = 'Line'; Kind = 'num' },
            @{ Name = 'Command'; Label = 'Command'; Kind = 'mono'; Wide = $true }, @{ Name = 'File'; Label = 'File'; Kind = 'mono' }))
    [void]$body.Append((New-IRReportSection -Id 'accounts' -Title 'Users and sessions' -Body $acctBody))

    [void]$nav.Add(@('collection', 'Collection'))
    $collectorRows = @($colls | ForEach-Object {
        [pscustomobject]@{ Collector = $_.name; Status = $_.status; Records = $_.records; ms = $_.durationMs; Note = (@($_.error, $_.note) | Where-Object { $_ }) -join ' ' }
    })
    $fileRows = @($m.files | ForEach-Object { [pscustomobject]@{ File = $_.path; Bytes = $_.bytes; SHA256 = $_.sha256 } })
    $collBody = '<h3>Collectors</h3>' +
        (ConvertTo-IRReportTable -Rows $collectorRows -Columns @(
            @{ Name = 'Collector'; Label = 'Collector'; Kind = 'mono' }, @{ Name = 'Status'; Label = 'Status'; Kind = 'chip' }, 'Records',
            @{ Name = 'ms'; Label = 'Time (ms)'; Kind = 'num' }, @{ Name = 'Note'; Label = 'Note'; Kind = 'text'; Wide = $true })) +
        '<h3>Evidence files</h3>' +
        (ConvertTo-IRReportTable -Rows $fileRows -Columns @(@{ Name = 'File'; Label = 'File'; Kind = 'mono' }, 'Bytes', @{ Name = 'SHA256'; Label = 'SHA-256'; Kind = 'mono' }))
    [void]$body.Append((New-IRReportSection -Id 'collection' -Title 'Collection' -Count "$okCount ok, $skipCount skipped, $errCount failed" -Body $collBody))

    $navHtml = ($nav | ForEach-Object { "<a href=""#$($_[0])"">$(ConvertTo-IRHtmlText $_[1])</a>" }) -join ''
    # Shown by the script once sections are collapsible.
    $navHtml += '<span class="nav-tools"><button type="button" data-fold-all="collapse" hidden>Collapse all</button><button type="button" data-fold-all="expand" hidden>Expand all</button></span>'
    $title = ConvertTo-IRHtmlText ("{0} triage {1}" -f $m.host.computerName, $m.case.caseId)
    $generated = ConvertTo-IRHtmlText ("Generated {0} UTC by {1}." -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $GeneratedBy)

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<style>
$script:IRReportCss
</style>
</head>
<body>
<header class="masthead">
  <div class="wrap">
    <div>
      <p class="eyebrow">IR triage &middot; Case $caseId</p>
      <h1 class="host">$hostName</h1>
      $ipHtml
    </div>
    <div>$integrityHtml</div>
    <dl class="facts">$factsHtml</dl>
  </div>
</header>
<div class="wrap">
  <div class="summary">
    <button type="button" class="tile high" data-jump-sev="high"><span class="n">$($counts.high)</span><span class="k">High leads</span></button>
    <button type="button" class="tile review" data-jump-sev="review"><span class="n">$($counts.review)</span><span class="k">Leads to review</span></button>
    <button type="button" class="tile info" data-jump-sev="info"><span class="n">$($counts.info)</span><span class="k">Context leads</span></button>
    <div class="tile"><span class="n">$($external.Count)</span><span class="k">External connections</span></div>
    <div class="tile"><span class="n">$okCount/$($colls.Count)</span><span class="k">Collectors succeeded</span></div>
  </div>
</div>
<nav class="sections" aria-label="Report sections"><div class="wrap">$navHtml</div></nav>
<main class="wrap">
$($body.ToString())
</main>
<footer class="wrap">$generated</footer>
<script>
$script:IRReportJs
</script>
</body>
</html>
"@
    [System.IO.File]::WriteAllText($OutFile, $html, (New-Object System.Text.UTF8Encoding($false)))
    return $OutFile
}
