"""Shared dark theme + DeepScan branding for the HTML reports.

Mirrors the web dashboard (``packages/web``): dark ``#0d1117`` background with a
teal accent (``#3fb6a8``), the ◈ Deep Scan brand mark, and the same severity
palette - so the findings and triage reports look like the product.
"""

from __future__ import annotations

import html

# Web palette (kept in sync with packages/web/.../style.css).
SEV_COLORS = {
    "critical": "#ff5c5c", "high": "#f0883e", "medium": "#d4a72c",
    "low": "#58a6ff", "info": "#8b949e",
}
PRIORITY_COLORS = {"P0": "#ff5c5c", "P1": "#f0883e", "P2": "#d4a72c", "P3": "#58a6ff"}

_CSS = """
:root{
  --bg:#0d1117; --bg-panel:#161b22; --bg-raised:#1c2330; --border:#2d333b;
  --text:#e6edf3; --text-dim:#8b949e; --accent:#3fb6a8; --accent-strong:#2ea043;
  --danger:#f85149;
  --sev-critical:#ff5c5c; --sev-high:#f0883e; --sev-medium:#d4a72c;
  --sev-low:#58a6ff; --sev-info:#8b949e;
}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;color:var(--text);
  font-family:"Segoe UI",system-ui,-apple-system,sans-serif;
  background:radial-gradient(1200px 500px at 80% -10%,rgba(63,182,168,.08),transparent),var(--bg)}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
code,.mono{font-family:"SFMono-Regular",ui-monospace,Consolas,monospace;
  background:#0b0f14;border:1px solid var(--border);border-radius:5px;padding:.05rem .35rem;font-size:.82rem}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:1rem;
  padding:.8rem 1.5rem;border-bottom:1px solid var(--border);background:rgba(13,17,23,.92);
  position:sticky;top:0;z-index:10;backdrop-filter:blur(6px)}
.brand{display:flex;align-items:baseline;gap:.6rem}
.brand h1{margin:0;font-size:1.25rem;letter-spacing:.04em}
.brand-mark{color:var(--accent);font-size:1.35rem}
.brand-sub{color:var(--text-dim);font-size:.8rem;text-transform:uppercase;letter-spacing:.18em}
.topmeta{color:var(--text-dim);font-size:.78rem;text-align:right;line-height:1.5}
.layout{max-width:72rem;margin:0 auto;padding:1.4rem 1.5rem 3rem}
.panel{background:var(--bg-panel);border:1px solid var(--border);border-radius:10px;
  padding:1.1rem 1.3rem 1.3rem;margin:1.1rem 0}
.panel>h2{margin:0 0 .9rem;font-size:1.02rem;letter-spacing:.03em;color:var(--text)}
h2.section{font-size:.78rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.12em;margin:1.6rem 0 .2rem}
.summary{display:flex;flex-wrap:wrap;gap:.5rem}
.statbox{background:var(--bg-raised);border:1px solid var(--border);border-radius:8px;
  padding:.5rem .9rem;display:flex;align-items:center;gap:.5rem;font-size:.9rem}
.statbox b{font-size:1.1rem}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th,td{text-align:left;padding:.5rem .7rem;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--text-dim);font-weight:600;font-size:.74rem;text-transform:uppercase;letter-spacing:.08em}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--bg-raised)}
.chip{display:inline-block;padding:.1rem .55rem;border-radius:999px;font-size:.74rem;
  font-weight:700;color:#0d1117;text-transform:uppercase;letter-spacing:.02em}
.chip.critical{background:var(--sev-critical)} .chip.high{background:var(--sev-high)}
.chip.medium{background:var(--sev-medium)} .chip.low{background:var(--sev-low)}
.chip.info{background:var(--sev-info)}
.badge{display:inline-block;padding:.1rem .55rem;border-radius:999px;font-size:.74rem;
  font-weight:600;border:1px solid var(--border);text-transform:uppercase;letter-spacing:.04em}
.badge.ok{color:var(--accent-strong);border-color:var(--accent-strong)}
.badge.skipped{color:var(--text-dim)}
.badge.error{color:var(--danger);border-color:var(--danger)}
.muted{color:var(--text-dim)} .small{font-size:.82rem}
.note{background:var(--bg-raised);border:1px solid var(--border);border-radius:8px;
  padding:.7rem .9rem;font-size:.9rem;line-height:1.5}
.item{background:var(--bg-panel);border:1px solid var(--border);border-left-width:4px;
  border-radius:10px;padding:.9rem 1.1rem;margin:.8rem 0}
.item h3{margin:.1rem 0 .55rem;font-size:1.02rem}
.kv{font-size:.88rem;margin:.32rem 0;line-height:1.5} .kv b{color:#cbd5e1}
.pill{display:inline-block;background:#0b0f14;border:1px solid var(--border);border-radius:6px;
  padding:.12rem .55rem;font-size:.74rem;font-weight:700;color:#0d1117}
.fp{color:#f0883e;font-weight:600}
.empty{color:var(--text-dim);padding:1rem 0}
ul{margin:.4rem 0;padding-left:1.2rem;font-size:.9rem;line-height:1.6}
/* sortable + filterable report tables */
.panel-head{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-bottom:.7rem}
.panel-head h2{margin:0}
.count{color:var(--text-dim);font-weight:400;font-size:.78rem;letter-spacing:0}
.toolbar{display:flex;gap:.5rem;flex-wrap:wrap}
.toolbar input[type=search],.toolbar select{background:var(--bg-raised);border:1px solid var(--border);
  color:var(--text);border-radius:6px;padding:.35rem .55rem;font-size:.85rem;outline:none}
.toolbar input[type=search]{min-width:12rem}
.toolbar input[type=search]:focus,.toolbar select:focus{border-color:var(--accent)}
.table-wrap{overflow-x:auto}
th.sortable{cursor:pointer;user-select:none;white-space:nowrap}
th.sortable:hover{color:var(--text)}
th .sort-ind{font-size:.72em;margin-left:.15rem;color:var(--accent)}
th.sorted{color:var(--text)}
tr.norows td{color:var(--text-dim);text-align:center;padding:1rem}
"""

# Inline, dependency-free client script for the static HTML report: click a
# header to sort (severity by rank, counts/duration numerically, the rest as
# text), and filter rows with the per-table search box + value dropdown. Targets
# any ``table.report-table`` and is a no-op when none exist (e.g. the triage
# report), so ``page()`` can carry it unconditionally where wanted.
REPORT_JS = """
(function(){
  function val(td){
    var d=td.getAttribute('data-sort');
    if(d!==null){var n=parseFloat(d);return isNaN(n)?d.toLowerCase():n;}
    return td.textContent.trim().toLowerCase();
  }
  function bodyRows(t){
    return Array.prototype.filter.call(t.tBodies[0].rows,function(r){return !r.classList.contains('norows');});
  }
  function sortTable(t,col,dir){
    var rs=bodyRows(t);
    rs.sort(function(a,b){var x=val(a.cells[col]),y=val(b.cells[col]);return x<y?-dir:x>y?dir:0;});
    var tb=t.tBodies[0];rs.forEach(function(r){tb.appendChild(r);});
    var nr=tb.querySelector('tr.norows');if(nr)tb.appendChild(nr);
  }
  function rowMatchesSelect(r,sel){
    var want=sel.value;if(!want)return true;
    var v=r.getAttribute('data-'+sel.getAttribute('data-filter-attr'))||'';
    // data-filter-list: the row attr is a '|'-wrapped token list (e.g. tools);
    // match membership. Otherwise an exact single-value match.
    return sel.hasAttribute('data-filter-list')?v.indexOf('|'+want+'|')>=0:v===want;
  }
  function applyFilters(t){
    var id=t.id;
    var si=document.querySelector('input[data-filter="'+id+'"]');
    var q=si?si.value.trim().toLowerCase():'';
    var sels=document.querySelectorAll('select[data-filter-table="'+id+'"]');
    var shown=0,total=0;
    bodyRows(t).forEach(function(r){
      total++;
      var vis=!q||r.textContent.toLowerCase().indexOf(q)>=0;
      if(vis){for(var i=0;i<sels.length;i++){if(!rowMatchesSelect(r,sels[i])){vis=false;break;}}}
      r.style.display=vis?'':'none';if(vis)shown++;
    });
    var nr=t.tBodies[0].querySelector('tr.norows');if(nr)nr.hidden=shown!==0;
    var c=document.querySelector('[data-count="'+id+'"]');
    if(c)c.textContent=shown===total?('('+total+')'):('('+shown+' / '+total+')');
  }
  function setIndicators(t,col,dir){
    Array.prototype.forEach.call(t.tHead.rows[0].cells,function(h){
      h.classList.toggle('sorted',h.cellIndex===col);
      var s=h.querySelector('.sort-ind');
      if(s)s.textContent=h.cellIndex===col?(dir===1?'\\u25B2':'\\u25BC'):'';
    });
  }
  Array.prototype.forEach.call(document.querySelectorAll('table.report-table'),function(t){
    Array.prototype.forEach.call(t.tHead.rows[0].cells,function(th,i){
      if(th.classList.contains('nosort'))return;
      th.classList.add('sortable');
      if(!th.querySelector('.sort-ind')){th.appendChild(document.createTextNode(' '));
        var s=document.createElement('span');s.className='sort-ind';th.appendChild(s);}
      th.addEventListener('click',function(){
        var cur=parseInt(t.getAttribute('data-sortcol'),10);
        var dir;
        if(cur===i){dir=(parseInt(t.getAttribute('data-sortdir'),10)===1)?-1:1;}
        else{dir=th.hasAttribute('data-desc')?-1:1;}
        t.setAttribute('data-sortcol',i);t.setAttribute('data-sortdir',dir);
        setIndicators(t,i,dir);sortTable(t,i,dir);
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll('input[data-filter="'+t.id+'"]'),
      function(inp){inp.addEventListener('input',function(){applyFilters(t);});});
    Array.prototype.forEach.call(document.querySelectorAll('select[data-filter-table="'+t.id+'"]'),
      function(sel){sel.addEventListener('change',function(){applyFilters(t);});});
    var dc=t.getAttribute('data-default-col');
    if(dc!==null){var i=parseInt(dc,10);var th=t.tHead.rows[0].cells[i];
      var dir=th.hasAttribute('data-desc')?-1:1;
      t.setAttribute('data-sortcol',i);t.setAttribute('data-sortdir',dir);
      setIndicators(t,i,dir);sortTable(t,i,dir);}
    applyFilters(t);
  });
})();
"""


def page(
    subtitle: str,
    body: str,
    *,
    title: str = "Deep Scan report",
    topmeta: str = "",
    script: str = "",
) -> str:
    """Wrap *body* in a full dark-themed page with the DeepScan brand header.

    *script* is inlined before ``</body>`` (e.g. the report's sort/filter JS);
    omit it for static pages like the triage report.
    """
    meta = f'<div class="topmeta">{topmeta}</div>' if topmeta else ""
    js = f"<script>{script}</script>" if script else ""
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head><body>"
        '<header class="topbar"><div class="brand">'
        '<span class="brand-mark">◈</span><h1>Deep&nbsp;Scan</h1>'
        f'<span class="brand-sub">{html.escape(subtitle)}</span></div>{meta}</header>'
        f'<main class="layout">{body}</main>{js}</body></html>'
    )


def chip(severity: str) -> str:
    sev = severity if severity in SEV_COLORS else "info"
    return f'<span class="chip {sev}">{html.escape(severity)}</span>'
