"""Interactive security graph viewer (``graph.html``).

Renders the security-annotated payload from :mod:`graph_view` with vis-network.
Design goals (from ``docs/graph`` + the requested UX):

* **Fast load** - node positions are precomputed at scan time and embedded, so
  the viewer renders with physics OFF (no browser layout cost) and positions
  stay stable across every interaction.
* **General view** - pan/zoom, filter by node type and edge relation and minimum
  degree, free-text search; **color by type**, **node size ∝ degree**, border
  color by security role (SINK/CRITICAL/ENTRY/SANITIZER).
* **Expand focus** - double-click a node to reveal it with its direct parents
  (callers) and children (callees) and hide the rest; double-click further nodes
  to grow the neighbourhood (climb the call tree) while keeping what is already
  shown. Parent vs child edges are colour-coded; "Show all" restores everything.
* **Move a connected set** - hold **Ctrl** and drag a node: its whole connected
  component travels with it, rigidly (relative distances preserved).
* **Select & reorganize** - box/shift select nodes, **right-click** for a menu
  to re-lay-out just the selection (force or circle), isolate, or select all.
* **Security layers** - a dropdown answers the AppSec questions (unsanitized
  sources, critical functions, endpoints→sink/taint, shortest/all paths to
  critical, external dependencies, vuln-deps→critical, attack paths, blast
  radius) by emphasizing the relevant nodes/paths over the same general view.

Pure presentation: it embeds the precomputed payload and executes nothing.
"""

from __future__ import annotations

import json

_PALETTE_CSS = ""  # placeholder kept for clarity; palette is computed in JS


def render_graph_html(payload: dict) -> str:
    return _TEMPLATE.replace("__DATA__", json.dumps(payload))


_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Deep Scan - security graph</title>
<!-- vis-network pinned to an exact version for reproducibility (local report artifact). -->
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
  :root{--bg:#0f172a;--panel:#1e293b;--ink:#e2e8f0;--muted:#94a3b8}
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--ink);height:100vh;display:flex;flex-direction:column}
  header{padding:.55rem 1rem;background:var(--panel);display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;border-bottom:1px solid #334155}
  header h1{font-size:1rem;margin:0 .8rem 0 0;font-weight:600}
  button{background:#334155;color:var(--ink);border:1px solid #475569;border-radius:6px;padding:.35rem .7rem;cursor:pointer;font-size:.8rem}
  button:hover{background:#475569}
  select{background:#334155;color:var(--ink);border:1px solid #475569;border-radius:6px;padding:.35rem;font-size:.8rem}
  #main{flex:1;display:flex;min-height:0}
  #net{flex:1;background:#0b1220}
  #side{width:23rem;background:var(--panel);border-left:1px solid #334155;padding:.9rem 1rem;overflow:auto;font-size:.82rem}
  #side h2{font-size:.76rem;margin:1rem 0 .45rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
  #side h2:first-child{margin-top:0}
  .kv{margin:.25rem 0}.kv b{color:#cbd5e1}
  .hint{color:var(--muted);font-size:.78rem;line-height:1.5}
  #banner{background:#1e293b;color:var(--muted);padding:.25rem .8rem;font-size:.72rem;border-bottom:1px solid #334155}
  input[type=text]{width:100%;background:#0b1220;color:var(--ink);border:1px solid #475569;border-radius:6px;padding:.4rem .5rem;font-size:.8rem}
  input[type=range]{width:100%}
  .chk{display:inline-flex;align-items:center;gap:.3rem;margin:.12rem .55rem .12rem 0;font-size:.77rem;cursor:pointer}
  .legend span{display:inline-flex;align-items:center;gap:.3rem;margin:.1rem .7rem .1rem 0;font-size:.74rem}
  .dot{width:.7rem;height:.7rem;border-radius:50%;display:inline-block}
  .ring{width:.7rem;height:.7rem;border-radius:50%;display:inline-block;border:2px solid}
  .bar{width:1rem;height:.2rem;border-radius:2px;display:inline-block}
  code{background:#0b1220;padding:.05rem .3rem;border-radius:4px}
  .note{background:#0b1220;border:1px solid #334155;border-radius:6px;padding:.5rem;font-size:.78rem;color:#cbd5e1}
  .legend span[data-tip]{cursor:help}
  .legend span[data-tip]:hover{color:#fff}
  #tip{position:fixed;z-index:100;max-width:20rem;background:#0b1220;border:1px solid #475569;border-radius:8px;padding:.55rem .65rem;font-size:.76rem;line-height:1.45;color:#cbd5e1;box-shadow:0 10px 30px rgba(0,0,0,.55);pointer-events:none;display:none}
  #tip b{color:#e2e8f0}
  #tip .crit{display:block;margin-top:.35rem;color:#94a3b8}
  #menu{position:fixed;display:none;z-index:50;background:#1e293b;border:1px solid #475569;border-radius:8px;padding:.3rem;box-shadow:0 8px 24px rgba(0,0,0,.5);min-width:12rem}
  #menu div{padding:.4rem .6rem;border-radius:6px;cursor:pointer;font-size:.8rem}
  #menu div:hover{background:#2563eb}
  #menu hr{border:none;border-top:1px solid #334155;margin:.2rem 0}
</style></head><body>
<header>
  <h1>Security graph</h1>
  <label class="hint">Layer
  <select id="layer">
    <option value="general">General overview</option>
    <option value="unsanitized">Unsanitized sources</option>
    <option value="critical">Critical functions</option>
    <option value="ep_reach_sink">Endpoints → sink</option>
    <option value="ep_reach_taint">Endpoints → taint</option>
    <option value="shortest_critical">Shortest paths → critical</option>
    <option value="all_paths_critical">All paths → critical</option>
    <option value="external_deps">External dependencies</option>
    <option value="deps_to_critical">Vuln deps → critical</option>
    <option value="attack_paths">Attack paths (impact)</option>
    <option value="blast_radius">Blast radius (click a node)</option>
  </select></label>
  <button id="fit">Fit</button>
  <button id="reset">Show all</button>
  <span class="hint" style="margin-left:auto">Ctrl+drag = move connected · right-click = menu · dbl-click = expand parents+children</span>
</header>
<div id="banner"></div>
<div id="main">
  <div id="net"></div>
  <div id="side">
    <h2>Layer</h2>
    <div id="note" class="note"></div>

    <h2>Filters</h2>
    <input type="text" id="q" placeholder="search label or file…" autocomplete="off">
    <div style="margin:.5rem 0"><div class="muted hint">Node type</div><div id="ftypes"></div></div>
    <div style="margin:.5rem 0"><div class="muted hint">Edge relation</div><div id="frels"></div></div>
    <div style="margin:.5rem 0"><div class="muted hint">Min degree: <span id="mindegv">0</span></div><input type="range" id="mindeg" min="0" value="0"></div>
    <button id="resetf">Reset filters</button>

    <h2>Details</h2>
    <div id="detail" class="hint"></div>

    <h2>Legend</h2>
    <div class="hint" style="margin-bottom:.35rem">Node colour = type · ring = security role. Hover an item for its meaning and criteria.</div>
    <div class="legend">
      <span data-tip="file"><i class="dot" style="background:#2563eb"></i>file</span>
      <span data-tip="function"><i class="dot" style="background:#16a34a"></i>function</span>
      <span data-tip="class"><i class="dot" style="background:#7c3aed"></i>class</span>
      <span data-tip="library"><i class="dot" style="background:#ca8a04"></i>library</span>
      <span data-tip="symbol"><i class="dot" style="background:#64748b"></i>symbol</span>
    </div>
    <div class="legend" style="margin-top:.3rem">
      <span data-tip="sink"><i class="ring" style="border-color:#ef4444"></i>sink</span>
      <span data-tip="critical"><i class="ring" style="border-color:#f59e0b"></i>critical</span>
      <span data-tip="entry"><i class="ring" style="border-color:#22d3ee"></i>entry</span>
      <span data-tip="sanitizer"><i class="ring" style="border-color:#22c55e"></i>sanitizer</span>
    </div>
    <div class="legend" style="margin-top:.3rem">
      <span data-tip="parentlink"><i class="bar" style="background:#ec4899"></i>parent link</span>
      <span data-tip="childlink"><i class="bar" style="background:#38bdf8"></i>child link</span>
    </div>
  </div>
</div>
<div id="menu"></div>
<div id="tip"></div>
<script>
const DATA = __DATA__;
const TYPE_COLOR={file:"#2563eb",function:"#16a34a","class":"#7c3aed",library:"#ca8a04",symbol:"#64748b"};
const TAG_BORDER=[["SINK","#ef4444"],["CRITICAL","#f59e0b"],["ENTRY","#22d3ee"],["SANITIZER","#22c55e"]];
const REL_COLOR={CALLS:"#3b82f6",CONTAINS:"#475569",IMPORTS:"#16a34a",IMPORTS_FROM:"#16a34a",REFERENCES:"#64748b",METHOD:"#7c3aed",IMPLEMENTS:"#0ea5e9",INHERITS:"#a855f7",DEFINES:"#475569",USES:"#64748b"};
const PARENT_LINK="#ec4899", CHILD_LINK="#38bdf8";  // expand mode: callers vs callees
const byId={}; let MAXDEG=0; DATA.nodes.forEach(n=>{byId[n.id]=n; if((n.degree||0)>MAXDEG)MAXDEG=n.degree||0;});
const out={}, inn={}, und={}; DATA.nodes.forEach(n=>{out[n.id]=[];inn[n.id]=[];und[n.id]=[];});
DATA.edges.forEach(e=>{ if(out[e.from]){out[e.from].push(e.to);inn[e.to]&&inn[e.to].push(e.from);und[e.from].push(e.to);und[e.to]&&und[e.to].push(e.from);} });
function bfs(start,adj,cap){const seen=new Set([start]),q=[start];while(q.length){const c=q.shift();for(const x of(adj[c]||[])){if(!seen.has(x)){seen.add(x);q.push(x);if(seen.size>cap)return seen;}}}return seen;}
function pathBetween(a,b){if(a===b)return[a];const q=[a],prev={[a]:null},seen=new Set([a]);while(q.length){const c=q.shift();for(const x of(out[c]||[])){if(!seen.has(x)){seen.add(x);prev[x]=c;if(x===b){const p=[b];let k=b;while(prev[k]!=null){k=prev[k];p.unshift(k);}return p;}q.push(x);}}}return null;}

// ---- node/edge datasets (loaded once with fixed positions) ----
function baseSize(n){return 6+Math.min(40,Math.sqrt(n.degree||0)*4);}
function tagBorder(n){for(const [t,c] of TAG_BORDER){if((n.tags||[]).includes(t))return c;}return "#0b1220";}
const nodes=new vis.DataSet(DATA.nodes.map(n=>({id:n.id,label:n.label,x:n.x,y:n.y,
  shape:(n.type==="file"?"box":(n.type==="library"?"diamond":"dot")),
  size:baseSize(n), color:{background:TYPE_COLOR[n.type]||"#64748b",border:tagBorder(n)},
  borderWidth:(n.tags&&n.tags.length?3:1), font:{color:"#e2e8f0",size:12},
  title:`${n.label}\n${n.file}${n.line?(":"+n.line):""}\ntype ${n.type} · deg ${n.degree} (in ${n.fan_in}/out ${n.fan_out})`+((n.tags&&n.tags.length)?("\ntags "+n.tags.join(",")):"")})));
const edges=new vis.DataSet(DATA.edges.map((e,i)=>({id:"e"+i,from:e.from,to:e.to,rel:e.rel,
  color:{color:REL_COLOR[e.rel]||"#334155",opacity:.35}, title:e.rel})));
const network=new vis.Network(document.getElementById("net"),{nodes,edges},{
  physics:false, layout:{improvedLayout:false},
  interaction:{hover:true,multiselect:true,navigationButtons:true,keyboard:true,hideEdgesOnDrag:true,hideEdgesOnZoom:true,tooltipDelay:150},
  edges:{smooth:false}, nodes:{borderWidth:1}
});

// ---- filter / layer state ----
const TYPES=[...new Set(DATA.nodes.map(n=>n.type))];
const RELS=[...new Set(DATA.edges.map(e=>e.rel||"(none)"))].sort();
let fq="", ftypes=new Set(TYPES), frels=new Set(RELS), fmindeg=0;
let layer="general", expandRoots=null, blastNode=null, fitAfterStable=false;

function buildFilters(){
  const ft=document.getElementById("ftypes");
  TYPES.forEach(t=>{const l=document.createElement("label");l.className="chk";
    l.innerHTML=`<input type=checkbox checked><i class=dot style="background:${TYPE_COLOR[t]||'#64748b'}"></i>${t}`;
    l.querySelector("input").onchange=e=>{e.target.checked?ftypes.add(t):ftypes.delete(t);paint();};ft.appendChild(l);});
  const fr=document.getElementById("frels");
  RELS.forEach(r=>{const l=document.createElement("label");l.className="chk";
    l.innerHTML=`<input type=checkbox checked>${r}`;
    l.querySelector("input").onchange=e=>{e.target.checked?frels.add(r):frels.delete(r);paint();};fr.appendChild(l);});
  const md=document.getElementById("mindeg");md.max=MAXDEG;
  md.oninput=e=>{fmindeg=+e.target.value;document.getElementById("mindegv").textContent=fmindeg;paint();};
  let qt=null; document.getElementById("q").oninput=e=>{clearTimeout(qt);const v=e.target.value.trim().toLowerCase();qt=setTimeout(()=>{fq=v;paint();},180);};
  document.getElementById("resetf").onclick=()=>{fq="";document.getElementById("q").value="";fmindeg=0;md.value=0;document.getElementById("mindegv").textContent="0";
    ftypes=new Set(TYPES);frels=new Set(RELS);ft.querySelectorAll("input").forEach(i=>i.checked=true);fr.querySelectorAll("input").forEach(i=>i.checked=true);paint();};
}

// ---- layer focus computation ----
function layerFocus(){
  if(layer==="general") return null;
  if(layer==="blast_radius"){ if(!blastNode)return {nodes:new Set(),edges:new Set()};
    const desc=bfs(blastNode,out,4000), anc=bfs(blastNode,inn,4000); const s=new Set([...desc,...anc]); s.add(blastNode);
    const pe=new Set(); s.forEach(a=>(out[a]||[]).forEach(b=>{if(s.has(b))pe.add(a+">"+b);})); return {nodes:s,edges:pe}; }
  const L=DATA.layers[layer]||{}; const s=new Set(L.nodes||[]); const pe=new Set();
  (L.paths||[]).forEach(p=>{p.forEach(id=>s.add(id)); for(let i=0;i<p.length-1;i++)pe.add(p[i]+">"+p[i+1]);});
  (L.focus||[]).forEach(id=>s.add(id));
  return {nodes:s,edges:pe,focus:new Set(L.focus||L.nodes||[])};
}

// ---- expand focus: every expanded root + its DIRECT parents and children ----
function expandVisible(){
  if(!expandRoots || !expandRoots.size) return null;
  const s=new Set();
  expandRoots.forEach(r=>{ s.add(r);
    (out[r]||[]).forEach(c=>s.add(c));   // children (callees)
    (inn[r]||[]).forEach(p=>s.add(p)); });// parents (callers)
  return s;
}

// ---- central paint: hidden + styling, positions untouched ----
function paint(){
  const foc=layerFocus();
  const exp = expandVisible();   // Set of visible ids while expanding, else null
  const hiddenMap={}; let shown=0;
  const nupd=DATA.nodes.map(n=>{
    const matchq = !fq || n.label.toLowerCase().includes(fq) || (n.file||"").toLowerCase().includes(fq);
    let hidden = !ftypes.has(n.type) || (n.degree||0) < fmindeg || !matchq;
    if(exp && !exp.has(n.id)) hidden=true;   // focus: only roots + their direct neighbours
    hidden = Boolean(hidden);
    hiddenMap[n.id]=hidden; if(!hidden)shown++;
    let bg=TYPE_COLOR[n.type]||"#64748b", bd=tagBorder(n), bw=(n.tags&&n.tags.length?3:1), sz=baseSize(n);
    if(exp){ if(expandRoots.has(n.id)){ bw=4; bd="#fff7ed"; sz+=4; } }  // expanded roots stand out
    else if(foc){ if(foc.nodes.has(n.id)){ bw=4; if(foc.focus&&foc.focus.has(n.id)){bd="#fff7ed";sz+=6;} }
      else { bg="#243044"; bd="#243044"; } }
    return {id:n.id,hidden,color:{background:bg,border:bd},borderWidth:bw,size:sz};
  });
  nodes.update(nupd);
  const eupd=DATA.edges.map((e,i)=>{
    const hidden = !frels.has(e.rel||"(none)") || hiddenMap[e.from] || hiddenMap[e.to];
    let width=1, col=REL_COLOR[e.rel]||"#334155", op=foc?.12:.32;
    if(exp){
      if(expandRoots.has(e.from)){ col=CHILD_LINK; op=.95; width=2.5; }       // root → callee
      else if(expandRoots.has(e.to)){ col=PARENT_LINK; op=.95; width=2.5; }   // caller → root
      else { op=.12; }                                                        // link among neighbours
    } else if(foc){ const on=foc.edges.has(e.from+">"+e.to); width=on?3:1; col=on?"#f59e0b":(REL_COLOR[e.rel]||"#334155"); op=on?1:.12; }
    return {id:"e"+i,hidden,width,color:{color:col,opacity:op}};
  });
  edges.update(eupd);
  let note;
  if(exp){ note="Focus mode - "+expandRoots.size+" expanded node(s) shown with their direct parents ("
      +"pink = callers) and children (blue = callees); the visible nodes are auto-arranged to avoid overlap. "
      +"Double-click another node to expand it too (previous nodes stay); double-click empty space or press ‘Show all’ to reset."; }
  else if(layer==="general"){ note="General overview - color by type, size by degree, border by security role. "
      +"Double-click a node to expand its direct parents+children; Ctrl+drag to move a connected set; right-click for the reorganize menu."; }
  else { note=(DATA.layers[layer]||{}).note||""; }
  document.getElementById("note").textContent=note;
  banner(`${shown}/${DATA.nodes.length} nodes shown · ${DATA.counts.functions} functions · ${DATA.counts.endpoints} endpoints · ${DATA.counts.sinks} sinks · ${DATA.counts.critical} critical`+(exp?` · focus: ${expandRoots.size} expanded`:""));
}
function banner(t){document.getElementById("banner").textContent=t;}
function detail(h){document.getElementById("detail").innerHTML=h;}

// vis-network's fit() is unreliable here (resets to scale 1), so frame the view
// manually from the visible nodes' current positions via moveTo().
function fitAll(animate){
  const all=nodes.get({fields:["id","hidden"]});
  const ids=all.filter(n=>!n.hidden).map(n=>n.id);
  if(!ids.length)return;
  const gp=network.getPositions(ids);
  let mnx=1e9,mny=1e9,mxx=-1e9,mxy=-1e9;
  ids.forEach(i=>{const p=gp[i]; if(!p)return; if(p.x<mnx)mnx=p.x; if(p.x>mxx)mxx=p.x; if(p.y<mny)mny=p.y; if(p.y>mxy)mxy=p.y;});
  const cont=document.getElementById("net"); const w=cont.clientWidth||1000, h=cont.clientHeight||800;
  const bw=(mxx-mnx)+160, bh=(mxy-mny)+160;
  const scale=Math.max(0.02, Math.min(w/bw, h/bh, 2));
  network.moveTo({position:{x:(mnx+mxx)/2,y:(mny+mxy)/2}, scale, animation: animate?{duration:400}:false});
}

// ---- interactions ----
document.getElementById("layer").onchange=e=>{layer=e.target.value; blastNode=null; if(expandRoots){restoreLayout();} expandRoots=null;
  if(layer==="blast_radius")detail("Click any node to see its blast radius (callers + everything it reaches)."); paint();};
document.getElementById("fit").onclick=()=>fitAll(true);
document.getElementById("reset").onclick=()=>{expandRoots=null;restoreLayout();network.unselectAll();paint();fitAll(true);};

// Double-click = expand a node into its DIRECT parents + children, hiding the
// rest. Double-clicking further nodes adds them (and their neighbours) to the
// view so you can climb the call tree without losing what is already unfolded.
// Double-click empty space (or "Show all") resets.
network.on("doubleClick",p=>{
  if(!p.nodes.length){ expandRoots=null; restoreLayout(); paint(); fitAll(true); return; }
  const id=p.nodes[0];
  if(!expandRoots) expandRoots=new Set();
  if(expandRoots.has(id) && expandRoots.size>1) expandRoots.delete(id);  // re-dblclick collapses it
  else expandRoots.add(id);
  paint(); layoutFocus();   // physics-spread just the visible parents/children
});

network.on("click",p=>{ if(!p.nodes.length)return; const n=byId[p.nodes[0]]; if(!n)return;
  detail("<div class='kv'><b>"+n.label+"</b></div><div class='kv'>type: "+n.type+(n.tags&&n.tags.length?(" · <b>"+n.tags.join(", ")+"</b>"):"")+"</div>"+
    "<div class='kv'>"+(n.file||"?")+(n.line?(":"+n.line):"")+"</div>"+
    "<div class='kv'>degree "+n.degree+" (in "+n.fan_in+" / out "+n.fan_out+") · community "+(n.community>=0?n.community:"-")+"</div>"+
    "<div class='kv'>hotness "+n.metrics.hotness+" · reachable sinks "+n.metrics.reachable_sinks+" · pagerank "+n.metrics.pagerank+"</div>");
  if(layer==="blast_radius"){blastNode=n.id;paint();} });

// ---- Ctrl+drag: move the whole connected component rigidly ----
let ctrl=false; window.addEventListener("keydown",e=>{if(e.key==="Control")ctrl=true;});
window.addEventListener("keyup",e=>{if(e.key==="Control")ctrl=false;});
let dragComp=null, dragStart=null, dragOrigin=null;
network.on("dragStart",p=>{ if(ctrl && p.nodes.length){ const root=p.nodes[0];
  const comp=[...bfs(root,und,8000)]; const pos=network.getPositions(comp);
  dragComp=comp; dragStart=pos; dragOrigin=network.getPositions([root])[root]; }});
network.on("dragging",p=>{ if(dragComp && p.pointer){
  const rootPos=network.DOMtoCanvas(p.pointer.DOM); const dx=rootPos.x-dragOrigin.x, dy=rootPos.y-dragOrigin.y;
  dragComp.forEach(id=>{const s=dragStart[id]; if(s)network.moveNode(id,s.x+dx,s.y+dy);}); }});
network.on("dragEnd",()=>{ if(dragComp){dragComp=null;dragStart=null;dragOrigin=null;network.storePositions();} });

// ---- right-click context menu (reorganize selection, etc.) ----
const menu=document.getElementById("menu");
function showMenu(x,y){ const sel=network.getSelectedNodes();
  menu.innerHTML="";
  const add=(label,fn,on=true)=>{const d=document.createElement("div");d.textContent=label;if(on)d.onclick=()=>{menu.style.display="none";fn();};else{d.style.opacity=.4;}menu.appendChild(d);};
  add(`Reorganize selection - force (${sel.length})`,()=>reorg("force"),sel.length>1);
  add(`Reorganize selection - circle (${sel.length})`,()=>reorg("circle"),sel.length>1);
  add(`Isolate selection (${sel.length})`,()=>isolate(sel),sel.length>0);
  const hr=document.createElement("hr");menu.appendChild(hr);
  add("Select all visible",selectVisible);
  add("Clear selection",()=>{network.unselectAll();});
  add("Show everything",()=>{expandRoots=null;restoreLayout();network.unselectAll();paint();fitAll(true);});
  menu.style.left=x+"px";menu.style.top=y+"px";menu.style.display="block";
}
network.on("oncontext",p=>{p.event.preventDefault(); const node=network.getNodeAt(p.pointer.DOM);
  if(node && network.getSelectedNodes().indexOf(node)<0) network.setSelection({nodes:[node]});
  showMenu(p.event.clientX,p.event.clientY);});
document.addEventListener("click",e=>{if(!menu.contains(e.target))menu.style.display="none";});

function selectVisible(){const ids=DATA.nodes.filter(n=>!nodes.get(n.id).hidden).map(n=>n.id);network.setSelection({nodes:ids});}
function isolate(sel){const s=new Set(sel);fq="";document.getElementById("q").value="";
  nodes.update(DATA.nodes.map(n=>({id:n.id,hidden:!s.has(n.id)})));
  edges.update(DATA.edges.map((e,i)=>({id:"e"+i,hidden:!(s.has(e.from)&&s.has(e.to))})));
  banner(sel.length+" isolated nodes (use 'Show everything' to restore)");}
function reorg(kind){ const sel=network.getSelectedNodes(); if(sel.length<2)return; const s=new Set(sel);
  if(kind==="circle"){ const pos=network.getPositions(sel); let cx=0,cy=0; sel.forEach(id=>{cx+=pos[id].x;cy+=pos[id].y;}); cx/=sel.length;cy/=sel.length;
    const R=60+sel.length*8; sel.forEach((id,i)=>{const a=2*Math.PI*i/sel.length; network.moveNode(id,cx+R*Math.cos(a),cy+R*Math.sin(a));}); network.storePositions(); return; }
  // force: fix everyone except the selection, run physics briefly, then freeze
  nodes.update(DATA.nodes.map(n=>({id:n.id,fixed:{x:!s.has(n.id),y:!s.has(n.id)}})));
  network.setOptions({physics:{enabled:true,stabilization:{enabled:true,iterations:120,fit:false},
    barnesHut:{springLength:120,gravitationalConstant:-9000,centralGravity:0.2,avoidOverlap:0.6}}});
  network.stabilize(120);
}
network.on("stabilizationIterationsDone",()=>{ try{ network.storePositions();
  nodes.update(DATA.nodes.map(n=>({id:n.id,fixed:false,physics:true}))); network.setOptions({physics:false});
  if(fitAfterStable){fitAfterStable=false; fitAll(true);} }catch(e){} });

// ---- focus-mode auto-layout ----------------------------------------------- //
// While drilling through parents/children the precomputed positions (laid out
// for the whole graph) leave the visible subset overlapping or far apart. Run
// physics on ONLY the visible nodes (the rest are excluded via physics:false)
// to spread them cleanly, then freeze. The original positions are kept in DATA
// and restored by restoreLayout() when the full graph is shown again.
function layoutFocus(){
  const exp=expandVisible(); if(!exp||!exp.size){ fitAll(true); return; }
  nodes.update(DATA.nodes.map(n=>({id:n.id,physics:exp.has(n.id),fixed:false})));
  fitAfterStable=true;
  network.setOptions({physics:{enabled:true,stabilization:{enabled:true,iterations:160,fit:false},
    barnesHut:{springLength:110,gravitationalConstant:-14000,centralGravity:0.35,avoidOverlap:0.9}}});
  network.stabilize(160);
}
function restoreLayout(){
  // back to the default whole-graph layout (physics off, precomputed positions).
  fitAfterStable=false;
  network.setOptions({physics:false});
  nodes.update(DATA.nodes.map(n=>({id:n.id,fixed:false,physics:true})));
  DATA.nodes.forEach(n=>network.moveNode(n.id,n.x,n.y));
  network.storePositions();
}

// ---- legend tooltips: [title, what it represents, qualifying criteria] ----
const TIPS={
  file:["File","A source file in the scanned project (drawn as a box in the graph).",
    "The node label looks like a filename - it ends with an extension such as .py, .ts or .go."],
  function:["Function / method","A function or method defined in the code - the unit the call graph and the taint analysis operate on.",
    "The node label ends with ()."],
  "class":["Class / type","A class or type defined in the scanned project.",
    "Defined in a scanned file and its (last) name segment starts with an uppercase letter."],
  library:["Library / external","An imported, third-party or built-in target that is not defined in the scanned code (drawn as a diamond).",
    "Referenced by the code but has no source file in the repository."],
  symbol:["Symbol","A module-level identifier that is neither a function nor a class - e.g. a variable, constant or config value.",
    "Defined in a scanned file and its name starts with a lowercase letter."],
  sink:["Sink","A function that performs (or contains) a dangerous, security-sensitive operation reached by data - e.g. exec(), an SQL query, a file open.",
    "It encloses the sink call of at least one finding produced by the analysis."],
  critical:["Critical","A high-impact function to review first - a hub on many paths and/or close to sinks.",
    "Ranks in the top 25 by hotness = callers×3 + reachable sinks×5 + PageRank×1000 + betweenness centrality×50."],
  entry:["Entry point","Somewhere the outside world can invoke - the start of an attack path.",
    "A web/CLI handler (matched by name, e.g. handle/route/main) or a function with no caller inside the repository."],
  sanitizer:["Sanitizer","A function that neutralizes untrusted input (escaping / encoding / validation) and stops taint from propagating.",
    "Its name matches a known sanitizer in the knowledge base - e.g. escapeshellarg, html.escape, Shellwords.escape."],
  parentlink:["Parent link","An incoming call edge - a caller of an expanded node, i.e. one level up the call tree.",
    "Shown in focus mode (after a double-click): edges arriving at an expanded node are drawn pink."],
  childlink:["Child link","An outgoing call edge - a callee of an expanded node, i.e. one level down the call tree.",
    "Shown in focus mode (after a double-click): edges leaving an expanded node are drawn blue."],
};
(function(){
  const tip=document.getElementById("tip");
  function move(e){const pad=14,w=tip.offsetWidth,h=tip.offsetHeight;
    let x=e.clientX+pad,y=e.clientY+pad;
    if(x+w>window.innerWidth-8)x=e.clientX-w-pad;
    if(y+h>window.innerHeight-8)y=e.clientY-h-pad;
    tip.style.left=Math.max(8,x)+"px";tip.style.top=Math.max(8,y)+"px";}
  function show(el,e){const t=TIPS[el.getAttribute("data-tip")];if(!t)return;
    tip.innerHTML="<b>"+t[0]+"</b><br>"+t[1]+"<span class='crit'><b>Criteria:</b> "+t[2]+"</span>";
    tip.style.display="block";move(e);}
  document.querySelectorAll(".legend span[data-tip]").forEach(el=>{
    el.addEventListener("mouseenter",e=>show(el,e));
    el.addEventListener("mousemove",move);
    el.addEventListener("mouseleave",()=>{tip.style.display="none";});
  });
})();

buildFilters(); paint();
// Frame the graph once the first frame has drawn (positions are applied then).
network.once("afterDrawing",()=>fitAll(false));
setTimeout(()=>fitAll(false),300);
</script></body></html>"""
