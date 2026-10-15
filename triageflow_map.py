"""Offline attack-surface map generation for TriageFlow."""
from __future__ import annotations

import csv
import hashlib
import html
import json
from pathlib import Path
from urllib.parse import urlsplit

LAYERS = {"root": 0, "host": 1, "url": 2, "endpoint": 3, "technology": 3, "login": 3, "finding": 4, "cve": 4}
COL_X = [55, 350, 645, 940, 1235]
NODE_W, NODE_H = 235, 62


def _csv(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    try:
        with path.open("r", newline="", encoding="utf-8", errors="replace") as stream:
            return list(csv.DictReader(stream))
    except OSError:
        return []


def _json(path: Path, fallback):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace")) if path.is_file() else fallback
    except (OSError, json.JSONDecodeError):
        return fallback


def _jsonl(path: Path) -> list[dict]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.is_file() else []
    except OSError:
        return []
    rows = []
    for line in lines:
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
        except json.JSONDecodeError:
            continue
    return rows


def _url(value) -> str:
    value = str(value or "").strip()
    try:
        parts = urlsplit(value)
    except ValueError:
        return ""
    return value if parts.scheme in ("http", "https") and parts.netloc else ""


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").casefold().rstrip(".")
    except ValueError:
        return ""


def _lines(path: Path) -> list[str]:
    try:
        return [x.strip() for x in path.read_text(encoding="utf-8", errors="replace").splitlines()
                if x.strip() and not x.lstrip().startswith("#")] if path.is_file() else []
    except OSError:
        return []


def build_attack_surface_graph(output_dir: Path) -> dict:
    """Create root -> host -> URL -> evidence relationships from saved run artifacts."""
    nodes, edges = {}, set()
    roots = sorted(set(x.casefold().rstrip(".") for x in _lines(output_dir / "root-domains.txt")))

    def add(kind, label, detail="", url="", identity=""):
        label = str(label or "").strip() or "(unnamed)"
        raw = kind + "|" + str(identity or label).casefold()
        node_id = kind + "-" + hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:14]
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": kind, "label": label[:300],
                              "detail": str(detail or "")[:2000], "url": _url(url)}
        elif detail and not nodes[node_id]["detail"]:
            nodes[node_id]["detail"] = str(detail)[:2000]
        return node_id

    def link(source, target):
        if source and target and source != target and source in nodes and target in nodes:
            edges.add((source, target))

    root_ids = {r: add("root", r, "Root scope/domain", identity=r) for r in roots}
    host_ids, url_ids, tech_ids = {}, {}, {}

    def root_for(host):
        match = next((r for r in sorted(roots, key=len, reverse=True)
                      if host == r or host.endswith("." + r)), "")
        if not match:
            match = host or "unknown-target"
            if match not in root_ids:
                root_ids[match] = add("root", match, "Inferred from observed asset", identity=match)
                roots.append(match)
        return match

    def host_node(host, detail=""):
        host = str(host or "").casefold().rstrip(".") or "unknown-host"
        if host not in host_ids:
            host_ids[host] = add("host", host, detail, identity=host)
            link(root_ids.get(root_for(host)), host_ids[host])
        elif detail and not nodes[host_ids[host]]["detail"]:
            nodes[host_ids[host]]["detail"] = detail[:2000]
        return host_ids[host]

    assets = _csv(output_dir / "asset-inventory.csv")
    for row in assets:
        url = _url(row.get("url"))
        host = str(row.get("hostname") or _host(url)).casefold().rstrip(".")
        if not host:
            continue
        host_id = host_node(host, "IP(s): " + str(row.get("ip_addresses") or "not reported"))
        if url:
            detail = "HTTP status: {0}\nTitle: {1}\nServer: {2}\nTechnologies: {3}".format(
                row.get("status_code") or "unknown", row.get("title") or "not reported",
                row.get("webserver") or "not reported", row.get("technologies") or "not reported")
            url_ids[url] = add("url", url, detail, url=url, identity=url)
            link(host_id, url_ids[url])

    for value in _lines(output_dir / "live.txt"):
        url = _url(value)
        host = _host(url)
        if url and host:
            host_id = host_node(host)
            if url not in url_ids:
                url_ids[url] = add("url", url, "Observed in live.txt", url=url, identity=url)
                link(host_id, url_ids[url])

    for row in _csv(output_dir / "vhost-findings.csv"):
        host = str(row.get("virtual_host") or "").casefold().rstrip(".")
        if host:
            host_node(host, "Virtual host candidate\nHTTP status: " + str(row.get("status_code") or "unknown"))

    for row in _csv(output_dir / "software-inventory.csv"):
        product = str(row.get("product") or "").strip()
        if not product:
            continue
        url = _url(row.get("url"))
        host = _host(url)
        version = str(row.get("version") or "").strip()
        label = product + ((" " + version) if version else "")
        tech_id = add("technology", label,
                      "URL: {0}\nSource: {1}\nEvidence: {2}".format(
                          url or "not reported", row.get("source") or "unknown",
                          row.get("raw_fingerprint") or ""),
                      url=url, identity=url + "|" + label)
        tech_ids[(host, product.casefold(), version.casefold())] = tech_id
        link(url_ids.get(url) or (host_node(host) if host else ""), tech_id)

    for row in _csv(output_dir / "login-panels.csv"):
        url = _url(row.get("login_url"))
        host = _host(url) or str(row.get("hostname") or "").casefold()
        if not host:
            continue
        title = str(row.get("title") or "title unavailable")
        login_id = add("login", "Login: " + title[:70],
                       "URL: {0}\nEvidence: {1}\nCredentials submitted: No".format(
                           url or "not reported", row.get("evidence") or "not reported"),
                       url=url, identity=(url or host) + "|" + title)
        link(url_ids.get(url) or host_node(host), login_id)

    for item in _jsonl(output_dir / "katana-findings.jsonl"):
        request = item.get("request") if isinstance(item.get("request"), dict) else {}
        url = _url(item.get("url") or item.get("endpoint") or request.get("endpoint"))
        if not url or url in url_ids:
            continue
        path = urlsplit(url).path or "/"
        label = path if len(path) <= 90 else path[:87] + "..."
        endpoint_id = add("endpoint", label, "Discovered by Katana\n" + url, url=url, identity=url)
        link(host_node(_host(url)), endpoint_id)

    for item in _jsonl(output_dir / "nuclei-findings.jsonl"):
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        url = _url(item.get("matched-at") or item.get("matched_at") or item.get("host"))
        severity = str(info.get("severity") or "unknown").upper()
        name = str(info.get("name") or item.get("template-id") or "Nuclei finding")
        finding_id = add("finding", severity + ": " + name,
                         "Severity: {0}\nTemplate: {1}\nMatched URL: {2}".format(
                             severity, item.get("template-id") or "not reported",
                             url or item.get("host") or "not reported"),
                         url=url, identity=str(item.get("template-id") or name) + "|" + str(url))
        link(url_ids.get(url) or (host_node(_host(url)) if _host(url) else ""), finding_id)

    cves = _json(output_dir / "cve-candidates.json", {})
    if isinstance(cves, dict):
        for product_row in cves.get("results", []) or []:
            product = str(product_row.get("product") or "Observed product")
            version = str(product_row.get("observed_version") or "")
            for cve in product_row.get("cves", []) or []:
                cve_name = str(cve.get("id") or cve.get("cve_id") or "").strip()
                if not cve_name:
                    continue
                severity = str(cve.get("severity") or "")
                label = cve_name + ((" (" + severity + ")") if severity else "")
                cve_id = add("cve", label,
                             "Candidate association only\nProduct: {0} {1}\nCVSS: {2}\n{3}".format(
                                 product, version, cve.get("cvss_score") or "unknown",
                                 cve.get("description") or ""),
                             url=_url(cve.get("url")), identity=cve_name + "|" + product.casefold() + "|" + version)
                matches = [n for (h, p, v), n in tech_ids.items()
                           if p == product.casefold() and (not version or v == version.casefold())]
                if matches:
                    for n in matches:
                        link(n, cve_id)

    node_list = list(nodes.values())
    edge_list = [{"source": a, "target": b} for a, b in sorted(edges)]
    return {"schema_version": 1, "generated_from": "saved TriageFlow output; no network requests",
            "node_count": len(node_list), "edge_count": len(edge_list),
            "nodes": node_list, "edges": edge_list}


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TriageFlow Attack Surface Map</title><style>
:root{color-scheme:dark;font-family:system-ui,Segoe UI,sans-serif;background:#0d1420;color:#e6edf7}
body{margin:0}header{padding:22px 26px;background:#172336;border-bottom:1px solid #33445b}
h1{font-size:clamp(1.4rem,3vw,2.2rem);margin:0 0 6px}p{color:#b8c7d9;margin:.35rem 0}
.tools{display:flex;gap:10px;flex-wrap:wrap;padding:14px 20px;align-items:center;background:#111b2a}
input{min-width:250px;flex:1;max-width:550px;padding:10px 12px;border-radius:8px;border:1px solid #465a73;background:#0d1420;color:#fff}
button{padding:9px 13px;border:1px solid #465a73;border-radius:8px;background:#1e2c40;color:#fff;cursor:pointer}
.meta{font-size:.9rem;color:#a8bdd4}.legend{display:flex;gap:12px;flex-wrap:wrap;margin:10px 20px;color:#c6d5e5;font-size:.85rem}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}
.canvas{margin:0 18px 20px;border:1px solid #33445b;border-radius:12px;overflow:auto;background:#0b111b;max-height:74vh}
svg{display:block;min-width:1500px}.node{cursor:pointer;transition:opacity .12s}
.node rect{stroke-width:1.4;rx:9;ry:9}.node text{font-size:12px;fill:#f4f7fb;pointer-events:none}
.node .sub{font-size:10px;fill:#bfcee0}.edge{stroke:#647991;stroke-width:1.25;opacity:.65;fill:none}
.column{font-size:13px;fill:#91aac5;font-weight:700;letter-spacing:.7px}
.root rect{fill:#17466b;stroke:#368dd3}.host rect{fill:#253750;stroke:#607d9e}
.url rect{fill:#163f36;stroke:#31a88b}.endpoint rect{fill:#293a25;stroke:#8dbb64}
.technology rect{fill:#3c2e56;stroke:#9f7de0}.login rect{fill:#51401f;stroke:#ddb15a}
.finding rect,.cve rect{fill:#522b35;stroke:#e67483}
.empty{padding:35px;text-align:center;color:#b8c7d9}
@media print{header,.tools{background:white;color:#111}body{background:white;color:#111}.canvas{max-height:none;overflow:visible}}
</style></head><body><header><h1>TriageFlow · Attack Surface Map</h1>
<p>Offline relationship map generated from this run's saved artifacts. It does not contact targets.</p>
<p class="meta">__COUNTS__ nodes · __EDGES__ relationships · <span id="filter-count">__COUNTS__ visible</span></p>
<p class="meta">Node types: __TYPES__</p></header>
<div class="tools"><input id="search" type="search" placeholder="Search host, URL, product, endpoint, CVE, finding…">
<button id="clear">Clear filter</button><button id="zoom-in">Zoom in</button><button id="zoom-out">Zoom out</button><button id="reset">Reset view</button></div>
<div class="legend"><span><i class="dot" style="background:#368dd3"></i>Root</span>
<span><i class="dot" style="background:#607d9e"></i>Host</span><span><i class="dot" style="background:#31a88b"></i>URL</span>
<span><i class="dot" style="background:#8dbb64"></i>Katana endpoint</span><span><i class="dot" style="background:#9f7de0"></i>Technology</span>
<span><i class="dot" style="background:#ddb15a"></i>Login</span><span><i class="dot" style="background:#e67483"></i>Finding / CVE</span></div>
<div class="canvas" id="canvas"><svg id="graph" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Interactive attack surface relationship map"></svg>
<div class="empty" id="empty" hidden>No assets or findings were available to map.</div></div>
<script type="application/json" id="graph-data">__GRAPH__</script>
<script>
(function(){
 const data=JSON.parse(document.getElementById('graph-data').textContent), svg=document.getElementById('graph');
 const canvas=document.getElementById('canvas'), search=document.getElementById('search'), empty=document.getElementById('empty');
 const NS='http://www.w3.org/2000/svg', xs=[55,350,645,940,1235], nw=235, nh=62;
 const layer={root:0,host:1,url:2,endpoint:3,technology:3,login:3,finding:4,cve:4};
 const names=['ROOT DOMAINS','HOSTS / VIRTUAL HOSTS','LIVE URLS','ENDPOINTS / TECHNOLOGIES / LOGINS','SECURITY FINDINGS'];
 const groups=[[],[],[],[],[]]; data.nodes.forEach(n=>groups[layer[n.type]===undefined?2:layer[n.type]].push(n));
 groups.forEach(g=>g.sort((a,b)=>(a.label||'').localeCompare(b.label||'')));
 const height=Math.max(850,...groups.map(g=>g.length*82+100)), width=1510;
 svg.setAttribute('width',width);svg.setAttribute('height',height);svg.setAttribute('viewBox','0 0 '+width+' '+height);
 const pos={};groups.forEach((g,c)=>{const gap=height/(g.length+1);g.forEach((n,i)=>{pos[n.id]={x:xs[c],y:gap*(i+1)-nh/2};});});
 const edgeEls=[];
 data.edges.forEach(e=>{const a=pos[e.source],b=pos[e.target];if(!a||!b)return;
   const p=document.createElementNS(NS,'path'),x1=a.x+nw,y1=a.y+nh/2,x2=b.x,y2=b.y+nh/2,mid=(x1+x2)/2;
   p.setAttribute('d','M '+x1+' '+y1+' C '+mid+' '+y1+', '+mid+' '+y2+', '+x2+' '+y2);
   p.setAttribute('class','edge');p.dataset.source=e.source;p.dataset.target=e.target;svg.appendChild(p);edgeEls.push(p);});
 const nodeEls=[];
 groups.forEach((g,c)=>{const h=document.createElementNS(NS,'text');h.setAttribute('x',xs[c]);h.setAttribute('y',27);h.setAttribute('class','column');h.textContent=names[c];svg.appendChild(h);
   g.forEach(n=>{const p=pos[n.id],group=document.createElementNS(NS,'g');group.setAttribute('class','node '+n.type);group.setAttribute('tabindex','0');
     group.dataset.id=n.id;group.dataset.search=[n.type,n.label,n.detail,n.url].join(' ').toLowerCase();
     const title=document.createElementNS(NS,'title');title.textContent=[n.label,n.detail,n.url].filter(Boolean).join('\n');group.appendChild(title);
     const rect=document.createElementNS(NS,'rect');rect.setAttribute('x',p.x);rect.setAttribute('y',p.y);rect.setAttribute('width',nw);rect.setAttribute('height',nh);group.appendChild(rect);
     const label=document.createElementNS(NS,'text');label.setAttribute('x',p.x+10);label.setAttribute('y',p.y+23);
     const full=n.label||'';label.textContent=full.length>31?full.slice(0,28)+'…':full;group.appendChild(label);
     const sub=document.createElementNS(NS,'text');sub.setAttribute('x',p.x+10);sub.setAttribute('y',p.y+43);sub.setAttribute('class','sub');
     const detail=(n.detail||n.url||'').replace(/\s+/g,' ');sub.textContent=detail.length>31?detail.slice(0,28)+'…':detail;group.appendChild(sub);
     if(n.url&&/^https?:\/\//i.test(n.url)){group.addEventListener('click',()=>window.open(n.url,'_blank','noopener,noreferrer'));}
     svg.appendChild(group);nodeEls.push(group);
   });});
 function update(){const q=search.value.trim().toLowerCase(),matched=new Set();let visible=0;
   nodeEls.forEach(el=>{const yes=!q||el.dataset.search.includes(q);el.style.opacity=yes?'1':'.12';if(yes){matched.add(el.dataset.id);visible++;}});
   edgeEls.forEach(el=>{el.style.opacity=!q||(matched.has(el.dataset.source)&&matched.has(el.dataset.target))?'.65':'.06';});
   document.getElementById('filter-count').textContent=visible+' visible';empty.hidden=data.nodes.length!==0;}
 search.addEventListener('input',update);document.getElementById('clear').addEventListener('click',()=>{search.value='';update();});
 let scale=1;function zoom(){svg.style.transformOrigin='top left';svg.style.transform='scale('+scale+')';}
 document.getElementById('zoom-in').addEventListener('click',()=>{scale=Math.min(1.8,scale+.1);zoom();});
 document.getElementById('zoom-out').addEventListener('click',()=>{scale=Math.max(.5,scale-.1);zoom();});
 document.getElementById('reset').addEventListener('click',()=>{scale=1;search.value='';svg.style.transform='';update();canvas.scrollTop=0;canvas.scrollLeft=0;});update();
})();
</script></body></html>
"""


def generate_attack_surface_map(output_dir: Path) -> dict:
    """Write JSON graph data and a self-contained offline interactive HTML map."""
    graph = build_attack_surface_graph(output_dir)
    json_path, html_path = output_dir / "attack-surface-map.json", output_dir / "attack-surface-map.html"
    json_path.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")
    safe_graph = json.dumps(graph, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    counts = {}
    for node in graph["nodes"]:
        counts[node["type"]] = counts.get(node["type"], 0) + 1
    types = ", ".join(k + ": " + str(v) for k, v in sorted(counts.items())) or "No nodes recorded"
    page = (HTML_TEMPLATE.replace("__COUNTS__", str(graph["node_count"]))
            .replace("__EDGES__", str(graph["edge_count"]))
            .replace("__TYPES__", html.escape(types))
            .replace("__GRAPH__", safe_graph))
    html_path.write_text(page, encoding="utf-8")
    return {"html_path": str(html_path), "json_path": str(json_path),
            "node_count": graph["node_count"], "edge_count": graph["edge_count"], "type_counts": counts}
