import os
import time
import re
import hashlib
import hmac
import requests
from flask import Flask, request, jsonify, Response, redirect, make_response, render_template_string
from functools import wraps
from urllib.parse import quote

app = Flask(__name__)

APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
OS_API_KEY = os.environ.get("OS_API_KEY", "")
TRACKERS_RAW = os.environ.get("TRACKERS", "")
DEFAULT_FEED_ID = os.environ.get("DEFAULT_FEED_ID", "")
SESSION_COOKIE = "dofe_session"
CACHE_SECONDS = 150
spot_cache = {}

def parse_trackers():
    raw = TRACKERS_RAW.strip()
    if not raw and DEFAULT_FEED_ID:
        raw = f"BOT1={DEFAULT_FEED_ID}"

    items = []
    seen = set()
    for part in re.split(r"[;\n\r]+", raw):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, feed = part.split("=", 1)
        name = name.strip()
        feed = feed.strip()
        if not name or not re.fullmatch(r"[A-Za-z0-9_-]{8,100}", feed):
            continue
        key = hashlib.sha256(feed.encode("utf-8")).hexdigest()[:12]
        if key in seen:
            continue
        seen.add(key)
        items.append({"id": key, "name": name, "feed": feed})
    return items

def tracker_by_id(tracker_id):
    for t in parse_trackers():
        if t["id"] == tracker_id:
            return t
    return None

def public_trackers():
    return [{"id": t["id"], "name": t["name"]} for t in parse_trackers()]

def session_token():
    return hashlib.sha256(("burton-dofe-v12|" + APP_PASSWORD).encode("utf-8")).hexdigest()

def logged_in():
    return request.cookies.get(SESSION_COOKIE) == session_token()

def require_login(fn):
    @wraps(fn)
    def inner(*args, **kwargs):
        if not logged_in():
            if request.path.startswith("/api/") or request.path.startswith("/os/"):
                return jsonify(error="Unauthorised"), 401
            return redirect("/login")
        return fn(*args, **kwargs)
    return inner

@app.route("/health")
def health():
    return "ok", 200

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        supplied = request.form.get("password", "")
        if APP_PASSWORD and hmac.compare_digest(supplied, APP_PASSWORD):
            resp = make_response(redirect("/"))
            resp.set_cookie(
                SESSION_COOKIE,
                session_token(),
                max_age=12 * 60 * 60,
                secure=True,
                httponly=True,
                samesite="Strict",
            )
            return resp
        return render_template_string(LOGIN_HTML, error="Incorrect password."), 401
    return render_template_string(LOGIN_HTML, error="")

@app.route("/logout")
def logout():
    resp = make_response(redirect("/login"))
    resp.delete_cookie(SESSION_COOKIE)
    return resp

@app.route("/")
@require_login
def index():
    if not APP_PASSWORD or not OS_API_KEY:
        return "Server secrets are not configured.", 500
    return render_template_string(APP_HTML)

@app.route("/api/trackers")
@require_login
def api_trackers():
    return jsonify(public_trackers())

@app.route("/api/spot/<tracker_id>")
@require_login
def spot(tracker_id):
    tracker = tracker_by_id(tracker_id)
    if not tracker:
        return jsonify(error="Unknown tracker."), 404

    feed = tracker["feed"]
    now = time.time()
    cached = spot_cache.get(feed)
    if cached and now - cached["time"] < CACHE_SECONDS:
        return jsonify(cached["data"])

    url = f"https://api.findmespot.com/spot-main-web/consumer/rest-api/2.0/public/feed/{feed}/message.json"

    try:
        r = requests.get(
            url,
            headers={"Accept": "application/json", "User-Agent": "Burton-DofE-Tracker/13.0"},
            timeout=20,
        )
        if r.status_code != 200:
            return jsonify(error=f"SPOT returned HTTP {r.status_code}"), 502

        data = r.json()
        spot_cache[feed] = {"time": now, "data": data}
        return jsonify(data)
    except requests.RequestException as exc:
        if cached:
            return jsonify(cached["data"])
        return jsonify(error=str(exc)), 502
    except ValueError:
        return jsonify(error="SPOT returned invalid JSON."), 502

@app.route("/os/<int:z>/<int:x>/<int:y>.png")
@require_login
def os_tile(z, x, y):
    if z < 0 or z > 9:
        return "Zoom out of range", 400

    url = f"https://api.os.uk/maps/raster/v1/zxy/Leisure_27700/{z}/{x}/{y}.png?key={quote(OS_API_KEY)}"

    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return f"OS tile error {r.status_code}", r.status_code

        resp = Response(r.content, status=200, mimetype=r.headers.get("Content-Type", "image/png"))
        resp.headers["Cache-Control"] = "private, max-age=300"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp
    except requests.RequestException as exc:
        return str(exc), 502

LOGIN_HTML = '''
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Burton DofE Live Tracker</title>
<style>
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#17202a;min-height:100vh;display:grid;place-items:center;padding:20px}
.box{background:#fff;width:min(390px,94vw);padding:24px;border-radius:14px;box-shadow:0 20px 60px #0005}
h1{font-size:22px;margin:0 0 8px}.muted{color:#666}.err{color:#a40000;font-weight:700}
input,button{width:100%;padding:12px;border-radius:8px;border:1px solid #aaa;font:inherit;margin-top:10px}
button{background:#17202a;color:white;border:0;font-weight:700;cursor:pointer}
</style>
</head>
<body>
<div class="box">
<h1>Burton DofE Live Tracker</h1>
<p class="muted">Leader access only</p>
{% if error %}<p class="err">{{ error }}</p>{% endif %}
<form method="post">
<input type="password" name="password" placeholder="Tracker password" autofocus required>
<button type="submit">Open tracker</button>
</form>
</div>
</body>
</html>
'''

APP_HTML = '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">\n<meta name="theme-color" content="#17202a">\n<title>Burton DofE Live Tracker</title>\n<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">\n<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>\n<script src="https://cdnjs.cloudflare.com/ajax/libs/proj4js/2.11.0/proj4.js"></script>\n<script src="https://unpkg.com/proj4leaflet@1.0.2/src/proj4leaflet.js"></script>\n<style>\n*{box-sizing:border-box}\nhtml,body{margin:0;height:100%;font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#222}\nheader{min-height:58px;background:#17202a;color:#fff;padding:9px 12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}\nh1{font-size:17px;margin:0;flex:1}\n.controls{display:flex;gap:7px;flex-wrap:wrap}\nbutton{padding:8px 10px;border:0;border-radius:7px;font:inherit;cursor:pointer}\nbutton:disabled{opacity:.5;cursor:not-allowed}\n.primary{background:#17202a;color:#fff;font-weight:700}\n.alert-on{background:#19743b;color:#fff;font-weight:700}\nmain{display:grid;grid-template-columns:340px 1fr;height:calc(100% - 58px)}\naside{overflow:auto;padding:10px;border-right:1px solid #ddd;background:#fff}\n#map{height:100%;width:100%;background:#ddd}\n.card{border:1px solid #ddd;border-radius:10px;padding:10px;margin-bottom:8px}\n.tracker-card{cursor:pointer}\n.tracker-card:hover{border-color:#888}\n.head{display:flex;justify-content:space-between;gap:8px}\n.name{font-weight:800}\n.muted{font-size:12px;color:#666}\n.good{color:#167c31;font-weight:700}\n.warn{color:#a76300;font-weight:700}\n.bad{color:#a40000;font-weight:700}\n.marker-label{background:#17202a;color:#fff;border:0;border-radius:5px;font-weight:700}\n.cp-label{background:#fff;color:#17202a;border:1px solid #17202a;border-radius:5px;font-weight:700}\n.summary{font-weight:700;margin-bottom:8px}\n.modal{display:none;position:fixed;inset:0;background:#0009;z-index:3000;align-items:center;justify-content:center;padding:15px}\n.modal.show{display:flex}\n.panel{background:#fff;width:min(560px,96vw);max-height:90vh;overflow:auto;border-radius:14px;padding:18px;box-shadow:0 10px 50px #0007}\n.panel h2{margin:0 0 5px}\n.choice{display:flex;align-items:center;gap:11px;border:1px solid #ddd;border-radius:10px;padding:12px;margin:8px 0;cursor:pointer}\n.choice input{width:20px;height:20px;flex:0 0 auto}\n.choice span{font-weight:700}\n.actions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;margin-top:15px}\n.empty{text-align:center;padding:16px 8px}\n.formrow{margin:12px 0}\n.formrow label{display:block;font-weight:700;margin-bottom:5px}\n.formrow input,.formrow select{width:100%;padding:10px;border:1px solid #aaa;border-radius:8px;font:inherit}\n.cpitem{border:1px solid #ddd;border-radius:10px;padding:10px;margin:8px 0}\n.cphead{display:flex;justify-content:space-between;gap:8px;align-items:flex-start}\n.cpbuttons{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}\n.cpbuttons button{padding:6px 8px}\n.banner{display:none;position:fixed;z-index:4500;left:50%;top:18px;transform:translateX(-50%);width:min(620px,94vw);background:#fff;border:4px solid #c03221;border-radius:14px;padding:16px;box-shadow:0 8px 35px #0008}\n.banner.show{display:block}\n.banner h2{margin:0 0 5px;color:#a40000}\n.banner .big{font-size:20px;font-weight:800}\n.placing{position:fixed;z-index:2500;left:50%;top:70px;transform:translateX(-50%);background:#17202a;color:#fff;padding:10px 14px;border-radius:10px;box-shadow:0 4px 18px #0006;font-weight:700;display:none}\n.placing.show{display:block}\n@media(max-width:760px){\nheader{min-height:54px}\nmain{display:block;height:calc(100% - 54px);position:relative}\n#map{height:100%}\naside{position:absolute;z-index:1000;left:8px;right:8px;bottom:8px;max-height:40%;border:0;border-radius:12px;box-shadow:0 4px 20px #0005;padding:8px}\n.card{padding:8px;margin-bottom:6px}\n.controls button{padding:7px 9px}\n.banner{top:8px}\n.placing{top:62px;width:92%;text-align:center}\n}\n</style>\n</head>\n<body>\n<header>\n<h1>Burton DofE - Live Tracking</h1>\n<div class="controls">\n<button onclick="refreshAll(true)">Refresh</button>\n<button onclick="openMyGroups()">My Groups</button>\n<button onclick="openCheckpoints()">Checkpoints</button>\n<button id="alertsBtn" onclick="enableAlerts()">Enable Alerts</button>\n<button onclick="location.href=\'/logout\'">Log out</button>\n</div>\n</header>\n\n<main>\n<aside>\n<div id="selectionSummary" class="summary"></div>\n<div id="trackerList"></div>\n<div class="card muted">Tap a group to centre the map. Tap anywhere on the OS map for a 6-figure grid reference.</div>\n</aside>\n<div id="map"></div>\n</main>\n\n<div id="groupsModal" class="modal">\n<div class="panel">\n<h2>My Groups</h2>\n<p class="muted">Tick the groups you are supervising. Your choice is remembered on this device.</p>\n<div id="groupChoices"></div>\n<div class="actions">\n<button onclick="selectAllGroups()">Select all</button>\n<button onclick="clearAllGroups()">Clear</button>\n<button class="primary" onclick="saveMyGroups()">Save</button>\n</div>\n</div>\n</div>\n\n<div id="checkpointModal" class="modal">\n<div class="panel">\n<h2>Checkpoints</h2>\n<p class="muted">Create a point on the map and choose which group it applies to. When that group reaches the checkpoint radius, this device will alert you.</p>\n<div id="checkpointList"></div>\n<hr>\n<h3>Add checkpoint</h3>\n<div class="formrow">\n<label for="cpName">Name</label>\n<input id="cpName" maxlength="50" placeholder="e.g. Road Crossing or CP3">\n</div>\n<div class="formrow">\n<label for="cpGroup">Group</label>\n<select id="cpGroup"></select>\n</div>\n<div class="formrow">\n<label for="cpRadius">Alert radius</label>\n<select id="cpRadius">\n<option value="100">100 metres</option>\n<option value="200">200 metres</option>\n<option value="250" selected>250 metres</option>\n<option value="300">300 metres</option>\n<option value="500">500 metres</option>\n</select>\n</div>\n<div class="actions">\n<button onclick="closeCheckpointModal()">Close</button>\n<button class="primary" onclick="beginPlaceCheckpoint()">Place on map</button>\n</div>\n</div>\n</div>\n\n<div id="alertBanner" class="banner">\n<h2>CHECKPOINT REACHED</h2>\n<div id="alertText" class="big"></div>\n<div id="alertGrid" style="margin-top:7px"></div>\n<div class="actions">\n<button class="primary" onclick="ackAlert()">Acknowledge</button>\n</div>\n</div>\n\n<div id="placingMessage" class="placing">Tap the map where you want the checkpoint.</div>\n\n<script>\nproj4.defs("EPSG:27700","+proj=tmerc +lat_0=49 +lon_0=-2 +k=0.9996012717 +x_0=400000 +y_0=-100000 +ellps=airy +towgs84=446.448,-125.157,542.06,0.15,0.247,0.842,-20.489 +units=m +no_defs");\nconst crs=new L.Proj.CRS("EPSG:27700",proj4.defs("EPSG:27700"),{resolutions:[896,448,224,112,56,28,14,7,3.5,1.75],origin:[-238375,1376256]});\nconst map=L.map("map",{crs,center:[53.135,-1.81],zoom:7,minZoom:0,maxZoom:9});\nL.tileLayer("/os/{z}/{x}/{y}.png",{minZoom:0,maxZoom:9,noWrap:true,attribution:"Contains OS data © Crown copyright and database rights"}).addTo(map);\n\nlet trackers=[],selectedIds=[],layers={},positions={},lastRefresh=0,clickMarker=null;\nlet checkpoints=[],checkpointLayers={},placingCheckpoint=null,audioCtx=null,alertQueue=[],alertActive=false;\nconst REFRESH_MS=150000;\nconst GROUP_STORAGE_KEY="burtonDofE_myGroups_v12";\nconst CP_STORAGE_KEY="burtonDofE_checkpoints_v13";\n\nfunction loadSelection(){try{const x=JSON.parse(localStorage.getItem(GROUP_STORAGE_KEY)||"null");return Array.isArray(x)?x:null}catch{return null}}\nfunction selectedTrackers(){return trackers.filter(t=>selectedIds.includes(t.id))}\nfunction parseMessages(d){let m=d?.response?.feedMessageResponse?.messages?.message??d?.response?.feedMessageResponse?.messages??[];if(!Array.isArray(m))m=[m];return m.filter(x=>x&&isFinite(+x.latitude)&&isFinite(+x.longitude)&&+x.latitude!=-99999&&+x.longitude!=-99999).sort((a,b)=>(+a.unixTime||0)-(+b.unixTime||0))}\nfunction toBNG(lat,lon){let [e,n]=proj4("EPSG:4326","EPSG:27700",[lon,lat]);return[Math.round(e),Math.round(n)]}\nfunction gridRef(e,n){if(e<0||e>=700000||n<0||n>=1300000)return"Outside BNG";let a=Math.floor(e/100000),b=Math.floor(n/100000),l1=(19-b)-(19-b)%5+Math.floor((a+10)/5),l2=(19-b)*5%25+a%5;if(l1>7)l1++;if(l2>7)l2++;return String.fromCharCode(65+l1)+String.fromCharCode(65+l2)+" "+String(Math.floor((e%100000)/100)).padStart(3,"0")+" "+String(Math.floor((n%100000)/100)).padStart(3,"0")}\nfunction localTime(s){return new Date(s).toLocaleString("en-GB",{dateStyle:"medium",timeStyle:"short",timeZone:"Europe/London"})}\nfunction statusInfo(s){let a=Math.max(0,(Date.now()-new Date(s).getTime())/60000);return a>30?{cls:"bad",text:"Stale"}:a>15?{cls:"warn",text:"Delayed"}:{cls:"good",text:"Current"}}\nfunction ensureLayer(k){if(!layers[k])layers[k]=L.layerGroup().addTo(map);return layers[k]}\nfunction removeUnselectedLayers(){Object.keys(layers).forEach(id=>{if(!selectedIds.includes(id)){map.removeLayer(layers[id]);delete layers[id];delete positions[id]}})}\nfunction trackerName(id){return trackers.find(t=>t.id===id)?.name||"Unknown group"}\n\nfunction loadCheckpoints(){\ntry{\nconst x=JSON.parse(localStorage.getItem(CP_STORAGE_KEY)||"[]");\ncheckpoints=Array.isArray(x)?x:[];\n}catch{checkpoints=[]}\n}\nfunction saveCheckpoints(){localStorage.setItem(CP_STORAGE_KEY,JSON.stringify(checkpoints))}\nfunction relevantGroupIds(cp){\nif(cp.groupId==="*") return selectedTrackers().map(t=>t.id);\nreturn [cp.groupId];\n}\nfunction cpStatus(cp){\nconst ids=relevantGroupIds(cp);\nif(!ids.length)return"Waiting";\nconst passed=ids.filter(id=>cp.passed&&cp.passed[id]);\nif(!passed.length)return"Waiting";\nif(passed.length===ids.length)return"Passed";\nreturn passed.length+" of "+ids.length+" passed";\n}\nfunction renderCheckpointLayers(){\nObject.values(checkpointLayers).forEach(x=>{map.removeLayer(x.group)});\ncheckpointLayers={};\ncheckpoints.forEach(cp=>{\nconst g=L.layerGroup().addTo(map);\nconst circle=L.circle([cp.lat,cp.lon],{radius:cp.radius,weight:2,fillOpacity:.08}).addTo(g);\nconst marker=L.marker([cp.lat,cp.lon]).addTo(g);\nmarker.bindTooltip(cp.name,{permanent:false,direction:"top",className:"cp-label"});\nmarker.bindPopup("<b>"+esc(cp.name)+"</b><br>"+esc(cp.groupId==="*"?"All my groups":trackerName(cp.groupId))+"<br>Radius: "+cp.radius+" m<br>Status: "+esc(cpStatus(cp)));\ncheckpointLayers[cp.id]={group:g,circle,marker};\n});\n}\n\nfunction renderTracker(t,d){\nconst m=parseMessages(d);if(!m.length)throw Error("No valid SPOT positions");\nconst layer=ensureLayer(t.id);layer.clearLayers();\nconst pts=m.map(x=>[+x.latitude,+x.longitude]);\nL.polyline(pts,{weight:3,opacity:.65}).addTo(layer);\nconst x=m.at(-1),lat=+x.latitude,lon=+x.longitude,[e,n]=toBNG(lat,lon),g=gridRef(e,n);\nL.marker([lat,lon]).bindTooltip(t.name,{permanent:true,direction:"top",className:"marker-label",offset:[0,-12]}).bindPopup("<b>"+esc(t.name)+"</b><br>"+localTime(x.dateTime)+"<br><b>"+g+"</b><br>Altitude: "+(x.altitude??"—")+" m<br>Battery: "+(x.batteryState??"—")).addTo(layer);\npositions[t.id]={lat,lon,latest:x,grid:g,count:m.length,messages:m};\ncheckCheckpointsForTracker(t,m);\n}\n\nasync function loadTrackers(){\nconst r=await fetch("/api/trackers",{cache:"no-store"});\nif(!r.ok)throw Error("Could not load tracker list");\ntrackers=await r.json();\n}\nasync function loadOne(t){\ntry{\nconst r=await fetch("/api/spot/"+encodeURIComponent(t.id),{cache:"no-store"});\nconst d=await r.json();\nif(!r.ok||d.error)throw Error(d.error||("HTTP "+r.status));\nrenderTracker(t,d);\n}catch(e){positions[t.id]={error:e.message}}\n}\n\nfunction renderList(){\nconst h=document.getElementById("trackerList"),sum=document.getElementById("selectionSummary");\nh.innerHTML="";\nconst chosen=selectedTrackers();\nsum.textContent=trackers.length?(chosen.length?"Showing "+chosen.length+" of "+trackers.length+" groups":"No groups selected"):"";\nif(!trackers.length){h.innerHTML=\'<div class="card"><b>No trackers configured</b><div class="muted">Add the TRACKERS environment variable in Render.</div></div>\';return}\nif(!chosen.length){h.innerHTML=\'<div class="card empty"><b>No groups selected</b><div class="muted" style="margin-top:5px">Tap My Groups and tick the groups you are supervising.</div><button class="primary" style="margin-top:10px" onclick="openMyGroups()">Choose my groups</button></div>\';return}\nchosen.forEach(t=>{\nconst p=positions[t.id],c=document.createElement("div");c.className="card tracker-card";\nif(!p)c.innerHTML=\'<div class="head"><span class="name">\'+esc(t.name)+\'</span><span class="muted">Loading…</span></div>\';\nelse if(p.error)c.innerHTML=\'<div class="head"><span class="name">\'+esc(t.name)+\'</span><span class="bad">Problem</span></div><div class="muted">\'+esc(p.error)+\'</div>\';\nelse{const st=statusInfo(p.latest.dateTime);c.innerHTML=\'<div class="head"><span class="name">\'+esc(t.name)+\'</span><span class="\'+st.cls+\'">\'+st.text+\'</span></div><div><b>\'+p.grid+\'</b></div><div class="muted">\'+localTime(p.latest.dateTime)+\' · Battery \'+(p.latest.batteryState??"—")+\' · Alt \'+(p.latest.altitude??"—")+\' m</div>\';c.onclick=()=>map.setView([p.lat,p.lon],8)}\nh.appendChild(c);\n});\n}\n\nfunction sleep(ms){return new Promise(r=>setTimeout(r,ms))}\nasync function refreshAll(force=false){\nif(!force&&Date.now()-lastRefresh<REFRESH_MS)return;\nconst chosen=selectedTrackers();renderList();\nif(!chosen.length){lastRefresh=Date.now();return}\n\n/* Load sequentially so multiple SPOT feeds are not hit simultaneously. */\nfor(let i=0;i<chosen.length;i++){\nawait loadOne(chosen[i]);\nif(i<chosen.length-1)await sleep(2200);\n}\n\nrenderList();renderCheckpointLayers();lastRefresh=Date.now();\nconst b=chosen.map(t=>positions[t.id]).filter(p=>p&&!p.error).map(p=>[p.lat,p.lon]);\nif(b.length===1)map.setView(b[0],8);else if(b.length>1)map.fitBounds(b,{padding:[35,35],maxZoom:8});\n}\n\nfunction openMyGroups(){\nconst box=document.getElementById("groupChoices");box.innerHTML="";\nif(!trackers.length)box.innerHTML=\'<div class="card">No trackers are configured yet.</div>\';\nelse trackers.forEach(t=>{\nconst label=document.createElement("label");label.className="choice";\nconst cb=document.createElement("input");cb.type="checkbox";cb.value=t.id;cb.checked=selectedIds.includes(t.id);\nconst span=document.createElement("span");span.textContent=t.name;\nlabel.appendChild(cb);label.appendChild(span);box.appendChild(label);\n});\ndocument.getElementById("groupsModal").classList.add("show");\n}\nfunction selectAllGroups(){document.querySelectorAll(\'#groupChoices input[type="checkbox"]\').forEach(cb=>cb.checked=true)}\nfunction clearAllGroups(){document.querySelectorAll(\'#groupChoices input[type="checkbox"]\').forEach(cb=>cb.checked=false)}\nfunction saveMyGroups(){\nselectedIds=[...document.querySelectorAll(\'#groupChoices input[type="checkbox"]:checked\')].map(cb=>cb.value);\nlocalStorage.setItem(GROUP_STORAGE_KEY,JSON.stringify(selectedIds));\nremoveUnselectedLayers();\ndocument.getElementById("groupsModal").classList.remove("show");\nrenderCheckpointLayers();\nlastRefresh=0;renderList();refreshAll(true);\n}\n\nfunction openCheckpoints(){\nrenderCheckpointList();\nconst sel=document.getElementById("cpGroup");\nsel.innerHTML="";\nconst mine=selectedTrackers();\nif(mine.length>1){\nconst o=document.createElement("option");o.value="*";o.textContent="All my selected groups";sel.appendChild(o);\n}\nmine.forEach(t=>{const o=document.createElement("option");o.value=t.id;o.textContent=t.name;sel.appendChild(o)});\nif(!mine.length){const o=document.createElement("option");o.value="";o.textContent="Choose My Groups first";sel.appendChild(o)}\ndocument.getElementById("checkpointModal").classList.add("show");\n}\nfunction closeCheckpointModal(){document.getElementById("checkpointModal").classList.remove("show")}\nfunction renderCheckpointList(){\nconst box=document.getElementById("checkpointList");box.innerHTML="";\nif(!checkpoints.length){box.innerHTML=\'<div class="muted">No checkpoints yet.</div>\';return}\ncheckpoints.forEach(cp=>{\nconst item=document.createElement("div");item.className="cpitem";\nlet status=cpStatus(cp);\nlet passText="";\nif(cp.passed){\nconst entries=Object.entries(cp.passed);\nif(entries.length)passText=\'<div class="muted">\'+entries.map(([id,v])=>esc(trackerName(id))+" - "+esc(localTime(v.time))).join("<br>")+"</div>";\n}\nitem.innerHTML=\'<div class="cphead"><div><b>\'+esc(cp.name)+\'</b><div class="muted">\'+esc(cp.groupId==="*"?"All my selected groups":trackerName(cp.groupId))+\' · \'+cp.radius+\' m</div></div><div class="\'+(status==="Passed"?"good":"warn")+\'">\'+esc(status)+\'</div></div>\'+passText+\'<div class="cpbuttons"><button onclick="zoomCheckpoint(\\\'\'+cp.id+\'\\\')">Show</button><button onclick="resetCheckpoint(\\\'\'+cp.id+\'\\\')">Reset</button><button onclick="deleteCheckpoint(\\\'\'+cp.id+\'\\\')">Delete</button></div>\';\nbox.appendChild(item);\n});\n}\nfunction beginPlaceCheckpoint(){\nconst name=document.getElementById("cpName").value.trim();\nconst groupId=document.getElementById("cpGroup").value;\nconst radius=+document.getElementById("cpRadius").value;\nif(!name){alert("Please give the checkpoint a name.");return}\nif(!groupId){alert("Please choose your groups first.");return}\nplacingCheckpoint={name,groupId,radius};\ncloseCheckpointModal();\ndocument.getElementById("placingMessage").classList.add("show");\nunlockAudio();\n}\nfunction placeCheckpoint(latlng){\nconst cp={\nid:"cp_"+Date.now()+"_"+Math.random().toString(36).slice(2,7),\nname:placingCheckpoint.name,\ngroupId:placingCheckpoint.groupId,\nradius:placingCheckpoint.radius,\nlat:latlng.lat,\nlon:latlng.lng,\ncreatedAt:new Date().toISOString(),\npassed:{}\n};\ncheckpoints.push(cp);saveCheckpoints();placingCheckpoint=null;\ndocument.getElementById("placingMessage").classList.remove("show");\ndocument.getElementById("cpName").value="";\nrenderCheckpointLayers();\nmap.setView([cp.lat,cp.lon],Math.max(map.getZoom(),7));\n}\nfunction zoomCheckpoint(id){\nconst cp=checkpoints.find(c=>c.id===id);if(!cp)return;\ncloseCheckpointModal();map.setView([cp.lat,cp.lon],8);\ncheckpointLayers[id]?.marker.openPopup();\n}\nfunction resetCheckpoint(id){\nconst cp=checkpoints.find(c=>c.id===id);if(!cp)return;\ncp.passed={};cp.createdAt=new Date().toISOString();saveCheckpoints();renderCheckpointList();renderCheckpointLayers();\n}\nfunction deleteCheckpoint(id){\ncheckpoints=checkpoints.filter(c=>c.id!==id);saveCheckpoints();renderCheckpointList();renderCheckpointLayers();\n}\n\nfunction pointToSegmentDistance(px,py,x1,y1,x2,y2){\nconst dx=x2-x1,dy=y2-y1;\nif(dx===0&&dy===0)return Math.hypot(px-x1,py-y1);\nlet t=((px-x1)*dx+(py-y1)*dy)/(dx*dx+dy*dy);\nt=Math.max(0,Math.min(1,t));\nconst x=x1+t*dx,y=y1+t*dy;\nreturn Math.hypot(px-x,py-y);\n}\nfunction checkCheckpointsForTracker(t,messages){\nif(!messages.length)return;\nlet changed=false;\ncheckpoints.forEach(cp=>{\nif(cp.groupId!=="*"&&cp.groupId!==t.id)return;\ncp.passed=cp.passed||{};\nif(cp.passed[t.id])return;\n\nconst created=new Date(cp.createdAt).getTime();\nconst [cx,cy]=toBNG(cp.lat,cp.lon);\nlet hit=null;\n\nfor(let i=0;i<messages.length;i++){\nconst cur=messages[i];\nconst tm=new Date(cur.dateTime).getTime();\nif(tm<created-30000)continue;\nconst [x,y]=toBNG(+cur.latitude,+cur.longitude);\nif(Math.hypot(cx-x,cy-y)<=cp.radius){hit=cur;break}\n\nif(i>0){\nconst prev=messages[i-1];\nconst ptm=new Date(prev.dateTime).getTime();\nif(tm>=created-30000 && ptm<=tm){\nconst [x1,y1]=toBNG(+prev.latitude,+prev.longitude);\nif(pointToSegmentDistance(cx,cy,x1,y1,x,y)<=cp.radius){hit=cur;break}\n}\n}\n}\nif(hit){\nconst [e,n]=toBNG(+hit.latitude,+hit.longitude);\ncp.passed[t.id]={time:hit.dateTime,grid:gridRef(e,n)};\nchanged=true;\nqueueCheckpointAlert(cp,t,hit);\n}\n});\nif(changed){saveCheckpoints();renderCheckpointLayers()}\n}\n\nfunction unlockAudio(){\ntry{\nif(!audioCtx)audioCtx=new (window.AudioContext||window.webkitAudioContext)();\nif(audioCtx.state==="suspended")audioCtx.resume();\n}catch{}\n}\nasync function enableAlerts(){\nunlockAudio();\nif("Notification" in window){\ntry{await Notification.requestPermission()}catch{}\n}\nconst b=document.getElementById("alertsBtn");\nb.textContent="Alerts On";b.classList.add("alert-on");\nplayBeep(false);\n}\nfunction playBeep(urgent=true){\nunlockAudio();\nif(!audioCtx)return;\ntry{\nconst now=audioCtx.currentTime;\nconst count=urgent?4:1;\nfor(let i=0;i<count;i++){\nconst osc=audioCtx.createOscillator(),gain=audioCtx.createGain();\nosc.type="square";osc.frequency.value=urgent?880:660;\ngain.gain.setValueAtTime(0.0001,now+i*.35);\ngain.gain.exponentialRampToValueAtTime(.18,now+i*.35+.02);\ngain.gain.exponentialRampToValueAtTime(.0001,now+i*.35+.22);\nosc.connect(gain);gain.connect(audioCtx.destination);\nosc.start(now+i*.35);osc.stop(now+i*.35+.24);\n}\n}catch{}\n}\nfunction queueCheckpointAlert(cp,t,hit){\nalertQueue.push({cp,t,hit});\nif(!alertActive)showNextAlert();\n}\nfunction showNextAlert(){\nif(!alertQueue.length){alertActive=false;return}\nalertActive=true;\nconst a=alertQueue[0];\nconst pass=a.cp.passed[a.t.id];\ndocument.getElementById("alertText").textContent=a.t.name+" reached "+a.cp.name;\ndocument.getElementById("alertGrid").textContent=(pass?.grid||"")+" · "+localTime(a.hit.dateTime);\ndocument.getElementById("alertBanner").classList.add("show");\nplayBeep(true);\nif("Notification" in window&&Notification.permission==="granted"){\ntry{\nnew Notification("DofE checkpoint reached",{body:a.t.name+" reached "+a.cp.name+" - "+(pass?.grid||"")});\n}catch{}\n}\n}\nfunction ackAlert(){\ndocument.getElementById("alertBanner").classList.remove("show");\nalertQueue.shift();alertActive=false;setTimeout(showNextAlert,150);\n}\n\nmap.on("click",e=>{\nif(placingCheckpoint){placeCheckpoint(e.latlng);return}\nconst [en,nn]=toBNG(e.latlng.lat,e.latlng.lng),g=gridRef(en,nn);\nif(clickMarker)map.removeLayer(clickMarker);\nclickMarker=L.marker(e.latlng).addTo(map).bindPopup(\'<b style="font-size:19px">\'+g+\'</b><br><br><button onclick="clearClickMarker()">Clear marker</button>\').openPopup();\n});\nfunction clearClickMarker(){if(clickMarker){map.removeLayer(clickMarker);clickMarker=null}}\nfunction esc(s){return String(s).replace(/[&<>"\']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",\'"\':"&quot;","\'":"&#039;"}[c]))}\n\nasync function startApp(){\nloadCheckpoints();\ntry{await loadTrackers()}catch(e){document.getElementById("trackerList").innerHTML=\'<div class="card bad">\'+esc(e.message)+\'</div>\';return}\nconst saved=loadSelection();\nif(saved===null){selectedIds=[];renderList();renderCheckpointLayers();openMyGroups();return}\nconst valid=new Set(trackers.map(t=>t.id));\nselectedIds=saved.filter(id=>valid.has(id));\nlocalStorage.setItem(GROUP_STORAGE_KEY,JSON.stringify(selectedIds));\nrenderList();renderCheckpointLayers();refreshAll(true);\nif("Notification" in window&&Notification.permission==="granted"){\nconst b=document.getElementById("alertsBtn");b.textContent="Enable Sound";b.title="Tap once after opening to allow alarm sound";\n}\n}\nstartApp();\nsetInterval(()=>refreshAll(false),REFRESH_MS);\n</script>\n</body>\n</html>'

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
