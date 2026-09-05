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
            headers={"Accept": "application/json", "User-Agent": "Burton-DofE-Tracker/12.0"},
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

APP_HTML = '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">\n<meta name="theme-color" content="#17202a">\n<title>Burton DofE Live Tracker</title>\n<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">\n<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>\n<script src="https://cdnjs.cloudflare.com/ajax/libs/proj4js/2.11.0/proj4.js"></script>\n<script src="https://unpkg.com/proj4leaflet@1.0.2/src/proj4leaflet.js"></script>\n<style>\n*{box-sizing:border-box}html,body{margin:0;height:100%;font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#222}\nheader{min-height:58px;background:#17202a;color:#fff;padding:9px 12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}\nh1{font-size:17px;margin:0;flex:1}.controls{display:flex;gap:7px;flex-wrap:wrap}\nbutton{padding:8px 10px;border:0;border-radius:7px;font:inherit;cursor:pointer}\nmain{display:grid;grid-template-columns:340px 1fr;height:calc(100% - 58px)}\naside{overflow:auto;padding:10px;border-right:1px solid #ddd;background:#fff}\n#map{height:100%;width:100%;background:#ddd}.card{border:1px solid #ddd;border-radius:10px;padding:10px;margin-bottom:8px}\n.tracker-card{cursor:pointer}.tracker-card:hover{border-color:#888}.head{display:flex;justify-content:space-between;gap:8px}.name{font-weight:800}\n.muted{font-size:12px;color:#666}.good{color:#167c31;font-weight:700}.warn{color:#a76300;font-weight:700}.bad{color:#a40000;font-weight:700}\n.marker-label{background:#17202a;color:#fff;border:0;border-radius:5px;font-weight:700}\n.summary{font-weight:700;margin-bottom:8px}.modal{display:none;position:fixed;inset:0;background:#0009;z-index:3000;align-items:center;justify-content:center;padding:15px}\n.modal.show{display:flex}.panel{background:#fff;width:min(520px,96vw);max-height:90vh;overflow:auto;border-radius:14px;padding:18px;box-shadow:0 10px 50px #0007}\n.panel h2{margin:0 0 5px}.choice{display:flex;align-items:center;gap:11px;border:1px solid #ddd;border-radius:10px;padding:12px;margin:8px 0;cursor:pointer}\n.choice input{width:20px;height:20px;flex:0 0 auto}.choice span{font-weight:700}.actions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;margin-top:15px}\n.primary{background:#17202a;color:#fff;font-weight:700}.empty{text-align:center;padding:16px 8px}\n@media(max-width:760px){header{min-height:54px}main{display:block;height:calc(100% - 54px);position:relative}#map{height:100%}\naside{position:absolute;z-index:1000;left:8px;right:8px;bottom:8px;max-height:40%;border:0;border-radius:12px;box-shadow:0 4px 20px #0005;padding:8px}\n.card{padding:8px;margin-bottom:6px}.controls button{padding:7px 9px}}\n</style>\n</head>\n<body>\n<header>\n<h1>Burton DofE - Live Tracking</h1>\n<div class="controls">\n<button onclick="refreshAll(true)">Refresh</button>\n<button onclick="openMyGroups()">My Groups</button>\n<button onclick="location.href=\'/logout\'">Log out</button>\n</div>\n</header>\n<main>\n<aside>\n<div id="selectionSummary" class="summary"></div>\n<div id="trackerList"></div>\n<div class="card muted">Tap a group to centre the map. Tap anywhere on the OS map for a 6-figure grid reference.</div>\n</aside>\n<div id="map"></div>\n</main>\n\n<div id="groupsModal" class="modal">\n<div class="panel">\n<h2>My Groups</h2>\n<p class="muted">Tick the groups you are supervising. Your choice is remembered on this device.</p>\n<div id="groupChoices"></div>\n<div class="actions">\n<button onclick="selectAllGroups()">Select all</button>\n<button onclick="clearAllGroups()">Clear</button>\n<button class="primary" onclick="saveMyGroups()">Save</button>\n</div>\n</div>\n</div>\n\n<script>\nproj4.defs("EPSG:27700","+proj=tmerc +lat_0=49 +lon_0=-2 +k=0.9996012717 +x_0=400000 +y_0=-100000 +ellps=airy +towgs84=446.448,-125.157,542.06,0.15,0.247,0.842,-20.489 +units=m +no_defs");\nconst crs=new L.Proj.CRS("EPSG:27700",proj4.defs("EPSG:27700"),{resolutions:[896,448,224,112,56,28,14,7,3.5,1.75],origin:[-238375,1376256]});\nconst map=L.map("map",{crs,center:[53.135,-1.81],zoom:7,minZoom:0,maxZoom:9});\nL.tileLayer("/os/{z}/{x}/{y}.png",{minZoom:0,maxZoom:9,noWrap:true,attribution:"Contains OS data © Crown copyright and database rights"}).addTo(map);\n\nlet trackers=[],selectedIds=[],layers={},positions={},lastRefresh=0,clickMarker=null;\nconst REFRESH_MS=150000, STORAGE_KEY="burtonDofE_myGroups_v12";\n\nfunction loadSelection(){try{const x=JSON.parse(localStorage.getItem(STORAGE_KEY)||"null");return Array.isArray(x)?x:null}catch{return null}}\nfunction selectedTrackers(){return trackers.filter(t=>selectedIds.includes(t.id))}\nfunction parseMessages(d){let m=d?.response?.feedMessageResponse?.messages?.message??d?.response?.feedMessageResponse?.messages??[];if(!Array.isArray(m))m=[m];return m.filter(x=>x&&isFinite(+x.latitude)&&isFinite(+x.longitude)&&+x.latitude!=-99999&&+x.longitude!=-99999).sort((a,b)=>(+a.unixTime||0)-(+b.unixTime||0))}\nfunction toBNG(lat,lon){let [e,n]=proj4("EPSG:4326","EPSG:27700",[lon,lat]);return[Math.round(e),Math.round(n)]}\nfunction gridRef(e,n){if(e<0||e>=700000||n<0||n>=1300000)return"Outside BNG";let a=Math.floor(e/100000),b=Math.floor(n/100000),l1=(19-b)-(19-b)%5+Math.floor((a+10)/5),l2=(19-b)*5%25+a%5;if(l1>7)l1++;if(l2>7)l2++;return String.fromCharCode(65+l1)+String.fromCharCode(65+l2)+" "+String(Math.floor((e%100000)/100)).padStart(3,"0")+" "+String(Math.floor((n%100000)/100)).padStart(3,"0")}\nfunction localTime(s){return new Date(s).toLocaleString("en-GB",{dateStyle:"medium",timeStyle:"short",timeZone:"Europe/London"})}\nfunction statusInfo(s){let a=Math.max(0,(Date.now()-new Date(s).getTime())/60000);return a>30?{cls:"bad",text:"Stale"}:a>15?{cls:"warn",text:"Delayed"}:{cls:"good",text:"Current"}}\nfunction ensureLayer(k){if(!layers[k])layers[k]=L.layerGroup().addTo(map);return layers[k]}\nfunction removeUnselectedLayers(){Object.keys(layers).forEach(id=>{if(!selectedIds.includes(id)){map.removeLayer(layers[id]);delete layers[id];delete positions[id]}})}\nfunction renderTracker(t,d){const m=parseMessages(d);if(!m.length)throw Error("No valid SPOT positions");const layer=ensureLayer(t.id);layer.clearLayers();const pts=m.map(x=>[+x.latitude,+x.longitude]);L.polyline(pts,{weight:3,opacity:.65}).addTo(layer);const x=m.at(-1),lat=+x.latitude,lon=+x.longitude,[e,n]=toBNG(lat,lon),g=gridRef(e,n);L.marker([lat,lon]).bindTooltip(t.name,{permanent:true,direction:"top",className:"marker-label",offset:[0,-12]}).bindPopup("<b>"+esc(t.name)+"</b><br>"+localTime(x.dateTime)+"<br><b>"+g+"</b><br>Altitude: "+(x.altitude??"—")+" m<br>Battery: "+(x.batteryState??"—")).addTo(layer);positions[t.id]={lat,lon,latest:x,grid:g,count:m.length}}\nasync function loadTrackers(){const r=await fetch("/api/trackers",{cache:"no-store"});if(!r.ok)throw Error("Could not load tracker list");trackers=await r.json()}\nasync function loadOne(t){try{const r=await fetch("/api/spot/"+encodeURIComponent(t.id),{cache:"no-store"});const d=await r.json();if(!r.ok||d.error)throw Error(d.error||("HTTP "+r.status));renderTracker(t,d)}catch(e){positions[t.id]={error:e.message}}}\n\nfunction renderList(){\nconst h=document.getElementById("trackerList"),sum=document.getElementById("selectionSummary");\nh.innerHTML="";\nconst chosen=selectedTrackers();\nsum.textContent=trackers.length?(chosen.length?"Showing "+chosen.length+" of "+trackers.length+" groups":"No groups selected"):"";\nif(!trackers.length){h.innerHTML=\'<div class="card"><b>No trackers configured</b><div class="muted">Add the TRACKERS environment variable in Render.</div></div>\';return}\nif(!chosen.length){h.innerHTML=\'<div class="card empty"><b>No groups selected</b><div class="muted" style="margin-top:5px">Tap My Groups and tick the groups you are supervising.</div><button class="primary" style="margin-top:10px" onclick="openMyGroups()">Choose my groups</button></div>\';return}\nchosen.forEach(t=>{\nconst p=positions[t.id],c=document.createElement("div");c.className="card tracker-card";\nif(!p)c.innerHTML=\'<div class="head"><span class="name">\'+esc(t.name)+\'</span><span class="muted">Loading…</span></div>\';\nelse if(p.error)c.innerHTML=\'<div class="head"><span class="name">\'+esc(t.name)+\'</span><span class="bad">Problem</span></div><div class="muted">\'+esc(p.error)+\'</div>\';\nelse{const st=statusInfo(p.latest.dateTime);c.innerHTML=\'<div class="head"><span class="name">\'+esc(t.name)+\'</span><span class="\'+st.cls+\'">\'+st.text+\'</span></div><div><b>\'+p.grid+\'</b></div><div class="muted">\'+localTime(p.latest.dateTime)+\' · Battery \'+(p.latest.batteryState??"—")+\' · Alt \'+(p.latest.altitude??"—")+\' m</div>\';c.onclick=()=>map.setView([p.lat,p.lon],8)}\nh.appendChild(c);\n});\n}\n\nasync function refreshAll(force=false){\nif(!force&&Date.now()-lastRefresh<REFRESH_MS)return;\nconst chosen=selectedTrackers();renderList();\nif(!chosen.length){lastRefresh=Date.now();return}\nawait Promise.all(chosen.map(loadOne));\nrenderList();lastRefresh=Date.now();\nconst b=chosen.map(t=>positions[t.id]).filter(p=>p&&!p.error).map(p=>[p.lat,p.lon]);\nif(b.length===1)map.setView(b[0],8);else if(b.length>1)map.fitBounds(b,{padding:[35,35],maxZoom:8});\n}\n\nfunction openMyGroups(){\nconst box=document.getElementById("groupChoices");box.innerHTML="";\nif(!trackers.length)box.innerHTML=\'<div class="card">No trackers are configured yet.</div>\';\nelse trackers.forEach(t=>{\nconst label=document.createElement("label");label.className="choice";\nconst cb=document.createElement("input");cb.type="checkbox";cb.value=t.id;cb.checked=selectedIds.includes(t.id);\nconst span=document.createElement("span");span.textContent=t.name;\nlabel.appendChild(cb);label.appendChild(span);box.appendChild(label);\n});\ndocument.getElementById("groupsModal").classList.add("show");\n}\nfunction selectAllGroups(){document.querySelectorAll(\'#groupChoices input[type="checkbox"]\').forEach(cb=>cb.checked=true)}\nfunction clearAllGroups(){document.querySelectorAll(\'#groupChoices input[type="checkbox"]\').forEach(cb=>cb.checked=false)}\nfunction saveMyGroups(){\nselectedIds=[...document.querySelectorAll(\'#groupChoices input[type="checkbox"]:checked\')].map(cb=>cb.value);\nlocalStorage.setItem(STORAGE_KEY,JSON.stringify(selectedIds));\nremoveUnselectedLayers();\ndocument.getElementById("groupsModal").classList.remove("show");\nlastRefresh=0;renderList();refreshAll(true);\n}\n\nmap.on("click",e=>{\nconst [en,nn]=toBNG(e.latlng.lat,e.latlng.lng),g=gridRef(en,nn);\nif(clickMarker)map.removeLayer(clickMarker);\nclickMarker=L.marker(e.latlng).addTo(map).bindPopup(\'<b style="font-size:19px">\'+g+\'</b><br><br><button onclick="clearClickMarker()">Clear marker</button>\').openPopup();\n});\nfunction clearClickMarker(){if(clickMarker){map.removeLayer(clickMarker);clickMarker=null}}\nfunction esc(s){return String(s).replace(/[&<>"\']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",\'"\':"&quot;","\'":"&#039;"}[c]))}\n\nasync function startApp(){\ntry{await loadTrackers()}catch(e){document.getElementById("trackerList").innerHTML=\'<div class="card bad">\'+esc(e.message)+\'</div>\';return}\nconst saved=loadSelection();\nif(saved===null){selectedIds=[];renderList();openMyGroups();return}\nconst valid=new Set(trackers.map(t=>t.id));\nselectedIds=saved.filter(id=>valid.has(id));\nlocalStorage.setItem(STORAGE_KEY,JSON.stringify(selectedIds));\nrenderList();refreshAll(true);\n}\nstartApp();\nsetInterval(()=>refreshAll(false),REFRESH_MS);\n</script>\n</body>\n</html>\n'

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
