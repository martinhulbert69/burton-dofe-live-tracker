import os
import time
import re
import requests
from flask import Flask, request, jsonify, Response, redirect, make_response, render_template_string
from functools import wraps
from urllib.parse import quote

app = Flask(__name__)

APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
OS_API_KEY = os.environ.get("OS_API_KEY", "")
DEFAULT_FEED_ID = os.environ.get("DEFAULT_FEED_ID", "")
SESSION_COOKIE = "dofe_session"
CACHE_SECONDS = 150
spot_cache = {}

def session_token():
    import hashlib
    return hashlib.sha256(("burton-dofe-v10|" + APP_PASSWORD).encode("utf-8")).hexdigest()

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
        import hmac
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
    return render_template_string(APP_HTML, default_feed=DEFAULT_FEED_ID)

@app.route("/api/spot")
@require_login
def spot():
    feed = (request.args.get("feed") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,100}", feed):
        return jsonify(error="Invalid or missing SPOT feed ID."), 400

    now = time.time()
    cached = spot_cache.get(feed)
    if cached and now - cached["time"] < CACHE_SECONDS:
        return jsonify(cached["data"])

    url = f"https://api.findmespot.com/spot-main-web/consumer/rest-api/2.0/public/feed/{feed}/message.json"

    try:
        r = requests.get(
            url,
            headers={"Accept": "application/json", "User-Agent": "Burton-DofE-Tracker/10.0"},
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

APP_HTML = '''
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<meta name="theme-color" content="#17202a">
<title>Burton DofE Live Tracker</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/proj4js/2.11.0/proj4.js"></script>
<script src="https://unpkg.com/proj4leaflet@1.0.2/src/proj4leaflet.js"></script>
<style>
*{box-sizing:border-box}html,body{margin:0;height:100%;font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#222}
header{min-height:58px;background:#17202a;color:#fff;padding:9px 12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
h1{font-size:17px;margin:0;flex:1}.controls{display:flex;gap:7px}
button{padding:8px 10px;border:0;border-radius:7px;font:inherit;cursor:pointer}
main{display:grid;grid-template-columns:340px 1fr;height:calc(100% - 58px)}
aside{overflow:auto;padding:10px;border-right:1px solid #ddd;background:#fff}
#map{height:100%;width:100%;background:#ddd}
.card{border:1px solid #ddd;border-radius:10px;padding:10px;margin-bottom:8px}
.tracker-card{cursor:pointer}.tracker-card:hover{border-color:#888}
.head{display:flex;justify-content:space-between;gap:8px}.name{font-weight:800}
.muted{font-size:12px;color:#666}.good{color:#167c31;font-weight:700}.warn{color:#a76300;font-weight:700}.bad{color:#a40000;font-weight:700}
.marker-label{background:#17202a;color:#fff;border:0;border-radius:5px;font-weight:700}
.modal{display:none;position:fixed;inset:0;background:#0008;z-index:2000;align-items:center;justify-content:center;padding:15px}
.modal.show{display:flex}.panel{background:#fff;width:min(680px,96vw);max-height:90vh;overflow:auto;border-radius:12px;padding:16px}
.row{display:grid;grid-template-columns:1fr 2fr auto;gap:7px;margin:7px 0}.row input{width:100%;padding:9px;border:1px solid #aaa;border-radius:7px}
@media(max-width:760px){
header{min-height:54px}main{display:block;height:calc(100% - 54px);position:relative}
#map{height:100%}
aside{position:absolute;z-index:1000;left:8px;right:8px;bottom:8px;max-height:38%;border:0;border-radius:12px;box-shadow:0 4px 20px #0005;padding:8px}
.row{grid-template-columns:1fr}.card{padding:8px;margin-bottom:6px}
}
</style>
</head>
<body>
<header>
<h1>Burton DofE - Live Tracking</h1>
<div class="controls">
<button onclick="refreshAll(true)">Refresh</button>
<button onclick="openSettings()">Trackers</button>
<button onclick="location.href='/logout'">Log out</button>
</div>
</header>

<main>
<aside>
<div id="trackerList"></div>
<div class="card muted">Tap a group to centre the map. Tap anywhere on the OS map for a 6-figure grid reference.</div>
</aside>
<div id="map"></div>
</main>

<div id="settings" class="modal">
<div class="panel">
<h2 style="margin-top:0">Tracker setup</h2>
<p class="muted">Names and feed IDs are saved on this device.</p>
<div id="trackerRows"></div>
<button onclick="addTrackerRow()">+ Add tracker</button>
<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px">
<button onclick="closeSettings()">Cancel</button>
<button onclick="saveSettings()">Save</button>
</div>
</div>
</div>

<script>
proj4.defs("EPSG:27700","+proj=tmerc +lat_0=49 +lon_0=-2 +k=0.9996012717 +x_0=400000 +y_0=-100000 +ellps=airy +towgs84=446.448,-125.157,542.06,0.15,0.247,0.842,-20.489 +units=m +no_defs");
const crs=new L.Proj.CRS("EPSG:27700",proj4.defs("EPSG:27700"),{resolutions:[896,448,224,112,56,28,14,7,3.5,1.75],origin:[-238375,1376256]});
const map=L.map("map",{crs,center:[53.135,-1.81],zoom:7,minZoom:0,maxZoom:9});
L.tileLayer("/os/{z}/{x}/{y}.png",{minZoom:0,maxZoom:9,noWrap:true,attribution:"Contains OS data © Crown copyright and database rights"}).addTo(map);

let layers={},positions={},lastRefresh=0,clickMarker=null;
const REFRESH_MS=150000;
const DEFAULT_FEED={{ default_feed|tojson }};
const DEFAULT_TRACKERS=DEFAULT_FEED?[{name:"BOT1",feed:DEFAULT_FEED}]:[];

function loadTrackers(){
try{
const saved=JSON.parse(localStorage.getItem("dofeTrackersRender")||"null");
return Array.isArray(saved)&&saved.length?saved:DEFAULT_TRACKERS;
}catch{return DEFAULT_TRACKERS}
}
let trackers=loadTrackers();

function parseMessages(d){
let m=d?.response?.feedMessageResponse?.messages?.message??d?.response?.feedMessageResponse?.messages??[];
if(!Array.isArray(m))m=[m];
return m.filter(x=>x&&isFinite(+x.latitude)&&isFinite(+x.longitude)&&+x.latitude!=-99999&&+x.longitude!=-99999)
.sort((a,b)=>(+a.unixTime||0)-(+b.unixTime||0));
}
function toBNG(lat,lon){let [e,n]=proj4("EPSG:4326","EPSG:27700",[lon,lat]);return[Math.round(e),Math.round(n)]}
function gridRef(e,n){
if(e<0||e>=700000||n<0||n>=1300000)return"Outside BNG";
let a=Math.floor(e/100000),b=Math.floor(n/100000),l1=(19-b)-(19-b)%5+Math.floor((a+10)/5),l2=(19-b)*5%25+a%5;
if(l1>7)l1++;if(l2>7)l2++;
return String.fromCharCode(65+l1)+String.fromCharCode(65+l2)+" "+
String(Math.floor((e%100000)/100)).padStart(3,"0")+" "+
String(Math.floor((n%100000)/100)).padStart(3,"0");
}
function localTime(s){return new Date(s).toLocaleString("en-GB",{dateStyle:"medium",timeStyle:"short",timeZone:"Europe/London"})}
function statusInfo(s){
let a=Math.max(0,(Date.now()-new Date(s).getTime())/60000);
return a>30?{cls:"bad",text:"Stale"}:a>15?{cls:"warn",text:"Delayed"}:{cls:"good",text:"Current"};
}
function ensureLayer(k){if(!layers[k])layers[k]=L.layerGroup().addTo(map);return layers[k]}

function renderTracker(t,d){
const m=parseMessages(d);if(!m.length)throw Error("No valid SPOT positions");
const layer=ensureLayer(t.feed);layer.clearLayers();
const pts=m.map(x=>[+x.latitude,+x.longitude]);
L.polyline(pts,{weight:3,opacity:.65}).addTo(layer);
const x=m.at(-1),lat=+x.latitude,lon=+x.longitude,[e,n]=toBNG(lat,lon),g=gridRef(e,n);
L.marker([lat,lon]).bindTooltip(t.name,{permanent:true,direction:"top",className:"marker-label",offset:[0,-12]})
.bindPopup("<b>"+esc(t.name)+"</b><br>"+localTime(x.dateTime)+"<br><b>"+g+"</b><br>Altitude: "+(x.altitude??"—")+" m<br>Battery: "+(x.batteryState??"—")).addTo(layer);
positions[t.feed]={lat,lon,latest:x,grid:g,count:m.length};
}
async function loadOne(t){
try{
const r=await fetch("/api/spot?feed="+encodeURIComponent(t.feed),{cache:"no-store"});
const d=await r.json();
if(!r.ok||d.error)throw Error(d.error||("HTTP "+r.status));
renderTracker(t,d);
}catch(e){positions[t.feed]={error:e.message}}
}
function renderList(){
const h=document.getElementById("trackerList");h.innerHTML="";
if(!trackers.length){
h.innerHTML='<div class="card"><b>No trackers configured</b><div class="muted">Tap Trackers above to add one.</div></div>';
return;
}
trackers.forEach(t=>{
const p=positions[t.feed],c=document.createElement("div");c.className="card tracker-card";
if(!p)c.innerHTML='<div class="head"><span class="name">'+esc(t.name)+'</span><span class="muted">Loading…</span></div>';
else if(p.error)c.innerHTML='<div class="head"><span class="name">'+esc(t.name)+'</span><span class="bad">Problem</span></div><div class="muted">'+esc(p.error)+'</div>';
else{
const s=statusInfo(p.latest.dateTime);
c.innerHTML='<div class="head"><span class="name">'+esc(t.name)+'</span><span class="'+s.cls+'">'+s.text+'</span></div><div><b>'+p.grid+'</b></div><div class="muted">'+localTime(p.latest.dateTime)+' · Battery '+(p.latest.batteryState??"—")+' · Alt '+(p.latest.altitude??"—")+' m</div>';
c.onclick=()=>map.setView([p.lat,p.lon],8);
}
h.appendChild(c);
});
}
async function refreshAll(force=false){
if(!force&&Date.now()-lastRefresh<REFRESH_MS)return;
renderList();
await Promise.all(trackers.map(loadOne));
renderList();lastRefresh=Date.now();
const b=trackers.map(t=>positions[t.feed]).filter(p=>p&&!p.error).map(p=>[p.lat,p.lon]);
if(b.length===1)map.setView(b[0],8);else if(b.length>1)map.fitBounds(b,{padding:[35,35],maxZoom:8});
}
map.on("click",e=>{
const [en,nn]=toBNG(e.latlng.lat,e.latlng.lng),g=gridRef(en,nn);
if(clickMarker)map.removeLayer(clickMarker);
clickMarker=L.marker(e.latlng).addTo(map).bindPopup('<b style="font-size:19px">'+g+'</b><br><br><button onclick="clearClickMarker()">Clear marker</button>').openPopup();
});
function clearClickMarker(){if(clickMarker){map.removeLayer(clickMarker);clickMarker=null}}
function openSettings(){
const h=document.getElementById("trackerRows");h.innerHTML="";
trackers.forEach(t=>addTrackerRow(t.name,t.feed));
document.getElementById("settings").classList.add("show");
}
function closeSettings(){document.getElementById("settings").classList.remove("show")}
function addTrackerRow(name="",feed=""){
const r=document.createElement("div");r.className="row";
r.innerHTML='<input class="name" placeholder="Group name" value="'+attr(name)+'"><input class="feed" placeholder="SPOT feed ID" value="'+attr(feed)+'"><button onclick="this.parentElement.remove()">Remove</button>';
document.getElementById("trackerRows").appendChild(r);
}
function saveSettings(){
const n=[...document.querySelectorAll("#trackerRows .row")].map(r=>({name:r.querySelector(".name").value.trim(),feed:r.querySelector(".feed").value.trim()})).filter(x=>x.name&&x.feed);
trackers=n;localStorage.setItem("dofeTrackersRender",JSON.stringify(n));
Object.values(layers).forEach(l=>map.removeLayer(l));layers={};positions={};
closeSettings();refreshAll(true);
}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]))}
function attr(s){return esc(s)}
renderList();refreshAll(true);setInterval(()=>refreshAll(false),REFRESH_MS);
</script>
</body>
</html>
'''

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
