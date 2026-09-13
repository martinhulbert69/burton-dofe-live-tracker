from datetime import datetime, timezone
import os
import secrets
import time
import re
import hashlib
import hmac
import requests
from flask import Flask, request, jsonify, Response, redirect, make_response, render_template_string
from functools import wraps
from urllib.parse import quote
import sqlite3
import os
import json
import threading
import math
import xml.etree.ElementTree as ET

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
    ensure_spot_poller()
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
            headers={"Accept": "application/json", "User-Agent": "COMPASS/16.1"},
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

@app.route("/api/spot-diagnostic/<tracker_id>")
@require_login
def spot_diagnostic(tracker_id):
    tracker = tracker_by_id(tracker_id)
    if not tracker:
        return jsonify(error="Unknown tracker."), 404

    feed = tracker["feed"]
    url = f"https://api.findmespot.com/spot-main-web/consumer/rest-api/2.0/public/feed/{feed}/message.json"
    try:
        r = requests.get(
            url,
            headers={"Accept": "application/json", "User-Agent": "COMPASS/16.1"},
            timeout=20,
        )
    except requests.RequestException as exc:
        return jsonify({
            "ok": False,
            "tracker": tracker["name"],
            "error": f"Request failed: {type(exc).__name__}: {exc}",
        }), 502

    result = {
        "ok": r.status_code == 200,
        "tracker": tracker["name"],
        "http_status": r.status_code,
        "content_type": r.headers.get("content-type", ""),
    }

    try:
        data = r.json()
    except ValueError:
        result["error"] = "SPOT returned a non-JSON response."
        return jsonify(result)

    response = data.get("response", {}) if isinstance(data, dict) else {}
    if response.get("errors"):
        result["spot_errors"] = response.get("errors")

    fmr = response.get("feedMessageResponse", {}) if isinstance(response, dict) else {}
    messages = fmr.get("messages", {}) if isinstance(fmr, dict) else {}
    msg = messages.get("message", []) if isinstance(messages, dict) else []
    if isinstance(msg, dict):
        msg = [msg]
    if not isinstance(msg, list):
        msg = []

    result["message_count"] = len(msg)
    result["latest"] = None
    if msg:
        latest = msg[0] if isinstance(msg[0], dict) else {}
        result["latest"] = {
            "message_type": latest.get("messageType"),
            "date_time": latest.get("dateTime"),
            "unix_time": latest.get("unixTime"),
            "latitude": latest.get("latitude"),
            "longitude": latest.get("longitude"),
            "altitude": latest.get("altitude"),
            "battery_state": latest.get("batteryState"),
        }
    return jsonify(result)

@app.route("/os/<int:z>/<int:x>/<int:y>.png")
@require_login
def os_tile(z, x, y):
    if z < 0 or z > 9:
        return "Zoom out of range", 400

    # COMPASS v15.4: persistent OS Leisure tile cache.
    # The browser keeps a tile for a week and Render keeps it on /var/data for 30 days.
    tile_root = os.path.join(DATA_DIR, "os_tiles")
    tile_path = os.path.join(tile_root, str(z), str(x), f"{y}.png")
    os.makedirs(os.path.dirname(tile_path), exist_ok=True)
    disk_max_age = 30 * 24 * 60 * 60
    browser_max_age = 7 * 24 * 60 * 60

    def tile_response(path, cache_state):
        with open(path, "rb") as fh:
            body = fh.read()
        resp = Response(body, status=200, mimetype="image/png")
        resp.headers["Cache-Control"] = f"private, max-age={browser_max_age}"
        resp.headers["X-COMPASS-Map-Cache"] = cache_state
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    if os.path.exists(tile_path):
        age = time.time() - os.path.getmtime(tile_path)
        if age < disk_max_age:
            return tile_response(tile_path, "HIT")

    url = f"https://api.os.uk/maps/raster/v1/zxy/Leisure_27700/{z}/{x}/{y}.png?key={quote(OS_API_KEY)}"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            tmp = tile_path + f".{os.getpid()}.{threading.get_ident()}.tmp"
            with open(tmp, "wb") as fh:
                fh.write(r.content)
            os.replace(tmp, tile_path)
            return tile_response(tile_path, "MISS")

        # If OS is temporarily unavailable, an older cached tile is still better than a blank square.
        if os.path.exists(tile_path):
            return tile_response(tile_path, "STALE")
        return f"OS tile error {r.status_code}", r.status_code
    except requests.RequestException as exc:
        if os.path.exists(tile_path):
            return tile_response(tile_path, "STALE")
        return str(exc), 502


# Shared water log for v14.2.1.
# Entries are shared between logged-in leaders while this Render process is running.
water_log = []

@app.route("/api/water", methods=["GET"])
@require_login
def get_water_log():
    tracker_id = request.args.get("tracker_id", "").strip()
    rows = [x for x in water_log if not tracker_id or x["tracker_id"] == tracker_id]
    return jsonify(rows[-200:])

@app.route("/api/water", methods=["POST"])
@require_login
def add_water_log():
    data = request.get_json(silent=True) or {}
    tracker_id = str(data.get("tracker_id", "")).strip()
    leader = str(data.get("leader", "")).strip()[:60]
    comments = str(data.get("comments", "")).strip()[:500]

    valid = {t["id"]: t["name"] for t in public_trackers()}
    if tracker_id not in valid:
        return jsonify(error="Unknown tracker"), 400
    if not leader:
        return jsonify(error="Leader name is required"), 400

    entry = {
        "id": secrets.token_hex(8),
        "tracker_id": tracker_id,
        "tracker_name": valid[tracker_id],
        "leader": leader,
        "comments": comments,
        "time": datetime.now(timezone.utc).isoformat(),
    }
    water_log.append(entry)
    if len(water_log) > 1000:
        del water_log[:-1000]
    return jsonify(entry), 201

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


# COMPASS v15 shared-data foundation.
# On Render set DATA_DIR=/var/data after attaching a persistent disk at /var/data.
DATA_DIR=os.environ.get("DATA_DIR","/tmp/compass-data")
os.makedirs(DATA_DIR,exist_ok=True)
DB_PATH=os.path.join(DATA_DIR,"compass.db")

def compass_db():
    c=sqlite3.connect(DB_PATH,timeout=10)
    c.row_factory=sqlite3.Row
    return c

def init_compass_db():
    with compass_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS group_details(
          tracker_id TEXT PRIMARY KEY, leader_name TEXT DEFAULT '',
          leader_phone TEXT DEFAULT '', candidate_names TEXT DEFAULT '',
          updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS notes(
          id INTEGER PRIMARY KEY AUTOINCREMENT, tracker_id TEXT NOT NULL,
          candidate_name TEXT DEFAULT '', status TEXT DEFAULT 'OK',
          note TEXT NOT NULL, leader TEXT DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS finish_log(
          tracker_id TEXT PRIMARY KEY, arrived_at TEXT, confirmed_at TEXT,
          confirmed_by TEXT DEFAULT '', status TEXT DEFAULT 'OUT');
        CREATE TABLE IF NOT EXISTS speed_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT, tracker_id TEXT NOT NULL,
          recorded_at TEXT NOT NULL, speed_kmh REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS water_log_v15(
          id INTEGER PRIMARY KEY AUTOINCREMENT, tracker_id TEXT NOT NULL,
          leader TEXT NOT NULL, comments TEXT DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS gpx_routes(
          tracker_id TEXT PRIMARY KEY,
          filename TEXT NOT NULL,
          points_json TEXT NOT NULL,
          distance_km REAL NOT NULL,
          uploaded_at TEXT NOT NULL);
        """)
init_compass_db()

def init_compass_state():
    with compass_db() as db:
        db.execute("CREATE TABLE IF NOT EXISTS compass_state(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
init_compass_state()

def compass_day_start():
    with compass_db() as db:
        row=db.execute("SELECT value FROM compass_state WHERE key='day_start'").fetchone()
        if row and row["value"]: return row["value"]
        now=datetime.now(timezone.utc).isoformat()
        db.execute("INSERT OR REPLACE INTO compass_state(key,value) VALUES('day_start',?)",(now,))
        return now

@app.route("/api/day")
@require_login
def api_day():
    return jsonify({"day_start":compass_day_start()})


# ---------------------------------------------------------------------------
# COMPASS v15.4 central SPOT cache
# One Render worker talks to SPOT at the safe interval; every leader reads the
# same shared snapshot. The latest successful snapshot is also persisted to
# /var/data, so a deploy/restart does not force every phone to wait for all feeds.
# ---------------------------------------------------------------------------
SPOT_SNAPSHOT_PATH = os.path.join(DATA_DIR, "spot_snapshot.json")
SPOT_REFRESH_SECONDS = 150
SPOT_REQUEST_GAP_SECONDS = 2.2
spot_snapshot_lock = threading.Lock()
spot_poller_start_lock = threading.Lock()
spot_poller_started = False

def load_spot_snapshot():
    try:
        with open(SPOT_SNAPSHOT_PATH, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}

spot_snapshot = load_spot_snapshot()

def save_spot_snapshot():
    try:
        tmp = SPOT_SNAPSHOT_PATH + f".{os.getpid()}.tmp"
        with spot_snapshot_lock:
            payload = json.dumps(spot_snapshot, separators=(",", ":"))
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp, SPOT_SNAPSHOT_PATH)
    except Exception:
        pass

def poll_spot_tracker(t):
    feed = t["feed"]
    url = f"https://api.findmespot.com/spot-main-web/consumer/rest-api/2.0/public/feed/{feed}/message.json"
    try:
        r = requests.get(
            url,
            headers={"Accept": "application/json", "User-Agent": "COMPASS/16.1"},
            timeout=20,
        )
        if r.status_code != 200:
            raise RuntimeError(f"SPOT HTTP {r.status_code}")
        data = r.json()
        item = {
            "data": data,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "error": None,
        }
        # Keep the legacy cache warm too, so diagnostic/manual calls benefit.
        spot_cache[feed] = {"time": time.time(), "data": data}
    except Exception as exc:
        # Never throw away the last known good data if a single poll fails.
        with spot_snapshot_lock:
            previous = spot_snapshot.get(t["id"], {})
        item = dict(previous) if isinstance(previous, dict) else {}
        item["error"] = str(exc)[:250]
        item["last_error_at"] = datetime.now(timezone.utc).isoformat()

    with spot_snapshot_lock:
        spot_snapshot[t["id"]] = item
    save_spot_snapshot()

def spot_poller_loop():
    while True:
        cycle_started = time.time()
        ts = parse_trackers()
        for idx, t in enumerate(ts):
            poll_spot_tracker(t)
            if idx < len(ts) - 1:
                time.sleep(SPOT_REQUEST_GAP_SECONDS)
        elapsed = time.time() - cycle_started
        time.sleep(max(5, SPOT_REFRESH_SECONDS - elapsed))

def ensure_spot_poller():
    global spot_poller_started
    if spot_poller_started:
        return
    with spot_poller_start_lock:
        if spot_poller_started:
            return
        spot_poller_started = True
        threading.Thread(target=spot_poller_loop, name="compass-spot-poller", daemon=True).start()

@app.route("/api/snapshot")
@require_login
def compass_snapshot():
    ensure_spot_poller()
    valid_ids = {t["id"] for t in public_trackers()}
    with spot_snapshot_lock:
        items = {k: v for k, v in spot_snapshot.items() if k in valid_ids}
    return jsonify({
        "trackers": items,
        "server_time": datetime.now(timezone.utc).isoformat(),
        "refresh_seconds": SPOT_REFRESH_SECONDS,
    })

def compass_tracker_ok(tid):
    return any(t.get("id")==tid for t in public_trackers())

@app.route("/api/group-details",methods=["GET","POST"])
@require_login
def compass_group_details():
    if request.method=="GET":
        with compass_db() as db: rows=db.execute("SELECT * FROM group_details").fetchall()
        return jsonify([dict(x) for x in rows])
    d=request.get_json(silent=True) or {}; tid=str(d.get("tracker_id",""))
    if not compass_tracker_ok(tid): return jsonify({"error":"Unknown tracker"}),400
    now=datetime.now(timezone.utc).isoformat()
    with compass_db() as db:
        db.execute("""INSERT INTO group_details VALUES(?,?,?,?,?)
        ON CONFLICT(tracker_id) DO UPDATE SET leader_name=excluded.leader_name,
        leader_phone=excluded.leader_phone,candidate_names=excluded.candidate_names,
        updated_at=excluded.updated_at""",(tid,str(d.get("leader_name",""))[:80],
        str(d.get("leader_phone",""))[:40],str(d.get("candidate_names",""))[:1500],now))
    return jsonify({"ok":True})

@app.route("/api/notes",methods=["GET","POST"])
@require_login
def compass_notes():
    if request.method=="GET":
        tid=request.args.get("tracker_id","")
        with compass_db() as db:
            rows=db.execute("SELECT * FROM notes WHERE tracker_id=? ORDER BY created_at DESC LIMIT 200",(tid,)).fetchall()
        return jsonify([dict(x) for x in rows])
    d=request.get_json(silent=True) or {}; tid=str(d.get("tracker_id",""))
    if not compass_tracker_ok(tid): return jsonify({"error":"Unknown tracker"}),400
    note=str(d.get("note","")).strip()[:1000]
    if not note:return jsonify({"error":"Note required"}),400
    status=str(d.get("status","OK"))
    if status not in ("OK","Keep an eye on","Needs attention"):status="OK"
    now=datetime.now(timezone.utc).isoformat()
    with compass_db() as db:
        db.execute("INSERT INTO notes(tracker_id,candidate_name,status,note,leader,created_at) VALUES(?,?,?,?,?,?)",
        (tid,str(d.get("candidate_name",""))[:80],status,note,str(d.get("leader",""))[:80],now))
    return jsonify({"ok":True,"created_at":now})

@app.route("/api/finish",methods=["GET","POST"])
@require_login
def compass_finish():
    if request.method=="GET":
        with compass_db() as db:rows=db.execute("SELECT * FROM finish_log").fetchall()
        return jsonify([dict(x) for x in rows])
    d=request.get_json(silent=True) or {}
    action=str(d.get("action","confirm"))
    if action=="new_day":
        now=datetime.now(timezone.utc).isoformat()
        with compass_db() as db:
            db.execute("""UPDATE finish_log
                          SET status='OUT',arrived_at=NULL,confirmed_at=NULL,confirmed_by=''""")
            db.execute("INSERT OR REPLACE INTO compass_state(key,value) VALUES('day_start',?)",(now,))
        return jsonify({"ok":True,"reset":"all","day_start":now})
    tid=str(d.get("tracker_id",""))
    if not compass_tracker_ok(tid):return jsonify({"error":"Unknown tracker"}),400
    now=datetime.now(timezone.utc).isoformat()
    with compass_db() as db:
        if action=="out":
            db.execute("""INSERT INTO finish_log(tracker_id,status) VALUES(?,'OUT')
            ON CONFLICT(tracker_id) DO UPDATE SET status='OUT',arrived_at=NULL,confirmed_at=NULL,confirmed_by=''""",(tid,))
        elif action=="arrived":
            at=str(d.get("arrived_at") or now)
            db.execute("""INSERT INTO finish_log(tracker_id,arrived_at,status) VALUES(?,?,'ARRIVED')
            ON CONFLICT(tracker_id) DO UPDATE SET arrived_at=COALESCE(finish_log.arrived_at,excluded.arrived_at),
            status=CASE WHEN finish_log.status='FINISHED' THEN 'FINISHED' ELSE 'ARRIVED' END""",(tid,at))
        else:
            db.execute("""INSERT INTO finish_log(tracker_id,arrived_at,confirmed_at,confirmed_by,status)
            VALUES(?,?,?,?,'FINISHED') ON CONFLICT(tracker_id) DO UPDATE SET
            arrived_at=COALESCE(finish_log.arrived_at,excluded.arrived_at),
            confirmed_at=excluded.confirmed_at,confirmed_by=excluded.confirmed_by,status='FINISHED'""",
            (tid,str(d.get("arrived_at") or now),now,str(d.get("leader",""))[:80]))
    return jsonify({"ok":True})

@app.route("/api/speed-log",methods=["GET","POST"])
@require_login
def compass_speed_log():
    if request.method=="GET":
        tid=request.args.get("tracker_id","")
        with compass_db() as db:rows=db.execute("SELECT * FROM speed_log WHERE tracker_id=? ORDER BY recorded_at",(tid,)).fetchall()
        return jsonify([dict(x) for x in rows])
    d=request.get_json(silent=True) or {};tid=str(d.get("tracker_id",""))
    if not compass_tracker_ok(tid):return jsonify({"error":"Unknown tracker"}),400
    try:speed=float(d.get("speed_kmh"))
    except:return jsonify({"error":"Invalid speed"}),400
    now=datetime.now(timezone.utc).isoformat()
    with compass_db() as db:
        last=db.execute("SELECT recorded_at FROM speed_log WHERE tracker_id=? ORDER BY recorded_at DESC LIMIT 1",(tid,)).fetchone()
        if last:
            try:
                if (datetime.now(timezone.utc)-datetime.fromisoformat(last["recorded_at"])).total_seconds()<1500:
                    return jsonify({"ok":True,"recorded":False})
            except:pass
        db.execute("INSERT INTO speed_log VALUES(NULL,?,?,?)",(tid,now,speed))
    return jsonify({"ok":True,"recorded":True})


def _gpx_haversine_km(a, b):
    r = 6371.0
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat, dlon = lat2-lat1, lon2-lon1
    q = math.sin(dlat/2)**2 + math.cos(lat1)*math.cos(lat2)*math.sin(dlon/2)**2
    return 2*r*math.asin(math.sqrt(q))

def _parse_gpx_text(text):
    if not isinstance(text, str) or not text.strip():
        raise ValueError("GPX file is empty.")
    if len(text.encode("utf-8", errors="ignore")) > 2_000_000:
        raise ValueError("GPX file is too large (2 MB maximum).")
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise ValueError("This GPX file contains unsupported XML declarations.")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("Could not read that GPX file.") from exc

    def lname(tag): return tag.rsplit("}", 1)[-1].lower()
    trk, rte = [], []
    for el in root.iter():
        n=lname(el.tag)
        if n not in ("trkpt","rtept"): continue
        try:
            lat=float(el.attrib.get("lat")); lon=float(el.attrib.get("lon"))
        except (TypeError,ValueError):
            continue
        if -90<=lat<=90 and -180<=lon<=180:
            (trk if n=="trkpt" else rte).append([lat,lon])
    points=trk if len(trk)>=2 else rte
    if len(points)<2: raise ValueError("No usable GPX track/route points were found.")
    if len(points)>10000: raise ValueError("GPX route has too many points (10,000 maximum).")
    if len(points)>3000:
        step=math.ceil(len(points)/3000)
        slim=points[::step]
        if slim[-1]!=points[-1]: slim.append(points[-1])
        points=slim
    distance=sum(_gpx_haversine_km(points[i-1],points[i]) for i in range(1,len(points)))
    return points,distance

@app.route("/api/gpx-routes", methods=["GET","POST","DELETE"])
@require_login
def compass_gpx_routes():
    if request.method=="GET":
        with compass_db() as db:
            rows=db.execute("SELECT tracker_id,filename,points_json,distance_km,uploaded_at FROM gpx_routes").fetchall()
        out=[]
        for row in rows:
            try: pts=json.loads(row["points_json"])
            except Exception: pts=[]
            out.append({"tracker_id":row["tracker_id"],"filename":row["filename"],"points":pts,
                        "distance_km":row["distance_km"],"uploaded_at":row["uploaded_at"]})
        return jsonify(out)

    d=request.get_json(silent=True) or {}
    tid=str(d.get("tracker_id","")).strip()
    if not compass_tracker_ok(tid): return jsonify({"error":"Unknown tracker"}),400

    if request.method=="DELETE":
        with compass_db() as db: db.execute("DELETE FROM gpx_routes WHERE tracker_id=?",(tid,))
        return jsonify({"ok":True})

    filename=os.path.basename(str(d.get("filename","route.gpx")))[:120] or "route.gpx"
    try: points,distance=_parse_gpx_text(d.get("gpx_text",""))
    except ValueError as exc: return jsonify({"error":str(exc)}),400
    now=datetime.now(timezone.utc).isoformat()
    with compass_db() as db:
        db.execute("""INSERT INTO gpx_routes(tracker_id,filename,points_json,distance_km,uploaded_at)
                      VALUES(?,?,?,?,?)
                      ON CONFLICT(tracker_id) DO UPDATE SET filename=excluded.filename,
                      points_json=excluded.points_json,distance_km=excluded.distance_km,
                      uploaded_at=excluded.uploaded_at""",
                   (tid,filename,json.dumps(points,separators=(",",":")),distance,now))
    return jsonify({"ok":True,"tracker_id":tid,"filename":filename,"points":points,
                    "distance_km":distance,"uploaded_at":now})


APP_HTML = '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">\n<meta name="theme-color" content="#17202a">\n<title>Burton DofE Live Tracker</title>\n<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">\n<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>\n<script src="https://cdnjs.cloudflare.com/ajax/libs/proj4js/2.11.0/proj4.js"></script>\n<script src="https://unpkg.com/proj4leaflet@1.0.2/src/proj4leaflet.js"></script>\n<style>\n*{box-sizing:border-box}\nhtml,body{margin:0;height:100%;font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#222}\nheader{min-height:58px;background:#17202a;color:#fff;padding:9px 12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}\nh1{font-size:17px;margin:0;flex:1}\n\n.menu-wrap{margin-left:auto;position:relative}\n.menu-btn{padding:8px 12px;font-weight:800;white-space:nowrap}\n.main-menu{\n  display:none;position:absolute;right:0;top:calc(100% + 7px);z-index:5000;\n  min-width:210px;max-height:min(72vh,620px);overflow-y:auto;\n  background:#fff;color:#17202a;border:1px solid #d7dce1;border-radius:10px;\n  box-shadow:0 8px 28px #0005;padding:7px\n}\n.main-menu.show{display:block}\n.main-menu button{\n  display:block;width:100%;text-align:left;margin:0;padding:10px 11px;\n  border:0;border-radius:7px;background:#fff;color:#17202a\n}\n.main-menu button:hover{background:#f1f4f6}\n.main-menu button.primary{background:#176b3a;color:#fff}\n.main-menu button.primary:hover{background:#135d32}\n.menu-sep{height:1px;background:#e1e5e8;margin:6px 3px}\n\nbutton{padding:8px 10px;border:0;border-radius:7px;font:inherit;cursor:pointer}\nbutton:disabled{opacity:.5;cursor:not-allowed}\n.primary{background:#17202a;color:#fff;font-weight:700}\n.alert-on{background:#19743b;color:#fff;font-weight:700}\nmain{display:grid;grid-template-columns:340px 1fr;height:calc(100% - 58px)}\naside{overflow:auto;padding:10px;border-right:1px solid #ddd;background:#fff}\n#map{height:100%;width:100%;background:#ddd}\n.card{border:1px solid #ddd;border-radius:10px;padding:10px;margin-bottom:8px}\n.tracker-card{cursor:pointer}\n.tracker-card:hover{border-color:#888}\n.head{display:flex;justify-content:space-between;gap:8px}\n.name{font-weight:800}\n.muted{font-size:12px;color:#666}\n.good{color:#167c31;font-weight:700}\n.warn{color:#a76300;font-weight:700}\n.bad{color:#a40000;font-weight:700}\n.marker-label{background:#17202a;color:#fff;border:0;border-radius:5px;font-weight:700}\n.cp-label{background:#fff;color:#17202a;border:1px solid #17202a;border-radius:5px;font-weight:700}\n.summary{font-weight:700;margin-bottom:8px}\n.modal{display:none;position:fixed;inset:0;background:#0009;z-index:3000;align-items:center;justify-content:center;padding:15px}\n.modal.show{display:flex}\n.panel{background:#fff;width:min(560px,96vw);max-height:90vh;overflow:auto;border-radius:14px;padding:18px;box-shadow:0 10px 50px #0007}\n.panel h2{margin:0 0 5px}\n.choice{display:flex;align-items:center;gap:11px;border:1px solid #ddd;border-radius:10px;padding:12px;margin:8px 0;cursor:pointer}\n.choice input{width:20px;height:20px;flex:0 0 auto}\n.choice span{font-weight:700}\n.actions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;margin-top:15px}\n.empty{text-align:center;padding:16px 8px}\n.formrow{margin:12px 0}\n.formrow label{display:block;font-weight:700;margin-bottom:5px}\n.formrow input,.formrow select{width:100%;padding:10px;border:1px solid #aaa;border-radius:8px;font:inherit}\n.cpitem{border:1px solid #ddd;border-radius:10px;padding:10px;margin:8px 0}\n.cphead{display:flex;justify-content:space-between;gap:8px;align-items:flex-start}\n.cpbuttons{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}\n.cpbuttons button{padding:6px 8px}\n.banner{display:none;position:fixed;z-index:4500;left:50%;top:18px;transform:translateX(-50%);width:min(650px,94vw);background:#fff;border:4px solid #c03221;border-radius:14px;padding:16px;box-shadow:0 8px 35px #0008}\n.banner.show{display:block}\n.banner.help{border-width:6px;background:#fff8f7}\n.banner h2{margin:0 0 5px;color:#a40000}\n.banner .big{font-size:20px;font-weight:800}\n.banner.help .big{font-size:24px;color:#a40000}\n.placing{position:fixed;z-index:2500;left:50%;top:70px;transform:translateX(-50%);background:#17202a;color:#fff;padding:10px 14px;border-radius:10px;box-shadow:0 4px 18px #0006;font-weight:700;display:none}\n.placing.show{display:block}\n.monitor-note{font-size:11px;color:#555;margin-top:4px}\n@media(max-width:760px){\nheader h1{font-size:1rem;line-height:1.15;margin:0;flex:1;min-width:0}\nheader h1 span{display:inline-block;margin-top:2px}\n.menu-wrap{flex:0 0 auto}\n.menu-btn{padding:7px 10px}\n.main-menu{position:fixed;right:8px;top:58px;left:8px;max-height:calc(100vh - 70px);min-width:0}\n\nheader{min-height:54px;padding:8px 10px;flex-wrap:nowrap}\nmain{display:block;height:calc(100% - 54px);position:relative}\n#map{height:100%}\naside{position:absolute;z-index:1000;left:8px;right:8px;bottom:8px;max-height:42%;border:0;border-radius:12px;box-shadow:0 4px 20px #0005;padding:8px}\n.card{padding:8px;margin-bottom:6px}\n\n.banner{top:8px}\n.placing{top:62px;width:92%;text-align:center}\n}\n\n.gpx-good{color:#147a37;font-weight:800}.gpx-warn{color:#9a6700;font-weight:800}.gpx-bad{color:#b42318;font-weight:800}\n.gpx-route-row{border:1px solid #ddd;border-radius:8px;padding:8px;margin:6px 0}\n</style>\n<style>\n.cc-big{font-size:1.5rem;font-weight:800;margin:8px 0}\n.cc-section{margin-top:14px}\n.cc-row{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;padding:9px 0;border-bottom:1px solid #ddd}\n.cc-actions{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}\n.cc-arrived{background:#fff8df;padding:8px;border-radius:8px}\n.cc-finished{opacity:.7}\n.note-item{padding:8px 0;border-bottom:1px solid #ddd}\n</style><style>\n.report-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:10px 0}\n.report-stat{background:#f4f4f4;border-radius:8px;padding:9px}\n.report-stat b{display:block;font-size:1.15rem}\n#speedCanvas{width:100%;height:230px;background:#fff;border:1px solid #ddd;border-radius:8px}\n.photo-preview{max-width:100%;max-height:48vh;border-radius:10px;margin-top:10px;display:none}\n@media(max-width:600px){.report-grid{grid-template-columns:1fr 1fr}}\n</style></head>\n<body>\n<header>\n<h1>Burton DofE - Live Tracking <span style="font-size:.72rem;font-weight:700;background:#176b3a;color:#fff;padding:3px 7px;border-radius:10px;vertical-align:middle">COMPASS v16.1</span></h1>\n<div class="menu-wrap">\n<button id="menuBtn" class="menu-btn" onclick="toggleMainMenu()" aria-expanded="false">☰ Menu</button>\n<div id="mainMenu" class="main-menu">\n<button onclick="closeMainMenu();refreshAll(true)">Refresh</button>\n<button onclick="closeMainMenu();openMyGroups()">My Groups</button>\n<button id="prepareMapsBtn" onclick="closeMainMenu();prepareMaps()">Prepare Maps</button>\n<button id="baseBtn" onclick="closeMainMenu();baseButton()" title="Return to saved Base">Base</button>\n<button onclick="closeMainMenu();setBaseButton()" title="Set Base at the centre of the map">Set Base</button>\n<button onclick="closeMainMenu();clearBase()" title="Delete the saved Base">Delete Base</button>\n<button onclick="closeMainMenu();openCheckpoints()">Checkpoints</button>\n<button onclick="closeMainMenu();openGPXRoutes()">GPX Routes</button>\n<button id="alertsBtn" onclick="closeMainMenu();enableAlerts()">Enable Alerts</button>\n<button id="locBtn" onclick="closeMainMenu();toggleMyLocation()">My Location</button>\n<button onclick="closeMainMenu();openSpotDiagnostic()">SPOT Diagnostic</button>\n<button class="primary" onclick="closeMainMenu();openControlCentre()">Control Centre</button>\n<div class="menu-sep"></div>\n<button onclick="location.href=\'/logout\'">Log out</button>\n</div>\n</div>\n</header>\n\n<main>\n<aside>\n<div id="selectionSummary" class="summary"></div>\n<div id="trackerList"></div>\n<div class="card muted">\nTap a group to centre the map. Tap anywhere on the OS map for a 6-figure grid reference.\n<div class="monitor-note"><b>Safety monitoring:</b> COMPASS centrally refreshes all configured SPOT feeds and every logged-in leader reads the same shared snapshot. HELP monitoring does not depend on My Groups.</div><div class="monitor-note"><b>Map speed:</b> OS map tiles are cached on COMPASS. Use <b>Prepare Maps</b> while on good Wi-Fi/Starlink to warm the current area before heading out.</div>\n<div class="monitor-note"><b>My Location:</b> uses this device GPS and displays it only in your browser; it is not added to the SPOT tracker list.</div>\n</div>\n</aside>\n<div id="map"></div><div id="gridRefReadout" style="display:none;position:absolute;z-index:1000;left:50%;transform:translateX(-50%);bottom:18px;background:rgba(255,255,255,.96);border:1px solid #bbb;border-radius:8px;padding:8px 10px;box-shadow:0 2px 8px rgba(0,0,0,.18);font-size:.95rem"></div>\n</main>\n\n<div id="groupsModal" class="modal">\n<div class="panel">\n<h2>My Groups</h2>\n<p class="muted">Tick the groups you want to see on the map. HELP alerts are monitored for every configured tracker.</p>\n<div id="groupChoices"></div>\n<div class="actions">\n<button onclick="selectAllGroups()">Select all</button>\n<button onclick="clearAllGroups()">Clear</button>\n<button class="primary" onclick="saveMyGroups()">Save</button>\n</div>\n</div>\n</div>\n\n\n<div id="gpxModal" class="modal">\n<div class="panel">\n<h2>GPX Routes</h2>\n<p class="muted">Upload the planned route for a group. Routes are shared between leaders and saved on COMPASS.</p>\n<div class="formrow"><label for="gpxGroup">Group</label><select id="gpxGroup"></select></div>\n<div class="formrow"><label for="gpxFile">GPX file</label><input id="gpxFile" type="file" accept=".gpx,application/gpx+xml,application/xml,text/xml"></div>\n<div class="actions"><button class="primary" onclick="uploadGPXRoute()">Upload / Replace Route</button><button onclick="closeGPXRoutes()">Close</button></div>\n<hr><div id="gpxRouteList"></div>\n<div class="muted" style="margin-top:10px">ETA uses recent progress along the planned route, including stationary/rest time. Treat it as an operational estimate rather than a guaranteed arrival time.</div>\n</div>\n</div>\n\n<div id="checkpointModal" class="modal">\n<div class="panel">\n<h2>Checkpoints</h2>\n<p class="muted">Create a point on the map and choose which group it applies to. A group with an active checkpoint is monitored even if you untick it from My Groups.</p>\n<div id="checkpointList"></div>\n<hr>\n<h3>Add checkpoint</h3>\n<div class="formrow">\n<label for="cpName">Name</label>\n<input id="cpName" maxlength="50" placeholder="e.g. Road Crossing or CP3">\n</div>\n<div class="formrow">\n<label for="cpGroup">Group</label>\n<select id="cpGroup"></select>\n</div>\n<div class="formrow">\n<label><input type="checkbox" id="cpFinish"> Control Centre finish point</label>\n<div class="muted">Reaching this point records the group\'s arrival time in Control Centre.</div>\n</div>\n<div class="formrow">\n<label for="cpRadius">Alert radius</label>\n<select id="cpRadius">\n<option value="100">100 metres</option>\n<option value="200">200 metres</option>\n<option value="250" selected>250 metres</option>\n<option value="300">300 metres</option>\n<option value="500">500 metres</option>\n</select>\n</div>\n<div class="actions">\n<button onclick="closeCheckpointModal()">Close</button>\n<button class="primary" onclick="beginPlaceCheckpoint()">Place on map</button>\n</div>\n</div>\n</div>\n\n<div id="alertBanner" class="banner">\n<h2 id="alertTitle">CHECKPOINT REACHED</h2>\n<div id="alertText" class="big"></div>\n<div id="alertGrid" style="margin-top:7px"></div>\n<div class="actions">\n<button class="primary" onclick="ackAlert()">Acknowledge</button>\n</div>\n</div>\n\n\n<div id="waterModal" class="modal">\n<div class="panel">\n<h2 id="waterTitle">Water top-up</h2>\n<p class="muted">Record when this group has been topped up with water.</p>\n<input type="hidden" id="waterTracker">\n<div class="formrow"><label for="waterLeader">Who topped them up?</label><input id="waterLeader" maxlength="60" placeholder="Leader name"></div>\n<div class="formrow"><label for="waterComments">Comments (optional)</label><textarea id="waterComments" maxlength="500" rows="4" style="width:100%;padding:10px;border:1px solid #aaa;border-radius:8px;font:inherit" placeholder="e.g. Everyone topped up - group in good spirits"></textarea></div>\n<div id="waterHistory" class="formrow"></div>\n<div class="actions"><button onclick="closeWater()">Cancel</button><button class="primary" onclick="saveWater()">Save water top-up</button></div>\n</div>\n</div>\n\n\n<div id="diagModal" class="modal">\n<div class="panel">\n<h2>SPOT Diagnostic</h2>\n<p class="muted">Select a tracker and COMPASS will ask SPOT directly what that feed is returning. The feed ID remains hidden.</p>\n<div class="formrow"><label for="diagTracker">Tracker</label><select id="diagTracker"></select></div>\n<div id="diagResult" class="card muted">Choose a tracker and press Run Diagnostic.</div>\n<div class="actions"><button onclick="closeSpotDiagnostic()">Close</button><button class="primary" onclick="runSpotDiagnostic()">Run Diagnostic</button></div>\n</div>\n</div>\n\n\n\n<div id="ccModal" class="modal">\n<div class="panel">\n<div style="display:flex;align-items:center;gap:8px;justify-content:space-between;flex-wrap:wrap">\n<h2 style="margin:0">Control Centre</h2>\n<div class="actions" style="margin:0">\n<button onclick="startNewDay()">Start New Day</button>\n<button onclick="closeControlCentre()">Close</button>\n</div>\n</div>\n<div id="ccOutCount" class="cc-big" style="margin-top:12px">Loading…</div>\n<div id="ccArrivedCount" class="muted"></div>\n<div class="cc-section"><h3>Groups still out</h3><div id="ccOutList"></div></div>\n<div class="cc-section"><h3>Arrived - confirm finished</h3><div id="ccArrivedList"></div></div>\n<div class="cc-section"><h3>Finished today</h3><div id="ccFinishedList"></div></div>\n<div class="actions"><button onclick="closeControlCentre()">Close</button></div>\n</div>\n</div>\n\n<div id="groupDetailsModal" class="modal">\n<div class="panel">\n<h2 id="gdTitle">Group Details</h2>\n<div class="formrow"><label>Leader name</label><input id="gdLeader" maxlength="80"></div>\n<div class="formrow"><label>Telephone</label><input id="gdPhone" type="tel" maxlength="40"></div>\n<div class="formrow"><label>Candidate first names</label><textarea id="gdCandidates" rows="3" maxlength="1500" placeholder="First names only, separated by commas"></textarea></div>\n<div class="actions"><button onclick="closeGroupDetails()">Close</button><button class="primary" onclick="saveGroupDetails()">Save details</button></div>\n<hr>\n<h3>Group / Candidate Notes</h3>\n<div class="formrow"><label>Candidate first name (optional)</label><input id="gdCandidate" maxlength="80"></div>\n<div class="formrow"><label>Status</label><select id="gdStatus"><option>OK</option><option>Keep an eye on</option><option>Needs attention</option></select></div>\n<div class="formrow"><label>Leader adding note</label><input id="gdNoteLeader" maxlength="80"></div>\n<div class="formrow"><label>Note</label><textarea id="gdNote" rows="3" maxlength="1000"></textarea></div>\n<button class="primary" onclick="saveGroupNote()">Add note</button>\n<div id="gdNotes"></div>\n</div>\n</div>\n\n\n<div id="speedReportModal" class="modal">\n  <div class="panel">\n    <h2 id="speedReportTitle">Daily Speed Report</h2>\n    <div id="speedReportSummary" class="report-grid"></div>\n    <canvas id="speedCanvas" width="700" height="230"></canvas>\n    <div id="speedReportTable" style="max-height:30vh;overflow:auto;margin-top:10px"></div>\n    <div class="actions">\n      <button onclick="closeSpeedReport()">Close</button>\n      <button class="primary" onclick="shareSpeedReport()">Share Report</button>\n    </div>\n  </div>\n</div>\n\n<div id="photoModal" class="modal">\n  <div class="panel">\n    <h2 id="photoTitle">Group Start Photo</h2>\n    <p class="muted">Take the group photograph, check it, then use Share Photo. On a phone, choose WhatsApp and Karen from the normal share screen.</p>\n    <input id="groupPhotoInput" type="file" accept="image/*" capture="environment">\n    <img id="groupPhotoPreview" class="photo-preview" alt="Group photo preview">\n    <div class="actions">\n      <button onclick="closeGroupPhoto()">Close</button>\n      <button id="sharePhotoBtn" class="primary" onclick="shareGroupPhoto()" disabled>Share Photo</button>\n    </div>\n  </div>\n</div>\n\n<div id="placingMessage" class="placing">Tap the map where you want the checkpoint.</div>\n\n<script>\nproj4.defs("EPSG:27700","+proj=tmerc +lat_0=49 +lon_0=-2 +k=0.9996012717 +x_0=400000 +y_0=-100000 +ellps=airy +towgs84=446.448,-125.157,542.06,0.15,0.247,0.842,-20.489 +units=m +no_defs");\nconst crs=new L.Proj.CRS("EPSG:27700",proj4.defs("EPSG:27700"),{resolutions:[896,448,224,112,56,28,14,7,3.5,1.75],origin:[-238375,1376256]});\nconst map=L.map("map",{crs,center:[53.135,-1.81],zoom:7,minZoom:0,maxZoom:9});\nL.tileLayer("/os/{z}/{x}/{y}.png",{minZoom:0,maxZoom:9,noWrap:true,keepBuffer:4,updateWhenIdle:true,reuseTiles:true,attribution:"Contains OS data © Crown copyright and database rights"}).addTo(map);\n\nlet trackers=[],selectedIds=[],layers={},positions={},lastRefresh=0,clickMarker=null;\nlet waterEntries=[];\nlet checkpoints=[],checkpointLayers={},placingCheckpoint=null,audioCtx=null,alertQueue=[],alertActive=false;\nlet sirenTimer=null,sirenNodes=[];\nlet locationWatchId=null,myLocationMarker=null,myAccuracyCircle=null;\nconst REFRESH_MS=20000;\nconst GROUP_STORAGE_KEY="burtonDofE_myGroups_v12";\nconst CP_STORAGE_KEY="burtonDofE_checkpoints_v13";\nconst HELP_SEEN_KEY="burtonDofE_helpSeen_v14";\n\nconst TRACE_COLOUR_KEY="compass_traceColours_v1531";\nconst TRACE_HOURS=2;\nlet compassDayStart=null;\nlet initialTrackerFitDone=false;\nlet gpxRoutes={},gpxLayers={},gpxModels={};\nlet compassBase=null;\nlet baseMarker=null;\n\nconst TRACE_PALETTE=["#d62728","#1f77b4","#2ca02c","#9467bd","#ff7f0e","#17becf","#e377c2","#8c564b","#bcbd22","#7f7f7f","#003f5c","#665191","#a05195","#d45087","#f95d6a","#ffa600"];\nlet traceColours={};\n\nfunction loadTraceColours(){\n  try{\n    const x=JSON.parse(localStorage.getItem(TRACE_COLOUR_KEY)||"{}");\n    traceColours=x&&typeof x==="object"?x:{};\n  }catch{traceColours={}}\n}\nfunction defaultTraceColour(id){\n  const idx=Math.max(0,trackers.findIndex(t=>t.id===id));\n  return TRACE_PALETTE[idx%TRACE_PALETTE.length];\n}\nfunction traceColour(id){return traceColours[id]||defaultTraceColour(id)}\nfunction saveTraceColours(){localStorage.setItem(TRACE_COLOUR_KEY,JSON.stringify(traceColours))}\nfunction setTraceColour(id,colour){\n  traceColours[id]=colour;\n  saveTraceColours();\n  const t=trackers.find(x=>x.id===id);\n  if(t && positions[id] && !positions[id].error) redrawTrackerTrace(t);\n}\nfunction recentTraceMessages(messages){\n  if(!messages?.length)return [];\n  const cutoff=Math.max(Date.now()-TRACE_HOURS*60*60*1000,compassDayStart?new Date(compassDayStart).getTime():0);\n  return messages.filter(m=>new Date(m.dateTime).getTime()>=cutoff);\n}\nfunction todayMessages(messages){\n  if(!messages?.length)return [];\n  const cutoff=compassDayStart?new Date(compassDayStart).getTime():new Date().setHours(0,0,0,0);\n  return messages.filter(m=>new Date(m.dateTime).getTime()>=cutoff);\n}\nfunction hasTodaySignal(messages){\n  if(!messages?.length)return false;\n  const latest=messages[messages.length-1];\n  const d=new Date(latest.dateTime);\n  const now=new Date();\n  if(Number.isNaN(d.getTime()))return false;\n  return d.getFullYear()===now.getFullYear() &&\n         d.getMonth()===now.getMonth() &&\n         d.getDate()===now.getDate();\n}\nfunction totalDistanceKm(messages){\n  const m=todayMessages(messages);let km=0;\n  for(let i=1;i<m.length;i++){\n    const d=haversineKm(m[i-1],m[i]);\n    if(Number.isFinite(d))km+=d;\n  }\n  return km;\n}\nasync function loadCompassDay(){\n  try{const d=await cjson("/api/day");compassDayStart=d.day_start||null}catch(e){console.warn("Day state",e)}\n}\nfunction redrawTrackerTrace(t){\n  const p=positions[t.id];\n  if(!p || p.error || !selectedIds.includes(t.id))return;\n  const layer=ensureLayer(t.id);layer.clearLayers();\n  if(!p.todaySignal)return;\n  const tm=recentTraceMessages(p.messages);\n  const pts=tm.map(x=>[+x.latitude,+x.longitude]);\n  if(pts.length>1)L.polyline(pts,{weight:4,opacity:.8,color:traceColour(t.id)}).addTo(layer);\n  const lat=p.lat,lon=p.lon,x=p.latest,g=p.grid;\n  L.circleMarker([lat,lon],{\n    bubblingMouseEvents:false,radius:7,weight:3,color:traceColour(t.id),fillColor:traceColour(t.id),fillOpacity:.9\n  }).bindTooltip(t.name,{permanent:true,direction:"top",className:"marker-label",offset:[0,-12]})\n    .bindPopup("<b>"+esc(t.name)+"</b><br>"+localTime(x.dateTime)+"<br><b>"+g+"</b><br>Altitude: "+(x.altitude??"—")+" m<br>Battery: "+(x.batteryState??"—")+"<br>Message: "+esc(latestMessageType(x))+"<br><span class=\'muted\'>Trace: last "+TRACE_HOURS+" hours</span>")\n    .addTo(layer);\n}\n\n\nfunction loadSelection(){try{const x=JSON.parse(localStorage.getItem(GROUP_STORAGE_KEY)||"null");return Array.isArray(x)?x:null}catch{return null}}\nfunction selectedTrackers(){return trackers.filter(t=>selectedIds.includes(t.id))}\nfunction parseMessages(d){\nlet m=d?.response?.feedMessageResponse?.messages?.message??d?.response?.feedMessageResponse?.messages??[];\nif(!Array.isArray(m))m=[m];\nreturn m\n.filter(x=>x&&isFinite(+x.latitude)&&isFinite(+x.longitude)&&+x.latitude!=-99999&&+x.longitude!=-99999)\n.sort((a,b)=>{\n  const ta=Date.parse(a.dateTime)||((+a.unixTime||0)*1000);\n  const tb=Date.parse(b.dateTime)||((+b.unixTime||0)*1000);\n  return ta-tb;\n});\n}\nfunction toBNG(lat,lon){let [e,n]=proj4("EPSG:4326","EPSG:27700",[lon,lat]);return[Math.round(e),Math.round(n)]}\nfunction gridRef(e,n){if(e<0||e>=700000||n<0||n>=1300000)return"Outside BNG";let a=Math.floor(e/100000),b=Math.floor(n/100000),l1=(19-b)-(19-b)%5+Math.floor((a+10)/5),l2=(19-b)*5%25+a%5;if(l1>7)l1++;if(l2>7)l2++;return String.fromCharCode(65+l1)+String.fromCharCode(65+l2)+" "+String(Math.floor((e%100000)/100)).padStart(3,"0")+" "+String(Math.floor((n%100000)/100)).padStart(3,"0")}\nfunction localTime(s){return new Date(s).toLocaleString("en-GB",{dateStyle:"medium",timeStyle:"short",timeZone:"Europe/London"})}\nfunction statusInfo(s){let a=Math.max(0,(Date.now()-new Date(s).getTime())/60000);return a>30?{cls:"bad",text:"Stale"}:a>15?{cls:"warn",text:"Delayed"}:{cls:"good",text:"Current"}}\nfunction ensureLayer(k){if(!layers[k])layers[k]=L.layerGroup().addTo(map);return layers[k]}\nfunction removeUnselectedLayers(){Object.keys(layers).forEach(id=>{if(!selectedIds.includes(id)){map.removeLayer(layers[id]);delete layers[id]}})}\nfunction trackerName(id){return trackers.find(t=>t.id===id)?.name||"Unknown group"}\nfunction esc(s){return String(s).replace(/[&<>"\']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",\'"\':"&quot;","\'":"&#039;"}[c]))}\n\nfunction loadCheckpoints(){try{const x=JSON.parse(localStorage.getItem(CP_STORAGE_KEY)||"[]");checkpoints=Array.isArray(x)?x:[]}catch{checkpoints=[]}}\nfunction saveCheckpoints(){localStorage.setItem(CP_STORAGE_KEY,JSON.stringify(checkpoints))}\nfunction relevantGroupIds(cp){if(cp.groupId==="*")return trackers.map(t=>t.id);return[cp.groupId]}\nfunction cpStatus(cp){\nconst ids=relevantGroupIds(cp);\nif(!ids.length)return"Waiting";\nconst passed=ids.filter(id=>cp.passed&&cp.passed[id]);\nif(!passed.length)return"Waiting";\nif(passed.length===ids.length)return"Passed";\nreturn passed.length+" of "+ids.length+" passed";\n}\nfunction renderCheckpointLayers(){\nObject.values(checkpointLayers).forEach(x=>map.removeLayer(x.group));\ncheckpointLayers={};\ncheckpoints.forEach(cp=>{\nconst g=L.layerGroup().addTo(map);\nconst circle=L.circle([cp.lat,cp.lon],{radius:cp.radius,weight:2,fillOpacity:.08}).addTo(g);\nconst marker=L.marker([cp.lat,cp.lon],{bubblingMouseEvents:false}).addTo(g);\nmarker.bindTooltip(cp.name,{permanent:false,direction:"top",className:"cp-label"});\nmarker.bindPopup("<b>"+esc(cp.name)+"</b><br>"+esc(cp.groupId==="*"?"All configured groups":trackerName(cp.groupId))+"<br>Radius: "+cp.radius+" m"+(cp.finishPoint?"<br><b>Control Centre finish point</b>":"")+"<br>Status: "+esc(cpStatus(cp)));\ncheckpointLayers[cp.id]={group:g,circle,marker};\n});\n}\n\nfunction latestMessageType(x){return String(x?.messageType||x?.type||x?.messageTypeDescription||"UNKNOWN").trim().toUpperCase()}\nfunction helpEventKey(t,m){return t.id+"|"+String(m.id||m.messageId||m.unixTime||m.dateTime||"")+"|"+latestMessageType(m)}\nfunction getHelpSeen(){try{const x=JSON.parse(localStorage.getItem(HELP_SEEN_KEY)||"[]");return Array.isArray(x)?x:[]}catch{return[]}}\nfunction markHelpSeen(key){\nlet x=getHelpSeen();\nif(!x.includes(key))x.push(key);\nif(x.length>200)x=x.slice(-200);\nlocalStorage.setItem(HELP_SEEN_KEY,JSON.stringify(x));\n}\nfunction hasSeenHelp(key){return getHelpSeen().includes(key)}\n\nfunction checkHelpMessages(t,messages){\nconst cutoff=Date.now()-24*60*60*1000;\nmessages.forEach(m=>{\nif(latestMessageType(m)!=="HELP")return;\nconst tm=new Date(m.dateTime).getTime();\nif(isFinite(tm)&&tm<cutoff)return;\nconst key=helpEventKey(t,m);\nif(hasSeenHelp(key))return;\nmarkHelpSeen(key);\nconst [e,n]=toBNG(+m.latitude,+m.longitude);\nqueueHelpAlert(t,m,gridRef(e,n));\n});\n}\n\nfunction renderTracker(t,d,showOnMap){\nconst m=parseMessages(d);if(!m.length)throw Error("No valid SPOT positions");\nconst x=m.at(-1),lat=+x.latitude,lon=+x.longitude,[e,n]=toBNG(lat,lon),g=gridRef(e,n);\nconst todaySignal=hasTodaySignal(m);\n\nconst layer=ensureLayer(t.id);layer.clearLayers();\nif(showOnMap && todaySignal){\nconst traceMessages=recentTraceMessages(m);\nconst pts=traceMessages.map(x=>[+x.latitude,+x.longitude]);\nif(pts.length>1)L.polyline(pts,{weight:4,opacity:.8,color:traceColour(t.id)}).addTo(layer);\nL.circleMarker([lat,lon],{bubblingMouseEvents:false,radius:7,weight:3,color:traceColour(t.id),fillColor:traceColour(t.id),fillOpacity:.9})\n.bindTooltip(t.name,{permanent:true,direction:"top",className:"marker-label",offset:[0,-12]})\n.bindPopup("<b>"+esc(t.name)+"</b><br>"+localTime(x.dateTime)+"<br><b>"+g+"</b><br>Altitude: "+(x.altitude??"—")+" m<br>Battery: "+(x.batteryState??"—")+"<br>Message: "+esc(latestMessageType(x))+"<br><span class=\'muted\'>Trace: last "+TRACE_HOURS+" hours</span>").addTo(layer);\n}\npositions[t.id]={lat,lon,latest:x,grid:g,count:m.length,messages:m,messageType:latestMessageType(x),todaySignal};\ncheckHelpMessages(t,m);\ncheckCheckpointsForTracker(t,m);\n}\n\nasync function loadTrackers(){\nconst r=await fetch("/api/trackers",{cache:"no-store"});\nif(!r.ok)throw Error("Could not load tracker list");\ntrackers=await r.json();\n}\nasync function loadSnapshot(){\nconst r=await fetch("/api/snapshot",{cache:"no-store"});\nconst snap=await r.json();\nif(!r.ok||snap.error)throw Error(snap.error||("HTTP "+r.status));\nconst rows=snap.trackers||{};\nlet loaded=0;\ntrackers.forEach(t=>{\n  const item=rows[t.id];\n  if(item&&item.data){\n    try{\n      renderTracker(t,item.data,selectedIds.includes(t.id));\n      loaded++;\n    }catch(e){positions[t.id]={error:e.message}}\n  }else if(!positions[t.id]){\n    positions[t.id]={error:"Waiting for first server update…"};\n  }\n});\nreturn loaded;\n}\n\n\n\nasync function loadGPXRoutes(){\n  try{\n    const rows=await cjson("/api/gpx-routes");\n    gpxRoutes={};gpxModels={};\n    rows.forEach(r=>{gpxRoutes[r.tracker_id]=r;gpxModels[r.tracker_id]=buildRouteModel(r)});\n    renderGPXLayers();\n  }catch(e){console.warn("GPX routes:",e)}\n}\nfunction buildRouteModel(route){\n  const pts=(route?.points||[]).map(p=>({lat:+p[0],lon:+p[1]})).filter(p=>Number.isFinite(p.lat)&&Number.isFinite(p.lon));\n  const cum=[0];let total=0;\n  for(let i=1;i<pts.length;i++){\n    total+=haversineKm({latitude:pts[i-1].lat,longitude:pts[i-1].lon},{latitude:pts[i].lat,longitude:pts[i].lon});\n    cum.push(total);\n  }\n  return {pts,cum,total};\n}\nfunction nearestRouteMatch(model,point,minAlong=null,maxAlong=null){\n  if(!model||model.pts.length<2)return null;\n  const plat=+point.latitude,plon=+point.longitude;\n  let best=null,all=[];\n  for(let i=0;i<model.pts.length-1;i++){\n    const a=model.pts[i],b=model.pts[i+1],ref=(plat+a.lat+b.lat)/3*Math.PI/180;\n    const mx=111320*Math.cos(ref),my=110540;\n    const bx=(b.lon-a.lon)*mx,by=(b.lat-a.lat)*my,px=(plon-a.lon)*mx,py=(plat-a.lat)*my;\n    const den=bx*bx+by*by;let t=den?((px*bx+py*by)/den):0;t=Math.max(0,Math.min(1,t));\n    const dist=Math.hypot(px-t*bx,py-t*by),along=model.cum[i]+(model.cum[i+1]-model.cum[i])*t;\n    if(minAlong!==null&&along<minAlong)continue;\n    if(maxAlong!==null&&along>maxAlong)continue;\n    const c={dist,along,segment:i,t};all.push(c);if(!best||dist<best.dist)best=c;\n  }\n  if(minAlong===null&&best){\n    const tied=all.filter(x=>x.dist<=best.dist+30).sort((x,y)=>x.along-y.along);\n    if(tied.length)best=tied[0];\n  }\n  return best;\n}\nfunction matchTrackToRoute(model,messages){\n  const msgs=(messages||[]).slice().sort((a,b)=>new Date(a.dateTime)-new Date(b.dateTime));\n  const out=[];let prev=null,prevMsg=null;\n  for(const m of msgs){\n    let match;\n    if(prev===null)match=nearestRouteMatch(model,m);\n    else{\n      const walked=prevMsg?haversineKm(prevMsg,m):0,maxJump=Math.max(0.8,walked*4+0.4);\n      match=nearestRouteMatch(model,m,Math.max(0,prev-0.15),Math.min(model.total,prev+maxJump));\n      if(!match)match=nearestRouteMatch(model,m);\n      if(match&&match.along<prev-0.25)match={...match,along:prev};\n    }\n    if(match){out.push({message:m,...match});prev=Math.max(prev??0,match.along);prevMsg=m}\n  }\n  return out;\n}\nfunction routeMetrics(t){\n  const route=gpxRoutes[t.id],model=gpxModels[t.id],p=positions[t.id];\n  if(!route||!model||!p||p.error||!p.messages?.length)return null;\n  const today=todayMessages(p.messages);\n  if(!today.length)return {distance:model.total,progress:null,remaining:model.total,currentDeviation:null,avgDeviation:null,eta:null,effectiveSpeed:null,status:"Waiting for today\'s track"};\n  const matched=matchTrackToRoute(model,today);if(!matched.length)return null;\n  const last=matched.at(-1),progress=Math.max(0,Math.min(model.total,last.along)),remaining=Math.max(0,model.total-progress);\n  const dev=matched.slice(-12).map(x=>x.dist).filter(Number.isFinite);\n  const avgDeviation=dev.length?dev.reduce((a,b)=>a+b,0)/dev.length:null,currentDeviation=last.dist;\n  const status=currentDeviation<=100?"ON ROUTE":currentDeviation<=250?"CHECK ROUTE":"OFF ROUTE";\n  const lastMs=new Date(last.message.dateTime).getTime(),cut=lastMs-90*60*1000;\n  const recent=matched.filter(x=>new Date(x.message.dateTime).getTime()>=cut);\n  let effectiveSpeed=null,eta=null;\n  if(recent.length>=2){\n    const first=recent[0],end=recent.at(-1),hrs=(new Date(end.message.dateTime)-new Date(first.message.dateTime))/3600000;\n    if(hrs>=0.20)effectiveSpeed=Math.max(0,end.along-first.along)/hrs;\n    if(effectiveSpeed!==null&&effectiveSpeed>=0.5&&remaining>0)eta=new Date(lastMs+(remaining/effectiveSpeed)*3600000);\n  }\n  return {distance:model.total,progress,remaining,currentDeviation,avgDeviation,eta,effectiveSpeed,status};\n}\nfunction routeMetricHTML(t,compact=false){\n  const m=routeMetrics(t);if(!m)return "";\n  if(m.progress===null)return \'<div class="muted"><b>GPX:</b> \'+m.status+\' · \'+m.distance.toFixed(1)+\' km planned</div>\';\n  const pct=m.distance?Math.min(100,Math.max(0,m.progress/m.distance*100)):0;\n  const cls=m.status==="ON ROUTE"?"gpx-good":m.status==="CHECK ROUTE"?"gpx-warn":"gpx-bad";\n  const eta=m.eta?m.eta.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}):"—";\n  if(compact)return \'<div class="muted"><b>GPX:</b> \'+pct.toFixed(0)+\'% · \'+m.remaining.toFixed(1)+\' km left · ETA \'+eta+\' · <span class="\'+cls+\'">\'+m.status+\'</span></div>\';\n  return \'<div style="margin-top:5px"><b>GPX route:</b> \'+m.progress.toFixed(1)+\' / \'+m.distance.toFixed(1)+\' km (\'+pct.toFixed(0)+\'%)</div>\'+\n    \'<div><b>Route accuracy:</b> <span class="\'+cls+\'">\'+m.status+\'</span> · current \'+Math.round(m.currentDeviation)+\' m\'+(m.avgDeviation!==null?\' · recent avg \'+Math.round(m.avgDeviation)+\' m\':\'\')+\'</div>\'+\n    \'<div><b>Remaining:</b> \'+m.remaining.toFixed(1)+\' km · <b>ETA:</b> \'+eta+(m.effectiveSpeed!==null?\' <span class="muted">(effective \'+m.effectiveSpeed.toFixed(1)+\' km/h incl. rests)</span>\':\'\')+\'</div>\';\n}\nfunction renderGPXLayers(){\n  Object.values(gpxLayers).forEach(l=>{try{map.removeLayer(l)}catch(e){}});\n  gpxLayers={};\n  selectedTrackers().forEach(t=>{\n    const r=gpxRoutes[t.id];if(!r?.points?.length)return;\n    gpxLayers[t.id]=L.polyline(r.points.map(p=>[+p[0],+p[1]]),{color:traceColour(t.id),weight:5,opacity:.55,dashArray:"10 8",interactive:false}).addTo(map);\n  });\n}\nfunction openGPXRoutes(){\n  const sel=document.getElementById("gpxGroup");sel.innerHTML="";\n  trackers.forEach(t=>{const o=document.createElement("option");o.value=t.id;o.textContent=t.name;sel.appendChild(o)});\n  renderGPXRouteList();document.getElementById("gpxModal").classList.add("show");\n}\nfunction closeGPXRoutes(){document.getElementById("gpxModal").classList.remove("show")}\nfunction renderGPXRouteList(){\n  const el=document.getElementById("gpxRouteList"),rows=trackers.filter(t=>gpxRoutes[t.id]);\n  if(!rows.length){el.innerHTML=\'<div class="muted">No GPX routes uploaded yet.</div>\';return}\n  el.innerHTML="";\n  rows.forEach(t=>{\n    const r=gpxRoutes[t.id],d=document.createElement("div");d.className="gpx-route-row";\n    d.innerHTML=\'<b>\'+esc(t.name)+\'</b> · \'+esc(r.filename)+\'<br><span class="muted">\'+(+r.distance_km).toFixed(1)+\' km · \'+(r.points?.length||0)+\' route points</span><br>\';\n    const show=document.createElement("button");show.textContent="Show Route";show.onclick=()=>zoomGPXRoute(t.id);\n    const del=document.createElement("button");del.textContent="Delete Route";del.onclick=()=>deleteGPXRoute(t.id);del.style.marginLeft="6px";\n    d.append(show,del);el.appendChild(d);\n  });\n}\nasync function uploadGPXRoute(){\n  const tid=document.getElementById("gpxGroup").value,file=document.getElementById("gpxFile").files[0];\n  if(!tid){alert("Choose a group.");return} if(!file){alert("Choose a GPX file.");return}\n  if(file.size>2000000){alert("GPX file is too large (2 MB maximum).");return}\n  let text;try{text=await file.text()}catch(e){alert("Could not read that file.");return}\n  try{\n    const r=await cjson("/api/gpx-routes",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tracker_id:tid,filename:file.name,gpx_text:text})});\n    gpxRoutes[tid]=r;gpxModels[tid]=buildRouteModel(r);renderGPXLayers();renderGPXRouteList();renderList();await renderControlCentre();\n    document.getElementById("gpxFile").value="";\n    const t=trackers.find(x=>x.id===tid);alert((t?t.name:"Group")+" route uploaded: "+(+r.distance_km).toFixed(1)+" km.");\n  }catch(e){alert("GPX upload failed: "+e.message)}\n}\nasync function deleteGPXRoute(tid){\n  const t=trackers.find(x=>x.id===tid);if(!confirm("Delete the GPX route for "+(t?t.name:"this group")+"?"))return;\n  try{\n    await cjson("/api/gpx-routes",{method:"DELETE",headers:{"Content-Type":"application/json"},body:JSON.stringify({tracker_id:tid})});\n    delete gpxRoutes[tid];delete gpxModels[tid];if(gpxLayers[tid]){map.removeLayer(gpxLayers[tid]);delete gpxLayers[tid]}\n    renderGPXRouteList();renderList();await renderControlCentre();\n  }catch(e){alert("Could not delete route: "+e.message)}\n}\nfunction zoomGPXRoute(tid){\n  const r=gpxRoutes[tid];if(!r?.points?.length)return;\n  map.fitBounds(r.points.map(p=>[+p[0],+p[1]]),{padding:[35,35],maxZoom:8});\n}\n\nfunction haversineKm(a,b){\nconst R=6371,rad=x=>x*Math.PI/180,dlat=rad(+b.latitude-+a.latitude),dlon=rad(+b.longitude-+a.longitude);\nconst q=Math.sin(dlat/2)**2+Math.cos(rad(+a.latitude))*Math.cos(rad(+b.latitude))*Math.sin(dlon/2)**2;\nreturn 2*R*Math.asin(Math.sqrt(q));\n}\nfunction movementStats(messages){\nif(!messages||messages.length<2)return {speed:null,stationary:null};\nconst latest=messages.at(-1),latestMs=new Date(latest.dateTime).getTime();\nconst cutoff=latestMs-30*60*1000;\nconst recent=messages.filter(m=>new Date(m.dateTime).getTime()>=cutoff);\nlet dist=0;\nfor(let i=1;i<recent.length;i++)dist+=haversineKm(recent[i-1],recent[i]);\nlet speed=null;\nif(recent.length>=2){\nconst hrs=(new Date(recent.at(-1).dateTime)-new Date(recent[0].dateTime))/3600000;\nif(hrs>0)speed=dist/hrs;\n}\nlet stationary=null;\nfor(let i=messages.length-2;i>=0;i--){\nconst d=haversineKm(messages[i],latest)*1000;\nif(d>=100){stationary=(latestMs-new Date(messages[i].dateTime).getTime())/60000;break}\n}\nif(stationary===null&&messages.length>1)stationary=(latestMs-new Date(messages[0].dateTime).getTime())/60000;\nreturn {speed,stationary};\n}\nasync function readJsonResponse(r){\nconst ct=r.headers.get("content-type")||"";\nif(!ct.includes("application/json")){\nawait r.text();\nthrow Error("Water log returned an unexpected server response ("+r.status+").");\n}\nreturn await r.json();\n}\nasync function loadWater(){\ntry{\nconst r=await fetch("/api/water",{cache:"no-store"});\nconst d=await readJsonResponse(r);\nif(!r.ok)throw Error(d.error||"Could not load water history");\nwaterEntries=d;\n}catch(e){console.warn("Water log:",e.message)}\n}\nfunction latestWater(id){return waterEntries.filter(x=>x.tracker_id===id).sort((a,b)=>new Date(a.time)-new Date(b.time)).at(-1)}\nfunction openWater(id){\nconst t=trackers.find(x=>x.id===id);if(!t)return;\ndocument.getElementById("waterTracker").value=id;\ndocument.getElementById("waterTitle").textContent="Water top-up - "+t.name;\ndocument.getElementById("waterComments").value="";\nconst hist=waterEntries.filter(x=>x.tracker_id===id).sort((a,b)=>new Date(b.time)-new Date(a.time)).slice(0,8);\ndocument.getElementById("waterHistory").innerHTML=hist.length?"<b>Recent water history</b><div class=\'muted\' style=\'margin-top:5px\'>"+hist.map(x=>esc(localTime(x.time))+" - "+esc(x.leader)+(x.comments?"<br>"+esc(x.comments):"")).join("<hr>")+"</div>":"<div class=\'muted\'>No water top-ups recorded yet.</div>";\ndocument.getElementById("waterModal").classList.add("show");\n}\nfunction closeWater(){document.getElementById("waterModal").classList.remove("show")}\nasync function saveWater(){\nconst tracker_id=document.getElementById("waterTracker").value;\nconst leader=document.getElementById("waterLeader").value.trim();\nconst comments=document.getElementById("waterComments").value.trim();\nif(!leader){alert("Please enter who topped the group up.");return}\ntry{\nconst r=await fetch("/api/water",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tracker_id,leader,comments})});\nconst d=await readJsonResponse(r);\nif(!r.ok)throw Error(d.error||"Could not save");\nlocalStorage.setItem("burtonDofE_waterLeader_v14",leader);\nawait loadWater();closeWater();renderList();\n}catch(e){alert("Water top-up could not be saved: "+e.message)}\n}\n\nfunction renderList(){\nconst h=document.getElementById("trackerList"),sum=document.getElementById("selectionSummary");\nh.innerHTML="";\nconst chosen=selectedTrackers();\nsum.textContent=trackers.length?(chosen.length?"Showing "+chosen.length+" of "+trackers.length+" groups":"No groups selected"):"";\nif(!trackers.length){h.innerHTML=\'<div class="card"><b>No trackers configured</b><div class="muted">Add the TRACKERS environment variable in Render.</div></div>\';return}\nif(!chosen.length){h.innerHTML=\'<div class="card empty"><b>No groups selected</b><div class="muted" style="margin-top:5px">Tap My Groups and tick the groups you want to see.</div><button class="primary" style="margin-top:10px" onclick="openMyGroups()">Choose my groups</button></div>\';return}\nchosen.forEach(t=>{\ntry{\nconst p=positions[t.id],c=document.createElement("div");c.className="card tracker-card";\nif(!p)c.innerHTML=\'<div class="head"><span class="name">\'+esc(t.name)+\'</span><span class="muted">Loading…</span></div>\';\nelse if(p.error)c.innerHTML=\'<div class="head"><span class="name">\'+esc(t.name)+\'</span><span class="bad">Problem</span></div><div class="muted">\'+esc(p.error)+\'</div>\';\nelse{\nconst finish=compassFinish[t.id]||{};\nconst isFinished=finish.status==="FINISHED";\nconst st=statusInfo(p.latest.dateTime);\nconst mt=p.messageType||"UNKNOWN";\nconst msgCls=mt==="HELP"?"bad":"muted";\nconst ms=movementStats(p.messages),w=latestWater(t.id);\nconst speedText=ms.speed===null?"—":ms.speed.toFixed(1)+" km/h";\nconst todayKm=totalDistanceKm(p.messages);\nconst todaySignal=p.todaySignal===true;\nif(!isFinished && todaySignal && ms.speed!==null) maybeLogSpeedSample(t.id,ms.speed);\nconst stopped=ms.stationary!==null&&ms.stationary>=20;\nconst waterText=w?("<div style=\\"margin-top:5px\\"><b>Water:</b> "+esc(localTime(w.time))+" - "+esc(w.leader)+(w.comments?"<div class=\\"muted\\">"+esc(w.comments)+"</div>":"")+"</div>"):"<div class=\\"muted\\" style=\\"margin-top:5px\\">Water: no top-up recorded</div>";\nif(isFinished){\nconst ft=finish.arrived_at?localTime(finish.arrived_at):"";\nc.style.opacity=".72";\nc.style.background="#f3f5f3";\nc.innerHTML=\'<div class="head"><span class="name">\'+esc(t.name)+\'</span><span class="good"><b>FINISHED ✓</b></span></div><div><b>\'+p.grid+\'</b></div><div class="muted">Last SPOT: \'+localTime(p.latest.dateTime)+\' · Battery \'+(p.latest.batteryState??"—")+\' · Alt \'+(p.latest.altitude??"—")+\' m</div>\'+(ft?\'<div><b>Finished:</b> \'+ft+\'</div>\':\'\')+\'<div><b>Today:</b> \'+todayKm.toFixed(1)+\' km</div>\'+routeMetricHTML(t)+\'<div class="\'+msgCls+\'"><b>SPOT message:</b> \'+esc(mt)+\'</div>\'+waterText+\'<button style="margin-top:7px" onclick="event.stopPropagation();openWater(\\\'\'+t.id+\'\\\')">Water</button> <button style="margin-top:7px" onclick="event.stopPropagation();openGroupDetails(\\\'\'+t.id+\'\\\')">Leader / Notes</button> <button style="margin-top:7px" onclick="event.stopPropagation();openSpeedReport(\\\'\'+t.id+\'\\\')">Speed Report</button>\';\n}else if(!todaySignal){\nc.style.background="#fff8e6";\nc.innerHTML=\'<div class="head"><span class="name">\'+esc(t.name)+\'</span><span class="warn"><b>WAITING FOR TODAY\\\'S SIGNAL</b></span></div><div class="muted"><b>Last poll:</b> \'+localTime(p.latest.dateTime)+\'</div><div><b>Today:</b> 0.0 km</div><div class="muted">This tracker will appear on the map automatically when COMPASS receives its first SPOT message dated today.</div>\'+waterText+\'<button style="margin-top:7px" onclick="event.stopPropagation();openWater(\\\'\'+t.id+\'\\\')">Water</button> <button style="margin-top:7px" onclick="event.stopPropagation();openGroupDetails(\\\'\'+t.id+\'\\\')">Leader / Notes</button>\';\n}else{\nc.innerHTML=\'<div class="head"><span class="name">\'+esc(t.name)+\'</span><span class="\'+st.cls+\'">\'+st.text+\'</span></div><div><b>\'+p.grid+\'</b></div><div class="muted">\'+localTime(p.latest.dateTime)+\' · Battery \'+(p.latest.batteryState??"—")+\' · Alt \'+(p.latest.altitude??"—")+\' m</div><div><b>Avg speed (30 min):</b> \'+speedText+\'</div><div><b>Today:</b> \'+todayKm.toFixed(1)+\' km</div>\'+(stopped?\'<div class="bad">NO MOVEMENT - \'+Math.floor(ms.stationary)+\' mins</div>\':\'\')+\'<div class="\'+msgCls+\'"><b>SPOT message:</b> \'+esc(mt)+\'</div>\'+waterText+\'<button style="margin-top:7px" onclick="event.stopPropagation();openWater(\\\'\'+t.id+\'\\\')">Water</button> <button style="margin-top:7px" onclick="event.stopPropagation();openGroupDetails(\\\'\'+t.id+\'\\\')">Leader / Notes</button> <button style="margin-top:7px" onclick="event.stopPropagation();openSpeedReport(\\\'\'+t.id+\'\\\')">Speed Report</button>\';\n}\nif(todaySignal)c.onclick=()=>map.setView([p.lat,p.lon],8)\n}\nh.appendChild(c);\n}catch(e){\n  console.error("Card render failed for",t.name,e);\n  const c=document.createElement("div");\n  c.className="card tracker-card";\n  c.innerHTML=\'<div class="head"><span class="name">\'+esc(t.name)+\'</span><span class="bad">Card error</span></div><div class="muted">\'+esc(e.message||String(e))+\'</div>\';\n  h.appendChild(c);\n}\n});\n}\n\nfunction sleep(ms){return new Promise(r=>setTimeout(r,ms))}\n\nfunction toggleMainMenu(){\n  const m=document.getElementById("mainMenu"),b=document.getElementById("menuBtn");\n  const open=!m.classList.contains("show");\n  m.classList.toggle("show",open);\n  b.setAttribute("aria-expanded",open?"true":"false");\n}\nfunction closeMainMenu(){\n  const m=document.getElementById("mainMenu"),b=document.getElementById("menuBtn");\n  if(m)m.classList.remove("show");\n  if(b)b.setAttribute("aria-expanded","false");\n}\ndocument.addEventListener("click",e=>{\n  const wrap=e.target.closest(".menu-wrap");\n  if(!wrap)closeMainMenu();\n});\ndocument.addEventListener("keydown",e=>{if(e.key==="Escape")closeMainMenu()});\n\nasync function refreshAll(force=false){\nif(!force&&Date.now()-lastRefresh<REFRESH_MS)return;\nawait loadWater();\ntry{await loadCompassAdmin()}catch(e){console.warn("Control Centre state",e)}\nrenderList();\nif(!trackers.length){lastRefresh=Date.now();return}\n\ntry{await loadSnapshot()}catch(e){console.warn("Tracker snapshot:",e)}\nrenderList();renderCheckpointLayers();lastRefresh=Date.now();\nconst b=selectedTrackers().map(t=>positions[t.id]).filter(p=>p&&!p.error&&p.todaySignal).map(p=>[p.lat,p.lon]);\nif(!initialTrackerFitDone&&b.length){if(b.length===1)map.setView(b[0],8);else map.fitBounds(b,{padding:[35,35],maxZoom:8});initialTrackerFitDone=true;}\n}\n\n\n\nfunction loadBase(){\n  try{\n    const b=JSON.parse(localStorage.getItem("compass_base_v1546")||"null");\n    if(b&&Number.isFinite(+b.lat)&&Number.isFinite(+b.lon)){\n      compassBase={lat:+b.lat,lon:+b.lon,grid:b.grid||""};\n      drawBaseMarker();\n    }\n  }catch(e){}\n}\nfunction saveBase(lat,lon){\n  const [e,n]=toBNG(lat,lon),g=gridRef(e,n);\n  compassBase={lat,lon,grid:g};\n  localStorage.setItem("compass_base_v1546",JSON.stringify(compassBase));\n  drawBaseMarker();\n  return g;\n}\nfunction drawBaseMarker(){\n  if(baseMarker){map.removeLayer(baseMarker);baseMarker=null}\n  if(!compassBase)return;\n  baseMarker=L.circleMarker([compassBase.lat,compassBase.lon],{\n    bubblingMouseEvents:false,radius:9,weight:3,fillOpacity:.9\n  }).bindTooltip("BASE",{permanent:true,direction:"top",className:"marker-label",offset:[0,-13]})\n    .bindPopup("<b>BASE</b><br>"+esc(compassBase.grid||""))\n    .addTo(map);\n}\nfunction baseButton(){\n  if(!compassBase){\n    alert("No Base is set yet.\\n\\nMove the map so Base is in the centre, then press Set Base.");\n    return;\n  }\n  map.setView([compassBase.lat,compassBase.lon],8);\n  if(baseMarker)baseMarker.openPopup();\n}\nfunction setBaseButton(){\n  const c=map.getCenter();\n  const [e,n]=toBNG(c.lat,c.lng),g=gridRef(e,n);\n  const msg=compassBase\n    ?"Replace the existing Base with the current centre of the map?\\n\\nNew Base: "+g\n    :"Set the current centre of the map as Base?\\n\\nBase: "+g;\n  if(!confirm(msg))return;\n  saveBase(c.lat,c.lng);\n  alert("Base set to "+g+".");\n}\nfunction setBaseFromMapCentre(){setBaseButton()}\nfunction changeBase(){setBaseButton()}\nfunction clearBase(){\n  if(!compassBase){\n    alert("There is no saved Base to delete.");\n    return;\n  }\n  if(!confirm("Delete the saved Base?\\n\\nYou can set a new one afterwards using Set Base."))return;\n  compassBase=null;\n  localStorage.removeItem("compass_base_v1546");\n  if(baseMarker){map.removeLayer(baseMarker);baseMarker=null}\n  alert("Base deleted. Move the map to the new location and press Set Base.");\n}\n\nasync function prepareMaps(){\n  const btn=document.getElementById("prepareMapsBtn");\n  if(!btn)return;\n  const original="Prepare Maps";\n  btn.disabled=true;\n  try{\n    const bounds=map.getBounds(), z0=map.getZoom();\n    const zooms=[z0];\n    if(z0<9)zooms.push(z0+1);\n    const urls=[];\n    zooms.forEach(z=>{\n      const nw=map.project(bounds.getNorthWest(),z).divideBy(256);\n      const se=map.project(bounds.getSouthEast(),z).divideBy(256);\n      let minX=Math.floor(Math.min(nw.x,se.x))-1,maxX=Math.floor(Math.max(nw.x,se.x))+1;\n      let minY=Math.floor(Math.min(nw.y,se.y))-1,maxY=Math.floor(Math.max(nw.y,se.y))+1;\n      for(let x=minX;x<=maxX;x++)for(let y=minY;y<=maxY;y++)urls.push("/os/"+z+"/"+x+"/"+y+".png");\n    });\n    const unique=[...new Set(urls)].slice(0,180);\n    let done=0,next=0;\n    async function worker(){\n      while(next<unique.length){\n        const i=next++;\n        try{await fetch(unique[i],{cache:"force-cache"})}catch(e){}\n        done++;\n        btn.textContent="Preparing "+done+"/"+unique.length;\n      }\n    }\n    await Promise.all(Array.from({length:Math.min(8,unique.length)},()=>worker()));\n    btn.textContent="Maps Ready ✓";\n    setTimeout(()=>{btn.textContent=original;btn.disabled=false},2500);\n  }catch(e){\n    btn.textContent="Prepare Maps";\n    btn.disabled=false;\n    alert("Could not prepare the map tiles: "+e.message);\n  }\n}\n\nfunction openMyGroups(){\nconst box=document.getElementById("groupChoices");box.innerHTML="";\nconst note=document.createElement("div");note.className="muted";note.style.marginBottom="8px";\nnote.textContent="Map traces show the most recent "+TRACE_HOURS+" hours. Use the colour square beside each group to make busy expedition maps easier to read.";\nbox.appendChild(note);\nif(!trackers.length)box.innerHTML+=\'<div class="card">No trackers are configured yet.</div>\';\nelse trackers.forEach(t=>{\nconst label=document.createElement("label");label.className="choice";label.style.display="grid";label.style.gridTemplateColumns="auto 1fr auto";label.style.alignItems="center";label.style.gap="8px";\nconst cb=document.createElement("input");cb.type="checkbox";cb.value=t.id;cb.checked=selectedIds.includes(t.id);\nconst span=document.createElement("span");span.textContent=t.name;\nconst colour=document.createElement("input");colour.type="color";colour.value=traceColour(t.id);colour.title="Trace colour for "+t.name;\ncolour.style.width="38px";colour.style.height="30px";colour.style.padding="0";colour.style.border="0";colour.style.background="transparent";\ncolour.addEventListener("click",e=>e.stopPropagation());\ncolour.addEventListener("input",e=>{e.stopPropagation();setTraceColour(t.id,colour.value)});\nlabel.appendChild(cb);label.appendChild(span);label.appendChild(colour);box.appendChild(label);\n});\ndocument.getElementById("groupsModal").classList.add("show");\n}\nfunction selectAllGroups(){document.querySelectorAll(\'#groupChoices input[type="checkbox"]\').forEach(cb=>cb.checked=true)}\nfunction clearAllGroups(){document.querySelectorAll(\'#groupChoices input[type="checkbox"]\').forEach(cb=>cb.checked=false)}\nfunction saveMyGroups(){\nselectedIds=[...document.querySelectorAll(\'#groupChoices input[type="checkbox"]:checked\')].map(cb=>cb.value);\nlocalStorage.setItem(GROUP_STORAGE_KEY,JSON.stringify(selectedIds));\nremoveUnselectedLayers();\ndocument.getElementById("groupsModal").classList.remove("show");\nrenderCheckpointLayers();renderList();\nselectedTrackers().forEach(t=>redrawTrackerTrace(t));\n/* No forced network refresh: all configured trackers are already monitored. */\nconst b=selectedTrackers().map(t=>positions[t.id]).filter(p=>p&&!p.error).map(p=>[p.lat,p.lon]);\nif(b.length===1)map.setView(b[0],8);else if(b.length>1)map.fitBounds(b,{padding:[35,35],maxZoom:8});\n}\n\nfunction openCheckpoints(){\nrenderCheckpointList();\nconst sel=document.getElementById("cpGroup");sel.innerHTML="";\nif(trackers.length>1){\nconst o=document.createElement("option");o.value="*";o.textContent="All configured groups";sel.appendChild(o);\n}\ntrackers.forEach(t=>{const o=document.createElement("option");o.value=t.id;o.textContent=t.name;sel.appendChild(o)});\nif(!trackers.length){const o=document.createElement("option");o.value="";o.textContent="No trackers configured";sel.appendChild(o)}\ndocument.getElementById("checkpointModal").classList.add("show");\n}\nfunction closeCheckpointModal(){document.getElementById("checkpointModal").classList.remove("show")}\nfunction renderCheckpointList(){\nconst box=document.getElementById("checkpointList");box.innerHTML="";\nif(!checkpoints.length){box.innerHTML=\'<div class="muted">No checkpoints yet.</div>\';return}\ncheckpoints.forEach(cp=>{\nconst item=document.createElement("div");item.className="cpitem";\nlet status=cpStatus(cp),passText="";\nif(cp.passed){\nconst entries=Object.entries(cp.passed);\nif(entries.length)passText=\'<div class="muted">\'+entries.map(([id,v])=>esc(trackerName(id))+" - "+esc(localTime(v.time))).join("<br>")+"</div>";\n}\nitem.innerHTML=\'<div class="cphead"><div><b>\'+esc(cp.name)+\'</b><div class="muted">\'+esc(cp.groupId==="*"?"All configured groups":trackerName(cp.groupId))+\' · \'+cp.radius+\' m</div></div><div class="\'+(status==="Passed"?"good":"warn")+\'">\'+esc(status)+\'</div></div>\'+passText+\'<div class="cpbuttons"><button onclick="zoomCheckpoint(\\\'\'+cp.id+\'\\\')">Show</button><button onclick="resetCheckpoint(\\\'\'+cp.id+\'\\\')">Reset</button><button onclick="deleteCheckpoint(\\\'\'+cp.id+\'\\\')">Delete</button></div>\';\nbox.appendChild(item);\n});\n}\nfunction beginPlaceCheckpoint(){\nconst name=document.getElementById("cpName").value.trim(),groupId=document.getElementById("cpGroup").value,radius=+document.getElementById("cpRadius").value;\nif(!name){alert("Please give the checkpoint a name.");return}\nif(!groupId){alert("Please choose a group.");return}\nplacingCheckpoint={name,groupId,radius,finishPoint:document.getElementById("cpFinish").checked};closeCheckpointModal();document.getElementById("placingMessage").classList.add("show");unlockAudio();\n}\nfunction placeCheckpoint(latlng){\nconst cp={id:"cp_"+Date.now()+"_"+Math.random().toString(36).slice(2,7),name:placingCheckpoint.name,groupId:placingCheckpoint.groupId,radius:placingCheckpoint.radius,lat:latlng.lat,lon:latlng.lng,createdAt:new Date().toISOString(),finishPoint:!!placingCheckpoint.finishPoint,passed:{}};\ncheckpoints.push(cp);saveCheckpoints();placingCheckpoint=null;document.getElementById("placingMessage").classList.remove("show");document.getElementById("cpName").value="";document.getElementById("cpFinish").checked=false;renderCheckpointLayers();map.setView([cp.lat,cp.lon],Math.max(map.getZoom(),7));\n}\nfunction zoomCheckpoint(id){const cp=checkpoints.find(c=>c.id===id);if(!cp)return;closeCheckpointModal();map.setView([cp.lat,cp.lon],8);checkpointLayers[id]?.marker.openPopup()}\nfunction resetCheckpoint(id){const cp=checkpoints.find(c=>c.id===id);if(!cp)return;cp.passed={};cp.createdAt=new Date().toISOString();saveCheckpoints();renderCheckpointList();renderCheckpointLayers()}\nfunction deleteCheckpoint(id){checkpoints=checkpoints.filter(c=>c.id!==id);saveCheckpoints();renderCheckpointList();renderCheckpointLayers()}\n\nfunction pointToSegmentDistance(px,py,x1,y1,x2,y2){\nconst dx=x2-x1,dy=y2-y1;if(dx===0&&dy===0)return Math.hypot(px-x1,py-y1);\nlet t=((px-x1)*dx+(py-y1)*dy)/(dx*dx+dy*dy);t=Math.max(0,Math.min(1,t));\nconst x=x1+t*dx,y=y1+t*dy;return Math.hypot(px-x,py-y);\n}\nfunction checkCheckpointsForTracker(t,messages){\nif(!messages.length)return;let changed=false;\ncheckpoints.forEach(cp=>{\nif(cp.groupId!=="*"&&cp.groupId!==t.id)return;\ncp.passed=cp.passed||{};if(cp.passed[t.id])return;\nconst created=new Date(cp.createdAt).getTime(),[cx,cy]=toBNG(cp.lat,cp.lon);let hit=null;\nfor(let i=0;i<messages.length;i++){\nconst cur=messages[i],tm=new Date(cur.dateTime).getTime();if(tm<created-30000)continue;\nconst [x,y]=toBNG(+cur.latitude,+cur.longitude);\nif(Math.hypot(cx-x,cy-y)<=cp.radius){hit=cur;break}\nif(i>0){\nconst prev=messages[i-1],ptm=new Date(prev.dateTime).getTime();\nif(tm>=created-30000&&ptm<=tm){\nconst [x1,y1]=toBNG(+prev.latitude,+prev.longitude);\nif(pointToSegmentDistance(cx,cy,x1,y1,x,y)<=cp.radius){hit=cur;break}\n}\n}\n}\nif(hit){\nconst [e,n]=toBNG(+hit.latitude,+hit.longitude);\ncp.passed[t.id]={time:hit.dateTime,grid:gridRef(e,n)};changed=true;\nif(cp.finishPoint){\nfetch("/api/finish",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tracker_id:t.id,action:"arrived",arrived_at:hit.dateTime})}).catch(()=>{});\n}\nqueueCheckpointAlert(cp,t,hit);\n}\n});\nif(changed){saveCheckpoints();renderCheckpointLayers()}\n}\n\nfunction unlockAudio(){\ntry{if(!audioCtx)audioCtx=new (window.AudioContext||window.webkitAudioContext)();if(audioCtx.state==="suspended")audioCtx.resume()}catch{}\n}\nasync function enableAlerts(){\nunlockAudio();\nif("Notification" in window){try{await Notification.requestPermission()}catch{}}\nconst b=document.getElementById("alertsBtn");b.textContent="Alerts On";b.classList.add("alert-on");playBeep(false);\n}\nfunction playBeep(urgent=true){\nunlockAudio();if(!audioCtx)return;\ntry{\nconst now=audioCtx.currentTime,count=urgent?8:1;\nfor(let i=0;i<count;i++){\nconst osc=audioCtx.createOscillator(),gain=audioCtx.createGain();\nosc.type=urgent?"square":"sine";osc.frequency.value=urgent?(i%2?1040:780):660;\ngain.gain.setValueAtTime(0.0001,now+i*.28);\ngain.gain.exponentialRampToValueAtTime(urgent?.24:.12,now+i*.28+.02);\ngain.gain.exponentialRampToValueAtTime(.0001,now+i*.28+.20);\nosc.connect(gain);gain.connect(audioCtx.destination);osc.start(now+i*.28);osc.stop(now+i*.28+.22);\n}\n}catch{}\n}\n\nfunction sirenBurst(){\nunlockAudio();if(!audioCtx)return;\ntry{\nconst now=audioCtx.currentTime,master=audioCtx.createGain();\nmaster.gain.setValueAtTime(.0001,now);\nmaster.gain.exponentialRampToValueAtTime(.34,now+.04);\nmaster.gain.setValueAtTime(.34,now+1.85);\nmaster.gain.exponentialRampToValueAtTime(.0001,now+1.98);\nmaster.connect(audioCtx.destination);\nconst o1=audioCtx.createOscillator(),o2=audioCtx.createOscillator();\no1.type="sawtooth";o2.type="square";\no1.frequency.setValueAtTime(620,now);\no1.frequency.linearRampToValueAtTime(1180,now+.48);\no1.frequency.linearRampToValueAtTime(620,now+.96);\no1.frequency.linearRampToValueAtTime(1180,now+1.44);\no1.frequency.linearRampToValueAtTime(620,now+1.92);\no2.frequency.setValueAtTime(470,now);\no2.frequency.linearRampToValueAtTime(880,now+.48);\no2.frequency.linearRampToValueAtTime(470,now+.96);\no2.frequency.linearRampToValueAtTime(880,now+1.44);\no2.frequency.linearRampToValueAtTime(470,now+1.92);\nconst g1=audioCtx.createGain(),g2=audioCtx.createGain();\ng1.gain.value=.52;g2.gain.value=.22;\no1.connect(g1);o2.connect(g2);g1.connect(master);g2.connect(master);\no1.start(now);o2.start(now);o1.stop(now+2);o2.stop(now+2);\nsirenNodes.push(o1,o2,master);\nsetTimeout(()=>{sirenNodes=sirenNodes.filter(n=>n!==o1&&n!==o2&&n!==master)},2300);\n}catch{}\n}\nfunction startSiren(){stopSiren();sirenBurst();sirenTimer=setInterval(sirenBurst,2000)}\nfunction stopSiren(){\nif(sirenTimer){clearInterval(sirenTimer);sirenTimer=null}\nsirenNodes.forEach(n=>{try{if(n.stop)n.stop();if(n.disconnect)n.disconnect()}catch{}});\nsirenNodes=[];\n}\n\nfunction queueCheckpointAlert(cp,t,hit){\nalertQueue.push({kind:"checkpoint",cp,t,hit});if(!alertActive)showNextAlert();\n}\nfunction queueHelpAlert(t,msg,grid){\nalertQueue.unshift({kind:"help",t,msg,grid});if(!alertActive)showNextAlert();\n}\nfunction showNextAlert(){\nif(!alertQueue.length){alertActive=false;return}\nalertActive=true;const a=alertQueue[0],banner=document.getElementById("alertBanner");\nif(a.kind==="help"){\nbanner.classList.add("help");\ndocument.getElementById("alertTitle").textContent="SPOT HELP REQUEST";\ndocument.getElementById("alertText").textContent=a.t.name+" has pressed HELP";\ndocument.getElementById("alertGrid").textContent=a.grid+" · "+localTime(a.msg.dateTime);\nstartSiren();\nif("Notification" in window&&Notification.permission==="granted"){\ntry{new Notification("SPOT HELP - "+a.t.name,{body:"HELP request at "+a.grid+" · "+localTime(a.msg.dateTime),requireInteraction:true})}catch{}\n}\n}else{\nbanner.classList.remove("help");\ndocument.getElementById("alertTitle").textContent="CHECKPOINT REACHED";\ndocument.getElementById("alertText").textContent=a.t.name+" reached "+a.cp.name;\nconst pass=a.cp.passed[a.t.id];\ndocument.getElementById("alertGrid").textContent=(pass?.grid||"")+" · "+localTime(a.hit.dateTime);\nplayBeep(true);\nif("Notification" in window&&Notification.permission==="granted"){\ntry{new Notification("DofE checkpoint reached",{body:a.t.name+" reached "+a.cp.name+" - "+(pass?.grid||"")})}catch{}\n}\n}\nbanner.classList.add("show");\n}\nfunction ackAlert(){\nstopSiren();\ndocument.getElementById("alertBanner").classList.remove("show");\ndocument.getElementById("alertBanner").classList.remove("help");\nalertQueue.shift();alertActive=false;setTimeout(showNextAlert,150);\n}\n\n\nfunction toggleMyLocation(){\nif(locationWatchId!==null){stopMyLocation();return}\nif(!navigator.geolocation){alert("This browser does not support location.");return}\nconst btn=document.getElementById("locBtn");btn.textContent="Finding…";\nnavigator.geolocation.getCurrentPosition(\npos=>updateMyLocation(pos,true),\nerr=>{btn.textContent="My Location";alert("Location could not be read. Please allow location access in your browser.");},\n{enableHighAccuracy:true,timeout:12000,maximumAge:30000}\n);\nlocationWatchId=navigator.geolocation.watchPosition(\npos=>updateMyLocation(pos,false),\nerr=>console.warn("Location watch:",err.message),\n{enableHighAccuracy:true,maximumAge:15000,timeout:20000}\n);\nbtn.textContent="Location On";btn.classList.add("alert-on");\n}\nfunction updateMyLocation(pos,centre){\nconst lat=pos.coords.latitude,lon=pos.coords.longitude,acc=pos.coords.accuracy||0;\nconst [e,n]=toBNG(lat,lon),g=gridRef(e,n);\nif(!myLocationMarker){\nmyLocationMarker=L.circleMarker([lat,lon],{radius:9,weight:3,fillOpacity:.9,bubblingMouseEvents:false}).addTo(map);\nmyAccuracyCircle=L.circle([lat,lon],{radius:acc,weight:1,fillOpacity:.06}).addTo(map);\n}else{\nmyLocationMarker.setLatLng([lat,lon]);\nmyAccuracyCircle.setLatLng([lat,lon]).setRadius(acc);\n}\nmyLocationMarker.bindTooltip("You",{permanent:true,direction:"top",className:"marker-label",offset:[0,-10]});\nmyLocationMarker.bindPopup("<b>Your location</b><br><b>"+g+"</b><br>Accuracy: about "+Math.round(acc)+" m");\nif(centre)map.setView([lat,lon],Math.max(map.getZoom(),8));\n}\nfunction stopMyLocation(){\nif(locationWatchId!==null){navigator.geolocation.clearWatch(locationWatchId);locationWatchId=null}\nif(myLocationMarker){map.removeLayer(myLocationMarker);myLocationMarker=null}\nif(myAccuracyCircle){map.removeLayer(myAccuracyCircle);myAccuracyCircle=null}\nconst btn=document.getElementById("locBtn");btn.textContent="My Location";btn.classList.remove("alert-on");\n}\n\nmap.on("click",e=>{\n  const g=toGridRef6(e.latlng.lat,e.latlng.lng);\n  const box=document.getElementById("gridRefReadout");\n  if(box){\n    box.innerHTML="<b>6-figure grid reference:</b> "+esc(g)+" <button id=\'copyGridRefBtn\'>Copy</button>";\n    box.style.display="block";\n    const copyBtn=document.getElementById("copyGridRefBtn");\n    if(copyBtn)copyBtn.onclick=()=>copyGridRef(g);\n    clearTimeout(window._gridRefHideTimer);\n    window._gridRefHideTimer=setTimeout(()=>{box.style.display="none"},12000);\n  }\n});\nfunction clearClickMarker(){if(clickMarker){map.removeLayer(clickMarker);clickMarker=null}}\n\n\nfunction openSpotDiagnostic(){\n  const sel=document.getElementById("diagTracker");\n  sel.innerHTML="";\n  trackers.forEach(t=>{\n    const o=document.createElement("option");\n    o.value=t.id;\n    o.textContent=t.name;\n    sel.appendChild(o);\n  });\n  document.getElementById("diagResult").textContent="Choose a tracker and press Run Diagnostic.";\n  document.getElementById("diagModal").classList.add("show");\n}\nfunction closeSpotDiagnostic(){\n  document.getElementById("diagModal").classList.remove("show");\n}\nasync function runSpotDiagnostic(){\n  const id=document.getElementById("diagTracker").value;\n  const out=document.getElementById("diagResult");\n  if(!id){out.textContent="No tracker selected.";return;}\n  out.textContent="Checking SPOT directly…";\n  try{\n    const r=await fetch("/api/spot-diagnostic/"+encodeURIComponent(id),{cache:"no-store"});\n    const text=await r.text();\n    let d;\n    try{d=JSON.parse(text);}\n    catch{throw new Error("Server returned an unexpected response (HTTP "+r.status+").");}\n    const lines=[\n      "Tracker: "+(d.tracker||"—"),\n      "HTTP status from SPOT: "+(d.http_status??"—"),\n      "SPOT request accepted: "+(d.ok?"YES":"NO"),\n      "Messages returned: "+(d.message_count??"—")\n    ];\n    if(d.latest){\n      lines.push("Latest message type: "+(d.latest.message_type||"—"));\n      lines.push("Latest time: "+(d.latest.date_time||"—"));\n      lines.push("Latitude: "+(d.latest.latitude??"—"));\n      lines.push("Longitude: "+(d.latest.longitude??"—"));\n      lines.push("Altitude: "+(d.latest.altitude??"—"));\n      lines.push("Battery: "+(d.latest.battery_state??"—"));\n    }else{\n      lines.push("Latest message: NONE");\n    }\n    if(d.spot_errors)lines.push("SPOT error: "+JSON.stringify(d.spot_errors));\n    if(d.error)lines.push("Error: "+d.error);\n    out.textContent=lines.join("\\n");\n  }catch(e){\n    out.textContent="Diagnostic failed: "+e.message;\n  }\n}\n\n\nlet compassDetails={},compassFinish={},activeDetailsTracker=null;\nasync function cjson(url,opts){\nconst r=await fetch(url,opts||{}),txt=await r.text();let d;\ntry{d=JSON.parse(txt)}catch{throw Error("Unexpected server response ("+r.status+")")}\nif(!r.ok)throw Error(d.error||("HTTP "+r.status));return d;\n}\nasync function loadCompassAdmin(){\nconst [gd,fl]=await Promise.all([cjson("/api/group-details"),cjson("/api/finish")]);\ncompassDetails=Object.fromEntries(gd.map(x=>[x.tracker_id,x]));\ncompassFinish=Object.fromEntries(fl.map(x=>[x.tracker_id,x]));\n}\nfunction openControlCentre(){document.getElementById("ccModal").classList.add("show");renderControlCentre()}\nfunction closeControlCentre(){document.getElementById("ccModal").classList.remove("show")}\nfunction ccTime(x){return x?localTime(x):"—"}\nfunction controlCentreMetrics(t){\nconst p=positions[t.id];\nif(!p||p.error||!p.messages?.length)return {speed:"—",distance:"0.0 km"};\nconst km=totalDistanceKm(p.messages),ms=movementStats(p.messages);\nconst speed=(p.todaySignal&&ms&&ms.speed!==null&&Number.isFinite(ms.speed))?ms.speed.toFixed(1)+" km/h":"—";\nreturn {speed:speed,distance:km.toFixed(1)+" km"};\n}\nasync function renderControlCentre(){\ntry{await loadCompassAdmin()}catch(e){alert("Control Centre could not load: "+e.message);return}\nconst out=[],arr=[],fin=[];\ntrackers.forEach(t=>{const f=compassFinish[t.id]||{status:"OUT"};(f.status==="FINISHED"?fin:f.status==="ARRIVED"?arr:out).push({t,f})});\ndocument.getElementById("ccOutCount").textContent=out.length+" GROUP"+(out.length===1?"":"S")+" STILL OUT";\ndocument.getElementById("ccArrivedCount").textContent=arr.length?arr.length+" group"+(arr.length===1?"":"s")+" arrived awaiting confirmation":"No groups awaiting confirmation";\nconst make=(elId,rows,type)=>{\nconst el=document.getElementById(elId);el.innerHTML="";\nif(!rows.length){el.innerHTML=\'<div class="muted">None</div>\';return}\nrows.forEach(({t,f})=>{\nconst d=compassDetails[t.id]||{},row=document.createElement("div");row.className="cc-row "+(type==="arr"?"cc-arrived":type==="fin"?"cc-finished":"");\nconst left=document.createElement("div");\nconst metric=controlCentreMetrics(t);\nleft.innerHTML="<b>"+esc(t.name)+"</b><br><span class=\'muted\'>Avg speed: "+metric.speed+" · Today: "+metric.distance+"</span>"+routeMetricHTML(t,true)+(d.leader_name?"<br>"+esc(d.leader_name):"")+(d.leader_phone?"<br><a href=\'tel:"+esc(d.leader_phone)+"\'>"+esc(d.leader_phone)+"</a>":"")+(type!=="out"?"<br><span class=\'muted\'>Arrived "+ccTime(f.arrived_at)+(type==="fin"?" - FINISHED ✓":"")+"</span>":"");\nconst act=document.createElement("div");act.className="cc-actions";\nconst det=document.createElement("button");det.textContent="Leader / Notes";det.onclick=()=>openGroupDetails(t.id);act.appendChild(det);\nif(type==="arr"){const b=document.createElement("button");b.className="primary";b.textContent="Confirm Finished";b.onclick=()=>finishAction(t.id,"confirm");act.appendChild(b)}\nif(type==="out"){const b=document.createElement("button");b.textContent="Mark Arrived";b.onclick=()=>finishAction(t.id,"arrived");act.appendChild(b)}\nif(type==="fin"){const b=document.createElement("button");b.textContent="Return to OUT";b.onclick=()=>finishAction(t.id,"out");act.appendChild(b)}\nrow.append(left,act);el.appendChild(row);\n});\n};\nmake("ccOutList",out,"out");make("ccArrivedList",arr,"arr");make("ccFinishedList",fin,"fin");\n}\nasync function startNewDay(){\nconst ok=confirm("Start a new expedition day?\\n\\nThis will return ALL groups to OUT and clear today\'s arrived/finished status.\\n\\nLeader details and notes are not affected.");\nif(!ok)return;\ntry{\n  await cjson("/api/finish",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"new_day"})});\n  await loadCompassAdmin();\n  await loadCompassDay();\n  Object.values(trackerLayers).forEach(layer=>layer.clearLayers());\n  Object.values(positions).forEach(p=>{if(p&&!p.error)p.todaySignal=false});\n  await renderControlCentre();\n  renderList();\n  selectedTrackers().forEach(t=>redrawTrackerTrace(t));\n  alert("New day started - all groups are now OUT and yesterday\'s trails have been cleared.");\n}catch(e){\n  alert("Could not start a new day: "+e.message);\n}\n}\n\nasync function finishAction(id,action){\nconst leader=localStorage.getItem("burtonDofE_waterLeader_v14")||"";\nawait cjson("/api/finish",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tracker_id:id,action,leader})});\nawait renderControlCentre();\nrenderList();\n}\nasync function openGroupDetails(id){\nactiveDetailsTracker=id;await loadCompassAdmin();\nconst t=trackers.find(x=>x.id===id),d=compassDetails[id]||{};\ndocument.getElementById("gdTitle").textContent=(t?t.name:id)+" - Leader & Notes";\ndocument.getElementById("gdLeader").value=d.leader_name||"";\ndocument.getElementById("gdPhone").value=d.leader_phone||"";\ndocument.getElementById("gdCandidates").value=d.candidate_names||"";\ndocument.getElementById("gdNoteLeader").value=localStorage.getItem("burtonDofE_waterLeader_v14")||"";\ndocument.getElementById("groupDetailsModal").classList.add("show");await loadGroupNotes();\n}\nfunction closeGroupDetails(){document.getElementById("groupDetailsModal").classList.remove("show")}\nasync function saveGroupDetails(){\nawait cjson("/api/group-details",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tracker_id:activeDetailsTracker,leader_name:document.getElementById("gdLeader").value,leader_phone:document.getElementById("gdPhone").value,candidate_names:document.getElementById("gdCandidates").value})});\nawait loadCompassAdmin();alert("Group details saved.");\n}\nasync function saveGroupNote(){\nconst leader=document.getElementById("gdNoteLeader").value.trim();if(leader)localStorage.setItem("burtonDofE_waterLeader_v14",leader);\nawait cjson("/api/notes",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tracker_id:activeDetailsTracker,candidate_name:document.getElementById("gdCandidate").value,status:document.getElementById("gdStatus").value,note:document.getElementById("gdNote").value,leader})});\ndocument.getElementById("gdNote").value="";document.getElementById("gdCandidate").value="";await loadGroupNotes();\n}\nasync function loadGroupNotes(){\nconst rows=await cjson("/api/notes?tracker_id="+encodeURIComponent(activeDetailsTracker)),el=document.getElementById("gdNotes");el.innerHTML="";\nif(!rows.length){el.innerHTML=\'<div class="muted" style="margin-top:10px">No notes yet.</div>\';return}\nrows.forEach(n=>{const d=document.createElement("div");d.className="note-item";d.innerHTML="<b>"+esc(n.candidate_name||"Group")+"</b> - "+esc(n.status)+"<br>"+esc(n.note)+"<br><span class=\'muted\'>"+esc(n.leader||"Leader")+" - "+localTime(n.created_at)+"</span>";el.appendChild(d)});\n}\n\n\nlet activeSpeedTracker=null, activeSpeedRows=[], activeSpeedShareText="", groupPhotoFile=null, groupPhotoTracker=null;\n\nasync function maybeLogSpeedSample(trackerId,speed){\n  if(!Number.isFinite(speed) || speed<0) return;\n  try{\n    await cjson("/api/speed-log",{\n      method:"POST",\n      headers:{"Content-Type":"application/json"},\n      body:JSON.stringify({tracker_id:trackerId,speed_kmh:speed})\n    });\n  }catch(e){ console.warn("Speed log:",e); }\n}\n\nfunction reportLocalDate(iso){\n  if(!iso)return "";\n  const d=new Date(iso);\n  return d.toLocaleDateString(undefined,{day:"2-digit",month:"short",year:"numeric"});\n}\nfunction reportTime(iso){\n  if(!iso)return "—";\n  return new Date(iso).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"});\n}\nasync function openSpeedReport(id){\n  activeSpeedTracker=id;\n  const t=trackers.find(x=>x.id===id);\n  document.getElementById("speedReportTitle").textContent=(t?t.name:id)+" - Daily Speed Report";\n  document.getElementById("speedReportModal").classList.add("show");\n  document.getElementById("speedReportSummary").innerHTML="<div class=\'muted\'>Loading…</div>";\n  document.getElementById("speedReportTable").innerHTML="";\n  try{\n    const rows=await cjson("/api/speed-log?tracker_id="+encodeURIComponent(id));\n    const today=new Date().toLocaleDateString();\n    activeSpeedRows=rows.filter(r=>new Date(r.recorded_at).toLocaleDateString()===today);\n    renderSpeedReport();\n  }catch(e){\n    document.getElementById("speedReportSummary").innerHTML="<div class=\'bad\'>Could not load speed history: "+esc(e.message)+"</div>";\n  }\n}\nfunction closeSpeedReport(){document.getElementById("speedReportModal").classList.remove("show")}\nfunction renderSpeedReport(){\n  const rows=activeSpeedRows;\n  const t=trackers.find(x=>x.id===activeSpeedTracker);\n  const name=t?t.name:activeSpeedTracker;\n  const summary=document.getElementById("speedReportSummary");\n  if(!rows.length){\n    summary.innerHTML="<div class=\'muted\'>No 30-minute speed samples recorded yet today.</div>";\n    drawSpeedChart([]);\n    activeSpeedShareText=name+" - no speed samples recorded today.";\n    return;\n  }\n  const vals=rows.map(r=>Number(r.speed_kmh)).filter(Number.isFinite);\n  const avg=vals.reduce((a,b)=>a+b,0)/vals.length;\n  const max=Math.max(...vals);\n  const min=Math.min(...vals);\n  summary.innerHTML=\n    "<div class=\'report-stat\'><span class=\'muted\'>Samples</span><b>"+rows.length+"</b></div>"+\n    "<div class=\'report-stat\'><span class=\'muted\'>Average</span><b>"+avg.toFixed(1)+" km/h</b></div>"+\n    "<div class=\'report-stat\'><span class=\'muted\'>Fastest</span><b>"+max.toFixed(1)+" km/h</b></div>"+\n    "<div class=\'report-stat\'><span class=\'muted\'>Slowest</span><b>"+min.toFixed(1)+" km/h</b></div>";\n  drawSpeedChart(rows);\n  const table=document.getElementById("speedReportTable");\n  table.innerHTML="<table style=\'width:100%;border-collapse:collapse\'><thead><tr><th style=\'text-align:left\'>Time</th><th style=\'text-align:right\'>30-min average</th></tr></thead><tbody>"+\n    rows.map(r=>"<tr><td style=\'padding:5px 0;border-bottom:1px solid #eee\'>"+reportTime(r.recorded_at)+"</td><td style=\'text-align:right;border-bottom:1px solid #eee\'>"+Number(r.speed_kmh).toFixed(1)+" km/h</td></tr>").join("")+\n    "</tbody></table>";\n  activeSpeedShareText=name+" - Speed Report - "+reportLocalDate(rows[0].recorded_at)+\n    "\\nAverage: "+avg.toFixed(1)+" km/h"+\n    "\\nFastest 30-min average: "+max.toFixed(1)+" km/h"+\n    "\\nSlowest 30-min average: "+min.toFixed(1)+" km/h"+\n    "\\n\\n"+rows.map(r=>reportTime(r.recorded_at)+" - "+Number(r.speed_kmh).toFixed(1)+" km/h").join("\\n");\n}\nfunction drawSpeedChart(rows){\n  const c=document.getElementById("speedCanvas"),ctx=c.getContext("2d");\n  const W=c.width,H=c.height,padL=42,padR=16,padT=18,padB=35;\n  ctx.clearRect(0,0,W,H);\n  ctx.font="12px sans-serif";ctx.fillStyle="#222";ctx.strokeStyle="#bbb";ctx.lineWidth=1;\n  ctx.beginPath();ctx.moveTo(padL,padT);ctx.lineTo(padL,H-padB);ctx.lineTo(W-padR,H-padB);ctx.stroke();\n  if(!rows.length){ctx.fillText("No speed samples yet",padL+15,padT+30);return}\n  const vals=rows.map(r=>Number(r.speed_kmh));\n  const ymax=Math.max(5,Math.ceil(Math.max(...vals)+1));\n  for(let i=0;i<=5;i++){\n    const y=padT+(H-padT-padB)*(i/5);\n    const v=(ymax*(1-i/5)).toFixed(1);\n    ctx.fillStyle="#555";ctx.fillText(v,padL-34,y+4);\n    ctx.strokeStyle="#eee";ctx.beginPath();ctx.moveTo(padL,y);ctx.lineTo(W-padR,y);ctx.stroke();\n  }\n  ctx.strokeStyle="#222";ctx.lineWidth=2;ctx.beginPath();\n  rows.forEach((r,i)=>{\n    const x=padL+(W-padL-padR)*(rows.length===1?.5:i/(rows.length-1));\n    const y=H-padB-(Number(r.speed_kmh)/ymax)*(H-padT-padB);\n    if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);\n  });\n  ctx.stroke();\n  ctx.fillStyle="#222";\n  const step=Math.max(1,Math.ceil(rows.length/6));\n  rows.forEach((r,i)=>{\n    if(i%step===0||i===rows.length-1){\n      const x=padL+(W-padL-padR)*(rows.length===1?.5:i/(rows.length-1));\n      ctx.fillText(reportTime(r.recorded_at),Math.max(padL,x-18),H-10);\n    }\n  });\n}\nasync function shareSpeedReport(){\n  if(!activeSpeedShareText)return;\n  if(navigator.share){\n    try{await navigator.share({title:"COMPASS Speed Report",text:activeSpeedShareText});return}catch(e){if(e.name==="AbortError")return}\n  }\n  try{await navigator.clipboard.writeText(activeSpeedShareText);alert("Report copied to the clipboard ready to paste into WhatsApp or a message.");}\n  catch{alert(activeSpeedShareText)}\n}\n\nfunction openGroupPhoto(id){\n  groupPhotoTracker=id;groupPhotoFile=null;\n  const t=trackers.find(x=>x.id===id);\n  document.getElementById("photoTitle").textContent=(t?t.name:id)+" - Group Start Photo";\n  document.getElementById("groupPhotoInput").value="";\n  const img=document.getElementById("groupPhotoPreview");\n  img.removeAttribute("src");img.style.display="none";\n  document.getElementById("sharePhotoBtn").disabled=true;\n  document.getElementById("photoModal").classList.add("show");\n}\nfunction closeGroupPhoto(){document.getElementById("photoModal").classList.remove("show")}\ndocument.getElementById("groupPhotoInput")?.addEventListener("change",e=>{\n  groupPhotoFile=e.target.files?.[0]||null;\n  const img=document.getElementById("groupPhotoPreview");\n  if(groupPhotoFile){\n    img.src=URL.createObjectURL(groupPhotoFile);\n    img.style.display="block";\n    document.getElementById("sharePhotoBtn").disabled=false;\n  }\n});\nasync function shareGroupPhoto(){\n  if(!groupPhotoFile)return;\n  const t=trackers.find(x=>x.id===groupPhotoTracker);\n  const name=t?t.name:groupPhotoTracker;\n  const caption=name+" - Group Start Photo - "+new Date().toLocaleString();\n  try{\n    if(navigator.share && (!navigator.canShare || navigator.canShare({files:[groupPhotoFile]}))){\n      await navigator.share({files:[groupPhotoFile],text:caption,title:"COMPASS Group Start Photo"});\n      return;\n    }\n  }catch(e){if(e.name==="AbortError")return}\n  alert("This browser cannot send the photo directly. Please use your phone\'s normal photo share option and choose WhatsApp.");\n}\n\nasync function copyGridRef(g){\n  try{\n    await navigator.clipboard.writeText(g);\n    const box=document.getElementById("gridRefReadout");\n    if(box)box.innerHTML="<b>6-figure grid reference:</b> "+esc(g)+" <span class=\'good\'>Copied ✓</span>";\n  }catch(e){}\n}\n\nasync function startApp(){\nloadTraceColours();\nloadBase();\nawait loadCompassDay();\nloadCheckpoints();\ndocument.getElementById("waterLeader").value=localStorage.getItem("burtonDofE_waterLeader_v14")||"";\nawait loadWater();\ntry{await loadTrackers()}catch(e){document.getElementById("trackerList").innerHTML=\'<div class="card bad">\'+esc(e.message)+\'</div>\';return}\nawait loadGPXRoutes();\nconst saved=loadSelection();\nif(saved===null){selectedIds=[];renderList();renderCheckpointLayers();openMyGroups();return}\nconst valid=new Set(trackers.map(t=>t.id));selectedIds=saved.filter(id=>valid.has(id));\nlocalStorage.setItem(GROUP_STORAGE_KEY,JSON.stringify(selectedIds));\nrenderList();renderCheckpointLayers();await refreshAll(true);\nif("Notification" in window&&Notification.permission==="granted"){\nconst b=document.getElementById("alertsBtn");b.textContent="Enable Sound";b.title="Tap once after opening to allow alarm sound";\n}\n}\nstartApp();\nsetInterval(()=>refreshAll(false),REFRESH_MS);\n</script>\n</body>\n</html>'

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)