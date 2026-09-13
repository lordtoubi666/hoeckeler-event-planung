from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from http.cookies import SimpleCookie
import json, threading, uuid, zipfile, os, hashlib, hmac, base64, time, secrets
from io import BytesIO
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DATA = ROOT / "data.json"
LOCK = threading.Lock()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
AUTH_SECRET = os.getenv("AUTH_SECRET", "change-this-in-production")
COOKIE_SECURE = os.getenv("COOKIE_SECURE","false").lower() in ("1","true","yes")
ALLOW_JSON_FALLBACK = os.getenv("ALLOW_JSON_FALLBACK","true").lower() in ("1","true","yes")
LOGIN_ATTEMPTS = {}
PASSWORD_ITERATIONS = 600000
BOOTSTRAP_ADMIN = os.getenv("BOOTSTRAP_ADMIN", "admin")
BOOTSTRAP_PASSWORD = os.getenv("BOOTSTRAP_PASSWORD", "ChangeMe123!")
ENVIRONMENT = os.getenv("ENVIRONMENT","development").strip().lower()
APP_VERSION = "v46"
CORS_ALLOWED_ORIGINS = {x.strip().rstrip("/") for x in os.getenv("CORS_ALLOWED_ORIGINS","").split(",") if x.strip()}
CROSS_SITE_COOKIES = os.getenv("CROSS_SITE_COOKIES","false").lower() in ("1","true","yes")
TEST_MODE = os.getenv("TEST_MODE","false").lower() in ("1","true","yes")
TEST_EMAIL_REDIRECT = os.getenv("TEST_EMAIL_REDIRECT","").strip()
TEST_SMS_REDIRECT = os.getenv("TEST_SMS_REDIRECT","").strip()
PASSWORD_RESET_ATTEMPTS = {}
CSRF_EXEMPT_PATHS={"/api/login","/api/request-password-reset","/api/complete-password-reset"}

def _validate_runtime_config():
    if ENVIRONMENT!="production": return
    problems=[]
    if not DATABASE_URL:problems.append("DATABASE_URL is required")
    if AUTH_SECRET=="change-this-in-production" or len(AUTH_SECRET)<32:problems.append("AUTH_SECRET must be random and at least 32 characters")
    if BOOTSTRAP_PASSWORD=="ChangeMe123!" or len(BOOTSTRAP_PASSWORD)<12:problems.append("BOOTSTRAP_PASSWORD must be changed and at least 12 characters")
    if not COOKIE_SECURE:problems.append("COOKIE_SECURE=true is required")
    if ALLOW_JSON_FALLBACK:problems.append("ALLOW_JSON_FALLBACK=false is required")
    if problems:raise RuntimeError("Unsafe production configuration: "+"; ".join(problems))

EMPTY = {
    "events": [], "people": [], "shifts": [], "assignments": [], "templates": [],
    "users": [], "availability": [], "swaps": [], "notifications": [], "audit_log": [], "confirmations": [], "waitlist": [], "signup_requests": [], "event_people": [], "skills": [], "person_skills": [], "shift_skills": [], "email_queue": [], "sms_queue": [], "password_resets": [], "reminder_log": [], "schema_version": 7, "settings": {"min_rest_hours": 8, "weekly_warning_hours": 40, "smtp_host": "", "smtp_port": 587, "smtp_user": "", "smtp_password": "", "smtp_from": "", "smtp_tls": True, "email_enabled": False, "sms_enabled": False, "sms_webhook_url": "", "sms_bearer_token": "", "sms_sender": "Hoeckeler", "automatic_reminders": True, "shift_reminder_days": "7,1", "availability_reminder_days": "3,1"}
}

def _default_data():
    return json.loads(json.dumps(EMPTY))

def _ensure_keys(data):
    for k,v in EMPTY.items(): data.setdefault(k, json.loads(json.dumps(v)))
    data.setdefault("settings",{})
    data["settings"].setdefault("min_rest_hours",8)
    data["settings"].setdefault("weekly_warning_hours",40)
    data.setdefault("audit_log",[])
    data["schema_version"]=max(int(data.get("schema_version",1)),7)
    for k,v in {"smtp_host":"","smtp_port":587,"smtp_user":"","smtp_password":"","smtp_from":"","smtp_tls":True,"email_enabled":False,"sms_enabled":False,"sms_webhook_url":"","sms_bearer_token":"","sms_sender":"Hoeckeler","automatic_reminders":True,"shift_reminder_days":"7,1","availability_reminder_days":"3,1"}.items(): data["settings"].setdefault(k,v)
    for user in data.get("users",[]):
        user.setdefault("calendar_token",secrets.token_urlsafe(32))
    if not data["users"]:
        salt=secrets.token_hex(16)
        data["users"].append({
            "id": uid("usr"), "username": BOOTSTRAP_ADMIN, "display_name": "Administrator",
            "role": "admin", "person_id": "", "active": True,
            "salt": salt, "password_hash": _hash_password(BOOTSTRAP_PASSWORD, salt), "password_iterations": PASSWORD_ITERATIONS,
            "must_change_password": True, "calendar_token": secrets.token_urlsafe(32)
        })
    return data

def _pg_load():
    import psycopg
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS app_state (id integer PRIMARY KEY, payload jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())")
            cur.execute("SELECT payload FROM app_state WHERE id=1")
            row=cur.fetchone()
            if not row:
                data=_ensure_keys(_default_data())
                cur.execute("INSERT INTO app_state(id,payload) VALUES (1,%s::jsonb)", (json.dumps(data),))
                conn.commit(); return data
            return _ensure_keys(row[0] if isinstance(row[0],dict) else json.loads(row[0]))

def _pg_save(data):
    import psycopg
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS app_state (id integer PRIMARY KEY, payload jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())")
            cur.execute("INSERT INTO app_state(id,payload) VALUES (1,%s::jsonb) ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload, updated_at=now()", (json.dumps(data),))
        conn.commit()

def load_data():
    with LOCK:
        if DATABASE_URL:
            try: return _pg_load()
            except Exception as e:
                print("PostgreSQL load failed:", e)
                if not ALLOW_JSON_FALLBACK: raise
                print("Using local JSON fallback because ALLOW_JSON_FALLBACK=true")
        if not DATA.exists(): DATA.write_text(json.dumps(_ensure_keys(_default_data()),indent=2),encoding="utf-8")
        try: data=json.loads(DATA.read_text(encoding="utf-8"))
        except Exception: data=_default_data()
        before=json.dumps(data,sort_keys=True,ensure_ascii=False)
        data=_ensure_keys(data)
        if json.dumps(data,sort_keys=True,ensure_ascii=False)!=before:
            DATA.write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding="utf-8")
        return data

def save_data(data):
    with LOCK:
        data=_ensure_keys(data)
        if DATABASE_URL:
            try:
                _pg_save(data); return
            except Exception as e:
                print("PostgreSQL save failed:", e)
                if not ALLOW_JSON_FALLBACK: raise
                print("Using local JSON fallback because ALLOW_JSON_FALLBACK=true")
        DATA.write_text(json.dumps(data,indent=2),encoding="utf-8")

def uid(prefix): return f"{prefix}_{uuid.uuid4().hex[:10]}"

def _hash_password(password, salt, iterations=PASSWORD_ITERATIONS):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations)).hex()

def _verify_password(password,user):
    try:
        iterations=int(user.get("password_iterations",200000))
        return hmac.compare_digest(_hash_password(password,user["salt"],iterations), user["password_hash"])
    except Exception:return False

def _sign(payload):
    raw=json.dumps(payload,separators=(",",":"),sort_keys=True).encode()
    body=base64.urlsafe_b64encode(raw).decode().rstrip("=")
    sig=hmac.new(AUTH_SECRET.encode(),body.encode(),hashlib.sha256).hexdigest()
    return body+"."+sig

def _unsign(token):
    try:
        body,sig=token.rsplit(".",1)
        good=hmac.new(AUTH_SECRET.encode(),body.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig,good): return None
        raw=base64.urlsafe_b64decode(body+"="*((4-len(body)%4)%4))
        obj=json.loads(raw)
        if obj.get("exp",0)<time.time(): return None
        return obj
    except Exception: return None

def _minutes(t):
    try:
        h,m=map(int,t.split(":")); return h*60+m
    except Exception:return 0

def _duration(shift):
    a,b=_minutes(shift.get("start","")),_minutes(shift.get("end",""))
    return (b-a if b>=a else 1440-a+b)/60.0
def _shift_bounds(shift):
    from datetime import datetime, timedelta
    try:
        start=datetime.fromisoformat(f"{shift.get('date','')}T{shift.get('start','00:00')}:00")
        end=datetime.fromisoformat(f"{shift.get('date','')}T{shift.get('end','00:00')}:00")
        if end<=start:end+=timedelta(days=1)
        return start,end
    except Exception:return None,None

def _overlap(a,b):
    sa,ea=_shift_bounds(a);sb,eb=_shift_bounds(b)
    return bool(sa and sb and sa<eb and sb<ea)

def _rest_hours(a,b):
    sa,ea=_shift_bounds(a);sb,eb=_shift_bounds(b)
    if not sa or not sb:return 9999
    if ea<=sb:return (sb-ea).total_seconds()/3600
    if eb<=sa:return (sa-eb).total_seconds()/3600
    return -1

def _xlsx_col(n):
    out = ""
    while n:
        n, r = divmod(n - 1, 26)
        out = chr(65 + r) + out
    return out

def _xlsx_sheet_xml(rows):
    def make_cell(row_idx, col_idx, value):
        ref = f"{_xlsx_col(col_idx)}{row_idx}"
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return f'<c r="{ref}"><v>{value}</v></c>'
        text = escape("" if value is None else str(value))
        return f'<c r="{ref}" t="inlineStr"><is><t>{text}</t></is></c>'
    body = []
    for ri, row in enumerate(rows, 1):
        cells = "".join(make_cell(ri, ci, v) for ci, v in enumerate(row, 1))
        body.append(f'<row r="{ri}">{cells}</row>')
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +         '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +         '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>' +         '<sheetData>' + "".join(body) + '</sheetData></worksheet>'

def build_xlsx_bytes(data, event_id="", date_filter=""):
    events = {e["id"]: e for e in data.get("events", [])}
    people = {p["id"]: p for p in data.get("people", [])}
    assignments = data.get("assignments", [])
    shifts = [
        sh for sh in data.get("shifts", [])
        if (not event_id or sh.get("event_id") == event_id)
        and (not date_filter or sh.get("date") == date_filter)
    ]
    shifts.sort(key=lambda x: (x.get("date",""), x.get("start",""), x.get("name","")))
    rows = [["Event","Date","Shift","Schichtleiter","Start","End","Required","Assigned","Person","Email","Phone"]]
    for sh in shifts:
        ass = [a for a in assignments if a.get("shift_id") == sh.get("id")]
        ev = events.get(sh.get("event_id"), {})
        if not ass:
            leader = people.get(sh.get("leader_person_id"), {})
            rows.append([ev.get("name",""),sh.get("date",""),sh.get("name",""),leader.get("name",""),
                         sh.get("start",""),sh.get("end",""),sh.get("required",1),0,"","",""])
        else:
            for a in ass:
                p = people.get(a.get("person_id"), {})
                leader = people.get(sh.get("leader_person_id"), {})
                rows.append([ev.get("name",""),sh.get("date",""),sh.get("name",""),leader.get("name",""),
                             sh.get("start",""),sh.get("end",""),sh.get("required",1),len(ass),
                             p.get("name",""),p.get("email",""),p.get("phone","")])

    content_types = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'       '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'       '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'       '<Default Extension="xml" ContentType="application/xml"/>'       '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'       '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'       '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'       '</Types>'
    root_rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'       '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'       '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'       '</Relationships>'
    workbook_xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'       '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'       '<sheets><sheet name="Shift Plan" sheetId="1" r:id="rId1"/></sheets></workbook>'
    workbook_rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'       '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'       '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'       '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'       '</Relationships>'
    styles = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'       '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'       '<fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>'       '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>'       '<borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'       '<cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs></styleSheet>'

    bio = BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook_xml)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/styles.xml", styles)
        z.writestr("xl/worksheets/sheet1.xml", _xlsx_sheet_xml(rows))
    return bio.getvalue()



def _send_email(settings,to_addr,subject,body):
    if TEST_MODE:
        subject="[TEST] "+subject
        if not TEST_EMAIL_REDIRECT:return False,"TEST_EMAIL_REDIRECT is required in test mode"
        to_addr=TEST_EMAIL_REDIRECT
    if not settings.get("email_enabled") or not settings.get("smtp_host") or not to_addr:
        return False,"email disabled or incomplete SMTP configuration"
    msg=EmailMessage();msg["Subject"]=subject;msg["From"]=settings.get("smtp_from") or settings.get("smtp_user");msg["To"]=to_addr
    msg.set_content(body)
    try:
        port=int(settings.get("smtp_port",587))
        with smtplib.SMTP(settings["smtp_host"],port,timeout=12) as smtp:
            if settings.get("smtp_tls",True):smtp.starttls(context=ssl.create_default_context())
            if settings.get("smtp_user"):smtp.login(settings["smtp_user"],settings.get("smtp_password",""))
            smtp.send_message(msg)
        return True,""
    except Exception as e:return False,str(e)

def _send_sms(settings,to_number,message):
    if TEST_MODE:
        if not TEST_SMS_REDIRECT:return False,"TEST_SMS_REDIRECT is required in test mode"
        to_number=TEST_SMS_REDIRECT
    if not settings.get("sms_enabled") or not settings.get("sms_webhook_url") or not to_number:
        return False,"SMS disabled or incomplete gateway configuration"
    payload=json.dumps({
        "to":to_number,
        "message":message,
        "sender":settings.get("sms_sender","Hoeckeler")
    }).encode("utf-8")
    headers={"Content-Type":"application/json","Accept":"application/json"}
    token=str(settings.get("sms_bearer_token","")).strip()
    if token:headers["Authorization"]="Bearer "+token
    req=urllib.request.Request(settings["sms_webhook_url"],data=payload,headers=headers,method="POST")
    try:
        with urllib.request.urlopen(req,timeout=12) as resp:
            code=getattr(resp,"status",200)
            if 200<=code<300:return True,""
            return False,f"SMS gateway HTTP {code}"
    except Exception as e:return False,str(e)

def _reset_code_hash(username,code):
    return hmac.new(AUTH_SECRET.encode(),f"{username.lower()}:{code}".encode(),hashlib.sha256).hexdigest()


def _notify_user(data,user_id,message,kind="info"):
    data.setdefault("notifications",[]).append({"id":uid("not"),"user_id":user_id,"message":message,"kind":kind,"created_at":time.strftime("%Y-%m-%dT%H:%M:%S"),"read":False})
    user=next((x for x in data.get("users",[]) if x.get("id")==user_id),None)
    person=next((p for p in data.get("people",[]) if user and p.get("id")==user.get("person_id")),None)
    if not user:return
    email=(person or {}).get("email","")
    if email and user.get("email_notifications",True):
        q={"id":uid("mail"),"user_id":user_id,"to":email,"subject":"Höckeler Event Planung","body":message,"status":"pending","created_at":time.strftime("%Y-%m-%dT%H:%M:%S"),"error":""}
        data.setdefault("email_queue",[]).append(q)
        ok,err=_send_email(data.get("settings",{}),email,q["subject"],message)
        q["status"]="sent" if ok else "failed";q["error"]=err;q["processed_at"]=time.strftime("%Y-%m-%dT%H:%M:%S")
    phone=(person or {}).get("phone","")
    if phone and user.get("sms_notifications",False):
        q={"id":uid("sms"),"user_id":user_id,"to":phone,"message":message,"status":"pending","created_at":time.strftime("%Y-%m-%dT%H:%M:%S"),"error":""}
        data.setdefault("sms_queue",[]).append(q)
        ok,err=_send_sms(data.get("settings",{}),phone,message)
        q["status"]="sent" if ok else "failed";q["error"]=err;q["processed_at"]=time.strftime("%Y-%m-%dT%H:%M:%S")

def _ics_escape(value):
    return str(value or "").replace("\\","\\\\").replace(",","\\,").replace(";","\\;").replace("\n","\\n")

def _calendar_bytes(data,pid):
    published={e["id"] for e in data.get("events",[]) if e.get("status","draft")=="published"}
    events={e["id"]:e for e in data.get("events",[])}
    lines=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//Hoeckeler//Event Planung//DE","CALSCALE:GREGORIAN","METHOD:PUBLISH","X-WR-CALNAME:Höckeler – Meine Schichten"]
    for a in data.get("assignments",[]):
        if a.get("person_id")!=pid:continue
        sh=next((x for x in data.get("shifts",[]) if x.get("id")==a.get("shift_id")),None)
        if not sh or sh.get("event_id") not in published:continue
        st,en=_shift_bounds(sh)
        if not st:continue
        ev=events.get(sh.get("event_id"),{})
        leader=next((x for x in data.get("people",[]) if x.get("id")==sh.get("leader_person_id")),None)
        assigned=[x for x in data.get("assignments",[]) if x.get("shift_id")==sh.get("id")]
        skill_ids={x.get("skill_id") for x in data.get("shift_skills",[]) if x.get("shift_id")==sh.get("id")}
        skills=[x.get("name","") for x in data.get("skills",[]) if x.get("id") in skill_ids]
        confirmation=next((x for x in data.get("confirmations",[]) if x.get("assignment_id")==a.get("id")),None)
        parts=[
            f"Event: {ev.get('name','')}",f"Schicht: {sh.get('name','')}",f"Datum: {sh.get('date','')}",
            f"Zeit: {sh.get('start','')} - {sh.get('end','')}",f"Ort: {ev.get('location','')}",
            f"Schichtleitung: {(leader or {}).get('name','')}",f"Besetzung: {len(assigned)}/{sh.get('required',1)}",
            f"Bestätigung: {'Bestätigt' if confirmation else 'Noch nicht bestätigt'}"
        ]
        if skills:parts.append("Qualifikationen: "+", ".join(skills))
        for key,label in (("meeting_point","Treffpunkt"),("clothing","Kleidung"),("contact","Kontakt"),("instructions","Aufgaben / Hinweise"),("notes","Schichtnotiz")):
            if sh.get(key):parts.append(f"{label}: {sh.get(key)}")
        if ev.get("notes"):parts.append("Eventnotiz: "+str(ev.get("notes")))
        summary=f"{ev.get('name','')} – {sh.get('name','')}".strip(" –")
        lines += ["BEGIN:VEVENT",f"UID:{sh['id']}@hoeckeler-plan",f"DTSTAMP:{time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())}",
                  f"DTSTART:{st.strftime('%Y%m%dT%H%M%S')}",f"DTEND:{en.strftime('%Y%m%dT%H%M%S')}",
                  f"SUMMARY:{_ics_escape(summary)}",f"LOCATION:{_ics_escape(ev.get('location'))}",
                  f"DESCRIPTION:{_ics_escape(chr(10).join(parts))}",f"STATUS:{'CONFIRMED' if confirmation else 'TENTATIVE'}",
                  f"CATEGORIES:{_ics_escape(', '.join(skills))}","END:VEVENT"]
    lines.append("END:VCALENDAR")
    return ("\r\n".join(lines)+"\r\n").encode("utf-8")

def _event_expected_people(data,event):
    pool=[x.get("person_id") for x in data.get("event_people",[]) if x.get("event_id")==event.get("id")]
    if pool:return list(dict.fromkeys(pool))
    linked={u.get("person_id") for u in data.get("users",[]) if u.get("active",True) and u.get("role")=="employee" and u.get("person_id")}
    return [p.get("id") for p in data.get("people",[]) if p.get("id") in linked]

def _event_availability_responders(data,event):
    start,end=event.get("start_date",""),event.get("end_date","")
    return {a.get("person_id") for a in data.get("availability",[]) if start<=a.get("date","")<=end}

def _parse_days(value,default):
    try:return sorted({max(0,int(x.strip())) for x in str(value).split(",") if x.strip()},reverse=True)
    except Exception:return default

def _process_automatic_reminders():
    from datetime import datetime,date
    data=load_data()
    if not data.get("settings",{}).get("automatic_reminders",True):return 0
    now=datetime.now();today=now.date();sent=0
    log=data.setdefault("reminder_log",[])
    sent_keys={x.get("key") for x in log}
    shift_days=_parse_days(data["settings"].get("shift_reminder_days","7,1"),[7,1])
    for a in data.get("assignments",[]):
        sh=next((x for x in data.get("shifts",[]) if x.get("id")==a.get("shift_id")),None)
        if not sh:continue
        ev=next((x for x in data.get("events",[]) if x.get("id")==sh.get("event_id")),None)
        if not ev or ev.get("status")!="published":continue
        try:days=(date.fromisoformat(sh.get("date"))-today).days
        except Exception:continue
        if days not in shift_days:continue
        key=f"shift:{a.get('id')}:{days}"
        if key in sent_keys:continue
        user=next((u for u in data.get("users",[]) if u.get("person_id")==a.get("person_id") and u.get("active",True)),None)
        if not user:continue
        confirmed=any(x.get("assignment_id")==a.get("id") for x in data.get("confirmations",[]))
        text=f"Erinnerung: {ev.get('name','Event')} – {sh.get('name','Schicht')} am {sh.get('date')} von {sh.get('start')} bis {sh.get('end')}."
        if not confirmed:text+=" Bitte bestätige deinen Einsatz noch."
        _notify_user(data,user["id"],text,"reminder")
        log.append({"key":key,"created_at":time.strftime("%Y-%m-%dT%H:%M:%S")});sent_keys.add(key);sent+=1
    av_days=_parse_days(data["settings"].get("availability_reminder_days","3,1"),[3,1])
    for ev in data.get("events",[]):
        dl=ev.get("availability_deadline")
        if not dl or ev.get("availability_locked"):continue
        try:days=(date.fromisoformat(dl)-today).days
        except Exception:continue
        if days not in av_days:continue
        responders=_event_availability_responders(data,ev)
        for pid in _event_expected_people(data,ev):
            if pid in responders:continue
            user=next((u for u in data.get("users",[]) if u.get("person_id")==pid and u.get("active",True)),None)
            if not user:continue
            key=f"availability:{ev.get('id')}:{pid}:{days}"
            if key in sent_keys:continue
            _notify_user(data,user["id"],f"Bitte trage deine Verfügbarkeit für {ev.get('name','das Event')} bis {dl} ein.","availability")
            log.append({"key":key,"created_at":time.strftime("%Y-%m-%dT%H:%M:%S")});sent_keys.add(key);sent+=1
    if len(log)>10000:data["reminder_log"]=log[-10000:]
    if sent:save_data(data)
    return sent

def _reminder_worker():
    while True:
        try:_process_automatic_reminders()
        except Exception as e:print("Reminder worker:",e)
        time.sleep(3600)

class Handler(SimpleHTTPRequestHandler):
    def _request_origin(self):
        return self.headers.get("Origin","").rstrip("/")

    def _origin_allowed(self):
        origin=self._request_origin()
        return not origin or origin in CORS_ALLOWED_ORIGINS

    def _cors_headers(self):
        origin=self._request_origin()
        if origin and origin in CORS_ALLOWED_ORIGINS:
            return {"Access-Control-Allow-Origin":origin,"Access-Control-Allow-Credentials":"true","Vary":"Origin"}
        return {}

    def _session_token(self):
        c=SimpleCookie();c.load(self.headers.get("Cookie",""));m=c.get("hes_session")
        return m.value if m else ""

    def _csrf_token(self):
        token=self._session_token()
        return hmac.new(AUTH_SECRET.encode(),("csrf:"+token).encode(),hashlib.sha256).hexdigest() if token else ""

    def _csrf_ok(self,path):
        if path in CSRF_EXEMPT_PATHS:return True
        token=self._session_token()
        if not token:return True
        supplied=self.headers.get("X-CSRF-Token","")
        expected=self._csrf_token()
        return bool(supplied and expected and hmac.compare_digest(supplied,expected))

    def do_OPTIONS(self):
        if not self._origin_allowed():return self._json(403,{"error":"origin not allowed"})
        self.send_response(204)
        for k,v in self._cors_headers().items():self.send_header(k,v)
        self.send_header("Access-Control-Allow-Methods","GET,POST,PATCH,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type,X-CSRF-Token")
        self.send_header("Access-Control-Max-Age","600")
        self.end_headers()

    def _json(self,status,payload,headers=None):
        body=json.dumps(payload,ensure_ascii=False).encode("utf-8")
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8")
        for k,v in self._cors_headers().items():self.send_header(k,v)
        if headers:
            for k,v in headers.items(): self.send_header(k,v)
        self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)

    def _body(self):
        size=int(self.headers.get("Content-Length","0") or 0); raw=self.rfile.read(size) if size else b"{}"
        try:return json.loads(raw.decode("utf-8"))
        except Exception:return {}

    def _current_user(self,data=None):
        data=data or load_data(); c=SimpleCookie(); c.load(self.headers.get("Cookie", "")); morsel=c.get("hes_session")
        if not morsel:return None
        sess=_unsign(morsel.value)
        if not sess:return None
        return next((u for u in data["users"] if u["id"]==sess.get("uid") and u.get("active",True)),None)

    def _public_user(self,u):
        if not u:return None
        return {k:u.get(k) for k in ("id","username","display_name","role","person_id","active","must_change_password","email_notifications","sms_notifications")}

    def _require(self,data,roles=None):
        u=self._current_user(data)
        if not u:
            self._json(401,{"error":"login required"}); return None
        if roles and u.get("role") not in roles:
            self._json(403,{"error":"forbidden"}); return None
        return u

    def _notify(self,data,user_id,message,kind="info"):
        _notify_user(data,user_id,message,kind)

    def _audit(self,data,user,action,kind,item_id="",details=""):
        data.setdefault("audit_log",[]).append({"id":uid("aud"),"created_at":time.strftime("%Y-%m-%dT%H:%M:%S"),"user_id":user.get("id","") if user else "","username":user.get("username","system") if user else "system","action":action,"kind":kind,"item_id":item_id,"details":str(details or "")})
        if len(data["audit_log"])>5000:data["audit_log"]=data["audit_log"][-5000:]

    def do_GET(self):
        p=urlparse(self.path)
        if p.path.startswith("/api/") and not self._origin_allowed():return self._json(403,{"error":"origin not allowed"})
        data=load_data()
        if p.path=="/api/health": return self._json(200,{"ok":True,"version":APP_VERSION,"environment":ENVIRONMENT,"test_mode":TEST_MODE,"storage":"postgresql" if DATABASE_URL else "json-development"})
        if p.path=="/api/me":
            u=self._current_user(data); return self._json(200,{"user":self._public_user(u)}) if u else self._json(401,{"error":"login required"})
        if p.path=="/api/csrf":
            u=self._current_user(data);return self._json(200,{"csrf_token":self._csrf_token()}) if u else self._json(401,{"error":"login required"})
        parts=[x for x in p.path.split("/") if x]
        if len(parts)==3 and parts[0]=="calendar" and parts[2]=="shifts.ics":
            token=parts[1]
            user=next((x for x in data.get("users",[]) if hmac.compare_digest(str(x.get("calendar_token","")),token) and x.get("active",True)),None)
            if not user or not user.get("person_id"):return self._json(404,{"error":"calendar not found"})
            payload=_calendar_bytes(data,user["person_id"]);self.send_response(200)
            self.send_header("Content-Type","text/calendar; charset=utf-8");self.send_header("Content-Disposition",'inline; filename="hoeckeler-schichten.ics"')
            self.send_header("Cache-Control","no-cache, no-store, must-revalidate");self.send_header("Content-Length",str(len(payload)));self.end_headers();self.wfile.write(payload);return

        # Public frontend files must be accessible before login so the
        # login screen itself can load. Only API routes below are protected.
        if not p.path.startswith("/api/"):
            if p.path in ("/",""):
                self.path="/index.html"
            return super().do_GET()

        u=self._require(data)
        if not u:
            return

        if p.path=="/api/state":
            state={k:data.get(k,[]) for k in EMPTY}
            state["settings"]=dict(data.get("settings",{}))
            state["settings"].pop("smtp_password",None);state["settings"].pop("sms_bearer_token",None)
            state["users"]=[self._public_user(x) for x in data["users"]] if u["role"]=="admin" else []
            state["current_user"]=self._public_user(u)
            state["runtime"]={"version":APP_VERSION,"environment":ENVIRONMENT,"test_mode":TEST_MODE}
            if u["role"]=="employee" and u.get("person_id"):
                pid=u["person_id"]
                # Employees only receive assignments/availability relevant to themselves, but all shifts/events for context.
                state["assignments"]=[a for a in state["assignments"] if a.get("person_id")==pid]
                state["availability"]=[a for a in state["availability"] if a.get("person_id")==pid]
                state["swaps"]=[x for x in state["swaps"] if x.get("requester_person_id")==pid or x.get("target_person_id")==pid]
                state["confirmations"]=[x for x in state["confirmations"] if x.get("person_id")==pid]
                state["waitlist"]=[x for x in state["waitlist"] if x.get("person_id")==pid]
                state["signup_requests"]=[x for x in state["signup_requests"] if x.get("person_id")==pid]
                # Event-pool membership is needed to decide which open shifts the employee may see.
                state["event_people"]=[x for x in state["event_people"] if x.get("person_id")==pid]
            return self._json(200,state)
        if p.path=="/api/calendar-subscription":
            if not u.get("person_id"):return self._json(400,{"error":"no person linked"})
            if not u.get("calendar_token"):u["calendar_token"]=secrets.token_urlsafe(32);save_data(data)
            proto=self.headers.get("X-Forwarded-Proto","https" if COOKIE_SECURE else "http").split(",")[0].strip()
            host=self.headers.get("Host","localhost")
            path=f"/calendar/{u['calendar_token']}/shifts.ics"
            return self._json(200,{"url":f"{proto}://{host}{path}","path":path})
        if p.path=="/api/sms-status":
            if u.get("role")!="admin":return self._json(403,{"error":"admin only"})
            rows=data.get("sms_queue",[]);return self._json(200,{"sent":sum(x.get("status")=="sent" for x in rows),"failed":sum(x.get("status")=="failed" for x in rows),"pending":sum(x.get("status")=="pending" for x in rows),"recent":list(reversed(rows[-30:]))})
        if p.path=="/api/email-status":
            if u.get("role")!="admin":return self._json(403,{"error":"admin only"})
            rows=data.get("email_queue",[]);return self._json(200,{"sent":sum(x.get("status")=="sent" for x in rows),"failed":sum(x.get("status")=="failed" for x in rows),"pending":sum(x.get("status")=="pending" for x in rows),"recent":list(reversed(rows[-30:]))})
        if p.path=="/api/audit":
            if u["role"]!="admin":return self._json(403,{"error":"admin only"})
            return self._json(200,{"audit_log":list(reversed(data.get("audit_log",[])[-1000:]))})
        if p.path=="/api/backup":
            if u["role"]!="admin":return self._json(403,{"error":"admin only"})
            payload=json.dumps(data,indent=2,ensure_ascii=False).encode(); self.send_response(200)
            self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Disposition",'attachment; filename="event-shift-planner-backup.json"'); self.send_header("Content-Length",str(len(payload))); self.end_headers(); self.wfile.write(payload); return
        if p.path=="/api/calendar.ics":
            pid=u.get("person_id","")
            if u["role"] in ("admin","manager"):pid=parse_qs(p.query).get("person_id",[pid])[0]
            if not pid:return self._json(400,{"error":"no person linked"})
            payload=_calendar_bytes(data,pid)
            self.send_response(200);self.send_header("Content-Type","text/calendar; charset=utf-8");self.send_header("Content-Disposition",'attachment; filename="meine-schichten.ics"');self.send_header("Content-Length",str(len(payload)));self.end_headers();self.wfile.write(payload);return

        if p.path=="/api/export.xlsx":
            if u["role"] not in ("admin","manager"):return self._json(403,{"error":"manager or admin required"})
            qs=parse_qs(p.query); payload=build_xlsx_bytes(data,qs.get("event_id",[""])[0],qs.get("date",[""])[0])
            self.send_response(200); self.send_header("Content-Type","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"); self.send_header("Content-Disposition",'attachment; filename="shift-plan.xlsx"'); self.send_header("Content-Length",str(len(payload))); self.end_headers(); self.wfile.write(payload); return
        return self._json(404,{"error":"not found"})

    def do_POST(self):
        p=urlparse(self.path)
        if not self._origin_allowed():return self._json(403,{"error":"origin not allowed"})
        data=load_data(); body=self._body()
        if not self._csrf_ok(p.path):return self._json(403,{"error":"invalid csrf token"})
        if p.path=="/api/login":
            username=str(body.get("username","")).strip().lower(); password=str(body.get("password",""))
            client=self.client_address[0] if self.client_address else "unknown";key=f"{client}:{username}";now=time.time();attempts=[t for t in LOGIN_ATTEMPTS.get(key,[]) if now-t<900]
            if len(attempts)>=5:return self._json(429,{"error":"too many login attempts; try again later"})
            user=next((x for x in data["users"] if x.get("username","").lower()==username and x.get("active",True)),None)
            if not user or not _verify_password(password,user):LOGIN_ATTEMPTS[key]=attempts+[now];return self._json(401,{"error":"invalid username or password"})
            LOGIN_ATTEMPTS.pop(key,None);token=_sign({"uid":user["id"],"exp":int(time.time()+12*3600)});secure="; Secure" if COOKIE_SECURE else "";same_site="None" if CROSS_SITE_COOKIES else "Lax"
            return self._json(200,{"user":self._public_user(user)},{"Set-Cookie":f"hes_session={token}; HttpOnly; SameSite={same_site}; Path=/; Max-Age=43200{secure}"})
        if p.path=="/api/logout":
            secure="; Secure" if COOKIE_SECURE else "";same_site="None" if CROSS_SITE_COOKIES else "Lax"
            return self._json(200,{"ok":True},{"Set-Cookie":f"hes_session=; HttpOnly; SameSite={same_site}; Path=/; Max-Age=0{secure}"})

        if p.path=="/api/request-password-reset":
            username=str(body.get("username","")).strip().lower()
            now=int(time.time());reset_key=f"{self.client_address[0] if self.client_address else 'unknown'}:{username}"
            recent=[x for x in PASSWORD_RESET_ATTEMPTS.get(reset_key,[]) if now-x<900]
            if len(recent)>=5:return self._json(429,{"error":"too many password reset requests; try again later"})
            PASSWORD_RESET_ATTEMPTS[reset_key]=recent+[now]
            user=next((x for x in data.get("users",[]) if x.get("username","").lower()==username and x.get("active",True)),None)
            # Always return a neutral response to avoid exposing account existence.
            if user:
                person=next((x for x in data.get("people",[]) if x.get("id")==user.get("person_id")),None)
                code=f"{secrets.randbelow(1000000):06d}"
                now=int(time.time())
                data["password_resets"]=[x for x in data.get("password_resets",[]) if x.get("expires_at",0)>now and not x.get("used")]
                data["password_resets"].append({"id":uid("rst"),"user_id":user["id"],"username":username,"code_hash":_reset_code_hash(username,code),"expires_at":now+900,"used":False,"created_at":time.strftime("%Y-%m-%dT%H:%M:%S")})
                delivered=False
                text=f"Dein Höckeler Passwort-Reset-Code lautet: {code}. Er ist 15 Minuten gültig."
                email=(person or {}).get("email","")
                phone=(person or {}).get("phone","")
                if email and data.get("settings",{}).get("email_enabled"):
                    ok,_=_send_email(data["settings"],email,"Höckeler Passwort zurücksetzen",text);delivered=delivered or ok
                if phone and data.get("settings",{}).get("sms_enabled"):
                    ok,_=_send_sms(data["settings"],phone,text);delivered=delivered or ok
                self._audit(data,user,"password_reset_requested","user",user["id"],"delivery attempted")
                save_data(data)
            return self._json(200,{"ok":True,"message":"Wenn ein aktives Konto mit hinterlegtem Kontakt existiert, wurde ein Reset-Code versendet."})

        if p.path=="/api/complete-password-reset":
            username=str(body.get("username","")).strip().lower();code=str(body.get("code","")).strip();new_password=str(body.get("new_password",""))
            if len(new_password)<10:return self._json(400,{"error":"new password must contain at least 10 characters"})
            user=next((x for x in data.get("users",[]) if x.get("username","").lower()==username and x.get("active",True)),None)
            if not user:return self._json(400,{"error":"invalid or expired reset code"})
            now=int(time.time());expected=_reset_code_hash(username,code)
            reset=next((x for x in reversed(data.get("password_resets",[])) if x.get("user_id")==user["id"] and not x.get("used") and x.get("expires_at",0)>=now and hmac.compare_digest(x.get("code_hash",""),expected)),None)
            if not reset:return self._json(400,{"error":"invalid or expired reset code"})
            salt=secrets.token_hex(16);user["salt"]=salt;user["password_hash"]=_hash_password(new_password,salt);user["password_iterations"]=PASSWORD_ITERATIONS;user["must_change_password"]=False;reset["used"]=True
            self._audit(data,user,"password_reset_completed","user",user["id"]);save_data(data)
            return self._json(200,{"ok":True})

        u=self._require(data)
        if not u:return
        manager=u["role"] in ("admin","manager")

        if p.path=="/api/notification-preferences":
            person=next((x for x in data.get("people",[]) if x.get("id")==u.get("person_id")),None)
            email_pref=bool(body.get("email_notifications",False));sms_pref=bool(body.get("sms_notifications",False))
            if email_pref and not (person or {}).get("email"):return self._json(400,{"error":"no email address is stored for your employee profile"})
            if sms_pref and not (person or {}).get("phone"):return self._json(400,{"error":"no phone number is stored for your employee profile"})
            u["email_notifications"]=email_pref;u["sms_notifications"]=sms_pref
            self._audit(data,u,"notification_preferences_changed","user",u["id"],f"email={email_pref},sms={sms_pref}")
            save_data(data);return self._json(200,self._public_user(u))

        if p.path=="/api/change-password":
            current=str(body.get("current_password",""));new_password=str(body.get("new_password",""))
            if len(new_password)<10:return self._json(400,{"error":"new password must contain at least 10 characters"})
            if not _verify_password(current,u):return self._json(403,{"error":"current password is incorrect"})
            salt=secrets.token_hex(16);u["salt"]=salt;u["password_hash"]=_hash_password(new_password,salt);u["password_iterations"]=PASSWORD_ITERATIONS;u["must_change_password"]=False;self._audit(data,u,"password_changed","user",u["id"]);save_data(data);return self._json(200,{"ok":True})

        if p.path=="/api/test-sms":
            if u.get("role")!="admin":return self._json(403,{"error":"admin only"})
            to=str(body.get("to","")).strip()
            ok,err=_send_sms(data.get("settings",{}),to,"Höckeler Event Planung – SMS Test")
            if not ok:return self._json(502,{"error":err})
            return self._json(200,{"ok":True})
        if p.path=="/api/test-email":
            if u.get("role")!="admin":return self._json(403,{"error":"admin only"})
            to=str(body.get("to","")).strip()
            ok,err=_send_email(data.get("settings",{}),to,"Höckeler Event Planung – Test","Die E-Mail-Konfiguration funktioniert.")
            if not ok:return self._json(502,{"error":err})
            return self._json(200,{"ok":True})
        if p.path=="/api/restore":
            if u["role"]!="admin":return self._json(403,{"error":"admin only"})
            if not isinstance(body,dict):return self._json(400,{"error":"backup must be a JSON object"})
            save_data(_ensure_keys(body)); return self._json(200,{"ok":True})

        if p.path=="/api/users":
            if u["role"]!="admin":return self._json(403,{"error":"admin only"})
            username=str(body.get("username","")).strip().lower(); password=str(body.get("password","")).strip(); role=body.get("role","employee")
            if not username or not password:return self._json(400,{"error":"username and password required"})
            if role not in ("admin","manager","employee"):return self._json(400,{"error":"invalid role"})
            if any(x.get("username","").lower()==username for x in data["users"]):return self._json(409,{"error":"username already exists"})
            salt=secrets.token_hex(16); item={"id":uid("usr"),"username":username,"display_name":str(body.get("display_name",username)).strip(),"role":role,"person_id":str(body.get("person_id","")).strip(),"active":True,"salt":salt,"password_hash":_hash_password(password,salt),"password_iterations":PASSWORD_ITERATIONS,"must_change_password":bool(body.get("must_change_password",False)),"email_notifications":bool(body.get("email_notifications",True)),"sms_notifications":bool(body.get("sms_notifications",False)),"calendar_token":secrets.token_urlsafe(32)}
            data["users"].append(item); save_data(data); return self._json(201,self._public_user(item))

        if p.path=="/api/skills":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            name=str(body.get("name","")).strip()
            if not name:return self._json(400,{"error":"skill name required"})
            if any(x.get("name","").lower()==name.lower() for x in data["skills"]):return self._json(409,{"error":"skill already exists"})
            item={"id":uid("skl"),"name":name,"notes":str(body.get("notes","")).strip()};data["skills"].append(item)
            self._audit(data,u,"skill_created","skill",item["id"],name);save_data(data);return self._json(201,item)

        if p.path=="/api/person-skills":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            person_id=str(body.get("person_id",""));skill_ids=[str(x) for x in body.get("skill_ids",[])]
            data["person_skills"]=[x for x in data["person_skills"] if x.get("person_id")!=person_id]
            data["person_skills"] += [{"id":uid("psk"),"person_id":person_id,"skill_id":sid} for sid in skill_ids if any(s.get("id")==sid for s in data["skills"])]
            save_data(data);return self._json(200,{"ok":True})

        if p.path=="/api/shift-skills":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            shift_id=str(body.get("shift_id",""));skill_ids=[str(x) for x in body.get("skill_ids",[])]
            data["shift_skills"]=[x for x in data["shift_skills"] if x.get("shift_id")!=shift_id]
            data["shift_skills"] += [{"id":uid("ssk"),"shift_id":shift_id,"skill_id":sid} for sid in skill_ids if any(s.get("id")==sid for s in data["skills"])]
            save_data(data);return self._json(200,{"ok":True})

        if p.path=="/api/availability":
            pid=str(body.get("person_id",u.get("person_id","") if u["role"]=="employee" else "")).strip()
            if u["role"]=="employee" and pid!=u.get("person_id"):return self._json(403,{"error":"employees can edit only their availability"})
            if not pid or not any(x["id"]==pid for x in data["people"]):return self._json(400,{"error":"unknown person"})
            item={"id":uid("avl"),"person_id":pid,"date":str(body.get("date","")).strip(),"status":str(body.get("status","available")).strip(),"start":str(body.get("start","")).strip(),"end":str(body.get("end","")).strip(),"notes":str(body.get("notes","")).strip()}
            if not item["date"] or item["status"] not in ("available","unavailable","preferred","vacation","sick"):
                return self._json(400,{"error":"date and valid status required"})
            # one entry per person/date
            data["availability"]=[x for x in data["availability"] if not (x.get("person_id")==pid and x.get("date")==item["date"])]
            data["availability"].append(item); save_data(data); return self._json(201,item)

        if p.path=="/api/self-assign":
            if u.get("role")!="employee":return self._json(403,{"error":"employee account required"})
            person_id=str(u.get("person_id","")).strip()
            if not person_id:return self._json(409,{"error":"user account is not linked to a person"})
            shift_id=str(body.get("shift_id","")).strip()
            shift=next((s for s in data["shifts"] if s.get("id")==shift_id),None)
            if not shift:return self._json(404,{"error":"shift not found"})
            event=next((e for e in data["events"] if e.get("id")==shift.get("event_id")),None)
            if not event or event.get("status","draft")!="published":return self._json(409,{"error":"shift is not published"})
            mode=event.get("signup_mode","direct")
            if mode=="disabled":return self._json(409,{"error":"self signup is disabled for this event"})
            pool=[x.get("person_id") for x in data.get("event_people",[]) if x.get("event_id")==event["id"]]
            if pool and person_id not in pool:return self._json(403,{"error":"you are not part of this event team"})
            required_skills={x.get("skill_id") for x in data.get("shift_skills",[]) if x.get("shift_id")==shift_id}
            person_skills={x.get("skill_id") for x in data.get("person_skills",[]) if x.get("person_id")==person_id}
            missing=required_skills-person_skills
            if missing:
                names=[x.get("name","") for x in data.get("skills",[]) if x.get("id") in missing]
                return self._json(409,{"error":"missing required skills","skills":names})
            if any(a.get("shift_id")==shift_id and a.get("person_id")==person_id for a in data["assignments"]):
                return self._json(409,{"error":"already assigned"})
            if any(x.get("shift_id")==shift_id and x.get("person_id")==person_id and x.get("status")=="pending" for x in data.get("signup_requests",[])):
                return self._json(409,{"error":"signup request already pending"})
            if any(x.get("shift_id")==shift_id and x.get("person_id")==person_id and x.get("status")=="waiting" for x in data.get("waitlist",[])):
                return self._json(409,{"error":"already on waiting list"})

            assigned_count=sum(1 for a in data["assignments"] if a.get("shift_id")==shift_id)
            required=max(1,int(shift.get("required",1) or 1))
            if assigned_count>=required:
                item={"id":uid("wait"),"shift_id":shift_id,"person_id":person_id,"status":"waiting","created_at":time.strftime("%Y-%m-%dT%H:%M:%S")}
                data["waitlist"].append(item)
                self._audit(data,u,"waitlist_joined","waitlist",item["id"],shift_id)
                save_data(data);return self._json(201,{"status":"waitlisted","item":item})

            conflicts=[]
            av_rows=[x for x in data.get("availability",[]) if x.get("person_id")==person_id and x.get("date")==shift.get("date")]
            blocked=next((x for x in av_rows if x.get("status") in ("unavailable","vacation","sick")),None)
            if blocked:conflicts.append("not available on this date")
            windows=[x for x in av_rows if x.get("start") and x.get("end") and x.get("status") in ("available","preferred")]
            if windows:
                ss,se=_shift_bounds(shift);inside=False
                for av in windows:
                    ars,are=_shift_bounds({"date":shift.get("date"),"start":av.get("start"),"end":av.get("end")})
                    if ss and ars and ss>=ars and se<=are:inside=True;break
                if not inside:conflicts.append("shift is outside your availability window")
            daily_hours=_duration(shift)
            for a in data["assignments"]:
                if a.get("person_id")!=person_id:continue
                other=next((s for s in data["shifts"] if s.get("id")==a.get("shift_id")),None)
                if not other:continue
                if _overlap(shift,other):conflicts.append(f"overlap with {other.get('name','shift')}")
                else:
                    rest=_rest_hours(shift,other);min_rest=float(data.get("settings",{}).get("min_rest_hours",8))
                    if min_rest and 0<=rest<min_rest:conflicts.append(f"rest period only {rest:.1f}h")
                if other.get("date")==shift.get("date"):daily_hours+=_duration(other)
            person=next((p for p in data["people"] if p.get("id")==person_id),None)
            max_hours=float((person or {}).get("max_hours_day",0) or 0)
            if max_hours and daily_hours>max_hours:conflicts.append(f"daily hours {daily_hours:.1f}h exceed max. {max_hours:g}h")
            if conflicts:return self._json(409,{"error":"schedule conflict","conflicts":conflicts})

            if mode=="approval":
                req={"id":uid("req"),"shift_id":shift_id,"person_id":person_id,"status":"pending","created_at":time.strftime("%Y-%m-%dT%H:%M:%S")}
                data["signup_requests"].append(req)
                self._audit(data,u,"signup_requested","signup_request",req["id"],shift_id)
                for manager_user in data.get("users",[]):
                    if manager_user.get("role") in ("admin","manager") and manager_user.get("active",True):
                        self._notify(data,manager_user["id"],f"{(person or {}).get('name','Mitarbeiter')} möchte sich für {shift.get('name','Schicht')} eintragen","signup")
                save_data(data);return self._json(202,{"status":"approval_required","item":req})

            item={"id":uid("asg"),"shift_id":shift_id,"person_id":person_id}
            data["assignments"].append(item)
            self._audit(data,u,"self_assigned","assignment",item["id"],f"{person_id}->{shift_id}")
            for manager_user in data.get("users",[]):
                if manager_user.get("role") in ("admin","manager") and manager_user.get("active",True):
                    self._notify(data,manager_user["id"],f"{(person or {}).get('name','Mitarbeiter')} hat sich selbst für {shift.get('name','Schicht')} eingetragen","assignment")
            save_data(data);return self._json(201,{"status":"assigned","item":item})

        if p.path=="/api/confirm-assignment":
            if u.get("role")!="employee":return self._json(403,{"error":"employee account required"})
            person_id=str(u.get("person_id","")).strip();assignment_id=str(body.get("assignment_id","")).strip()
            ass=next((a for a in data["assignments"] if a.get("id")==assignment_id and a.get("person_id")==person_id),None)
            if not ass:return self._json(404,{"error":"assignment not found"})
            existing=next((x for x in data["confirmations"] if x.get("assignment_id")==assignment_id),None)
            if existing:return self._json(200,existing)
            item={"id":uid("cnf"),"assignment_id":assignment_id,"person_id":person_id,"confirmed_at":time.strftime("%Y-%m-%dT%H:%M:%S")}
            data["confirmations"].append(item);self._audit(data,u,"assignment_confirmed","assignment",assignment_id);save_data(data);return self._json(201,item)

        if p.path=="/api/calendar-token/regenerate":
            u["calendar_token"]=secrets.token_urlsafe(32);self._audit(data,u,"calendar_token_regenerated","user",u["id"]);save_data(data)
            return self._json(200,{"ok":True})
        if p.path=="/api/run-reminders":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            count=_process_automatic_reminders();return self._json(200,{"sent":count})
        if p.path=="/api/availability-reminders":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            event_id=str(body.get("event_id",""));ev=next((x for x in data["events"] if x.get("id")==event_id),None)
            if not ev:return self._json(404,{"error":"event not found"})
            responders=_event_availability_responders(data,ev);count=0
            for pid in _event_expected_people(data,ev):
                if pid in responders:continue
                user=next((x for x in data["users"] if x.get("person_id")==pid and x.get("active",True)),None)
                if user:self._notify(data,user["id"],f"Bitte trage deine Verfügbarkeit für {ev.get('name','das Event')} bis {ev.get('availability_deadline') or 'zur Planung'} ein.","availability");count+=1
            self._audit(data,u,"availability_reminders_sent","event",event_id,str(count));save_data(data);return self._json(200,{"sent":count})
        if p.path=="/api/event-pool":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            event_id=str(body.get("event_id","")).strip();person_ids=[str(x) for x in body.get("person_ids",[]) if str(x)]
            if not any(e.get("id")==event_id for e in data["events"]):return self._json(404,{"error":"event not found"})
            valid={p["id"] for p in data["people"]};person_ids=[x for x in person_ids if x in valid]
            data["event_people"]=[x for x in data["event_people"] if x.get("event_id")!=event_id]
            data["event_people"] += [{"id":uid("evp"),"event_id":event_id,"person_id":pid} for pid in person_ids]
            self._audit(data,u,"event_pool_updated","event",event_id,f"{len(person_ids)} people")
            save_data(data);return self._json(200,{"event_id":event_id,"person_ids":person_ids})

        if p.path=="/api/swaps":
            assignment_id=str(body.get("assignment_id","")).strip(); ass=next((a for a in data["assignments"] if a["id"]==assignment_id),None)
            if not ass:return self._json(400,{"error":"assignment not found"})
            if u["role"]=="employee" and ass.get("person_id")!=u.get("person_id"):return self._json(403,{"error":"not your assignment"})
            item={"id":uid("swp"),"assignment_id":assignment_id,"requester_person_id":ass["person_id"],"target_person_id":str(body.get("target_person_id","")).strip(),"status":"pending","notes":str(body.get("notes","")).strip(),"created_at":time.strftime("%Y-%m-%dT%H:%M:%S")}
            data["swaps"].append(item)
            self._audit(data,u,"swap_requested","swap",item["id"],item.get("notes",""))
            for admin in data["users"]:
                if admin.get("role") in ("admin","manager"): self._notify(data,admin["id"],"Neue Schichttausch-Anfrage","swap")
            save_data(data); return self._json(201,item)

        if p.path=="/api/clone-event":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            from datetime import date,timedelta
            source_id=str(body.get("source_event_id",""));src=next((e for e in data["events"] if e.get("id")==source_id),None)
            if not src:return self._json(404,{"error":"source event not found"})
            try:
                old_start=date.fromisoformat(src.get("start_date",""));new_start=date.fromisoformat(str(body.get("start_date","")))
            except Exception:return self._json(400,{"error":"valid new start date required"})
            delta=new_start-old_start
            ev=dict(src);ev["id"]=uid("evt");ev["name"]=str(body.get("name","")).strip() or src.get("name","")+" Kopie";ev["start_date"]=new_start.isoformat()
            if src.get("end_date"):
                try:ev["end_date"]=(date.fromisoformat(src["end_date"])+delta).isoformat()
                except Exception:pass
            ev["status"]="draft";ev["availability_locked"]=False;ev["availability_deadline"]="";data["events"].append(ev)
            shift_map={}
            if body.get("copy_shifts",True):
                for sh in [x for x in data["shifts"] if x.get("event_id")==source_id]:
                    n=dict(sh);oldid=n["id"];n["id"]=uid("shf");n["event_id"]=ev["id"]
                    try:n["date"]=(date.fromisoformat(sh["date"])+delta).isoformat()
                    except Exception:pass
                    data["shifts"].append(n);shift_map[oldid]=n["id"]
                for x in list(data.get("shift_skills",[])):
                    if x.get("shift_id") in shift_map:data["shift_skills"].append({"id":uid("ssk"),"shift_id":shift_map[x["shift_id"]],"skill_id":x["skill_id"]})
            if body.get("copy_event_team",True):
                for x in [x for x in data.get("event_people",[]) if x.get("event_id")==source_id]:
                    data["event_people"].append({"id":uid("evp"),"event_id":ev["id"],"person_id":x["person_id"]})
            if body.get("copy_assignments",False):
                for a in list(data["assignments"]):
                    if a.get("shift_id") in shift_map:data["assignments"].append({"id":uid("asg"),"shift_id":shift_map[a["shift_id"]],"person_id":a["person_id"]})
            self._audit(data,u,"event_cloned","event",ev["id"],f"from {source_id}")
            save_data(data);return self._json(201,{"event":ev,"shifts_created":len(shift_map)})

        if p.path=="/api/events":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            item={"id":uid("evt"),"name":str(body.get("name","")).strip(),"location":str(body.get("location","")).strip(),"start_date":body.get("start_date",""),"end_date":body.get("end_date",""),"notes":str(body.get("notes","")).strip(),"status":str(body.get("status","draft")).strip() or "draft","signup_mode":str(body.get("signup_mode","direct")).strip() or "direct","availability_deadline":str(body.get("availability_deadline","")).strip(),"availability_locked":bool(body.get("availability_locked",False))}
            if not item["name"] or not item["start_date"] or not item["end_date"]:return self._json(400,{"error":"name, start_date and end_date are required"})
            data["events"].append(item);self._audit(data,u,"event_created","event",item["id"],item["name"]); save_data(data); return self._json(201,item)
        if p.path=="/api/people":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            item={"id":uid("per"),"name":str(body.get("name","")).strip(),"email":str(body.get("email","")).strip(),"phone":str(body.get("phone","")).strip(),"max_hours_day":float(body.get("max_hours_day") or 10)}
            if not item["name"]:return self._json(400,{"error":"name is required"})
            data["people"].append(item); save_data(data); return self._json(201,item)
        if p.path=="/api/templates":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            item={"id":uid("tpl"),"event_id":str(body.get("event_id","")).strip(),"date":str(body.get("date","")).strip(),"leader_person_id":str(body.get("leader_person_id","")).strip(),"name":str(body.get("name","")).strip(),"start":body.get("start",""),"end":body.get("end",""),"required":int(body.get("required") or 1),"notes":str(body.get("notes","")).strip()}
            if not all(item[k] for k in ("event_id","date","name","start","end")):return self._json(400,{"error":"template event, date, name, start and end are required"})
            data["templates"].append(item); save_data(data); return self._json(201,item)
        if p.path=="/api/shifts":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            item={"id":uid("shf"),"event_id":body.get("event_id",""),"name":str(body.get("name","")).strip(),"leader_person_id":str(body.get("leader_person_id","")).strip(),"date":body.get("date",""),"start":body.get("start",""),"end":body.get("end",""),"required":int(body.get("required") or 1),"notes":str(body.get("notes","")).strip(),"meeting_point":str(body.get("meeting_point","")).strip(),"clothing":str(body.get("clothing","")).strip(),"instructions":str(body.get("instructions","")).strip(),"contact":str(body.get("contact","")).strip()}
            if not all(item[k] for k in ("event_id","name","date","start","end")):return self._json(400,{"error":"event, name, date, start and end are required"})
            data["shifts"].append(item); save_data(data); return self._json(201,item)
        if p.path=="/api/assignments":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            person_id,shift_id=body.get("person_id",""),body.get("shift_id",""); shift=next((x for x in data["shifts"] if x["id"]==shift_id),None); person=next((x for x in data["people"] if x["id"]==person_id),None)
            if not person or not shift:return self._json(400,{"error":"unknown person or shift"})
            if any(a["person_id"]==person_id and a["shift_id"]==shift_id for a in data["assignments"]):return self._json(409,{"error":"person is already assigned to this shift"})
            conflicts=[]
            required_skills={x.get("skill_id") for x in data.get("shift_skills",[]) if x.get("shift_id")==shift_id}
            person_skills={x.get("skill_id") for x in data.get("person_skills",[]) if x.get("person_id")==person_id}
            missing=required_skills-person_skills
            if missing:
                names=[x.get("name","") for x in data.get("skills",[]) if x.get("id") in missing]
                conflicts.append("Fehlende Qualifikation: "+", ".join(names))
            for a in data["assignments"]:
                if a["person_id"]!=person_id:continue
                other=next((x for x in data["shifts"] if x["id"]==a["shift_id"]),None)
                if other:
                    if _overlap(shift,other):conflicts.append(f"Überschneidung mit {other['name']}")
                    else:
                        rest=_rest_hours(shift,other);min_rest=float(data.get("settings",{}).get("min_rest_hours",8))
                        if min_rest and 0<=rest<min_rest:conflicts.append(f"Ruhezeit nur {rest:.1f}h zu {other['name']} (min. {min_rest:g}h)")
            av=next((x for x in data["availability"] if x.get("person_id")==person_id and x.get("date")==shift["date"]),None)
            if av and av.get("status")=="unavailable": conflicts.append("Person als nicht verfügbar markiert")
            # daily work-hour warning
            hours=sum(_duration(x) for x in data["shifts"] if x["date"]==shift["date"] and any(a["person_id"]==person_id and a["shift_id"]==x["id"] for a in data["assignments"])) + _duration(shift)
            if hours>float(person.get("max_hours_day",10)): conflicts.append(f"Tageslimit überschritten ({hours:.1f}h)")
            if conflicts and not body.get("force"):return self._json(409,{"error":"schedule conflict","conflicts":conflicts})
            item={"id":uid("asg"),"person_id":person_id,"shift_id":shift_id}; data["assignments"].append(item);self._audit(data,u,"assignment_created","assignment",item["id"],f"{person_id}->{shift_id}")
            linked=next((x for x in data["users"] if x.get("person_id")==person_id),None)
            if linked:self._notify(data,linked["id"],f"Neue Schicht zugewiesen: {shift['name']} am {shift['date']}","shift")
            save_data(data); return self._json(201,item)
        return self._json(404,{"error":"not found"})

    def do_PATCH(self):
        p=urlparse(self.path)
        if not self._origin_allowed():return self._json(403,{"error":"origin not allowed"})
        if not self._csrf_ok(p.path):return self._json(403,{"error":"invalid csrf token"})
        parts=[x for x in p.path.split("/") if x]; data=load_data(); body=self._body(); u=self._require(data)
        if not u:return
        if len(parts)!=3 or parts[0]!="api":return self._json(404,{"error":"not found"})
        kind,item_id=parts[1],parts[2]; manager=u["role"] in ("admin","manager")
        if kind=="settings" and item_id=="config":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            if "min_rest_hours" in body:data["settings"]["min_rest_hours"]=float(body["min_rest_hours"])
            if "weekly_warning_hours" in body:data["settings"]["weekly_warning_hours"]=float(body["weekly_warning_hours"])
            for key in ("smtp_host","smtp_user","smtp_password","smtp_from","sms_webhook_url","sms_bearer_token","sms_sender"):
                if key in body:data["settings"][key]=str(body[key])
            if "smtp_port" in body:data["settings"]["smtp_port"]=int(body["smtp_port"] or 587)
            if "smtp_tls" in body:data["settings"]["smtp_tls"]=bool(body["smtp_tls"])
            if "email_enabled" in body:data["settings"]["email_enabled"]=bool(body["email_enabled"])
            if "sms_enabled" in body:data["settings"]["sms_enabled"]=bool(body["sms_enabled"])
            if "automatic_reminders" in body:data["settings"]["automatic_reminders"]=bool(body["automatic_reminders"])
            for key in ("shift_reminder_days","availability_reminder_days"):
                if key in body:data["settings"][key]=str(body[key])
            save_data(data);return self._json(200,{k:v for k,v in data["settings"].items() if k not in ("smtp_password","sms_bearer_token")})
        if kind=="notifications":
            item=next((x for x in data["notifications"] if x["id"]==item_id and x.get("user_id")==u["id"]),None)
            if not item:return self._json(404,{"error":"notification not found"})
            item["read"]=bool(body.get("read",True)); save_data(data); return self._json(200,item)
        if kind=="signup_requests":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            req=next((x for x in data["signup_requests"] if x.get("id")==item_id),None)
            if not req:return self._json(404,{"error":"request not found"})
            status=str(body.get("status",""))
            if status not in ("approved","rejected"):return self._json(400,{"error":"invalid status"})
            if status=="approved":
                sh=next((s for s in data["shifts"] if s.get("id")==req.get("shift_id")),None)
                if not sh:return self._json(409,{"error":"shift not found"})
                if sum(1 for a in data["assignments"] if a.get("shift_id")==sh["id"])>=int(sh.get("required",1) or 1):
                    return self._json(409,{"error":"shift is already full"})
                if not any(a.get("shift_id")==sh["id"] and a.get("person_id")==req["person_id"] for a in data["assignments"]):
                    data["assignments"].append({"id":uid("asg"),"shift_id":sh["id"],"person_id":req["person_id"]})
                req["status"]="approved"
            else:req["status"]="rejected"
            linked=next((x for x in data["users"] if x.get("person_id")==req.get("person_id")),None)
            if linked:self._notify(data,linked["id"],f"Deine Schichtanmeldung wurde {'genehmigt' if status=='approved' else 'abgelehnt'}","signup")
            self._audit(data,u,"signup_"+status,"signup_request",item_id);save_data(data);return self._json(200,req)

        if kind=="waitlist":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            item=next((x for x in data["waitlist"] if x.get("id")==item_id),None)
            if not item:return self._json(404,{"error":"waitlist entry not found"})
            if body.get("status")!="promoted":return self._json(400,{"error":"invalid status"})
            sh=next((s for s in data["shifts"] if s.get("id")==item.get("shift_id")),None)
            if not sh:return self._json(409,{"error":"shift not found"})
            if sum(1 for a in data["assignments"] if a.get("shift_id")==sh["id"])>=int(sh.get("required",1) or 1):
                return self._json(409,{"error":"shift is still full"})
            if not any(a.get("shift_id")==sh["id"] and a.get("person_id")==item["person_id"] for a in data["assignments"]):
                data["assignments"].append({"id":uid("asg"),"shift_id":sh["id"],"person_id":item["person_id"]})
            item["status"]="promoted"
            linked=next((x for x in data["users"] if x.get("person_id")==item.get("person_id")),None)
            if linked:self._notify(data,linked["id"],f"Du wurdest von der Warteliste für {sh.get('name','Schicht')} übernommen","waitlist")
            self._audit(data,u,"waitlist_promoted","waitlist",item_id);save_data(data);return self._json(200,item)

        if kind=="swaps":
            if not manager:return self._json(403,{"error":"manager or admin required"})
            sw=next((x for x in data["swaps"] if x["id"]==item_id),None)
            if not sw:return self._json(404,{"error":"swap not found"})
            status=str(body.get("status",""))
            if status not in ("approved","rejected"):return self._json(400,{"error":"invalid status"})
            ass=next((a for a in data["assignments"] if a["id"]==sw.get("assignment_id")),None)
            if not ass:return self._json(409,{"error":"assignment no longer exists"})
            shift=next((s for s in data["shifts"] if s["id"]==ass.get("shift_id")),None)
            requester=sw.get("requester_person_id","")
            target=str(body.get("target_person_id",sw.get("target_person_id",""))).strip()
            if status=="approved":
                if not target:return self._json(409,{"error":"target person required before approval"})
                if not any(p["id"]==target for p in data["people"]):return self._json(400,{"error":"target person not found"})
                conflicts=[]
                if shift:
                    for a in data["assignments"]:
                        if a.get("person_id")!=target or a.get("id")==ass.get("id"):continue
                        other=next((s for s in data["shifts"] if s["id"]==a.get("shift_id")),None)
                        if other:
                            if _overlap(shift,other):conflicts.append(f"Überschneidung mit {other.get('name','Schicht')}")
                            else:
                                rest=_rest_hours(shift,other);min_rest=float(data.get("settings",{}).get("min_rest_hours",8))
                                if min_rest and 0<=rest<min_rest:conflicts.append(f"Ruhezeit nur {rest:.1f}h")
                    av=next((x for x in data["availability"] if x.get("person_id")==target and x.get("date")==shift.get("date")),None)
                    if av and av.get("status") in ("unavailable","vacation","sick"):conflicts.append("Zielperson ist nicht verfügbar")
                if conflicts:return self._json(409,{"error":"swap conflict","conflicts":conflicts})
                ass["person_id"]=target; sw["target_person_id"]=target; sw["status"]="completed"
            else: sw["status"]="rejected"
            for person_id in {requester,target}:
                linked=next((x for x in data["users"] if x.get("person_id")==person_id),None)
                if linked:self._notify(data,linked["id"],f"Schichttausch wurde {'genehmigt' if sw['status']=='completed' else 'abgelehnt'}","swap")
            self._audit(data,u,"swap_"+sw["status"],"swap",sw["id"]);save_data(data); return self._json(200,sw)
        if kind=="users":
            if u["role"]!="admin":return self._json(403,{"error":"admin only"})
            item=next((x for x in data["users"] if x["id"]==item_id),None)
            if not item:return self._json(404,{"error":"user not found"})
            for k in ("display_name","role","person_id","active","must_change_password","email_notifications","sms_notifications"):
                if k in body:item[k]=body[k]
            if body.get("password"):
                salt=secrets.token_hex(16); item["salt"]=salt; item["password_hash"]=_hash_password(str(body["password"]),salt); item["password_iterations"]=PASSWORD_ITERATIONS; item["must_change_password"]=False
            save_data(data); return self._json(200,self._public_user(item))
        if not manager:return self._json(403,{"error":"manager or admin required"})
        coll={"events":"events","people":"people","templates":"templates","shifts":"shifts","assignments":"assignments"}.get(kind)
        if not coll:return self._json(404,{"error":"not found"})
        item=next((x for x in data[coll] if x["id"]==item_id),None)
        if not item:return self._json(404,{"error":f"{kind} not found"})
        allowed={"events":("name","location","start_date","end_date","notes","status","signup_mode","availability_deadline","availability_locked"),"people":("name","email","phone","max_hours_day"),"templates":("event_id","date","leader_person_id","name","start","end","required","notes"),"shifts":("event_id","name","leader_person_id","date","start","end","required","notes","meeting_point","clothing","instructions","contact"),"assignments":("person_id","actual_hours")}[kind]
        old_status=item.get("status","draft") if kind=="events" else ""
        before=dict(item)
        for k in allowed:
            if k in body:item[k]=float(body[k]) if k in ("max_hours_day","actual_hours") and str(body[k])!="" else int(body[k]) if k=="required" else bool(body[k]) if k=="availability_locked" else body[k]
        if kind=="shifts":
            critical=("name","leader_person_id","date","start","end","meeting_point","clothing","instructions","contact")
            changed=[k for k in critical if k in body and before.get(k)!=item.get(k)]
            if changed:
                ass=[a for a in data["assignments"] if a.get("shift_id")==item_id];ass_ids={a["id"] for a in ass}
                data["confirmations"]=[x for x in data.get("confirmations",[]) if x.get("assignment_id") not in ass_ids]
                for a in ass:
                    linked=next((x for x in data["users"] if x.get("person_id")==a.get("person_id") and x.get("active",True)),None)
                    if linked:self._notify(data,linked["id"],f"Deine Schicht {item.get('name','')} am {item.get('date','')} wurde geändert ({', '.join(changed)}). Bitte bestätige den Einsatz erneut.","shift_changed")
        if kind=="events" and "location" in body and before.get("location")!=item.get("location"):
            shift_ids={x["id"] for x in data["shifts"] if x.get("event_id")==item_id};ass=[a for a in data["assignments"] if a.get("shift_id") in shift_ids];ass_ids={a["id"] for a in ass}
            data["confirmations"]=[x for x in data.get("confirmations",[]) if x.get("assignment_id") not in ass_ids]
            for a in ass:
                linked=next((x for x in data["users"] if x.get("person_id")==a.get("person_id") and x.get("active",True)),None)
                if linked:self._notify(data,linked["id"],f"Der Ort für {item.get('name','Event')} wurde geändert auf {item.get('location','')}. Bitte bestätige deine Schicht erneut.","event_changed")
        if kind=="events" and "status" in body and item.get("status")!=old_status:
            shift_ids={s["id"] for s in data["shifts"] if s.get("event_id")==item["id"]}; person_ids={a["person_id"] for a in data["assignments"] if a.get("shift_id") in shift_ids}
            for pid in person_ids:
                linked=next((x for x in data["users"] if x.get("person_id")==pid),None)
                if linked:self._notify(data,linked["id"],f"Event {item.get('name','')} wurde {'veröffentlicht' if item.get('status')=='published' else 'zurück auf Entwurf gesetzt'}","event")
        self._audit(data,u,"updated",kind,item_id,",".join(body.keys()))
        save_data(data); return self._json(200,item)

    def do_DELETE(self):
        p=urlparse(self.path)
        if not self._origin_allowed():return self._json(403,{"error":"origin not allowed"})
        if not self._csrf_ok(p.path):return self._json(403,{"error":"invalid csrf token"})
        parts=[x for x in p.path.split("/") if x]; data=load_data(); u=self._require(data)
        if not u:return
        if len(parts)!=3 or parts[0]!="api":return self._json(404,{"error":"not found"})
        kind,item_id=parts[1],parts[2]
        if kind=="availability":
            item=next((x for x in data["availability"] if x["id"]==item_id),None)
            if not item:return self._json(404,{"error":"not found"})
            if u["role"]=="employee" and item.get("person_id")!=u.get("person_id"):return self._json(403,{"error":"forbidden"})
            data["availability"]=[x for x in data["availability"] if x["id"]!=item_id]; save_data(data); return self._json(200,{"ok":True})
        if u["role"] not in ("admin","manager"):return self._json(403,{"error":"manager or admin required"})
        if kind=="templates":data["templates"]=[x for x in data["templates"] if x["id"]!=item_id]
        elif kind=="assignments":
            data["assignments"]=[x for x in data["assignments"] if x["id"]!=item_id]
            data["confirmations"]=[x for x in data["confirmations"] if x.get("assignment_id")!=item_id]
        elif kind=="events":
            shift_ids={x["id"] for x in data["shifts"] if x.get("event_id")==item_id}; data["events"]=[x for x in data["events"] if x["id"]!=item_id]; data["shifts"]=[x for x in data["shifts"] if x["id"] not in shift_ids]; data["assignments"]=[x for x in data["assignments"] if x["shift_id"] not in shift_ids]
        elif kind=="people":
            data["people"]=[x for x in data["people"] if x["id"]!=item_id]; data["assignments"]=[x for x in data["assignments"] if x.get("person_id")!=item_id]
            for x in data["shifts"]+data["templates"]:
                if x.get("leader_person_id")==item_id:x["leader_person_id"]=""
        elif kind=="shifts":
            ass_ids={x["id"] for x in data["assignments"] if x.get("shift_id")==item_id}
            data["shifts"]=[x for x in data["shifts"] if x["id"]!=item_id]
            data["assignments"]=[x for x in data["assignments"] if x.get("shift_id")!=item_id]
            data["confirmations"]=[x for x in data["confirmations"] if x.get("assignment_id") not in ass_ids]
            data["waitlist"]=[x for x in data["waitlist"] if x.get("shift_id")!=item_id]
            data["signup_requests"]=[x for x in data["signup_requests"] if x.get("shift_id")!=item_id]
        elif kind=="users" and u["role"]=="admin":data["users"]=[x for x in data["users"] if x["id"]!=item_id]
        else:return self._json(404,{"error":"not found"})
        save_data(data); return self._json(200,{"ok":True})

    def translate_path(self,path):
        p=urlparse(path).path
        if p.startswith("/api/"):return str(STATIC/"__no_file__")
        if p.startswith("/static/"):p=p[len("/static"):]
        target="index.html" if p in ("/","") else p.lstrip("/"); resolved=(STATIC/target).resolve()
        try:resolved.relative_to(STATIC.resolve())
        except ValueError:return str(STATIC/"__no_file__")
        return str(resolved)

    def end_headers(self):
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("X-Frame-Options","DENY")
        self.send_header("Referrer-Policy","same-origin")
        self.send_header("Permissions-Policy","camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy","default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' https: http://localhost:* http://127.0.0.1:*; base-uri 'self'; frame-ancestors 'none'")
        if not self.path.startswith("/api/"):
            self.send_header("Cache-Control","no-store, no-cache, must-revalidate"); self.send_header("Pragma","no-cache"); self.send_header("Expires","0")
        super().end_headers()

if __name__=="__main__":
    _validate_runtime_config()
    host,port="0.0.0.0",int(os.getenv("PORT","8080"))
    print(f"Höckeler Event Planung {APP_VERSION} ({ENVIRONMENT}) on http://localhost:{port}");print("Storage:","PostgreSQL" if DATABASE_URL else "local JSON development fallback")
    threading.Thread(target=_reminder_worker,name="reminder-worker",daemon=True).start()
    ThreadingHTTPServer((host,port),Handler).serve_forever()
