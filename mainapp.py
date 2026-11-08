import psycopg2
from psycopg2.extras import DictCursor
import random, re, json,resend, uuid, edge_tts, asyncio, base64, os, io, smtplib, secrets, hmac, threading, time, subprocess, csv
from flask import redirect, url_for
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename 
from flask import Flask, render_template, request, jsonify, session, g, has_request_context
from flask_cors import CORS
from google import genai
from google.genai import types
from groq import Groq
from PIL import Image
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart # NAYA: Multi-part email support
from email.mime.image import MIMEImage # NAYA: Image attachment support
from datetime import date, datetime, timedelta
from urllib.parse import quote_plus, urlsplit, unquote, parse_qs
from functools import wraps
from collections import defaultdict, deque
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from markupsafe import escape
from dotenv import load_dotenv
import memory_store

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Define absolute paths for shared Docker volumes
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
OUTPUTS_DIR = os.path.join(BASE_DIR, "static", "outputs")

# Auto-create directories with open permissions if they don't exist
for directory in [UPLOADS_DIR, OUTPUTS_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
        # 0o777 ensures Docker container (running as root/different user) has full write access
        os.chmod(directory, 0o777) 

print(f"System Check: Uploads mapped to -> {UPLOADS_DIR}")
print(f"System Check: Outputs mapped to -> {OUTPUTS_DIR}")
print("Starting Sisca AI Server...")


app = Flask(__name__)

# ===============================
# SECURITY CONFIG
# ===============================
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    # Koi known/default key kabhi use nahi hoti. Production me SECRET_KEY zaroor set karein.
    _secret = secrets.token_hex(32)
    print("SECURITY WARNING: SECRET_KEY env var is not set. Using a temporary random key (logins reset on restart).")
app.secret_key = _secret
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=14),
    MAX_CONTENT_LENGTH=30 * 1024 * 1024,  # 30 MB se bari requests reject
)
_cors_origins = [o.strip() for o in os.environ.get(
    "CORS_ORIGINS", "https://siscaai.online,http://localhost:5000,http://127.0.0.1:5000").split(",") if o.strip()]
CORS(app, origins=_cors_origins)
chat_histories = {}

TRUST_PROXY = os.environ.get("TRUST_PROXY", "0") == "1"
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.send']
approval_serializer = URLSafeTimedSerializer(app.secret_key, salt="approve-test-user")


def client_ip():
    """Real client IP. Proxy (Render/nginx) ke peeche ho to TRUST_PROXY=1 set karein."""
    if TRUST_PROXY:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return str(request.remote_addr)


def current_user_email():
    """Logged-in user ki email SIRF server-side session se. Client ka bheja hua email kabhi trust nahi hota."""
    return session.get("user_email")


def history_key_for(user_email):
    """Har guest ki alag chat memory (pehle sab guests ek hi 'guest' history share karte thay)."""
    if user_email and user_email != "guest":
        return user_email
    if "gid" not in session:
        session["gid"] = secrets.token_hex(8)
    return "guest:" + session["gid"]


# ---- Rate limiting (in-memory, per process) ----
_rate_hits = defaultdict(deque)
_rate_lock = threading.Lock()


def _hit(key, max_calls, per_seconds):
    now = time.time()
    with _rate_lock:
        if len(_rate_hits) > 20000:
            for k in [k for k, q in _rate_hits.items() if not q or now - q[-1] > 3600]:
                del _rate_hits[k]
        q = _rate_hits[key]
        while q and now - q[0] > per_seconds:
            q.popleft()
        if len(q) >= max_calls:
            return False, int(per_seconds - (now - q[0])) + 1
        q.append(now)
        return True, 0


def rate_limit(max_calls, per_seconds):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            allowed, retry = _hit((fn.__name__, client_ip()), max_calls, per_seconds)
            if not allowed:
                resp = jsonify({"error": "Too many attempts. Please try again later."})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(retry)
                return resp
            return fn(*args, **kwargs)
        return wrapper
    return deco


# ---- OTP store (secure random, 10 min expiry, max 5 wrong tries, 60s resend cooldown) ----
OTP_TTL = 600
OTP_MAX_WRONG = 5
OTP_RESEND_COOLDOWN = 60
_otp_store = {}
_otp_lock = threading.Lock()


def issue_otp(purpose, email):
    """New OTP banata hai. Cooldown ke andar dobara maange to None return karta hai."""
    key = (purpose, email.lower())
    now = time.time()
    with _otp_lock:
        for k in [k for k, v in _otp_store.items() if v["expires"] < now]:
            del _otp_store[k]
        old = _otp_store.get(key)
        if old and now - old["sent_at"] < OTP_RESEND_COOLDOWN:
            return None
        code = f"{secrets.randbelow(1000000):06d}"
        _otp_store[key] = {"code": code, "expires": now + OTP_TTL, "wrong": 0, "sent_at": now}
        return code


def check_otp(purpose, email, code):
    key = (purpose, email.lower())
    now = time.time()
    with _otp_lock:
        rec = _otp_store.get(key)
        if not rec or rec["expires"] < now:
            _otp_store.pop(key, None)
            return False
        if hmac.compare_digest(rec["code"], str(code)):
            return True
        rec["wrong"] += 1
        if rec["wrong"] >= OTP_MAX_WRONG:
            del _otp_store[key]
        return False


def clear_otp(purpose, email):
    with _otp_lock:
        _otp_store.pop((purpose, email.lower()), None)


# ---- Input validation ----
def valid_email(e):
    return bool(e) and len(e) <= 254 and re.match(r'^[^@\s<>"\',;]+@[^@\s<>"\',;]+\.[^@\s<>"\',;]+$', e) is not None


def password_error(pw):
    if len(pw) < 8:
        return "Password must be at least 8 characters long."
    if len(pw) > 128:
        return "Password is too long."
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$', pw):
        return "Password must contain at least one uppercase, lowercase, and a number."
    return None


# ---- Google OAuth: client secret kabhi DB/code me nahi, sirf env ya client_secret.json (gitignored) se ----
def _google_client_credentials():
    cid = os.environ.get("CLIENT_ID")
    csec = os.environ.get("CLIENT_SECRET")
    if cid and csec:
        return cid, csec
    path = os.path.join(BASE_DIR, "client_secret.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        cfg = cfg.get("web") or cfg.get("installed") or {}
        if cfg.get("client_id") and cfg.get("client_secret"):
            return cfg["client_id"], cfg["client_secret"]
    raise RuntimeError("Google OAuth client is not configured (set CLIENT_ID / CLIENT_SECRET).")


def build_oauth_flow(redirect_uri, state=None):
    cid, csec = _google_client_credentials()
    if "localhost" in redirect_uri or "127.0.0.1" in redirect_uri:
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # sirf local http testing ke liye
    config = {"web": {
        "client_id": cid, "client_secret": csec,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [redirect_uri],
    }}
    return Flow.from_client_config(config, scopes=GMAIL_SCOPES, state=state, redirect_uri=redirect_uri)


def load_google_credentials(token_json):
    """DB me sirf user ke tokens hain; client_id/secret hamesha config se aate hain."""
    info = json.loads(token_json)
    cid, csec = _google_client_credentials()
    info["client_id"] = cid
    info["client_secret"] = csec
    info.setdefault("token_uri", "https://oauth2.googleapis.com/token")
    return Credentials.from_authorized_user_info(info, GMAIL_SCOPES)

# ===============================
# DATABASE SETUP
# ===============================

DB_URL= os.environ.get("DATABASE_URL")       
if not DB_URL:   # Agar Render par key nahi mili, toh local text file se uthayega
    if os.path.exists("database_url.txt"):
        with open("database_url.txt", "r", encoding="utf-8") as f:
            DB_URL = f.read().strip()
    else:
        print("System Notification: DataBase URL is missing.")
        DB_URL = None
    
def get_db_connection():
    if not DB_URL:
        print("WARNING: DATABASE_URL is missing. Please set your Supabase URI.")
        return None
    # PostgreSQL connection return karega
    return psycopg2.connect(DB_URL)

def init_db():
    conn = get_db_connection()
    if not conn: return
    
    c = conn.cursor()
    # NAYA: SQLite ke 'INTEGER PRIMARY KEY' ki jagah 'SERIAL PRIMARY KEY' use hota hai
    c.execute("""CREATE TABLE IF NOT EXISTS users 
                 (id SERIAL PRIMARY KEY, 
                  first_name TEXT, 
                  last_name TEXT, 
                  email TEXT UNIQUE, 
                  password TEXT,
                  google_token TEXT,
                  test_status INTEGER DEFAULT 0,
                  agent_credits INTEGER DEFAULT 5)""") # NAYA: Agent credits ka column
                  
    c.execute("""CREATE TABLE IF NOT EXISTS scheduled_emails 
                 (id SERIAL PRIMARY KEY, 
                  user_email TEXT, 
                  to_email TEXT, 
                  subject TEXT, 
                  body TEXT, 
                  send_time TEXT)""")

    # Daily usage limits (guests by IP, logged-in users by email) - survive restarts/redeploys/multi-workers
    c.execute("""CREATE TABLE IF NOT EXISTS daily_usage
                 (usage_key TEXT,
                  usage_date TEXT,
                  general_count INTEGER DEFAULT 0,
                  agent_count INTEGER DEFAULT 0,
                  PRIMARY KEY (usage_key, usage_date))""")
    c.execute("DELETE FROM daily_usage WHERE usage_date < %s", (str(date.today() - timedelta(days=7)),))
    conn.commit()
    conn.close()

if DB_URL:
    init_db()
    memory_store.init_tables(get_db_connection)

# ===============================
# GLOBAL SETTINGS
# ===============================

# --- NAYA: System Prompt ab Mode Check Karega ---
def get_system_prompt(is_voice=False, is_agent_active=False, user_email="guest"):
    base_prompt = (
        "You are Sisca AI, a personal helpful assistant developed by Masahir Abbas. "
        "If the user types command in roman urdu, reply in roman urdu. If the user speaks in urdu script, reply in proper urdu script, don't reply in roman urdu. otherwise reply in english."
        "Your answers must be concise if Fast mode is ON and detailed if Research mode is ON. Always prefer clear answers."
        "Bold the important text in your response\n\n"
    )
    
    # Mode ke hisaab se AI ki limits set hongi
    if is_agent_active:
        mode_rules = (
            "*** AGENT MODE CAPABILITIES ***\n"
            "You have access to the 'perform_autonomous_research' tool. "
            "For any research-oriented query (e.g., 'check latest mobiles on priceoye', 'compare prices'), you MUST use the 'perform_autonomous_research' tool but don't tell the user about that tool until or unless the user explicity asks you.\n\n"
        )
    else:
        mode_rules = (
            "*** FAST MODE CAPABILITIES ***\n"
            "CRITICAL RULE: You are in FAST MODE. You DO NOT have access to live internet browsing or the autonomous research tool. "
            "If the user asks for live prices, market research, or live data from a specific website (like PakWheels, PriceOye), DO NOT guess or hallucinate data."
            "You MUST reply exactly with: 'I cannot browse live websites in Fast Mode. Please toggle the **Research Mode** ON from the dashboard to get the latest live data.'\n\n"
        )

    email_tool_rules = (
        "*** EMAIL & ACTION PROTOCOL (STRICT) ***\n"
        f"0. The current logged-in user's email address is: '{user_email}'.\n"
        "1. You have tools: 'send_email', 'schedule_email', 'search_google', 'get_current_time'.\n"
        "2. If user confirms an email draft, immediately call 'send_email' or 'schedule_email' tool. Do NOT just output text saying 'I will send it'.\n"
        "3. If user asks to email a Data Analysis Report, use the 'send_email' tool. Set the 'subject' dynamically based on the DATASET NAME in your memory (e.g., 'Sales_Data.csv Analysis Report'). Write the full report inside the 'body' using HTML (<b>, <br>). If you have a CHART_IMAGE_URL in memory, pass it exactly as it is into the tool's 'chart_image_url' parameter. DO NOT manually write an HTML <img> tag for the chart in the body.\n"
        f"4. IMPORTANT: If the user asks to send ANY email to 'me', 'myself', or 'my email', you MUST use their exact email ('{user_email}') as the 'to_email' parameter.\n\n"
    )
    
    if is_voice:
        language_rule = "VOICE MODE: If user speaks in Urdu/Roman Urdu, reply in proper Urdu script. NEVER Roman Urdu."
    else:
        language_rule = "TEXT MODE: Reply in the same language/script the user uses (Roman Urdu, Urdu script, or English)."
        
    return base_prompt + mode_rules + email_tool_rules + language_rule

# ===============================
# LOAD API KEYS (GEMINI & GROQ)
# ===============================

available_keys = []
key_cooldowns = {}

# Gemini keys load karne ka function
def load_api_keys():
    env_keys = os.environ.get("GEMINI_API_KEYS")
    if env_keys:
        return [k.strip() for k in env_keys.split(",") if k.strip()]
    try:
        if os.path.exists("api_key.txt"):
            with open("api_key.txt", "r", encoding="utf-8") as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        return []
    except Exception as e:
        print("Error loading Gemini API keys:", e)
        return []
    
available_keys = load_api_keys()

# --- Groq keys load karne ke liye ---
available_groq_keys = []

def load_groq_keys():
    env_keys = os.environ.get("GROQ_API_KEYS")
    if env_keys:
        return [k.strip() for k in env_keys.split(",") if k.strip()]
    try:
        if os.path.exists("groq_api_key.txt"):
            with open("groq_api_key.txt", "r", encoding="utf-8") as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        return []
    except Exception as e:
        print("Error loading Groq API keys:", e)
        return []

available_groq_keys = load_groq_keys()

# ===============================
# USER-SUPPLIED API KEYS (per request)
# ===============================
# Frontend ("API KEYS" popup) user ki apni Gemini / Groq keys browser me rakhta hai aur har /api/chat
# request ke saath bhejta hai. Keys server par save NAHI hoti aur kabhi log nahi hoti.
# Agar user ne kisi provider ki keys di hain to us request me sirf wahi use hoti hain (server ki keys
# kharch nahi hoti); warna purani server wali keys hi chalti hain.
MAX_USER_KEYS = 20          # Gemini aur Groq: har ek ki max 20 keys
_USER_KEY_RE = re.compile(r"^[A-Za-z0-9_.\-]{20,200}$")

def _clean_key_list(raw, prefix=None):
    out = []
    if not isinstance(raw, list):
        return out
    for k in raw:
        if not isinstance(k, str):
            continue
        k = k.strip()
        if not _USER_KEY_RE.match(k):
            continue
        if prefix and not k.startswith(prefix):
            continue
        if k not in out:
            out.append(k)
        if len(out) >= MAX_USER_KEYS:
            break
    return out

def set_request_user_keys(raw):
    """Request ki user-supplied keys validate karke flask.g me rakhta hai (sirf isi request ke liye)."""
    raw = raw if isinstance(raw, dict) else {}
    g.user_keys = {
        "gemini": _clean_key_list(raw.get("gemini")),
        "groq": _clean_key_list(raw.get("groq"), prefix="gsk_"),
    }

def _request_keys(provider):
    if has_request_context():
        mine = (getattr(g, "user_keys", None) or {}).get(provider)
        if mine:
            return mine
    return available_keys if provider == "gemini" else available_groq_keys

def active_gemini_keys():
    return _request_keys("gemini")

def active_groq_keys():
    return _request_keys("groq")

def send_system_email(to_email: str, subject: str, body: str):
    try:        
        api_key = os.environ.get("SISCA_EMAIL_PASS")
        
        # 2. Agar Render par key nahi mili, toh local text file se uthaega
        if not api_key:
            if os.path.exists("Sisca_email_Pass.txt"):
                with open("Sisca_email_Pass.txt", "r", encoding="utf-8") as f:
                    api_key = f.read().strip()
            else:
                return "System Notification: Resend API key is missing."
                
        # Resend library ko key de di
        resend.api_key = api_key

        # Email ka structure
        params = {
            "from": "Sisca AI <no-reply@siscaai.online>",
            "to": [to_email],
            "subject": subject,
            "html": f"<p>{body.replace(chr(10), '<br>')}</p>"
        }

        # API Call
        resend.Emails.send(params)
        return "System Notification: Email sent successfully."

    except Exception as e:
        return f"System Notification: Email failed: {e}"
        
def get_current_time():
    # NAYA: Pakistan Time (UTC+5) ke hisaab se waqt dega taake scheduling sahi ho
    pkt_time = datetime.utcnow() + timedelta(hours=5)
    return pkt_time.strftime("%Y-%m-%d %H:%M:%S")

def perform_autonomous_research(query: str, api_key: str):
    print(f"Executing BrowserAgent for query: {query}")
    try:

        result = execute_browser_agent(query, api_key)
        return f"System Notification: BrowserAgent completed. Result: {result}"
    except Exception as e:
        return f"System Notification: BrowserAgent failed. Error: {e}"

def search_google(query: str):
    return f"System: Requesting search for {query}"

# NAYA FIX: Smart Sender Routing (Sisca AI vs User's Gmail)
def _deliver_email(user_email, to_email: str, subject: str, body: str, chart_image_url: str = ""):
    try:
        if not user_email: return "System Notification: Tell the user they must be logged in."

        # Smart Check: Is the user sending the email to themselves?
        is_self = (to_email.strip().lower() == user_email.strip().lower())

        # Setup standard MIME structure for both services
        message = MIMEMultipart('related')
        message['to'] = to_email
        message['subject'] = subject
        
        if is_self:
            message['from'] = "Sisca AI <no-reply@siscaai.online>"

        msg_alternative = MIMEMultipart('alternative')
        message.attach(msg_alternative)
        
        html_body = body.replace('\n', '<br>')
        
        if chart_image_url:
            filename = chart_image_url.split('/')[-1]
            local_path = os.path.join(OUTPUTS_DIR, filename)
            
            if os.path.exists(local_path):
                html_body += f"<br><br><img src='cid:chart_image' style='width:100%; max-width:600px; border-radius:10px; margin-top:20px; border: 1px solid #ddd;'>"
                with open(local_path, 'rb') as img_file:
                    img = MIMEImage(img_file.read())
                    img.add_header('Content-ID', '<chart_image>')
                    img.add_header('Content-Disposition', 'inline', filename=filename)
                    message.attach(img)
        
        msg_alternative.attach(MIMEText(html_body, 'html', 'utf-8'))

        # --- 1. SEND VIA SISCA AI (RESEND SMTP) IF SENDING TO SELF ---
        if is_self:
            api_key = os.environ.get("SISCA_EMAIL_PASS")
            if not api_key:
                if os.path.exists("Sisca_email_Pass.txt"):
                    with open("Sisca_email_Pass.txt", "r", encoding="utf-8") as f:
                        api_key = f.read().strip()
                else:
                    return "System Notification: Resend API key is missing."
            
            # Using Python's native SMTP library guarantees 100% compatibility with embedded CID images
            with smtplib.SMTP_SSL("smtp.resend.com", 465) as server:
                server.login("resend", api_key)
                server.send_message(message)
            return "System Notification: Email sent successfully from Sisca AI!"

        # --- 2. SEND VIA USER'S GMAIL API IF SENDING TO SOMEONE ELSE ---
        else:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT google_token FROM users WHERE email = %s", (user_email,))
            row = c.fetchone()
            conn.close()
            if not row or not row[0]: return "System Notification: Explicitly tell the user that their Gmail is not integrated."

            creds = load_google_credentials(row[0])
            service = build('gmail', 'v1', credentials=creds)

            raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
            service.users().messages().send(userId='me', body={'raw': raw}).execute()
            return f"System Notification: Email sent successfully to {to_email} via your connected Gmail!"
            
    except Exception as e:
        return f"System Notification: Email failed to send. Error: {e}."

def send_email(to_email: str, subject: str, body: str, chart_image_url: str = ""):
    # AI tool wrapper (same signature as before): reads the logged-in user from the HTTP request.
    return _deliver_email(current_user_email(), to_email, subject, body, chart_image_url)

# --- NAYA TOOL: Schedule Email ---
def schedule_email(to_email: str, subject: str, body: str, scheduled_time: str):
    user_email = current_user_email()
    
    if not user_email:
        return "System Notification: Tell the user they must be logged in to schedule emails."

    # BULLETPROOF TIME FORMATTING WITH SMART FIX
    try:
        scheduled_time = scheduled_time.strip()
        parsed_dt = None
        
        # Check for AM/PM formats first
        formats_to_try = [
            "%Y-%m-%d %I:%M:%S %p",
            "%Y-%m-%d %I:%M %p",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M"
        ]
        for fmt in formats_to_try:
            try:
                parsed_dt = datetime.strptime(scheduled_time, fmt)
                break
            except ValueError:
                pass
        
        if parsed_dt:
            pkt_now = datetime.utcnow() + timedelta(hours=5)
            
            # SMART LOGIC: Agar time guzray hue waqt me show ho rha he
            if parsed_dt < pkt_now:
                # 1. Agar AI ne ghalti se 24h clock miss kar di (e.g. 9 PM ko 9 AM likh diya)
                if parsed_dt + timedelta(hours=12) > pkt_now and parsed_dt.hour < 12:
                    parsed_dt = parsed_dt + timedelta(hours=12)
                # 2. Agar waqai time guzar chuka hai (jaise aaj ki bajaye kal ka kehna tha)
                else:
                    parsed_dt = parsed_dt + timedelta(days=1)

            scheduled_time = parsed_dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        pass

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT google_token FROM users WHERE email = %s", (user_email,))
        row = c.fetchone()
        if not row or not row[0]:
            conn.close()
            return "System Notification: Explicitly tell the user that their Gmail is not integrated."

        # Save scheduled email to DB
        c.execute("INSERT INTO scheduled_emails (user_email, to_email, subject, body, send_time) VALUES (%s, %s, %s, %s, %s)",
                  (user_email, to_email, subject, body, scheduled_time))
        conn.commit()
        conn.close()
        return "System Notification: Email scheduled successfully!"
    except Exception as e:
        return f"System Notification: Email scheduling failed. Error: {e}."

# --- NAYA: Background Email Scheduler ---
def background_email_scheduler():
    while True:
        conn = None
        try:
            conn = get_db_connection()
            if not conn: 
                time.sleep(60)
                continue
            c = conn.cursor(cursor_factory=DictCursor)
            pkt_now = datetime.utcnow() + timedelta(hours=5)
            current_time_str = pkt_now.strftime("%Y-%m-%d %H:%M:%S")

            c.execute("SELECT * FROM scheduled_emails WHERE send_time <= %s", (current_time_str,))
            emails_to_send = c.fetchall()

            for email_data in emails_to_send:
                print(f"Sending scheduled email to {email_data['to_email']}...")
                # No Flask request exists in this thread, so call the worker directly
                _deliver_email(email_data['user_email'], email_data['to_email'], email_data['subject'], email_data['body'])

                c.execute("DELETE FROM scheduled_emails WHERE id = %s", (email_data['id'],))
                conn.commit()
        except Exception as e:
            print(f"Error in background email scheduler: {e}")
        finally:
            if conn:
                conn.close()
            time.sleep(30) # Check every 30 seconds

# Start the scheduler in a separate thread
scheduler_thread = threading.Thread(target=background_email_scheduler)
scheduler_thread.daemon = True
scheduler_thread.start()

# ===============================
# TOOL MAP (AI Tools)
# ===============================

TOOL_MAP = {
    "get_current_time": get_current_time,
    "perform_autonomous_research": perform_autonomous_research,
    "search_google": search_google,
    "send_email": send_email,
    "schedule_email": schedule_email,
}

# ===============================
# AUTONOMOUS BROWSER AGENT (ENHANCED RESEARCHER)
# ===============================
AGENT_LOG_PATH = os.path.join(BASE_DIR, "agent_scripts", "agent_run.log")
AGENT_ACTIVE_MARKER = os.path.join(BASE_DIR, "agent_scripts", ".agent_active")
AGENT_MARKER_MAX_AGE = 21 * 60   # run max 20 min; older marker = stale (crashed server)


def _agent_phase():
    """Frontend loading screen ke liye: agent ab kis stage par hai? Sirf phase/step, raw log kabhi nahi."""
    try:
        if time.time() - os.path.getmtime(AGENT_ACTIVE_MARKER) > AGENT_MARKER_MAX_AGE:
            return {"phase": "starting", "step": 0}
    except OSError:
        return {"phase": "starting", "step": 0}   # koi run abhi shuru nahi hua
    try:
        with open(AGENT_LOG_PATH, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 16384))
            tail = f.read().decode("utf-8", "ignore")
    except OSError:
        return {"phase": "starting", "step": 0}
    if "Finished with a report" in tail or "Stopped without a report" in tail:
        return {"phase": "done", "step": 0}
    steps = re.findall(r"\[Step (\d+)\]", tail)
    if steps:
        return {"phase": "ready", "step": int(steps[-1])}
    if "Launching browser" in tail:
        return {"phase": "launching", "step": 0}
    return {"phase": "starting", "step": 0}


def execute_browser_agent(topic_name, api_key):
    print(f"Executing Visual Engine Sandbox Agent for query target: {topic_name}")
    try:
        # Purani run ka log saaf karo, phir marker lagao (is order se loading screen kabhi purani run ka phase nahi dekhti)
        subprocess.run(["docker", "exec", "sisca_agent_sandbox", "sh", "-c", ": > /app/agent_scripts/agent_run.log"], check=False)
        try:
            with open(AGENT_ACTIVE_MARKER, "w") as _m:
                _m.write(str(time.time()))
        except OSError:
            pass
        # --- NAYA FIX: Completely wipe the Chrome profile to prevent "Profile Error" and Multi-tab restores ---
        subprocess.run(["docker", "exec", "sisca_agent_sandbox", "sh", "-c", "rm -rf /app/agent_scripts/google_user_profile"], check=False)
        
        # Ensure koi purana chromium zombie pending me na ho
        subprocess.run(["docker", "exec", "sisca_agent_sandbox", "pkill", "-9", "-f", "chrome"], check=False)
        subprocess.run(["docker", "exec", "sisca_agent_sandbox", "pkill", "-9", "-f", "chromium"], check=False)

        # Command setup directing workflow execution to Docker container sandbox
        command = [
            "docker", "exec", "sisca_agent_sandbox",
            "python", "/app/agent_scripts/researcher.py",
            topic_name, api_key
        ]
        
        # Capture cleanly as text payload string directly.
        # Added a 20-minute execution window threshold (1200 seconds) to completely avoid web thread drops.
        process = subprocess.run(command, capture_output=True, text=True, check=False, timeout=1200)
        
        final_output = process.stdout.strip()
        error_output = process.stderr.strip()
        
        if process.returncode != 0:
            return f"Vision Engine System Exception: {error_output}"
            
        if not final_output:
            return "Vision Engine completed tracking evaluation but processing pipeline returned no text string summaries."
            
        return final_output
            
    except subprocess.TimeoutExpired:
        return "System Notification Error: Visual Agent exceeded the 20-minute processing threshold window limit."
    except Exception as e:
        return f"System Thread Tracking Failure Error Details: {str(e)}"
    finally:
        try:
            os.remove(AGENT_ACTIVE_MARKER)
        except OSError:
            pass

# ===============================
# GEMINI HELPERS
# ===============================

def create_client(api_key: str):
    # IMPORTANT:
    # For Gemini Developer API (API key based), do not force v1 here.
    # Official SDK docs show v1alpha for Gemini Developer API when overriding
    # versions, while v1 examples are shown for Vertex AI.
    # The SDK default is v1beta, which supports chat + function calling.
    return genai.Client(api_key=api_key)


def create_chat(client, model_name: str, history=None, sys_prompt=""): 
    config = types.GenerateContentConfig(
        system_instruction=sys_prompt, # NAYI LINE: Ab yeh dynamic prompt use karega
        tools=list(TOOL_MAP.values()),
        automatic_function_calling=types.AutomaticFunctionCallingConfig(
            disable=True
        ),
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(mode="AUTO")
        ),
    )

    chat = client.chats.create(
        model=model_name,
        config=config,
        history=history
    )
    return chat

def decode_image_part(image_base64: str):
    try:
        raw = base64.b64decode(image_base64)
        img = Image.open(io.BytesIO(raw))
        img.load()
        return img
    except Exception as e:
        raise ValueError(f"Invalid image data: {e}")


@app.route('/db-heartbeat')
def db_heartbeat():
    try:
        conn = get_db_connection()
        if not conn:
            return "Database Error: No connection available", 500
        c = conn.cursor()
        c.execute("SELECT 1")
        conn.close()
        return "Database is alive!", 200
    except Exception as e:
        print(f"Heartbeat error: {e}")
        return "Database Error", 500

@app.route('/authorize')
def authorize():
    # Identity server-side session se aati hai, ?email= parameter ab ignore hota hai
    email = current_user_email()
    if not email:
        return redirect('/auth')
    session['oauth_email'] = email

    redirect_uri = url_for('oauth2callback', _external=True)
    if "localhost" not in redirect_uri and "127.0.0.1" not in redirect_uri:
        redirect_uri = redirect_uri.replace("http://", "https://")

    try:
        flow = build_oauth_flow(redirect_uri)
    except Exception as e:
        print(f"OAuth setup error: {e}")
        return "Gmail integration is not configured on the server.", 500

    # Removed the PKCE challenge method
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )

    session['oauth_state'] = state
    return redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    state = session.get('oauth_state')
    email = session.get('oauth_email')

    # Sirf wahi logged-in user apna Gmail connect kar sakta hai jis ne process shuru kiya
    if not state or not email or email != current_user_email():
        return "Session expired. Please try connecting again."

    redirect_uri = url_for('oauth2callback', _external=True)
    if "localhost" not in redirect_uri and "127.0.0.1" not in redirect_uri:
        redirect_uri = redirect_uri.replace("http://", "https://")

    try:
        flow = build_oauth_flow(redirect_uri, state=state)

        auth_response = request.url
        if "localhost" not in auth_response and "127.0.0.1" not in auth_response:
            auth_response = auth_response.replace("http://", "https://")

        flow.fetch_token(authorization_response=auth_response)
        credentials = flow.credentials
    except Exception as e:
        print(f"OAuth callback error: {e}")
        return "Google authorization failed. Please try connecting again."

    # SECURITY: client_id / client_secret / token_uri DB me save nahi hotay (sirf user ke tokens).
    cred_dict = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'scopes': list(credentials.scopes or GMAIL_SCOPES),
    }

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET google_token = %s WHERE email = %s", (json.dumps(cred_dict), email))
    conn.commit()
    conn.close()

    session.pop('oauth_state', None)
    return redirect('/?gmail_connected=true')

# ===============================
# TOOL HANDLER
# ===============================

def handle_tool_call(fc, chat, api_key):
    args = dict(fc.args) if fc.args else {}

    if fc.name == "search_google":
        query = args.get("query", "").strip()
        if query:
            ret = {
                "action": "open_url",
                "url": f"https://www.google.com/search?q={quote_plus(query)}",
                "response": f"Searching for {query}...",
            }
        else:
            ret = {"action": "speak", "response": "Search query missing."}
        # Every function_call in Gemini history must be followed by a function_response,
        # otherwise the NEXT message of this user fails with a 400 error.
        try:
            chat.send_message(types.Part.from_function_response(
                name=fc.name, response={"result": ret["response"]}))
        except Exception:
            pass
        return ret

    try:
        func = TOOL_MAP.get(fc.name)

        if not func:
            result = f"Unsupported tool: {fc.name}"
        else:
            if fc.name == "perform_autonomous_research":
                result = func(api_key=api_key, **args)
            else:
                result = func(**args)

    except Exception as e:
        result = f"Tool error: {e}"

    tool_response = types.Part.from_function_response(
        name=fc.name,
        response={"result": result},
    )

    final = chat.send_message(tool_response)
    # --- Chain Execution ---
    # Agar AI ek tool chalane ke foran baad doosra tool chalana chahti hai 
    # (Example: Pehle Time check kiya, aur phir usi waqt Email Schedule ki)
    if getattr(final, "function_calls", None):
        return handle_tool_call(final.function_calls[0], chat, api_key)
    # -----------------------------------

    final_text = getattr(final, "text", None)
    return {
        "action": "speak",
        "response": final_text if final_text else str(result),
    }

def execute_data_interpreter(query, filename):
    
    gem_keys = active_gemini_keys()
    if not gem_keys:
        return "System Error: No API keys available for Data Sandbox.", None

    # Har execution ki ek unique ID hogi taake 2 users ka data aapas mein clash (mix) na ho
    session_id = str(uuid.uuid4())[:8]
    
    # Paths strictly mapped to Docker's internal volumes
    file_path = f"/app/uploads/{filename}"
    output_chart_name = f"chart_{session_id}.png"
    output_chart = f"/app/static/outputs/{output_chart_name}"

    # --- NAYA VALUE-ADD: CSV Headers Extraction ---
    # AI ko columns batana zaroori hai taake wo sahi columns par chart banaye
    columns_info = ""
    try:
        local_path = os.path.join(UPLOADS_DIR, filename)
        if local_path.lower().endswith('.csv'):
            with open(local_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                headers = next(reader)
                columns_info = f"\nThe dataset has the following columns: {headers}"
    except Exception:
        pass
    
    prompt = f"""You are an Expert Data Scientist. Write raw Python code to analyze the data file at '{file_path}'.{columns_info}
    User Query: {query}
    
    CRITICAL ARCHITECTURE RULES:
    1. LIBRARIES: You can safely use pandas, matplotlib, seaborn, scikit-learn, and numpy. They are pre-installed.
    2. DATA HYGIENE: Real-world data can have NaNs. You MUST safely handle/drop missing values before plotting or performing aggregations to prevent runtime crashes.
    3. VISUALIZATION: Use matplotlib.pyplot or seaborn to create the chart. 
    4. EXPORT: You MUST save the generated chart exactly to '{output_chart}'. Do NOT use plt.show().
    5. REPORTING: Print a concise, analytical text summary of the findings using print().
    6. FORMAT: Output ONLY valid, executable Python code. NO markdown formatting. NO explanations."""
    
    try:
        code = None
        last_error = "Unknown Error"
        num_keys = len(gem_keys)
        start_index = random.randint(0, num_keys - 1)

        # --- NAYA FIX: Smart Fallback Logic ---
        for i in range(num_keys):
            idx = (start_index + i) % num_keys
            key = gem_keys[idx]

            if time.time() < key_cooldowns.get(key, 0): 
                continue

            try:
                # 1. Pehle PRO model try karein
                client = create_client(key)
                response = client.models.generate_content(
                    model='gemini-pro-latest',
                    contents=prompt,
                )
                code = response.text.strip()
                break # Success! Loop se bahar aayen
            except Exception as e:
                last_error = str(e).lower()
                
                # 2. Agar PRO model fail ho (jaise Limit 0 ho), toh BINA cooldown lagaye FLASH try karein!
                try:
                    response = client.models.generate_content(
                        model='gemini-flash-latest',
                        contents=prompt,
                    )
                    code = response.text.strip()
                    break # Flash Success!
                except Exception as e2:
                    last_error = str(e2).lower()
                    # 3. Agar DONO (Pro aur Flash) fail ho jayen, phir us key ko global cooldown par daalein
                    if "429" in last_error or "resource_exhausted" in last_error:
                        key_cooldowns[key] = time.time() + 15
                    continue # Agli key try karein
                    
        if not code:
            return f"System Thread Failure: Code generation failed across all keys and models. Last Error: {last_error}", None

        # NAYA FIX: Bulletproof Regex jo har qisam ka markdown code block clean kar degi
        code = re.sub(r"^```(?:python|py)?\n", "", code, flags=re.MULTILINE | re.IGNORECASE)
        code = re.sub(r"```$", "", code, flags=re.MULTILINE).strip()
            
        # Save script to the shared agent_scripts directory with unique name
        script_name = f"data_interpreter_{session_id}.py"
        script_path = os.path.join(BASE_DIR, "agent_scripts", script_name)
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(code)
            
        # Execute INSIDE the secure Docker Sandbox
        cmd = ["docker", "exec", "sisca_agent_sandbox", "python", f"/app/agent_scripts/{script_name}"]
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        # Clean up local Python script after execution
        if os.path.exists(script_path):
            os.remove(script_path)
        
        if process.returncode != 0:
            return f"Code Execution Error in Sandbox:\n{process.stderr}", None
        
        # Check karein agar Sandbox ne sach mein Chart banaya hai ya sirf text report di hai
        chart_url = None
        if os.path.exists(os.path.join(OUTPUTS_DIR, output_chart_name)):
            chart_url = f"/static/outputs/{output_chart_name}?t={int(time.time())}"
        
        summary = process.stdout.strip()
        if not summary and not chart_url:
            summary = "Analysis complete, but the agent returned no printable summary or visual chart."
            
        return summary, chart_url
        
    except Exception as e:
        return f"System Thread Failure: {str(e)}", None

def process_with_gemini(user_message, image_base64=None, data_file=None, user_email="guest", is_voice=False, is_agent_active=False):
    hkey = history_key_for(user_email)   # har guest/user ki alag chat memory
    gem_keys = active_gemini_keys()      # user ki apni keys (agar di hon) warna server ki
    groq_keys = active_groq_keys()
    
    if hkey not in chat_histories:
        chat_histories[hkey] = []
        # PERSISTENT MEMORY: server restart / naye worker ke baad DB se purani chat wapas load karo
        try:
            for _role, _text in memory_store.load_recent_messages(get_db_connection, user_email):
                chat_histories[hkey].append(types.Content(role=_role, parts=[types.Part.from_text(text=_text)]))
        except Exception as e:
            print("Memory history restore skipped:", e)
        
    current_history = chat_histories[hkey]
    current_sys_prompt = get_system_prompt(is_voice, is_agent_active, user_email)
    # PERSISTENT MEMORY: is user ki relevant long-term facts system prompt me inject
    try:
        current_sys_prompt += memory_store.memory_prompt_block(
            memory_store.relevant_facts(get_db_connection, user_email, user_message))
    except Exception as e:
        print("Memory inject skipped:", e)
    
    # ---------------------------------------------------------
    # HELPER 1: GEMINI ENGINE (For Images, Tools & Action Execution)
    # ---------------------------------------------------------
    # Ab ye custom_msg accept karega (Agent chaining ke liye)
    def run_gemini(model_name, custom_msg=None):
        if not gem_keys: return None, "No API keys."
        num_keys = len(gem_keys)
        start_index = random.randint(0, num_keys - 1)
        
        # NAYA: Agar custom_msg aaya hai toh wo use karo, warna default user_message
        content = [custom_msg if custom_msg else user_message]
        if image_base64:
            try: content.append(decode_image_part(image_base64))
            except Exception as e: return {"action": "speak", "response": f"Image Error: {e}"}, None

        last_error = "Unknown error"
        for i in range(num_keys):
            idx = (start_index + i) % num_keys
            key = gem_keys[idx]

            if time.time() < key_cooldowns.get(key, 0): continue
            client = None
            try:
                client = create_client(key)
                chat = create_chat(client, model_name, history=current_history, sys_prompt=current_sys_prompt)
                response = chat.send_message(content)
                
                if getattr(response, "function_calls", None):
                    tool_result = handle_tool_call(response.function_calls[0], chat, key)
                    chat_histories[hkey] = chat.get_history()
                    return tool_result, None

                chat_histories[hkey] = chat.get_history()
                return {"action": "speak", "response": response.text if getattr(response, "text", None) else str(response)}, None

            except Exception as e:
                last_error = str(e).lower()
                if "connection" in last_error or "network" in last_error or "getaddrinfo" in last_error:
                    return {"action": "speak", "response": "Network Error: Please check your internet connection."}, None
                
                # BUG FIX: Cooldown ko 60 seconds se kam kar ke 15 seconds kar diya taake keys jaldi unlock hon
                if "429" in last_error or "resource_exhausted" in last_error:
                    key_cooldowns[key] = time.time() + 15 
                continue
            finally:
                if client:
                    try: client.close()
                    except: pass
        return None, last_error

    # ---------------------------------------------------------
    # HELPER 2: GROQ ENGINE (For High-Quality Text & Email Drafting)
    # ---------------------------------------------------------
    def run_groq():
        if not groq_keys: return None, "No Groq keys."
        
        # NAYI LINE: Drafting format ko bilkul clear kar diya gaya hai
        groq_sys_prompt = current_sys_prompt + "\nIMPORTANT: You are in DRAFTING mode. You cannot send emails. Write the draft and ask the user for confirmation. Once they confirm to send, the system will switch to Gemini to actually send it."
        
        messages = [{"role": "system", "content": groq_sys_prompt}]
        
        # BUG FIX: Groq ke liye sirf plain text messages filter karein taake tool data se wo crash na ho
        for msg in current_history:
            role = "assistant" if msg.role == "model" else "user"
            text = ""
            try:
                if hasattr(msg, 'parts') and msg.parts:
                    part = msg.parts[0]
                    if hasattr(part, 'text') and part.text:
                        text = part.text
            except: pass
            
            if text and text.strip():
                messages.append({"role": role, "content": text.strip()})
                
        messages.append({"role": "user", "content": user_message})
        
        last_error = "Unknown"
        for groq_key in groq_keys:
            try:
                groq_client = Groq(api_key=groq_key)
                completion = groq_client.chat.completions.create(
                    model="openai/gpt-oss-120b",
                    messages=messages
                )
                groq_response = completion.choices[0].message.content
                
                chat_histories[hkey].append(types.Content(role="user", parts=[types.Part.from_text(text=user_message)]))
                chat_histories[hkey].append(types.Content(role="model", parts=[types.Part.from_text(text=groq_response)]))
                
                return {"action": "speak", "response": groq_response}, None
            except Exception as e:
                last_error = str(e).lower()
                if "connection" in last_error or "network" in last_error or "timeout" in last_error:
                    return {"action": "speak", "response": "Network Error: Please check your internet connection."}, None
                continue
        return None, last_error

   # =========================================================
    # MAIN ROUTING LOGIC (AI Smart Intent Detection)
    # =========================================================
    def get_ai_intent(user_msg):
        if not groq_keys: return "CHAT" # Agar Groq nahi hai toh fallback
        try:
            # Gemini ke bajaye ab hum Groq (Llama) ko router banayenge
            groq_client = Groq(api_key=groq_keys[0])
        
            prompt = f"""Analyze the user's message. Classify intent as: 
            1. DATA: Explicitly asking to analyze, visualize, plot, chart, or work with a data file (CSV, Excel, etc.).
            2. ACTION: Confirming a draft (yes, ok, send it), OR asking to open websites. 
            3. DRAFT: Asking to COMPOSE/WRITE a new email. 
            4. AGENT: Asking for complex research or web search. 
            5. CHAT: General talk, greetings. 
            User: "{user_msg}" 
            Reply ONLY with one word: DATA, ACTION, DRAFT, AGENT, or CHAT."""
        
            completion = groq_client.chat.completions.create(
                model="openai/gpt-oss-120b",
                messages=[{"role": "user", "content": prompt}]
            )
            intent = completion.choices[0].message.content.strip().upper()
            return intent if intent in ["DATA", "ACTION", "DRAFT", "AGENT", "CHAT"] else "CHAT"
        except:
            return "CHAT"

    global_last_error = "Unknown error"
    smart_intent = "CHAT"
    
    # Image nahi hai toh pehle AI se intent check karwao
    if not image_base64:
        smart_intent = get_ai_intent(user_message)
        print(f"AI Intent Result: {smart_intent}")

    # Frontend se explicitly mode check karein
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        data = {}
    is_visualize_active = data.get("is_visualize_active", False)

    # ---------------------------------------------------------
    # TIER 0: DATA SANDBOX MODE (Code Interpreter)
    # ---------------------------------------------------------
    # Agar frontend se Visualize mode ON hai, YA file attach hai aur intent DATA ka hai
    if data_file and (is_visualize_active or smart_intent == "DATA"):
        print(f"Data Sandbox Triggered for file: {data_file}")
        summary, chart_url = execute_data_interpreter(user_message, data_file)
        
        # --- NAYA FIX: AI Amnesia Fix (Save report & Chart URL to AI memory) ---
        if summary:
            # Provide exact dataset name for the Subject line and clean chart URL for embedding
            ai_memory_text = f"DATASET NAME: {data_file}\nDATA ANALYSIS REPORT GENERATED:\n{summary}\nCHART_IMAGE_URL: {chart_url}"
            
            chat_histories[hkey].append(types.Content(role="user", parts=[types.Part.from_text(text=user_message)]))
            chat_histories[hkey].append(types.Content(role="model", parts=[types.Part.from_text(text=ai_memory_text)]))
            
            # --- NAYA FIX 2: Data -> Action Chaining (Auto-Email) ---
            action_keywords = ["send", "email", "bhej", "schedule", "forward", "mail"]
            if any(word in user_message.lower() for word in action_keywords):
                print("  Data Analysis Done! Now routing to Flash for Email Execution...")
                
                # Combine user's intent with the fresh data and force Gemini to use the tool
                combined_msg = f"User's Original Request: '{user_message}'\n\nDataset Name: {data_file}\nReport Data:\n{summary}\nChart URL: {chart_url}\n\nTask: The user asked to email this dataset report in their original request. Extract the target email address from their request. If they said 'me' or 'myself', use '{user_email}'. Call the 'send_email' tool IMMEDIATELY to send this report to the target email. Use the dataset name in the subject (e.g. '{data_file} Analysis Report'), format the report nicely in the body using HTML, and pass the Chart URL exactly into the 'chart_image_url' parameter."
                
                result, err = run_gemini("gemini-flash-latest", custom_msg=combined_msg)
                
                if result: 
                    # CRITICAL: Re-inject the chart_url into the dictionary so the Frontend UI still pops open the glass panel!
                    result["chart_url"] = chart_url
                    return result
            # ---------------------------------------------------------
        # -----------------------------------------------------------------------
        
        return {
            "action": "speak",
            "response": summary if summary else "Data analysis and chart generation completed.",
            "chart_url": chart_url
        }

    # === NAYI LOGIC ===
    # Agar AI kehti hai Agent chalao, lekin user ne button OFF kiya hua hai, 
    # toh hum usay zabardasti normal 'CHAT' par bhej denge.
    if smart_intent == "AGENT" and not is_agent_active:
        print("Agent request detected, but UI Toggle is OFF. Falling back to normal CHAT.")
        smart_intent = "CHAT"

    # ---------------------------------------------------------
    # TIER 1 (PREMIUM): AGENT MODE (Browser Automation)
    # ---------------------------------------------------------
    if smart_intent == "AGENT":
        print("  Activating Browser-Use Agent...")
        
        try:
            if not gem_keys:
                return {"action": "speak", "response": "No API keys available for Agent."}
                
            # --- NAYA FIX: Pass ALL keys to the Docker sandbox for internal rotation ---
            all_keys_string = ",".join(gem_keys)
                
            # Pass the entire comma-separated string of keys to the sandbox
            agent_response = perform_autonomous_research(user_message, all_keys_string)
            
            # --- NAYI LOGIC: Agent -> Tool Chaining ---
            # 2. Check karo kya user email ya koi aur action bhi chahta tha?
            action_keywords = ["send", "email", "bhej", "schedule", "forward"]
            if any(word in user_message.lower() for word in action_keywords):
                print("  Research Done! Now routing to Flash for Tool Execution...")
                
                # 3. Dono cheezon ko mila kar Flash ko ek task de do
                combined_msg = f"User's Original Request: '{user_message}'\n\nAgent's Research Data:\n{agent_response}\n\nTask: Fulfill the user's original request using this research data. The user asked to send an email. Extract the target email address from their request (if they said 'me' or 'myself', use '{user_email}'). Call the 'send_email' tool IMMEDIATELY to send this research data to that target email. Cleanly format the research data in the email body."
                
                # Flash (Tool Master) ko pukaaro
                result, err = run_gemini("gemini-flash-latest", custom_msg=combined_msg)
                
                if result: 
                    return result
                # Agar tool fail ho jaye, toh sirf research dikha do
                return {"action": "speak", "response": f"Research completed but tool action failed ({err}).\n\nResults:\n{agent_response}"}
            
            # Agar koi email nahi bhejni thi, toh direct result dikhao
            final_output = f"{agent_response}\n\n[Agent Task Completed (Testing Mode).]"
            return {"action": "speak", "response": final_output}
            
        except Exception as e:
            return {"action": "speak", "response": f"Agent Execution Error: {e}"}
        
    # Condition 1: Agar Action/Confirmation hai ya Image hai
    # NAYA: Agar user 'send' ya 'schedule' kahe confirmation ke baad, toh Gemini hi handle karega
    if image_base64 or smart_intent == "ACTION" or any(word in user_message.lower() for word in ["send", "bhej", "schedule", "yes", "ok"]):
        print("Action/Confirmation detected -> Using Gemini 3.1 Flash")
        result, err = run_gemini("gemini-flash-latest")
        if result: return result
        
        print(f"Flash failed -> Fallback to Gemini 3.1 Pro")
        result, err = run_gemini("gemini-pro-latest")
        if result: return result
        global_last_error = err
        
    # Condition 2: Agar Draft ya normal Chat hai
    else:
        print("Text/Drafting detected -> Using Groq")
        result, err = run_groq()
        if result: return result
        
        print(f"Groq failed -> Fallback to Fast Gemini 3.1 Flash")
        result, err = run_gemini("gemini-flash-latest")
        if result: return result
        global_last_error = err

    # Agar tamaam models fail ho jayen toh exact error bataye ga
    return {"action": "speak", "response": f"All AI models are currently busy. Error details: {global_last_error}"}


# ===============================
# ROUTES
# ===============================

ALLOWED_UPLOAD_EXT = {'.csv', '.xlsx', '.xls', '.json', '.txt', '.png', '.jpg', '.jpeg', '.gif', '.webp'}

@app.route("/api/upload-data", methods=["POST"])
@rate_limit(30, 3600)
def upload_data():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    # NAYA FIX: File name ko secure karein taake Path Traversal attack na ho sakay
    filename = secure_filename(file.filename)
    if not filename or os.path.splitext(filename)[1].lower() not in ALLOWED_UPLOAD_EXT:
        return jsonify({"error": "This file type is not allowed."}), 400
    filepath = os.path.join(UPLOADS_DIR, filename)
    file.save(filepath)
    return jsonify({"success": True, "filename": filename})

@app.route("/api/feedback", methods=["POST"])
@rate_limit(5, 3600)
def feedback():
    try:
        data = request.get_json(silent=True) or {}
        feedback_text = str(data.get("text", "")).strip()[:2000]
        user_email = current_user_email()  # client ka bheja hua email ignore hota hai

        if not feedback_text:
            return jsonify({"error": "Feedback text is empty."}), 400

        if feedback_text.startswith("TEST USER REQUEST:"):
            if not user_email:
                return jsonify({"error": "Please login first."}), 401

            # 1. Database me status '1' (Requested) kar dein
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("UPDATE users SET test_status = 1 WHERE email = %s", (user_email,))
            conn.commit()
            conn.close()

            # 2. Email me SIGNED Approve link bhjy ga (token ke baghair koi khud ko approve nahi kar sakta)
            subject = "New Test User Request for Sisca AI"
            token = approval_serializer.dumps(user_email)
            approve_link = f"{request.host_url}api/approve-test-user?token={token}"
            body = f"A user has requested integration access:\n\nEmail: {user_email}\n\nClick the link below to APPROVE this user (valid for 7 days):\n{approve_link}"
        else:
            subject = "New Feedback from Sisca AI User"
            body = f"User has submitted the following feedback:\n\n{feedback_text}"

        result = send_system_email("no-reply@siscaai.online", subject, body)

        if "failed" in result.lower():
            return jsonify({"error": "Could not send your request. Please try again later."}), 500

        return jsonify({"success": True, "message": "Request processed successfully."})

    except Exception as e:
        print(f"Feedback error: {e}")
        return jsonify({"error": "Could not process your request. Please try again."}), 500


# --- Admin Email me link par click karne par (signed token zaroori) ---
@app.route("/api/approve-test-user", methods=["GET"])
def approve_test_user():
    token = request.args.get("token", "")
    try:
        email = approval_serializer.loads(token, max_age=7 * 24 * 3600)
    except SignatureExpired:
        return "This approval link has expired. Ask the user to send a new request.", 400
    except BadSignature:
        return "Invalid approval link.", 400

    try:
        # Status ko '2' (Approved) kar dega
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET test_status = 2 WHERE email = %s", (email,))
        conn.commit()
        conn.close()
        return f"<h1 style='color: green; font-family: sans-serif; text-align: center; margin-top: 50px;'>Success!</h1><p style='text-align: center; font-family: sans-serif;'><b>{escape(email)}</b> has been successfully APPROVED as a Test User.<br>They can now connect their Gmail.</p>"
    except Exception as e:
        print(f"Approve error: {e}")
        return "Something went wrong while approving this user.", 500

# --- Frontend live status check karega (identity session se) ---

@app.route("/api/check-status", methods=["POST"])
def check_status():
    email = current_user_email()
    if not email:
        return jsonify({"test_status": 0, "gmail_connected": False, "logged_in": False})

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT test_status, google_token FROM users WHERE email = %s", (email,))
        row = c.fetchone()
        conn.close()

        if row:
            test_status = row[0] if row[0] else 0
            has_token = bool(row[1])
            return jsonify({"test_status": test_status, "gmail_connected": has_token, "logged_in": True})

        return jsonify({"test_status": 0, "gmail_connected": False, "logged_in": True})

    except Exception as e:
        print(f"Check-status error: {e}")
        return jsonify({"error": "Could not check status."}), 500

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/auth")
def auth_page():
    return render_template("auth.html")

# ===============================
# FORGOT PASSWORD ROUTES
# ===============================
@app.route("/api/forgot-otp", methods=["POST"])
@rate_limit(5, 3600)
def forgot_otp():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()

    if not email:
        return jsonify({"error": "Email is required!"}), 400
    if not valid_email(email):
        return jsonify({"error": "Please enter a valid email address."}), 400

    # Same jawab chahe email registered ho ya nahi (taake koi emails ki list na nikal sake)
    generic_ok = jsonify({"success": True, "message": "If this email is registered, a reset code has been sent."})

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE email = %s", (email,))
        exists = c.fetchone()
        conn.close()
    except Exception as e:
        print(f"forgot-otp DB error: {e}")
        return jsonify({"error": "Something went wrong. Please try again."}), 500

    if not exists:
        return generic_ok

    otp = issue_otp("reset", email)
    if otp is None:   # 60 sec cooldown ke andar dobara request
        return generic_ok

    subject = "Sisca AI - Password Reset Code"
    body = f"We received a request to reset your password.\n\nYour 6-digit reset code is: {otp}\n\nThis code expires in 10 minutes. If you didn't request this, please ignore this email."

    result = send_system_email(email, subject, body)

    if "failed" in result.lower():
        return jsonify({"error": "Failed to send email. Please try again later."}), 500

    return generic_ok


@app.route("/api/reset-password", methods=["POST"])
@rate_limit(10, 3600)
def reset_password():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    otp = str(data.get("otp", "")).strip()
    new_password = str(data.get("new_password", ""))

    if not email or not otp or not new_password:
        return jsonify({"error": "All fields are required!"}), 400

    if not check_otp("reset", email, otp):
        return jsonify({"error": "Invalid or expired Reset Code!"}), 400

    pw_err = password_error(new_password)
    if pw_err:
        return jsonify({"error": pw_err}), 400

    hashed_pw = generate_password_hash(new_password)

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
        conn.commit()
        conn.close()

        # Reset kamyab hone par OTP delete kar dein
        clear_otp("reset", email)

        return jsonify({"success": True, "message": "Password changed successfully! You can now login."})
    except Exception as e:
        print(f"reset-password error: {e}")
        return jsonify({"error": "Something went wrong. Please try again."}), 500

@app.route("/api/clear-chat", methods=["POST"])
def clear_chat_history():
    # Sirf us specific user (ya us guest session) ki chat clear hogi
    key = history_key_for(current_user_email() or "guest")
    if key in chat_histories:
        chat_histories[key] = []
    if current_user_email():
        try: memory_store.delete_messages(get_db_connection, current_user_email())
        except Exception as e: print("Memory clear skipped:", e)

    return jsonify({"success": True, "message": "Chat memory cleared."})

@app.route("/api/send-otp", methods=["POST"])
@rate_limit(5, 3600)
def send_otp():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()

    if not email:
        return jsonify({"error": "Email is required to send OTP!"}), 400
    if not valid_email(email):
        return jsonify({"error": "Please enter a valid email address."}), 400

    # Check karein ke email pehle se registered to nahi
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE email = %s", (email,))
        already = c.fetchone()
        conn.close()
    except Exception as e:
        print(f"send-otp DB error: {e}")
        return jsonify({"error": "Something went wrong. Please try again."}), 500

    if already:
        return jsonify({"error": "Email is already registered! Please login."}), 400

    otp = issue_otp("signup", email)
    if otp is None:
        return jsonify({"error": "Please wait a minute before requesting another code."}), 429

    subject = "Sisca AI - Verification Code"
    body = f"Welcome to Sisca AI!\n\nYour 6-digit verification code is: {otp}\n\nThis code expires in 10 minutes. Please enter it to complete your registration."

    result = send_system_email(email, subject, body)

    if "failed" in result.lower():
        return jsonify({"error": "Failed to send email. Please try again later."}), 500

    return jsonify({"success": True, "message": "Verification code sent to your email!"})

@app.route("/api/signup", methods=["POST"])
@rate_limit(10, 3600)
def signup():
    data = request.get_json(silent=True) or {}
    first_name = str(data.get("first_name", "")).strip()
    last_name = str(data.get("last_name", "")).strip()
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", ""))
    otp = str(data.get("otp", "")).strip()

    if not first_name or not last_name or not email or not password or not otp:
        return jsonify({"error": "All fields including OTP are required!"}), 400
    if len(first_name) > 50 or len(last_name) > 50:
        return jsonify({"error": "Name is too long."}), 400
    if not valid_email(email):
        return jsonify({"error": "Please enter a valid email address."}), 400

    # OTP Verification Check
    if not check_otp("signup", email, otp):
        return jsonify({"error": "Invalid or expired Verification Code!"}), 400

    pw_err = password_error(password)
    if pw_err:
        return jsonify({"error": pw_err}), 400

    hashed_pw = generate_password_hash(password)

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
                  (first_name, last_name, email, hashed_pw))
        conn.commit()
        conn.close()

        clear_otp("signup", email)

        return jsonify({"success": True, "message": "Account created successfully! Please login."})
    except psycopg2.IntegrityError:
        return jsonify({"error": "Email already registered."}), 400
    except Exception as e:
        print(f"signup error: {e}")
        return jsonify({"error": "Something went wrong. Please try again."}), 500


@app.route("/api/login", methods=["POST"])
@rate_limit(30, 900)
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", "")).strip()

    # Ek hi email par brute-force rokne ke liye: 15 minute me max 8 koshishein
    allowed, _ = _hit(("login-email", email.lower()), 8, 900)
    if not allowed:
        return jsonify({"error": "Too many login attempts. Please try again in a few minutes."}), 429

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT first_name, last_name, password, google_token FROM users WHERE email = %s", (email,))
        user = c.fetchone()
        conn.close()
    except Exception as e:
        print(f"login DB error: {e}")
        return jsonify({"error": "Something went wrong. Please try again."}), 500

    if user and check_password_hash(user[2], password):
        has_token = bool(user[3])

        # SERVER-SIDE LOGIN: ab identity cookie-session me hai (sirf localStorage par nahi)
        session.clear()
        session["user_email"] = email
        session.permanent = True

        return jsonify({
            "success": True,
            "first_name": user[0],
            "last_name": user[1],
            "email": email,
            "gmail_connected": has_token
        })
    else:
        return jsonify({"error": "Invalid email or password!"}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})


# ===============================
# TEXT TO SPEECH (TTS) ENGINE
# ===============================
def generate_tts_audio(text):
    # AI ke markdown (*, #) ko remove kar rahe hain taake wo bolte waqt inhein symbols ki tarah na parhay
    clean_text = re.sub(r'[*#_]', '', text)
    
    if re.search(r'[\u0600-\u06FF]', clean_text):
        voice_model = "ur-PK-UzmaNeural" # Pakistani Female Urdu Voice
    else:
        voice_model = "en-US-AriaNeural" # Default English Female Voice
        
    async def _generate():
        # Ab dynamic voice model use hoga
        communicate = edge_tts.Communicate(clean_text, voice_model)
        audio_bytes = b""
        async for chunk in communicate.stream():
            if chunk["type"] == "audio":
                audio_bytes += chunk["data"]
        return base64.b64encode(audio_bytes).decode('utf-8')
        
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        b64_audio = loop.run_until_complete(_generate())
        loop.close()
        return b64_audio
    except Exception as e:
        print(f"TTS Error: {e}")
        return None
# Route se pehle ek global dictionary bnai IP tracking ke liye
_usage_fallback = {}  # sirf tab use hota hai jab DB available na ho

def consume_usage(key, field, limit):
    """Atomically count one use of `field` ('general_count' or 'agent_count') for `key` today.
    Returns (allowed, count_now). If the daily limit is already reached nothing is incremented."""
    if field not in ("general_count", "agent_count"):
        raise ValueError("bad field")
    today = str(date.today())
    conn = None
    try:
        conn = get_db_connection()
        if conn:
            c = conn.cursor()
            c.execute(f"""INSERT INTO daily_usage (usage_key, usage_date, {field}) VALUES (%s, %s, 1)
                          ON CONFLICT (usage_key, usage_date)
                          DO UPDATE SET {field} = daily_usage.{field} + 1
                          WHERE daily_usage.{field} < %s
                          RETURNING {field}""", (key, today, limit))
            row = c.fetchone()
            conn.commit()
            return (True, row[0]) if row else (False, limit)
    except Exception as e:
        print(f"Usage limit DB error (falling back to memory): {e}")
    finally:
        if conn:
            try: conn.close()
            except Exception: pass
    # Fallback: in-memory (same behaviour as before)
    k = (key, today, field)
    n = _usage_fallback.get(k, 0)
    if n >= limit:
        return False, n
    _usage_fallback[k] = n + 1
    return True, n + 1

@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.get_json() or {}
    user_message = str(data.get("message", "")).strip()[:8000]
    image_base64 = data.get("image", None)
    data_file = data.get("data_file", None)
    if data_file:
        # Path traversal se bachao: sirf uploads folder ki asli file allow
        data_file = secure_filename(str(data_file))
        if not data_file or not os.path.isfile(os.path.join(UPLOADS_DIR, data_file)):
            data_file = None
    user_email = current_user_email() or "guest"   # server-side session (client email ignore)
    
    is_voice = data.get("isVoice", False)      
    is_agent_active = data.get("is_agent_active", False)

    if not user_message:
        return jsonify({"action": "speak", "response": "Please provide a message."}), 400

    # ==========================================
    # RATE LIMITING LOGIC (General & Agent)
    # ==========================================
    warning_message = None

    if user_email == "guest":
        # --- GUEST LIMITS ---
        guest_key = "ip:" + client_ip()

        # Check Agent Limit for Guest (Max 3)
        if is_agent_active:
            allowed, _ = consume_usage(guest_key, "agent_count", 3)
            if not allowed:
                return jsonify({"action": "speak", "response": "Guest Limit Reached: You have used your 3 free Research queries for today. Please **Login** to get 10 daily queries!"})

        # Check General Limit (Max 10)
        allowed, current_count = consume_usage(guest_key, "general_count", 10)
        if not allowed:
            return jsonify({"error": "LIMIT_REACHED"}), 403

        if current_count == 5:
            warning_message = "You have 5 free messages left for today. Login for unlimited access!"

    else:
        # --- LOGGED-IN USER AGENT LIMITS (Max 10 per day) ---
        if is_agent_active:
            allowed, _ = consume_usage("user:" + user_email, "agent_count", 10)
            if not allowed:
                return jsonify({"action": "speak", "response": "Daily Limit Reached: You have used all 10 Research Mode queries for today. Please try again tomorrow."})

    # ==========================================

    # User ki apni Gemini/Groq keys (optional) - sirf is request ke liye
    set_request_user_keys(data.get("user_keys"))

    response = process_with_gemini(user_message, image_base64, data_file, user_email, is_voice, is_agent_active)

    # PERSISTENT MEMORY: exchange DB me save + naye durable facts background me nikalo
    if user_email != "guest" and response and response.get("response"):
        try:
            memory_store.save_exchange(get_db_connection, user_email, user_message, response["response"])
            _gk, _qk = list(active_gemini_keys()), list(active_groq_keys())  # request context khatam hone se pehle
            memory_store.extract_and_store_async(
                get_db_connection, user_email, user_message, response["response"],
                lambda prompt: _memory_llm(prompt, _gk, _qk))
        except Exception as e:
            print("Memory save skipped:", e)
    
    # --- NAYI LOGIC: Generate Audio if Voice Command was used ---
    if is_voice and response and "response" in response:
        # Pabandiyaan (Length limit) hata di taake lamba text bhi bol sakay
        audio_b64 = generate_tts_audio(response["response"])
        if audio_b64:
            response["audio"] = audio_b64
    
    # Agar warning deni hai toh response ke sath bhej dein
    if warning_message:
        response["warning_alert"] = warning_message

    return jsonify(response)

# ===============================
# PERSISTENT MEMORY (helpers + endpoints)
# ===============================
def _memory_llm(prompt, gemini_keys, groq_keys):
    """Chhota text-only call, fact extraction ke liye. Pehle Groq, phir Gemini."""
    for k in groq_keys or []:
        try:
            r = Groq(api_key=k).chat.completions.create(
                model="openai/gpt-oss-120b", messages=[{"role": "user", "content": prompt}])
            return r.choices[0].message.content
        except Exception:
            continue
    for k in gemini_keys or []:
        client = None
        try:
            client = create_client(k)
            return client.models.generate_content(model="gemini-flash-latest", contents=prompt).text
        except Exception:
            continue
        finally:
            if client:
                try: client.close()
                except Exception: pass
    return ""


@app.route("/api/memories", methods=["GET"])
def list_memories():
    email = current_user_email()
    if not email:
        return jsonify({"error": "Login required"}), 401
    return jsonify({"memories": memory_store.list_facts(get_db_connection, email)})


@app.route("/api/memories/<int:fact_id>", methods=["DELETE"])
def delete_memory(fact_id):
    email = current_user_email()
    if not email:
        return jsonify({"error": "Login required"}), 401
    return jsonify({"success": memory_store.delete_fact(get_db_connection, email, fact_id)})


@app.route("/api/memories", methods=["DELETE"])
def delete_all_memories():
    email = current_user_email()
    if not email:
        return jsonify({"error": "Login required"}), 401
    memory_store.delete_all_facts(get_db_connection, email)
    return jsonify({"success": True})


# ===============================
# USER'S SUPABASE (connection test)
# ===============================
def _parse_supabase_url(raw):
    """User ki Supabase Postgres connection string ko strict validate karta hai.
    SSRF se bachne ke liye: sirf *.supabase.co / *.supabase.com host, sirf port 5432/6543,
    aur URI query me host/hostaddr jaisi libpq overrides allow nahi (sirf sslmode)."""
    if not raw or len(raw) > 600:
        return None, "Enter a valid Supabase connection string."
    try:
        u = urlsplit(raw)
        host = (u.hostname or "").lower()
        port = u.port
    except Exception:
        return None, "Enter a valid Supabase connection string."
    if u.scheme not in ("postgresql", "postgres"):
        return None, "Connection string must start with postgresql://"
    if not (host.endswith(".supabase.co") or host.endswith(".supabase.com")):
        return None, "Host must be a Supabase host (*.supabase.co or *.supabase.com)."
    if port not in (None, 5432, 6543):
        return None, "Supabase port must be 5432 or 6543."
    if not u.username or not u.password:
        return None, "Connection string must include the database user and password."
    q = parse_qs(u.query)
    if any(k.lower() != "sslmode" for k in q):
        return None, "Only the sslmode option is allowed in the connection string."
    dbname = unquote(u.path.lstrip("/")) or "postgres"
    return {
        "host": host, "port": port or 5432,
        "user": unquote(u.username), "password": unquote(u.password),
        "dbname": dbname,
    }, None

@app.route("/api/test-supabase", methods=["POST"])
@rate_limit(10, 300)
def test_supabase():
    data = request.get_json(silent=True) or {}
    params, err = _parse_supabase_url(str(data.get("url", "")).strip())
    if err:
        return jsonify({"ok": False, "error": err}), 400
    conn = None
    try:
        conn = psycopg2.connect(sslmode="require", connect_timeout=8, **params)
        c = conn.cursor()
        c.execute("SELECT 1")
        c.fetchone()
        return jsonify({"ok": True})
    except Exception as e:
        # URL/password kabhi log nahi karte, sirf error ki type
        print(f"supabase test failed: {type(e).__name__}")
        return jsonify({"ok": False, "error": "Could not connect. Check the connection string/password and that the project is not paused."})
    finally:
        if conn:
            try: conn.close()
            except Exception: pass

@app.route("/api/agent-status", methods=["GET"])
def agent_status():
    resp = jsonify(_agent_phase())
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/stop-agent", methods=["POST"])
@rate_limit(30, 60)
def stop_agent():
    print("System Notification: Signal received to forcefully terminate agent process.")
    try:
        # 1. Container ke andar chalne wali Python script ko forcefully (SIGKILL) kill karein
        subprocess.run(["docker", "exec", "sisca_agent_sandbox", "pkill", "-9", "-f", "researcher.py"], check=False)
        
        # 2. Zombie Chrome/Chromium processes ko forcefully shoot karein
        subprocess.run(["docker", "exec", "sisca_agent_sandbox", "pkill", "-9", "-f", "chrome"], check=False)
        subprocess.run(["docker", "exec", "sisca_agent_sandbox", "pkill", "-9", "-f", "chromium"], check=False)
        
        # 3. NAYA FIX: Tamam Profile directory ko tabah kar dein. Forceful kill se DB corrupt hoti hai, fresh profile zaroori hai.
        subprocess.run(["docker", "exec", "sisca_agent_sandbox", "sh", "-c", "rm -rf /app/agent_scripts/google_user_profile"], check=False)
        
        return jsonify({"success": True, "message": "Agent and Browser processes successfully terminated."}), 200
    except Exception as e:
        print(f"Error terminating agent process: {e}")
        return jsonify({"success": False, "message": "Failed to terminate agent process."}), 500

if __name__ == '__main__':
    _debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    # Debug mode me Werkzeug debugger remote code execution deta hai, is liye sirf localhost par.
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)), host='127.0.0.1' if _debug else '0.0.0.0')