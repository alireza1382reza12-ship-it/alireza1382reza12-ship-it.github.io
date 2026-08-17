import os
import json
import time
import secrets
import hashlib
import html
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from http import cookies

BASE = os.path.expanduser("~/music-site")
PORT = 8080

USERS_FILE = os.path.join(BASE, "users.json")
SESSIONS = {}

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(users):
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)
    os.replace(tmp, USERS_FILE)

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    result = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120000
    ).hex()
    return salt + "$" + result

def check_password(password, stored):
    try:
        salt, old_hash = stored.split("$", 1)
        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            120000
        ).hex()
        return secrets.compare_digest(new_hash, old_hash)
    except Exception:
        return False

def get_session_user(handler):
    raw = handler.headers.get("Cookie", "")
    jar = cookies.SimpleCookie()
    try:
        jar.load(raw)
    except Exception:
        return None

    sid = jar.get("nava_session")
    if not sid:
        return None

    sid = sid.value
    data = SESSIONS.get(sid)

    if not data:
        return None

    if data["expires"] < time.time():
        SESSIONS.pop(sid, None)
        return None

    return data["username"]

def send_json(handler, obj, status=200):
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)

def read_json(handler):
    try:
        length = int(handler.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = handler.rfile.read(length)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}

AUTH_UI = r"""
<style>
#nava-menu-button{
position:fixed;top:18px;right:18px;z-index:99999;
width:48px;height:48px;border:0;border-radius:50%;
background:rgba(30,30,38,.95);color:white;font-size:28px;
box-shadow:0 4px 20px rgba(0,0,0,.35);cursor:pointer
}
#nava-menu-box{
display:none;position:fixed;top:74px;right:14px;z-index:99998;
width:270px;padding:16px;border-radius:20px;
background:#17151d;color:white;border:1px solid #6330a8;
box-shadow:0 10px 35px rgba(0,0,0,.55)
}
#nava-menu-box button{
width:100%;margin:6px 0;padding:13px;border:0;border-radius:13px;
background:#292431;color:white;font-size:15px;cursor:pointer
}
#nava-auth{
display:none;position:fixed;inset:0;z-index:100000;
background:rgba(0,0,0,.72);align-items:center;justify-content:center;
padding:20px
}
#nava-auth-card{
width:min(390px,100%);background:#17151d;color:white;
border:1px solid #7b2cff;border-radius:24px;padding:24px;
box-shadow:0 15px 50px rgba(0,0,0,.6)
}
#nava-auth-card h2{text-align:center;margin-top:0}
#nava-auth-card input{
box-sizing:border-box;width:100%;padding:14px;margin:7px 0;
border-radius:12px;border:1px solid #49404f;background:#0d0b10;
color:white;font-size:16px
}
#nava-auth-card .main{
width:100%;padding:14px;border:0;border-radius:13px;
background:linear-gradient(90deg,#8b20ff,#a52cff);
color:white;font-size:16px;margin-top:10px
}
#nava-auth-card .close{
float:left;background:none;border:0;color:#aaa;font-size:25px
}
#nava-msg{text-align:center;margin-top:12px;color:#ddd;min-height:22px}
.nava-user{
padding:12px;text-align:center;border-radius:13px;
background:#21192d;margin-bottom:8px;color:#c68cff
}
</style>

<button id="nava-menu-button" onclick="navaToggleMenu()">⋮</button>

<div id="nava-menu-box">
  <div id="nava-user-box" class="nava-user">مهمان</div>
  <button onclick="navaOpenAuth('login')">🔐 ورود</button>
  <button onclick="navaOpenAuth('register')">👤 ثبت‌نام</button>
  <button onclick="navaAccount()">👤 حساب من</button>
  <button onclick="navaLogout()">🚪 خروج</button>
</div>

<div id="nava-auth">
  <div id="nava-auth-card">
    <button class="close" onclick="navaCloseAuth()">×</button>
    <h2 id="nava-auth-title">ورود به NAVA</h2>

    <input id="nava-name" placeholder="نام کاربری" autocomplete="username">
    <input id="nava-pass" type="password" placeholder="رمز عبور" autocomplete="current-password">
    <input id="nava-pass2" type="password" placeholder="تکرار رمز عبور"
           style="display:none" autocomplete="new-password">

    <button class="main" onclick="navaSubmit()">ادامه</button>
    <div id="nava-msg"></div>
  </div>
</div>

<script>
let navaMode = "login";

function navaToggleMenu(){
  const x=document.getElementById("nava-menu-box");
  x.style.display=x.style.display==="block"?"none":"block";
  navaMe();
}

function navaOpenAuth(mode){
  navaMode=mode;
  document.getElementById("nava-auth").style.display="flex";
  document.getElementById("nava-pass2").style.display =
      mode==="register" ? "block" : "none";
  document.getElementById("nava-auth-title").innerText =
      mode==="register" ? "ساخت حساب NAVA" : "ورود به NAVA";
  document.getElementById("nava-msg").innerText="";
  document.getElementById("nava-menu-box").style.display="none";
}

function navaCloseAuth(){
  document.getElementById("nava-auth").style.display="none";
}

async function navaSubmit(){
  const username=document.getElementById("nava-name").value.trim();
  const password=document.getElementById("nava-pass").value;
  const password2=document.getElementById("nava-pass2").value;
  const msg=document.getElementById("nava-msg");

  if(!username || !password){
    msg.innerText="نام کاربری و رمز عبور را وارد کن.";
    return;
  }

  if(navaMode==="register" && password!==password2){
    msg.innerText="تکرار رمز عبور درست نیست.";
    return;
  }

  const url=navaMode==="register"?"/api/register":"/api/login";

  try{
    const r=await fetch(url,{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({username,password})
    });

    const d=await r.json();
    msg.innerText=d.message||"خطا";

    if(r.ok){
      setTimeout(()=>{
        navaCloseAuth();
        navaMe();
      },500);
    }
  }catch(e){
    msg.innerText="ارتباط با سرور برقرار نشد.";
  }
}

async function navaMe(){
  try{
    const r=await fetch("/api/me",{cache:"no-store"});
    const d=await r.json();

    document.getElementById("nava-user-box").innerText =
      d.logged_in ? "👤 "+d.username : "👤 مهمان";
  }catch(e){}
}

async function navaLogout(){
  try{
    await fetch("/api/logout",{method:"POST"});
    navaMe();
    alert("از حساب خارج شدی.");
  }catch(e){}
}

async function navaAccount(){
  try{
    const r=await fetch("/api/me",{cache:"no-store"});
    const d=await r.json();

    if(!d.logged_in){
      navaOpenAuth("login");
      return;
    }

    document.getElementById("nava-menu-box").style.display="none";
    alert("حساب کاربری\n\nنام کاربری: "+d.username);
  }catch(e){}
}

navaMe();
</script>
"""

class Handler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE, **kwargs)

    def log_message(self, format, *args):
        pass

    def send_error_json(self, message, status=400):
        send_json(self, {"ok":False,"message":message}, status)

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/me":
            username = get_session_user(self)
            send_json(self, {
                "ok": True,
                "logged_in": bool(username),
                "username": username
            })
            return

        if path == "/" or path == "/index.html":
            index = os.path.join(BASE, "index.html")

            if not os.path.exists(index):
                self.send_error(404, "index.html not found")
                return

            try:
                with open(index, "r", encoding="utf-8") as f:
                    page = f.read()

                if "id=\"nava-menu-button\"" not in page:
                    if "</body>" in page:
                        page = page.replace("</body>", AUTH_UI + "\n</body>")
                    else:
                        page += AUTH_UI

                data = page.encode("utf-8")

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

            except Exception as e:
                self.send_error(500, str(e))
                return

        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        data = read_json(self)

        if path == "/api/register":
            username = str(data.get("username","")).strip()
            password = str(data.get("password",""))

            if len(username) < 3:
                self.send_error_json("نام کاربری باید حداقل ۳ حرف باشد.")
                return

            if len(username) > 30:
                self.send_error_json("نام کاربری خیلی طولانی است.")
                return

            if len(password) < 6:
                self.send_error_json("رمز عبور باید حداقل ۶ کاراکتر باشد.")
                return

            if any(c in username for c in "/\\<>\"'"):
                self.send_error_json("نام کاربری نامعتبر است.")
                return

            users = load_users()

            if username.lower() in {u.lower() for u in users}:
                self.send_error_json("این نام کاربری قبلاً ثبت شده است.")
                return

            users[username] = {
                "password": hash_password(password),
                "created_at": int(time.time())
            }

            save_users(users)

            sid = secrets.token_urlsafe(32)
            SESSIONS[sid] = {
                "username": username,
                "expires": time.time() + 60*60*24*30
            }

            send_json(self, {
                "ok":True,
                "message":"حساب با موفقیت ساخته شد."
            })

            self.send_header if False else None
            return

        if path == "/api/login":
            username = str(data.get("username","")).strip()
            password = str(data.get("password",""))

            users = load_users()
            real_username = next(
                (u for u in users if u.lower() == username.lower()),
                None
            )

            if not real_username or not check_password(
                password, users[real_username]["password"]
            ):
                self.send_error_json("نام کاربری یا رمز عبور اشتباه است.", 401)
                return

            sid = secrets.token_urlsafe(32)
            SESSIONS[sid] = {
                "username": real_username,
                "expires": time.time() + 60*60*24*30
            }

            data_out = json.dumps({
                "ok":True,
                "message":"با موفقیت وارد شدی."
            }, ensure_ascii=False).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type","application/json; charset=utf-8")
            self.send_header("Set-Cookie",
                             f"nava_session={sid}; Path=/; HttpOnly; SameSite=Lax")
            self.send_header("Content-Length",str(len(data_out)))
            self.end_headers()
            self.wfile.write(data_out)
            return

        if path == "/api/logout":
            raw = self.headers.get("Cookie","")
            jar = cookies.SimpleCookie()
            try:
                jar.load(raw)
            except Exception:
                pass

            sid = jar.get("nava_session")
            if sid:
                SESSIONS.pop(sid.value, None)

            data_out = '{"ok":true,"message":"خارج شدی."}'.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type","application/json; charset=utf-8")
            self.send_header(
                "Set-Cookie",
                "nava_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            )
            self.send_header("Content-Length",str(len(data_out)))
            self.end_headers()
            self.wfile.write(data_out)
            return

        self.send_error(404)

print("================================")
print("       NAVA MUSIC SERVER")
print("================================")
print("http://127.0.0.1:8080")
print("ثبت‌نام و ورود فعال است")
print("Ctrl+C برای توقف")

server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)

try:
    server.serve_forever()
except KeyboardInterrupt:
    print("\nServer stopped")
finally:
    server.server_close()
