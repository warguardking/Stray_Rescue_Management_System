"""SRMS - Stray Rescue Management System. Run: python server.py  then open http://localhost:8000"""
import hashlib, json, os, secrets, sqlite3, time
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

HERE = os.path.dirname(os.path.abspath(__file__)); DB = os.path.join(HERE, "srms.db")
# One entry per module table. who = which role may create rows; st = status list (first one is the default).
T = {"reports":   dict(cols=["species", "address", "description", "photo"], req=["species", "address"], who="user",
                       st=["Reported", "Under review", "Rescue in progress", "Rescued", "Closed"]),
     "animals":   dict(cols=["kind", "name", "species", "breed", "sex", "birth", "description", "photo"], req=["kind", "name", "species"], who="shelter",
                       st=["Available", "On hold", "Adopted", "Rehomed", "Fostered"]),
     "requests":  dict(cols=["animal_id", "message"], req=["animal_id"], who="user", st=["Pending", "Approved", "Rejected"]),
     "events":    dict(cols=["title", "date", "address", "description"], req=["title", "date", "address"], who="shelter", st=["Open", "Closed"]),
     "regs":      dict(cols=["event_id", "message"], req=["event_id"], who="user", st=["Registered", "Confirmed", "Declined"]),
     "donations": dict(cols=["amount", "method", "reference"], req=["amount"], who="user", st=["Submitted", "Verified", "Acknowledged"])}
SESS = {}

def run(sql, args=()):
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    cur = c.execute(sql, args); rows = cur.fetchall(); c.commit(); lid = cur.lastrowid; c.close()
    return rows, lid

def init():
    run("create table if not exists users(id integer primary key autoincrement, name text, email text unique, salt text, pw text, role text, address text, phone text, verified integer default 0, code text)")
    for t, c in T.items():
        run(f"create table if not exists {t}(id integer primary key autoincrement, uid integer, ts text, status text, note text, {','.join(c['cols'])})")

hp = lambda pw, salt: hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100000).hex()
now = lambda: time.strftime("%Y-%m-%d %H:%M")

def new_code(email):                     # stands in for the verification email (printed here and shown on screen)
    code = str(secrets.randbelow(900000) + 100000)
    run("update users set code=? where email=?", (code, email)); print(f"[email to {email}] code: {code}")
    return code

def rows(t, me):
    sql = f"select x.*, u.name uname, u.email uemail from {t} x left join users u on u.id=x.uid"
    if T[t]["who"] == "user" and me["role"] != "shelter": sql += f" where x.uid={int(me['id'])}"
    return [dict(r) for r in run(sql + " order by x.id desc")[0]]

class H(BaseHTTPRequestHandler):
    def send(self, body, ctype="application/json", code=200, cookie=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data)))
        if cookie: self.send_header("Set-Cookie", cookie)
        self.end_headers(); self.wfile.write(data)
    def me(self):
        c = SimpleCookie(self.headers.get("Cookie", "")); s = c.get("sid")
        if not s or s.value not in SESS: return None
        r = run("select id,name,email,role,address,phone from users where id=?", (SESS[s.value],))[0]
        return dict(r[0]) if r else None
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self.send(open(os.path.join(HERE, "static", "index.html"), "rb").read(), "text/html; charset=utf-8")
        me = self.me()
        if self.path == "/api/me": return self.send({"me": me})
        if self.path == "/api/data" and me:
            d = {t: rows(t, me) for t in T}
            d["shelters"] = [dict(r) for r in run("select name,address,phone from users where role='shelter' and verified=1")[0]]
            d["statuses"] = {t: c["st"] for t, c in T.items()}
            return self.send(d)
        self.send({"error": "Please log in"}, code=401)
    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n > 3_000_000: raise ValueError("File too large")
            d = json.loads(self.rfile.read(n) or b"{}"); p = self.path.strip("/").split("/"); email = (d.get("email") or "").strip().lower()
            if p == ["api", "register"]:
                if "@" not in email or "." not in email: raise ValueError("Enter a valid email")
                if len(d.get("password", "")) < 6: raise ValueError("Password needs at least 6 characters")
                if not (d.get("name") or "").strip(): raise ValueError("Enter your name")
                role = d.get("role")
                if role not in ("user", "shelter"): raise ValueError("Choose an account type")
                if role == "shelter" and not (d.get("address") or "").strip(): raise ValueError("Shelters must enter an address")
                if run("select 1 from users where email=?", (email,))[0]: raise ValueError("This email is already registered")
                salt = secrets.token_hex(8)
                run("insert into users(name,email,salt,pw,role,address,phone) values(?,?,?,?,?,?,?)", (d["name"].strip(), email, salt, hp(d["password"], salt), role, (d.get("address") or "").strip(), (d.get("phone") or "").strip()))
                return self.send({"ok": True, "code": new_code(email)})
            if p == ["api", "resend"] or p == ["api", "forgot"]:
                if not run("select 1 from users where email=?", (email,))[0]: raise ValueError("No account with this email")
                return self.send({"ok": True, "code": new_code(email)})
            if p == ["api", "verify"]:
                u = run("select * from users where email=?", (email,))[0]
                if not u or not u[0]["code"] or u[0]["code"] != str(d.get("code", "")).strip(): raise ValueError("Wrong verification code")
                run("update users set verified=1, code='' where email=?", (email,)); return self.send({"ok": True})
            if p == ["api", "reset"]:
                u = run("select * from users where email=?", (email,))[0]
                if not u or not u[0]["code"] or u[0]["code"] != str(d.get("code", "")).strip(): raise ValueError("Wrong code")
                if len(d.get("password", "")) < 6: raise ValueError("Password needs at least 6 characters")
                salt = secrets.token_hex(8); run("update users set salt=?, pw=?, code='', verified=1 where email=?", (salt, hp(d["password"], salt), email))
                return self.send({"ok": True})
            if p == ["api", "login"]:
                u = run("select * from users where email=?", (email,))[0]
                if not u or u[0]["pw"] != hp(d.get("password", ""), u[0]["salt"]): raise ValueError("Wrong email or password")
                if not u[0]["verified"]: return self.send({"error": "Verify your email first", "verify": True}, code=400)
                tok = secrets.token_hex(16); SESS[tok] = u[0]["id"]
                return self.send({"ok": True}, cookie=f"sid={tok}; HttpOnly; Path=/; SameSite=Lax")
            if p == ["api", "logout"]:
                m = SimpleCookie(self.headers.get("Cookie", "")).get("sid"); SESS.pop(m.value if m else "", None)
                return self.send({"ok": True}, cookie="sid=; Max-Age=0; Path=/")
            me = self.me()
            if not me: return self.send({"error": "Please log in"}, code=401)
            if p[:2] == ["api", "add"] and p[2] in T:
                t = p[2]; c = T[t]
                if me["role"] != c["who"]: raise ValueError("Your account type cannot do this")
                v = {k: str(d.get(k) or "").strip() for k in c["cols"]}
                if any(not v[k] for k in c["req"]): raise ValueError("Fill in all required fields")
                if "photo" in v and not v["photo"].startswith("data:image/"): v["photo"] = ""
                if t == "donations":
                    try:
                        if float(v["amount"]) <= 0: raise ValueError
                    except ValueError: raise ValueError("Enter a donation amount above 0")
                if t == "requests":
                    a = run("select * from animals where id=?", (v["animal_id"],))[0]
                    if not a or a[0]["status"] != "Available": raise ValueError("This animal is not available")
                if t == "regs":
                    e = run("select * from events where id=?", (v["event_id"],))[0]
                    if not e or e[0]["status"] != "Open": raise ValueError("This event is closed")
                run(f"insert into {t}(uid,ts,status,note,{','.join(c['cols'])}) values(?,?,?,'',{','.join('?' * len(c['cols']))})", (me["id"], now(), c["st"][0], *v.values()))
                return self.send({"ok": True})
            if p[:2] == ["api", "update"] and p[2] in T:
                if me["role"] != "shelter": raise ValueError("Only shelters can update records")
                if d.get("status") not in T[p[2]]["st"]: raise ValueError("Invalid status")
                run(f"update {p[2]} set status=?, note=? where id=?", (d["status"], (d.get("note") or "").strip()[:300], int(p[3])))
                return self.send({"ok": True})
            self.send({"error": "not found"}, code=404)
        except (ValueError, KeyError, TypeError, IndexError) as e:
            self.send({"error": str(e) or "Check the form"}, code=400)
    def log_message(self, *a): pass

if __name__ == "__main__":
    init(); print("SRMS running at http://localhost:8000  (Ctrl+C to stop)")
    ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
