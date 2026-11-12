"""AdGuard Home Portal — consulta, desbloqueo y página de bloqueo para AdGuard Home.

© 2026 Zigma (https://zigma.com.uy) · Licencia MIT / MIT License.
https://github.com/christiannieveslauz/adguard-home-portal
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import time
from datetime import datetime
from functools import wraps
from urllib.parse import urlencode, urlparse

import requests
from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   session, url_for)
from markupsafe import Markup
from werkzeug.middleware.proxy_fix import ProxyFix

from i18n import LANGS, T

# --------------------------------------------------------------------------
# Configuración (variables de entorno)
# --------------------------------------------------------------------------
ADGUARD_URL = os.environ.get("ADGUARD_URL", "http://127.0.0.1").rstrip("/")
ADGUARD_USER = os.environ.get("ADGUARD_USERNAME", "")
ADGUARD_PASS = os.environ.get("ADGUARD_PASSWORD", "")
# Instancias adicionales (réplicas) de las que solo se lee el registro.
EXTRA_URLS = [u.strip().rstrip("/") for u in os.environ.get("ADGUARD_EXTRA_URLS", "").split(",") if u.strip()]

APP_USER = os.environ.get("APP_USERNAME", "")
APP_PASS = os.environ.get("APP_PASSWORD", "")

OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")  # vacío = cliente público con PKCE
OIDC_NAME = os.environ.get("OIDC_PROVIDER_NAME", "PocketID")
OIDC_ALLOWED = {u.strip().lower() for u in os.environ.get("OIDC_ALLOWED_USERS", "").split(",") if u.strip()}

RULE_TAG = os.environ.get("RULE_TAG", "adguard-home-portal")
SITE_TITLE = os.environ.get("SITE_TITLE", "AdGuard Home Portal")
QUERYLOG_LIMIT = int(os.environ.get("QUERYLOG_LIMIT", "1000"))
DEFAULT_LANG = os.environ.get("DEFAULT_LANG", "es") if os.environ.get("DEFAULT_LANG", "es") in ("es", "en") else "es"

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
    PERMANENT_SESSION_LIFETIME=int(os.environ.get("SESSION_HOURS", "12")) * 3600,
)

def get_lang() -> str:
    """Idioma: cookie elegida por el usuario, luego el navegador, luego DEFAULT_LANG."""
    c = request.cookies.get("lang", "")
    if c in LANGS:
        return c
    return request.accept_languages.best_match(LANGS) or DEFAULT_LANG


def tr(key: str, **kw) -> str:
    text = T[get_lang()].get(key) or T["es"].get(key, key)
    return text.format(**kw) if kw else text


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")


def password_enabled() -> bool:
    return bool(APP_USER and APP_PASS)


def oidc_enabled() -> bool:
    return bool(OIDC_ISSUER and OIDC_CLIENT_ID)


# --------------------------------------------------------------------------
# Cliente de AdGuard Home
# --------------------------------------------------------------------------
class AdGuard:
    def __init__(self, url: str):
        self.url = url
        self.s = requests.Session()
        self.s.auth = (ADGUARD_USER, ADGUARD_PASS)

    def get(self, path, **params):
        r = self.s.get(self.url + path, params=params, timeout=15)
        r.raise_for_status()
        return r.json() if r.content else None

    def post(self, path, payload):
        r = self.s.post(self.url + path, json=payload, timeout=30)
        r.raise_for_status()
        return r


primary = AdGuard(ADGUARD_URL)
_lists_cache: dict = {"t": 0, "map": {}}


def list_names() -> dict:
    if time.time() - _lists_cache["t"] > 300:
        st = primary.get("/control/filtering/status")
        m = {}
        for f in (st.get("filters") or []) + (st.get("whitelist_filters") or []):
            m[f["id"]] = f["name"]
        _lists_cache.update(t=time.time(), map=m)
    return _lists_cache["map"]


def list_label(names: dict, lid) -> str:
    if lid in (0, None):
        return tr("custom_rules")
    return names.get(lid, f"#{lid}")


def normalize(raw: str) -> str:
    raw = (raw or "").strip().lower()
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    raw = raw.split("/")[0].split(":")[0].strip(".")
    if raw.startswith("*."):
        raw = raw[2:]
    return raw


REASONS = {
    "NotFilteredNotFound": "permitido", "NotFilteredWhiteList": "permitido", "NotFilteredError": "error",
    "FilteredBlackList": "bloqueado", "FilteredSafeBrowsing": "bloqueado", "FilteredParental": "bloqueado",
    "FilteredInvalid": "bloqueado", "FilteredSafeSearch": "reescrito", "FilteredBlockedService": "bloqueado",
    "Rewrite": "reescrito", "RewriteEtcHosts": "reescrito", "RewriteRule": "reescrito",
}


def check(domain: str) -> dict:
    d = primary.get("/control/filtering/check_host", name=domain)
    names = list_names()
    reason = d.get("reason", "")
    state, text = REASONS.get(reason, "desconocido"), tr(reason)
    rules = [{"text": r.get("text", ""), "list": list_label(names, r.get("filter_list_id"))}
             for r in (d.get("rules") or [])]
    return {"domain": domain, "state": state, "reason": d.get("reason"), "text": text,
            "rules": rules, "service": d.get("service_name") or "",
            "exception": exception_rule(domain) in user_rules(),
            "removable": any(x["domain"] == domain for x in app_exceptions())}


def user_rules() -> list[str]:
    return list(primary.get("/control/filtering/status").get("user_rules") or [])


def exception_rule(domain: str) -> str:
    return f"@@||{domain}^$important"


def set_rules(rules: list[str]):
    primary.post("/control/filtering/set_rules", {"rules": rules})


def add_exception(domain: str, who: str) -> bool:
    rules = [r for r in user_rules() if r != ""]
    rule = exception_rule(domain)
    if rule in rules:
        return False
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    rules += [f"! [{RULE_TAG}] {domain} — {who} — {stamp}", rule]
    set_rules(rules)
    return True


def remove_exception(domain: str) -> bool:
    """Quita solo excepciones creadas por esta app (las manuales no se tocan)."""
    rules = user_rules()
    rule = exception_rule(domain)
    if rule not in rules or not any(x["domain"] == domain for x in app_exceptions()):
        return False
    out, skip_comment = [], f"! [{RULE_TAG}] {domain} "
    for r in rules:
        if r == rule or r.startswith(skip_comment):
            continue
        out.append(r)
    set_rules(out)
    return True


def app_exceptions() -> list[dict]:
    rules = user_rules()
    out = []
    for i, r in enumerate(rules):
        m = re.match(rf"^! \[{re.escape(RULE_TAG)}\] (\S+) — (.*) — (.*)$", r)
        if m and exception_rule(m.group(1)) in rules:
            out.append({"domain": m.group(1), "who": m.group(2), "when": m.group(3)})
    return list(reversed(out))


def recent_blocked(client: str = "") -> dict:
    names = list_names()
    domains: dict = {}
    clients: dict = {}
    for url in [ADGUARD_URL] + EXTRA_URLS:
        inst = primary if url == ADGUARD_URL else AdGuard(url)
        try:
            params = {"response_status": "blocked", "limit": QUERYLOG_LIMIT}
            if client:
                params["search"] = client
            data = inst.get("/control/querylog", **params).get("data") or []
        except Exception:  # una réplica caída no rompe la vista
            continue
        server = urlparse(url).hostname
        for e in data:
            ip = e.get("client", "")
            cname = (e.get("client_info") or {}).get("name") or ""
            c = clients.setdefault(ip, {"ip": ip, "name": cname, "count": 0})
            c["count"] += 1
            c["name"] = c["name"] or cname
            if client and ip != client:
                continue
            q = (e.get("question") or {}).get("name", "").rstrip(".")
            key = (q, ip)
            rules = e.get("rules") or []
            lid = rules[0].get("filter_list_id") if rules else e.get("filterId")
            item = domains.setdefault(key, {
                "domain": q, "client": ip, "client_name": cname, "count": 0,
                "last": e.get("time", ""), "rule": (rules[0].get("text") if rules else e.get("rule", "")),
                "list": list_label(names, lid) if lid is not None else e.get("reason", ""), "servers": set()})
            item["count"] += 1
            item["servers"].add(server)
            if e.get("time", "") > item["last"]:
                item["last"] = e.get("time", "")
    items = sorted(domains.values(), key=lambda x: x["last"], reverse=True)
    for i in items:
        i["servers"] = sorted(i["servers"])
    return {"items": items[:400],
            "clients": sorted(clients.values(), key=lambda c: c["count"], reverse=True)}


# --------------------------------------------------------------------------
# Autenticación
# --------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify(error="no autenticado"), 401
            return redirect(url_for("login", next=request.full_path))
        return f(*a, **k)
    return wrapper


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def require_csrf():
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf", "")
    if not hmac.compare_digest(sent, session.get("csrf", "-")):
        abort(403)


SHIELD = Markup('<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#67b279" d="M12 1.5 3.5 4.6v6.2c0 5.4 3.6 '
                '10.3 8.5 11.7 4.9-1.4 8.5-6.3 8.5-11.7V4.6z"/><path fill="#fff" d="m10.6 15.6-3.4-3.4 1.4-1.4 2 2 '
                '4.8-4.8 1.4 1.4z"/></svg>')
def js_strings() -> dict:
    return {k: v for k, v in T[get_lang()].items() if k.startswith(("js_", "st_"))}


app.jinja_env.globals.update(csrf_token=csrf_token, site_title=SITE_TITLE, shield=SHIELD,
                             t=tr, get_lang=get_lang, js_strings=js_strings)


@app.route("/lang/<code>")
def set_lang(code):
    nxt = request.args.get("next", "/")
    if not nxt.startswith("/") or nxt.startswith("//"):
        nxt = "/"
    resp = redirect(nxt)
    if code in LANGS:
        resp.set_cookie("lang", code, max_age=365 * 86400, samesite="Lax")
    return resp

_failed: dict = {}


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    nxt = request.values.get("next", "/")
    if not nxt.startswith("/") or nxt.startswith("//"):
        nxt = "/"
    if request.method == "POST" and password_enabled():
        ip = request.remote_addr or "?"
        fails = [t for t in _failed.get(ip, []) if time.time() - t < 900]
        if len(fails) >= 8:
            error = tr("too_many")
        else:
            u, p = request.form.get("username", ""), request.form.get("password", "")
            if hmac.compare_digest(u, APP_USER) and hmac.compare_digest(p, APP_PASS):
                session.clear()
                session.permanent = True
                session["user"] = u
                _failed.pop(ip, None)
                return redirect(nxt)
            fails.append(time.time())
            _failed[ip] = fails
            error = tr("bad_login")
    return render_template("login.html", error=error, next=nxt, pw=password_enabled(),
                           oidc=oidc_enabled(), oidc_name=OIDC_NAME)


_discovery: dict = {}


def discovery() -> dict:
    if not _discovery:
        _discovery.update(requests.get(OIDC_ISSUER + "/.well-known/openid-configuration", timeout=10).json())
    return _discovery


@app.route("/login/oidc")
def login_oidc():
    if not oidc_enabled():
        abort(404)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(24)
    session.update(oidc_state=state, oidc_verifier=verifier, oidc_next=request.args.get("next", "/"))
    params = {"response_type": "code", "client_id": OIDC_CLIENT_ID, "scope": "openid profile email",
              "redirect_uri": url_for("oidc_callback", _external=True), "state": state,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    return redirect(discovery()["authorization_endpoint"] + "?" + urlencode(params))


@app.route("/auth/callback")
def oidc_callback():
    if not oidc_enabled():
        abort(404)
    if request.args.get("state") != session.pop("oidc_state", None):
        abort(400, "state inválido")
    data = {"grant_type": "authorization_code", "code": request.args.get("code", ""),
            "redirect_uri": url_for("oidc_callback", _external=True),
            "client_id": OIDC_CLIENT_ID, "code_verifier": session.pop("oidc_verifier", "")}
    auth = (OIDC_CLIENT_ID, OIDC_CLIENT_SECRET) if OIDC_CLIENT_SECRET else None
    tok = requests.post(discovery()["token_endpoint"], data=data, auth=auth, timeout=15)
    if not tok.ok:
        abort(401, "El proveedor rechazó el código")
    info = requests.get(discovery()["userinfo_endpoint"], timeout=15,
                        headers={"Authorization": "Bearer " + tok.json()["access_token"]}).json()
    user = info.get("preferred_username") or info.get("email") or info.get("sub")
    if OIDC_ALLOWED and str(user).lower() not in OIDC_ALLOWED and str(info.get("email", "")).lower() not in OIDC_ALLOWED:
        abort(403, "Usuario no autorizado")
    nxt = session.pop("oidc_next", "/")
    session.clear()
    session.permanent = True
    session["user"] = user
    return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Vistas y API
# --------------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    return render_template("index.html", user=session["user"], query=normalize(request.args.get("d", "")))


@app.get("/api/check")
@login_required
def api_check():
    d = normalize(request.args.get("d", ""))
    if not DOMAIN_RE.match(d):
        return jsonify(error=tr("invalid_domain")), 400
    return jsonify(check(d))


@app.post("/api/unblock")
@login_required
def api_unblock():
    require_csrf()
    d = normalize((request.get_json(silent=True) or {}).get("domain", ""))
    if not DOMAIN_RE.match(d):
        return jsonify(error=tr("invalid_domain")), 400
    added = add_exception(d, session["user"])
    return jsonify(added=added, result=check(d))


@app.post("/api/reblock")
@login_required
def api_reblock():
    require_csrf()
    d = normalize((request.get_json(silent=True) or {}).get("domain", ""))
    removed = remove_exception(d)
    return jsonify(removed=removed, result=check(d) if DOMAIN_RE.match(d) else None)


@app.get("/api/recent")
@login_required
def api_recent():
    return jsonify(recent_blocked(request.args.get("client", "").strip()))


@app.get("/api/exceptions")
@login_required
def api_exceptions():
    return jsonify(app_exceptions())


@app.get("/healthz")
def healthz():
    return "ok"


@app.errorhandler(requests.RequestException)
def adguard_error(e):
    return jsonify(error=f"{tr('adguard_error')}: {e.__class__.__name__}"), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, debug=False)
