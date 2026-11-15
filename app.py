"""
Blood Pressure Diary: a Flask (Python) server that talks to Supabase.

How the pieces fit together:
  Phone/laptop browser  <->  THIS Python server  <->  Supabase (database + logins)

  - The browser shows the page (static/index.html) and asks this server for data.
  - This server signs people in with Supabase, remembers them with a secure cookie,
    and fetches / adds / deletes their readings using THEIR login token.
  - Supabase's Row Level Security rules then make sure each person only ever
    reaches their own readings.

Settings come from environment variables (so no secrets are written in the code):
  SUPABASE_URL  - your Project URL
  SUPABASE_KEY  - your PUBLISHABLE key (starts sb_publishable_). Never the secret key.
  SECRET_KEY    - any long random text; used to sign the login cookie
"""

import functools
import mimetypes
import os
import time
from datetime import datetime, timedelta

import requests                       # lets Python call web addresses (Supabase's API)
from flask import Flask, jsonify, request, send_from_directory, session

# ---------------------------------------------------------------------
# PART 1: SETTINGS
# ---------------------------------------------------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
TIMEOUT = 15                          # give up on Supabase after 15 seconds

mimetypes.add_type("application/manifest+json", ".webmanifest")   # so phones recognise the app manifest

# static_url_path="" makes files in the static folder available at the top level (e.g. /icon-192.png)
app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "change-me-for-local-testing-only")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,                         # page scripts can't read the login cookie
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")), # only send the cookie over https when hosted on Render
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),        # stay signed in for 30 days
)


# ---------------------------------------------------------------------
# PART 2: HELPERS FOR TALKING TO SUPABASE
# ---------------------------------------------------------------------
def error(message, status):
    """Send an error message back to the page as JSON."""
    return jsonify({"error": message}), status


def auth_headers(token=None):
    """Headers Supabase wants: our publishable key, plus the person's login token if we have one."""
    return {"apikey": SUPABASE_KEY,
            "Authorization": "Bearer " + (token or SUPABASE_KEY),
            "Content-Type": "application/json"}


def supabase_message(response, default):
    """Pull a readable message out of a failed Supabase reply."""
    try:
        data = response.json()
    except ValueError:
        return default
    return data.get("error_description") or data.get("msg") or data.get("message") or default


def store_session(data):
    """Remember the person's login in the signed cookie (called after sign-in or token refresh)."""
    session["access_token"] = data["access_token"]        # short-lived pass (about 1 hour)
    session["refresh_token"] = data["refresh_token"]      # lets us get a new pass without a password
    session["expires_at"] = int(time.time()) + int(data.get("expires_in", 3600)) - 60
    session["email"] = (data.get("user") or {}).get("email", "")
    session.permanent = True


def current_token():
    """Return a valid login token for this visitor, refreshing it if it has run out. None = not signed in."""
    if "access_token" not in session:
        return None
    if time.time() >= session.get("expires_at", 0):       # the short-lived pass has expired
        try:
            r = requests.post(f"{SUPABASE_URL}/auth/v1/token", params={"grant_type": "refresh_token"},
                              json={"refresh_token": session["refresh_token"]},
                              headers=auth_headers(), timeout=TIMEOUT)
        except requests.RequestException:
            return None
        if r.status_code != 200:                          # refresh refused: they must sign in again
            session.clear()
            return None
        store_session(r.json())
    return session["access_token"]


def login_required(view):
    """Decorator: only let signed-in people reach a route. The token is passed in as the first argument."""
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        token = current_token()
        if token is None:
            return error("Please sign in again.", 401)
        return view(token, *args, **kwargs)
    return wrapper


@app.before_request
def check_settings():
    """Stop early with a clear message if the Supabase settings were never provided."""
    if request.path.startswith("/api/") and not (SUPABASE_URL and SUPABASE_KEY):
        return error("The server is missing its Supabase settings.", 500)


# ---------------------------------------------------------------------
# PART 3: CHECKING INCOMING READINGS
# The page checks too, but the server never trusts the browser.
# ---------------------------------------------------------------------
def to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def validate_reading(data):
    """Return (row_for_database, None) if valid, or (None, error_message)."""
    sys_, dia = to_int(data.get("sys")), to_int(data.get("dia"))
    pulse = to_int(data.get("pulse")) if data.get("pulse") not in (None, "") else None
    note = str(data.get("note") or "").strip()[:500]
    when = str(data.get("time") or "")

    try:
        datetime.strptime(when, "%Y-%m-%dT%H:%M")        # e.g. 2026-11-15T08:30
    except ValueError:
        return None, "Please choose a date and time."
    if sys_ is None or dia is None:
        return None, "Please enter both the top and bottom numbers."
    if not 50 <= sys_ <= 260:
        return None, "The top number looks wrong. Please check it."
    if not 30 <= dia <= 160:
        return None, "The bottom number looks wrong. Please check it."
    if dia >= sys_:
        return None, "The top number should be bigger than the bottom number."
    if pulse is not None and not 30 <= pulse <= 220:
        return None, "The pulse looks wrong. Please check it."

    # Names here match the columns in the Supabase table
    return {"taken_at": when, "systolic": sys_, "diastolic": dia, "pulse": pulse, "note": note}, None


# ---------------------------------------------------------------------
# PART 4: ROUTES - THE PAGE AND SIGN-IN
# ---------------------------------------------------------------------
@app.get("/")
def home():
    """Send the web page."""
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/me")
def me():
    """Tell the page whether this visitor is signed in."""
    return jsonify({"signedIn": current_token() is not None, "email": session.get("email", "")})


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    try:
        r = requests.post(f"{SUPABASE_URL}/auth/v1/token", params={"grant_type": "password"},
                          json={"email": data.get("email", ""), "password": data.get("password", "")},
                          headers=auth_headers(), timeout=TIMEOUT)
    except requests.RequestException:
        return error("Could not reach the sign-in service. Please try again.", 503)
    if r.status_code != 200:
        return error("Could not sign in. Check your email and password.", 401)
    store_session(r.json())
    return jsonify({"ok": True})


@app.post("/api/signup")
def signup():
    data = request.get_json(silent=True) or {}
    try:
        r = requests.post(f"{SUPABASE_URL}/auth/v1/signup",
                          json={"email": data.get("email", ""), "password": data.get("password", "")},
                          headers=auth_headers(), timeout=TIMEOUT)
    except requests.RequestException:
        return error("Could not reach the sign-in service. Please try again.", 503)
    if r.status_code not in (200, 201):
        return error("Could not create the account: " + supabase_message(r, "please check the details."), 400)
    result = r.json()
    if result.get("access_token"):                        # confirmation emails are off: signed in straight away
        store_session(result)
        return jsonify({"ok": True, "signedIn": True})
    return jsonify({"ok": True, "signedIn": False})       # they need to click the email link first


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------
# PART 5: ROUTES - THE READINGS
# ---------------------------------------------------------------------
def readings_url():
    return f"{SUPABASE_URL}/rest/v1/readings"


@app.get("/api/readings")
@login_required
def list_readings(token):
    """Return this person's readings, oldest first."""
    try:
        r = requests.get(readings_url(), params={"select": "*", "order": "taken_at.asc"},
                         headers=auth_headers(token), timeout=TIMEOUT)
    except requests.RequestException:
        return error("Could not reach the database. Please try again.", 503)
    if r.status_code in (401, 403):
        return error("Please sign in again.", 401)
    if r.status_code != 200:
        return error("The database returned an error.", 502)
    return jsonify([{"id": x["id"], "time": x["taken_at"], "sys": x["systolic"], "dia": x["diastolic"],
                     "pulse": x["pulse"], "note": x["note"]} for x in r.json()])


@app.post("/api/readings")
@login_required
def add_reading(token):
    """Check a new reading and store it. Supabase fills in the id and the owner automatically."""
    row, problem = validate_reading(request.get_json(silent=True) or {})
    if problem:
        return error(problem, 400)
    try:
        r = requests.post(readings_url(), json=row, timeout=TIMEOUT,
                          headers={**auth_headers(token), "Prefer": "return=minimal"})
    except requests.RequestException:
        return error("Could not reach the database. Please try again.", 503)
    if r.status_code in (401, 403):
        return error("Please sign in again.", 401)
    if r.status_code != 201:
        return error("Could not save the reading.", 502)
    return jsonify({"ok": True}), 201


@app.delete("/api/readings/<int:reading_id>")
@login_required
def delete_reading(token, reading_id):
    """Delete one reading. Row Level Security means it only works on the person's own."""
    try:
        r = requests.delete(readings_url(), params={"id": f"eq.{reading_id}"},
                            headers=auth_headers(token), timeout=TIMEOUT)
    except requests.RequestException:
        return error("Could not reach the database. Please try again.", 503)
    if r.status_code in (401, 403):
        return error("Please sign in again.", 401)
    if r.status_code not in (200, 204):
        return error("Could not delete the reading.", 502)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------
# PART 6: RUN LOCALLY (on Render, gunicorn starts the app instead)
# ---------------------------------------------------------------------
if __name__ == "__main__":
    app.run(port=5001)
