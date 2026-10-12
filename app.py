"""
Automated Banking Cloud - simple base version
Flask REST API + SQLite. Amounts are stored as integer cents to avoid
floating point errors.
"""
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = os.environ.get("DB_PATH", "bank.db")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=os.path.join(BASE_DIR, "static"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    account_no    TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    balance       INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    token      TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transactions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id    INTEGER NOT NULL REFERENCES accounts(id),
    type          TEXT NOT NULL,          -- deposit | withdraw | transfer_in | transfer_out
    amount        INTEGER NOT NULL,
    counterparty  TEXT,
    balance_after INTEGER NOT NULL,
    created_at    TEXT NOT NULL
);
"""


# ---------- helpers ----------
def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db():
    if "db" not in g:
        # isolation_level=None -> we control transactions manually
        g.db = sqlite3.connect(DB_PATH, isolation_level=None)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    db.close()


def to_cents(value):
    """Convert user input to positive integer cents, or raise ValueError."""
    try:
        d = Decimal(str(value))
    except InvalidOperation:
        raise ValueError("Invalid amount")
    if d <= 0 or d != d.quantize(Decimal("0.01")):
        raise ValueError("Amount must be positive with at most 2 decimals")
    return int(d * 100)


def money(cents):
    return round(cents / 100, 2)


def error(msg, code=400):
    return jsonify({"error": msg}), code


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        row = get_db().execute(
            "SELECT a.* FROM tokens t JOIN accounts a ON a.id = t.account_id "
            "WHERE t.token = ?", (token,)).fetchone()
        if not row:
            return error("Unauthorized", 401)
        g.user = row
        return fn(*args, **kwargs)
    return wrapper


def record(db, account_id, type_, amount, counterparty, balance_after):
    db.execute(
        "INSERT INTO transactions (account_id, type, amount, counterparty, "
        "balance_after, created_at) VALUES (?,?,?,?,?,?)",
        (account_id, type_, amount, counterparty, balance_after, now()))


# ---------- routes ----------
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    password = data.get("password") or ""
    if not name or len(password) < 6:
        return error("Name required and password must be at least 6 characters")
    try:
        initial = to_cents(data["initial_deposit"]) if data.get("initial_deposit") else 0
    except ValueError as e:
        return error(str(e))

    db = get_db()
    account_no = "ABC" + "".join(secrets.choice("0123456789") for _ in range(9))
    db.execute("BEGIN IMMEDIATE")
    try:
        cur = db.execute(
            "INSERT INTO accounts (account_no, name, password_hash, balance, created_at) "
            "VALUES (?,?,?,?,?)",
            (account_no, name, generate_password_hash(password), initial, now()))
        if initial:
            record(db, cur.lastrowid, "deposit", initial, None, initial)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return jsonify({"account_no": account_no, "name": name,
                    "balance": money(initial)}), 201


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    db = get_db()
    acc = db.execute("SELECT * FROM accounts WHERE account_no = ?",
                     (data.get("account_no", ""),)).fetchone()
    if not acc or not check_password_hash(acc["password_hash"], data.get("password", "")):
        return error("Invalid account number or password", 401)
    token = secrets.token_hex(24)
    db.execute("INSERT INTO tokens (token, account_id, created_at) VALUES (?,?,?)",
               (token, acc["id"], now()))
    return {"token": token, "account_no": acc["account_no"], "name": acc["name"]}


@app.post("/api/logout")
@login_required
def logout():
    token = request.headers["Authorization"].removeprefix("Bearer ").strip()
    get_db().execute("DELETE FROM tokens WHERE token = ?", (token,))
    return {"message": "Logged out"}


@app.get("/api/balance")
@login_required
def balance():
    return {"account_no": g.user["account_no"], "name": g.user["name"],
            "balance": money(g.user["balance"])}


def change_balance(kind):
    data = request.get_json(silent=True) or {}
    try:
        amount = to_cents(data.get("amount"))
    except ValueError as e:
        return error(str(e))

    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        bal = db.execute("SELECT balance FROM accounts WHERE id = ?",
                         (g.user["id"],)).fetchone()["balance"]
        new_bal = bal + amount if kind == "deposit" else bal - amount
        if new_bal < 0:
            db.execute("ROLLBACK")
            return error("Insufficient funds")
        db.execute("UPDATE accounts SET balance = ? WHERE id = ?", (new_bal, g.user["id"]))
        record(db, g.user["id"], kind, amount, None, new_bal)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return {"message": f"{kind.capitalize()} successful", "balance": money(new_bal)}


@app.post("/api/deposit")
@login_required
def deposit():
    return change_balance("deposit")


@app.post("/api/withdraw")
@login_required
def withdraw():
    return change_balance("withdraw")


@app.post("/api/transfer")
@login_required
def transfer():
    data = request.get_json(silent=True) or {}
    try:
        amount = to_cents(data.get("amount"))
    except ValueError as e:
        return error(str(e))
    to_no = (data.get("to_account") or "").strip()
    if to_no == g.user["account_no"]:
        return error("Cannot transfer to your own account")

    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        dest = db.execute("SELECT * FROM accounts WHERE account_no = ?", (to_no,)).fetchone()
        if not dest:
            db.execute("ROLLBACK")
            return error("Destination account not found", 404)
        src_bal = db.execute("SELECT balance FROM accounts WHERE id = ?",
                             (g.user["id"],)).fetchone()["balance"]
        if src_bal < amount:
            db.execute("ROLLBACK")
            return error("Insufficient funds")
        new_src = src_bal - amount
        new_dst = dest["balance"] + amount
        db.execute("UPDATE accounts SET balance = ? WHERE id = ?", (new_src, g.user["id"]))
        db.execute("UPDATE accounts SET balance = ? WHERE id = ?", (new_dst, dest["id"]))
        record(db, g.user["id"], "transfer_out", amount, to_no, new_src)
        record(db, dest["id"], "transfer_in", amount, g.user["account_no"], new_dst)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return {"message": "Transfer successful", "balance": money(new_src)}


@app.get("/api/transactions")
@login_required
def transactions():
    rows = get_db().execute(
        "SELECT type, amount, counterparty, balance_after, created_at "
        "FROM transactions WHERE account_id = ? ORDER BY id DESC LIMIT 50",
        (g.user["id"],)).fetchall()
    return jsonify([{
        "type": r["type"], "amount": money(r["amount"]),
        "counterparty": r["counterparty"],
        "balance_after": money(r["balance_after"]),
        "date": r["created_at"]} for r in rows])


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
