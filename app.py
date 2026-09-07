"""Finora Bank - a pretend online banking app made with Streamlit.

Run it with: streamlit run app.py

This is just a demo for learning and showing off. It does not connect to
a real bank, a real payment system, a real SMS service, or a real cash
machine. No real money ever moves here.
"""

from __future__ import annotations

import csv
import base64
import calendar
import hashlib
import hmac
import html
import io
import json
import os
import secrets
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components


# -----------------------------------------------------------------------------
# App settings
# -----------------------------------------------------------------------------
APP_DIR = Path(__file__).resolve().parent
DATA_FILE = APP_DIR / "bank_data.json"
DATA_LOCK = threading.RLock()
OTP_VALID_SECONDS = 60
SESSION_TIMEOUT_SECONDS = 5 * 60
ACCOUNT_LOCK_SECONDS = 60
MAX_LOGIN_ATTEMPTS = 3
ACCOUNT_NUMBER_LENGTH = 10
DATA_SCHEMA_VERSION = 4
DEMO_CARD_NUMBER = "5212345678904821"

DEEP_BLUE = "#123B6D"
SKY_BLUE = "#6EC1E4"
LIGHT_BLUE = "#EAF6FB"
MINT_GREEN = "#8FD9C7"
DARK_NAVY = "#1F2D3D"

BILLERS = {
    "Electricity": ["Tenaga Nasional Berhad (TNB)"],
    "Water": ["Air Selangor", "SAJ Ranhill"],
    "Internet": ["Unifi", "Maxis Fibre", "TIME Internet"],
    "Mobile": ["CelcomDigi", "Maxis", "U Mobile"],
    "Insurance": ["AIA", "Allianz", "Prudential"],
}

NAVIGATION_LABELS = {
    "Dashboard": "🏠  Dashboard",
    "Transfer": "↗️  Transfer",
    "Pay Bills": "🧾  Pay Bills",
    "Credit Card": "💳  Credit Card",
    "Deposit": "➕  Deposit",
    "Budget Planner": "📊  Budget Planner",
    "Transactions": "📄  Transactions",
    "Security": "🛡️  Security",
}


class BankingError(Exception):
    """An error message we can show straight to the user, like "wrong OTP" or "not enough balance." """


class DataStoreError(Exception):
    """Raised when we can't read or save the bank_data.json file."""


# Password, OTP, and file-saving helpers
def hash_password(password: str, salt_hex: str | None = None) -> dict[str, str]:
    """Turn a plain password into a hash, so we never store the real password.

    We add a random "salt" first. That way, even if two people pick the
    exact same password, the saved hash still looks different for each
    of them.
    """
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return {"salt": salt.hex(), "hash": derived.hex()}


def verify_password(password: str, stored: dict[str, str]) -> bool:
    """Check if the typed password matches the saved hash."""
    candidate = hash_password(password, stored["salt"])["hash"]
    return hmac.compare_digest(candidate, stored["hash"])


def now_text() -> str:
    """Return the current date and time as a plain text string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def transaction_record(
    transaction_type: str,
    description: str,
    amount: float,
    balance_after: float,
    reference: str | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    """Build one transaction entry with the same fields every time.

    If no `category` is given, we just use the transaction type instead.
    That way old records, and records that aren't bills, still show up
    sensibly in the spending chart.
    """
    return {
        "id": reference or f"FNB-{datetime.now():%Y%m%d}-{uuid.uuid4().hex[:8].upper()}",
        "date": now_text(),
        "type": transaction_type,
        "category": category or transaction_type,
        "description": description,
        "amount": round(float(amount), 2),
        "balance_after": round(float(balance_after), 2),
    }


def create_seed_data() -> dict[str, Any]:
    """Set up two fake demo accounts the first time the app runs."""
    paulina_transactions = [
        {
            "id": "FNB-20260825-OPEN01",
            "date": "2026-08-25 09:00:00",
            "type": "Deposit",
            "description": "Opening balance",
            "amount": 15000.00,
            "balance_after": 15000.00,
        },
        {
            "id": "FNB-20260828-BILL01",
            "date": "2026-08-28 14:18:00",
            "type": "Bill Payment",
            "description": "TNB - 88002145",
            "amount": -210.20,
            "balance_after": 14789.80,
        },
        {
            "id": "FNB-20260901-DEP001",
            "date": "2026-09-01 10:05:00",
            "type": "Deposit",
            "description": "Cash deposit",
            "amount": 1000.00,
            "balance_after": 15789.80,
        },
        {
            "id": "FNB-20260902-TRF001",
            "date": "2026-09-02 17:30:00",
            "type": "Transfer",
            "description": "Transfer to Alex Tan",
            "amount": -369.00,
            "balance_after": 15420.80,
        },
    ]
    return {
        "schema_version": DATA_SCHEMA_VERSION,
        "users": {
            "paulina": {
                "full_name": "Paulina",
                "account_number": "8800251573",
                "password": hash_password("Finora@123"),
                "balance": 15420.80,
                "credit_card": {"number": DEMO_CARD_NUMBER, "limit": 10000.0, "outstanding": 2000.0},
                "failed_attempts": 0,
                "locked_until": 0.0,
                "monthly_budget": 3000.0,
                "security_log": [],
                "transactions": paulina_transactions,
            },
            "alex": {
                "full_name": "Alex Tan",
                "account_number": "8800259999",
                "password": hash_password("Alex@123"),
                "balance": 8250.00,
                "credit_card": {"number": "5412098765431109", "limit": 6000.0, "outstanding": 780.0},
                "failed_attempts": 0,
                "locked_until": 0.0,
                "monthly_budget": 2000.0,
                "security_log": [],
                "transactions": [
                    {
                        "id": "FNB-20260820-OPEN02",
                        "date": "2026-08-20 11:00:00",
                        "type": "Deposit",
                        "description": "Opening balance",
                        "amount": 8250.0,
                        "balance_after": 8250.0,
                    }
                ],
            },
        },
    }


def save_data(data: dict[str, Any]) -> None:
    """Save the bank data to disk safely, so a crash mid-save can't corrupt the file."""
    temporary_file = DATA_FILE.with_suffix(".tmp")
    try:
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        with temporary_file.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_file, DATA_FILE)
    except (OSError, TypeError) as exc:
        temporary_file.unlink(missing_ok=True)
        raise DataStoreError("The account data could not be saved. Please try again.") from exc


def load_data() -> dict[str, Any]:
    """Load the saved bank data, or create fresh demo data if none exists yet."""
    with DATA_LOCK:
        if not DATA_FILE.exists():
            data = create_seed_data()
            save_data(data)
            return data
        try:
            with DATA_FILE.open("r", encoding="utf-8") as file:
                data = json.load(file)
            if not isinstance(data.get("users"), dict):
                raise ValueError("Missing users collection")

            # Old save files used a different username - keep them working.
            data_changed = False
            if "chai" in data["users"] and "paulina" not in data["users"]:
                data["users"]["paulina"] = data["users"].pop("chai")
                data["users"]["paulina"]["full_name"] = "Paulina"
                data_changed = True

            current_schema = int(data.get("schema_version", 1))
            if current_schema < 2:
                paulina = data["users"].get("paulina")
                if paulina:
                    paulina["credit_card"]["outstanding"] = 2000.0
                data_changed = True

            if current_schema < 3:
                paulina = data["users"].get("paulina")
                if paulina:
                    paulina["credit_card"]["number"] = DEMO_CARD_NUMBER
                alex = data["users"].get("alex")
                if alex:
                    alex["credit_card"]["number"] = "5412098765431109"

            # Schema 4 adds a personal monthly budget and a persistent
            # security audit trail. setdefault also repairs older save files
            # that do not contain one of these fields.
            for user in data["users"].values():
                if "monthly_budget" not in user:
                    user["monthly_budget"] = 3000.0
                    data_changed = True
                if "security_log" not in user:
                    user["security_log"] = []
                    data_changed = True

            if current_schema < DATA_SCHEMA_VERSION:
                data["schema_version"] = DATA_SCHEMA_VERSION
                data_changed = True

            if data_changed:
                save_data(data)
            return data
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise DataStoreError(
                "The account data file is unavailable or invalid. Restore bank_data.json or reset the demo."
            ) from exc


def find_username_by_account(data: dict[str, Any], account_number: str) -> str | None:
    """Find which username owns this exact account number."""
    for username, user in data["users"].items():
        if user["account_number"] == account_number.strip():
            return username
    return None


def valid_account_number(account_number: str) -> bool:
    """Check that the account number is exactly 10 digits, nothing else."""
    cleaned = account_number.strip()
    return cleaned.isdigit() and len(cleaned) == ACCOUNT_NUMBER_LENGTH


def card_number_digits(card_number: str) -> str:
    """Strip out everything except the digits from a card number."""
    return "".join(character for character in str(card_number) if character.isdigit())


def masked_card_number(card_number: str) -> str:
    """Hide most of the card number, keep the last 4 digits visible."""
    digits = card_number_digits(card_number)
    return f"•••• •••• •••• {digits[-4:]}"


def visible_card_number(card_number: str) -> str:
    """Show the full demo card number, split into groups of 4 digits."""
    digits = card_number_digits(card_number)
    return " ".join(digits[index:index + 4] for index in range(0, len(digits), 4))


# Login and money-moving logic
def authenticate(username: str, password: str) -> tuple[str, str]:
    """Check a username and password, and save failed-login/lockout info."""
    username = username.strip().lower()
    with DATA_LOCK:
        data = load_data()
        user = data["users"].get(username)
        if user is None:
            return "invalid", "Invalid username or password."

        current_time = time.time()
        if float(user.get("locked_until", 0)) > current_time:
            remaining = int(user["locked_until"] - current_time) + 1
            add_security_event(user, "Login attempt", "Blocked", "Account is temporarily locked")
            save_data(data)
            return "locked", f"Account locked. Try again in {remaining} seconds."

        # The lockout time is over, so reset the failed-attempt counter.
        if user.get("locked_until", 0):
            user["locked_until"] = 0.0
            user["failed_attempts"] = 0

        if verify_password(password, user["password"]):
            user["failed_attempts"] = 0
            user["locked_until"] = 0.0
            add_security_event(user, "Login", "Successful", "Password verified")
            save_data(data)
            return "success", "Login successful."

        user["failed_attempts"] = int(user.get("failed_attempts", 0)) + 1
        attempts_left = MAX_LOGIN_ATTEMPTS - user["failed_attempts"]
        if attempts_left <= 0:
            user["locked_until"] = current_time + ACCOUNT_LOCK_SECONDS
            add_security_event(user, "Account lock", "Blocked", "3 incorrect password attempts")
            save_data(data)
            return "locked", "Account locked for 60 seconds after 3 unsuccessful attempts."

        add_security_event(
            user,
            "Login",
            "Failed",
            f"Incorrect password; {attempts_left} attempt(s) remaining",
        )
        save_data(data)
        return "invalid", f"Invalid username or password. {attempts_left} attempt(s) remaining."


def security_event_record(event: str, status: str, details: str = "") -> dict[str, str]:
    """Create one consistently formatted security audit entry."""
    return {"date": now_text(), "event": event, "status": status, "details": details}


def add_security_event(user: dict[str, Any], event: str, status: str, details: str = "") -> None:
    """Add an event to a user record and retain the latest 100 entries."""
    log = user.setdefault("security_log", [])
    log.append(security_event_record(event, status, details))
    user["security_log"] = log[-100:]


def record_security_event(username: str, event: str, status: str, details: str = "") -> None:
    """Load, append and safely persist a security event for one user."""
    if not username:
        return
    with DATA_LOCK:
        data = load_data()
        user = data["users"].get(username.strip().lower())
        if user:
            add_security_event(user, event, status, details)
            save_data(data)


def add_transaction(
    user: dict[str, Any],
    kind: str,
    description: str,
    amount: float,
    ref: str,
    category: str | None = None,
) -> None:
    """Add one new transaction to this user's history."""
    user["transactions"].append(
        transaction_record(kind, description, amount, user["balance"], reference=ref, category=category)
    )


def balance_history_frame(transactions: list[dict[str, Any]]) -> pd.DataFrame:
    """Turn the transaction list into balance-over-time data for the line chart."""
    if not transactions:
        return pd.DataFrame(columns=["Date", "Balance (RM)"])

    history = pd.DataFrame(transactions)
    history["Date"] = pd.to_datetime(history["date"], errors="coerce")
    history["Balance (RM)"] = pd.to_numeric(history["balance_after"], errors="coerce")
    return (
        history.dropna(subset=["Date", "Balance (RM)"])
        .sort_values("Date")[["Date", "Balance (RM)"]]
        .set_index("Date")
    )


def spending_summary(transactions: list[dict[str, Any]]) -> pd.DataFrame:
    """Add up outgoing money, grouped by category, for the spending chart.

    Bill payments are grouped by their real category (Electricity, Water,
    Internet, and so on) instead of the generic "Bill Payment" label, so
    the chart shows where the money actually went. Everything else -
    transfers, card payments, or old records saved before we tracked
    categories - just falls back to its transaction type.
    """
    outgoing = [item for item in transactions if float(item.get("amount", 0)) < 0]
    if not outgoing:
        return pd.DataFrame(columns=["Category", "Spending (RM)"])

    spending = pd.DataFrame(outgoing)
    if "category" in spending.columns:
        spending["Category"] = spending["category"].where(
            spending["category"].notna(), spending["type"]
        )
    else:
        spending["Category"] = spending["type"]
    spending["Spending (RM)"] = pd.to_numeric(spending["amount"], errors="coerce").abs()
    return (
        spending.groupby("Category", as_index=False)["Spending (RM)"]
        .sum()
        .sort_values("Spending (RM)", ascending=False)
    )


def current_month_transactions(
    transactions: list[dict[str, Any]], reference_date: datetime | None = None
) -> list[dict[str, Any]]:
    """Return only records from the selected month (the current month by default)."""
    target = reference_date or datetime.now()
    selected: list[dict[str, Any]] = []
    for item in transactions:
        try:
            item_date = datetime.strptime(str(item.get("date", "")), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if item_date.year == target.year and item_date.month == target.month:
            selected.append(item)
    return selected


def monthly_spending_summary(
    transactions: list[dict[str, Any]], reference_date: datetime | None = None
) -> pd.DataFrame:
    """Summarise outgoing transactions for one calendar month by category."""
    return spending_summary(current_month_transactions(transactions, reference_date))


def update_monthly_budget(username: str, amount: float) -> None:
    """Save a user's preferred monthly spending limit."""
    if amount < 0:
        raise BankingError("Monthly budget cannot be negative.")
    with DATA_LOCK:
        data = load_data()
        user = data["users"].get(username)
        if not user:
            raise BankingError("The logged-in account no longer exists.")
        user["monthly_budget"] = round(float(amount), 2)
        add_security_event(user, "Budget updated", "Successful", f"New limit: {money(amount)}")
        save_data(data)


def transactions_csv(transactions: list[dict[str, Any]]) -> bytes:
    """Turn a list of transactions into a CSV file the user can download."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["date", "id", "type", "category", "description", "amount", "balance_after"],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(transactions)
    # This little marker (BOM) helps the file open correctly in Excel.
    return output.getvalue().encode("utf-8-sig")


def process_transaction(username: str, pending: dict[str, Any]) -> dict[str, Any]:
    """Check and save one transaction, after its OTP has been approved."""
    with DATA_LOCK:
        data = load_data()  # Load the newest saved balance first, in case it changed.
        user = data["users"].get(username)
        if user is None:
            raise BankingError("The logged-in account no longer exists.")

        kind = pending["kind"]
        details = pending["details"]
        amount = round(float(details["amount"]), 2)
        if amount <= 0:
            raise BankingError("Amount must be greater than RM 0.00.")

        ref = f"FNB-{datetime.now():%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"

        if kind == "Transfer":
            recipient_account = str(details["recipient_account"]).strip()
            if not valid_account_number(recipient_account):
                raise BankingError("Recipient account number must contain exactly 10 digits.")
            recipient_username = find_username_by_account(data, recipient_account)
            if recipient_username == username:
                raise BankingError("You cannot transfer money to the same account.")
            if user["balance"] < amount:
                raise BankingError("Insufficient balance for this transfer.")

            user["balance"] = round(user["balance"] - amount, 2)
            note = str(details.get("note", "")).strip()
            note_suffix = f" - {note}" if note else ""

            if recipient_username:
                recipient = data["users"][recipient_username]
                recipient["balance"] = round(recipient["balance"] + amount, 2)
                recipient_label = recipient["full_name"]
                add_transaction(
                    recipient,
                    "Transfer Received",
                    f"Transfer from {user['full_name']}{note_suffix}",
                    amount,
                    ref,
                )
            else:
                recipient_label = f"external account •••• {recipient_account[-4:]}"

            add_transaction(
                user, "Transfer", f"Transfer to {recipient_label}{note_suffix}", -amount, ref
            )

        elif kind == "Bill Payment":
            if user["balance"] < amount:
                raise BankingError("Insufficient balance for this bill payment.")
            user["balance"] = round(user["balance"] - amount, 2)
            category = details.get("category", "Bill")
            description = f"{category}: {details['provider']} - {details['customer_reference']}"
            add_transaction(user, "Bill Payment", description, -amount, ref, category=category)

        elif kind == "Credit Card Payment":
            outstanding = float(user["credit_card"]["outstanding"])
            if amount > outstanding:
                raise BankingError("Payment cannot be higher than the outstanding card balance.")
            if user["balance"] < amount:
                raise BankingError("Insufficient balance for this credit card payment.")
            user["balance"] = round(user["balance"] - amount, 2)
            user["credit_card"]["outstanding"] = round(outstanding - amount, 2)
            add_transaction(
                user,
                "Credit Card",
                f"Card payment {masked_card_number(user['credit_card']['number'])}",
                -amount,
                ref,
            )

        elif kind == "Deposit":
            # This is just a demo - no real cash is actually deposited.
            user["balance"] = round(user["balance"] + amount, 2)
            add_transaction(user, "Deposit", details["source"], amount, ref)

        else:
            raise BankingError("Unknown transaction type.")

        save_data(data)
        return {
            "reference": ref,
            "kind": kind,
            "amount": amount,
            "balance": user["balance"],
            "message": f"{kind} completed successfully.",
        }


def create_pending_transaction(kind: str, details: dict[str, Any], summary: str) -> None:
    """Make a new one-time OTP code, and only save its hash, not the code."""
    otp = f"{secrets.randbelow(1_000_000):06d}"
    created_at = time.time()
    st.session_state.pending_transaction = {
        "otp_id": uuid.uuid4().hex[:10],
        "kind": kind,
        "details": details,
        "summary": summary,
        "otp_hash": hashlib.sha256(otp.encode("utf-8")).hexdigest(),
        "created_at": created_at,
        "expires_at": created_at + OTP_VALID_SECONDS,
        # Don't start the 60-second timer yet. We start it later, once the
        # OTP box is actually on screen, so page-loading time doesn't eat
        # into the time the user actually gets to enter the code.
        "countdown_started": False,
        "verification_attempts": 0,
    }
    # A real bank would text this code to the user. Here we just show it
    # on screen instead, since this is only a demo.
    st.session_state.demo_otp = otp
    record_security_event(
        st.session_state.get("username", ""),
        "OTP generated",
        "Active",
        f"{kind} verification; expires in {OTP_VALID_SECONDS} seconds",
    )


# Styling and image helpers
def image_data_uri(path: Path) -> str | None:
    """Turn a local image file into text, so it can be embedded in the page."""
    if not path.exists():
        return None
    mime_type = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime_type};base64,{encoded}"


def inject_css() -> None:
    """Add the Finora look (blue, sky blue, white, and mint colors) to the page."""
    login_background = image_data_uri(APP_DIR / "assets" / "finora_background_v2.png")
    inside_background = image_data_uri(APP_DIR / "assets" / "finora_dashboard_background.png")
    if st.session_state.get("authenticated") and inside_background:
        page_background = (
            f"url('{inside_background}') center center / cover fixed no-repeat"
        )
    elif login_background:
        page_background = (
            "linear-gradient(rgba(5, 28, 65, .18), rgba(5, 45, 88, .30)), "
            f"url('{login_background}') center center / cover fixed no-repeat"
        )
    else:
        page_background = f"linear-gradient(135deg, {LIGHT_BLUE} 0%, #FFFFFF 55%, #F1FFFB 100%)"

    st.markdown(
        f"""
        <style>
        .stApp {{ background: {page_background}; min-height: 100vh; }}
        [data-testid="stSidebar"] {{ background: linear-gradient(180deg, #0B2D55 0%, {DEEP_BLUE} 70%, #145B79 100%); }}
        [data-testid="stSidebar"] * {{ color: white; }}
        [data-testid="stSidebar"] [role="radiogroup"] label {{
            padding:.72rem .82rem; border-radius:11px; margin:.14rem 0;
            border-left:3px solid transparent; transition:all .20s ease;
            cursor:pointer;
        }}
        [data-testid="stSidebar"] [role="radiogroup"] input[type="radio"] {{
            display:none !important;
        }}
        [data-testid="stSidebar"] [role="radiogroup"] label:hover {{
            background:rgba(110,193,228,.17); transform:translateX(3px);
        }}
        [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {{
            background:linear-gradient(90deg, rgba(110,193,228,.32), rgba(143,217,199,.16));
            border-left-color:{MINT_GREEN}; box-shadow:0 7px 18px rgba(2,24,55,.20);
        }}
        [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) p {{
            color:#FFFFFF !important; font-weight:750;
        }}
        [data-testid="stSidebar"] div.stButton > button {{
            width:100%; color:#FFFFFF !important;
            background:rgba(255,255,255,.06) !important;
            border:1px solid {SKY_BLUE} !important;
            box-shadow:none !important;
        }}
        [data-testid="stSidebar"] div.stButton > button:hover {{
            color:#FFFFFF !important;
            background:rgba(110,193,228,.20) !important;
            border-color:#FFFFFF !important;
        }}
        [data-testid="stSidebar"] div.stButton > button:focus,
        [data-testid="stSidebar"] div.stButton > button:active {{
            color:#FFFFFF !important;
            background:rgba(110,193,228,.28) !important;
            border-color:{MINT_GREEN} !important;
            box-shadow:0 0 0 2px rgba(143,217,199,.22) !important;
        }}
        [data-testid="stSidebar"] div.stButton > button p {{ color:#FFFFFF !important; }}
        .block-container {{ max-width: 1180px; padding-top: 4.5rem; padding-bottom: 3rem; }}
        h1, h2, h3 {{ color: {DEEP_BLUE}; letter-spacing: -.02em; }}
        .brand-row {{ display:flex; align-items:center; gap:.75rem; margin-bottom:1.1rem; }}
        .brand-mark {{
            width:48px; height:48px; border-radius:14px; display:flex; align-items:center;
            justify-content:center; color:white; font-weight:800; font-size:26px;
            background:linear-gradient(145deg,{SKY_BLUE},{DEEP_BLUE}); box-shadow:0 8px 24px #123B6D35;
        }}
        .brand-name {{ font-size:1.35rem; line-height:1; font-weight:800; color:{DEEP_BLUE}; }}
        .brand-sub {{ color:#4D7890; font-size:.76rem; letter-spacing:.12em; margin-top:.28rem; }}
        .brand-logo-login {{
            display:flex; justify-content:center; align-items:center;
            width:100%; max-width:390px; margin:1.35rem auto .90rem auto;
        }}
        .brand-logo-login img {{ display:block; width:100%; height:auto; object-fit:contain; }}
        .brand-logo-compact {{
            display:flex; justify-content:flex-start; align-items:center;
            width:100%; max-width:190px; margin:0 0 1rem 0;
        }}
        .brand-logo-compact img {{ display:block; width:100%; height:auto; object-fit:contain; }}
        .hero {{
            border-radius:20px; padding:1.45rem 1.55rem; color:white; margin-bottom:1rem;
            background:radial-gradient(circle at 85% 0%, #69D7EE 0%, transparent 30%),
                       linear-gradient(120deg,#092A55 0%,{DEEP_BLUE} 55%,#087DA2 100%);
            box-shadow:0 14px 34px #123B6D25;
        }}
        .hero h2 {{ color:white; margin:0 0 .2rem 0; }}
        .hero p {{ color:#DDF6FF; margin:0; }}
        .dashboard-hero {{
            min-height:330px; border-radius:22px; padding:2rem 2.2rem 1.45rem;
            display:flex; flex-direction:column; justify-content:center;
            color:white; margin-bottom:1.15rem; overflow:hidden;
            background-size:cover; background-position:center;
            box-shadow:0 18px 42px #123B6D35;
        }}
        .dashboard-hero .eyebrow {{
            color:{MINT_GREEN}; font-size:.78rem; letter-spacing:.14em;
            font-weight:800; margin-bottom:.65rem;
        }}
        .dashboard-hero h2 {{ color:white; font-size:2.15rem; max-width:480px; margin:0 0 .65rem 0; }}
        .dashboard-hero p {{ color:#E3F7FF; max-width:455px; font-size:1rem; margin:0; line-height:1.55; }}
        .hero-features {{
            display:grid; grid-template-columns:repeat(3, 1fr); gap:.65rem;
            max-width:760px; margin-top:1.35rem;
        }}
        .hero-feature {{
            min-height:72px; padding:.70rem .78rem; border-radius:12px;
            background:rgba(5,39,82,.66); border:1px solid rgba(174,231,244,.42);
            backdrop-filter:blur(7px); -webkit-backdrop-filter:blur(7px);
            box-shadow:0 8px 22px rgba(2,25,58,.20);
        }}
        .hero-feature strong {{ display:block; color:#FFFFFF; font-size:.82rem; margin-bottom:.26rem; }}
        .hero-feature span {{ display:block; color:#D9F4FB; font-size:.70rem; line-height:1.35; }}
        div[data-testid="stMetric"] {{
            background:rgba(255,255,255,.96); border:1px solid #D8EDF6; border-radius:16px;
            padding:1rem 1.05rem; box-shadow:0 8px 24px #123B6D12;
        }}
        div[data-testid="stMetric"] label {{ color:#567286; }}
        div[data-testid="stMetricValue"] {{ color:{DEEP_BLUE}; }}
        .card-number-panel {{
            min-height:108px; padding:1rem 1.05rem; border-radius:16px;
            background:rgba(255,255,255,.96); border:1px solid #D8EDF6;
            box-shadow:0 8px 24px #123B6D12; display:flex;
            flex-direction:column; justify-content:center;
        }}
        .card-number-label {{ color:#567286; font-size:.88rem; margin-bottom:.35rem; }}
        .card-number-value {{
            color:{DEEP_BLUE}; font-size:clamp(1.12rem, 2.1vw, 1.72rem);
            line-height:1.2; letter-spacing:.025em; white-space:nowrap;
        }}
        .card-number-note {{ color:#7890A0; font-size:.68rem; margin-top:.32rem; letter-spacing:.08em; }}
        div.stButton > button, div.stDownloadButton > button {{
            border-radius:10px; border:1px solid {DEEP_BLUE}; font-weight:650;
        }}
        div.stButton > button[kind="primary"] {{
            color:white; background:linear-gradient(90deg,{DEEP_BLUE},#0A78A0); border:0;
        }}
        div.stButton > button:hover, div.stDownloadButton > button:hover {{
            border-color:{SKY_BLUE}; color:{DEEP_BLUE}; box-shadow:0 5px 16px #6EC1E435;
        }}
        div[data-testid="stForm"] {{
            background:rgba(255,255,255,.96); border:1px solid #D7EDF5; border-radius:16px;
            padding:1.1rem 1.2rem; box-shadow:0 12px 32px #071F4140;
        }}
        [data-testid="stExpander"] {{ background:rgba(255,255,255,.92); border-radius:12px; }}
        .success-card {{
            background:#E9FBF6; border-left:5px solid {MINT_GREEN}; border-radius:14px;
            padding:1.1rem 1.2rem; color:{DARK_NAVY}; margin:.75rem 0;
        }}
        .muted {{ color:#607B8C; }}
        .footer {{ text-align:center; color:#7790A0; font-size:.78rem; margin-top:2.5rem; }}
        @media (max-width: 760px) {{
            .dashboard-hero {{ min-height:auto; padding:1.45rem; background-position:62% center; }}
            .hero-features {{ grid-template-columns:1fr; max-width:330px; }}
            .hero-feature {{ min-height:auto; }}
        }}
        @media (max-width: 480px) {{
            .block-container {{ padding-top: 3rem; padding-left: .8rem; padding-right: .8rem; }}
            .dashboard-hero {{ padding:1.1rem; }}
            .dashboard-hero h2 {{ font-size:1.5rem; max-width:100%; }}
            .dashboard-hero p {{ font-size:.85rem; max-width:100%; }}
            .hero-feature {{ padding:.55rem .65rem; }}
            .hero-feature strong {{ font-size:.76rem; }}
            .hero-feature span {{ font-size:.66rem; }}
            .card-number-value {{ font-size:1.0rem; white-space:normal; }}
            [data-testid="stSidebar"] [role="radiogroup"] label {{ padding:.55rem .6rem; }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def brand_header(compact: bool = False) -> None:
    """Show the Finora logo image, or a text logo if the image file is missing."""
    logo_path = APP_DIR / "assets" / "finora_logo.png"
    if logo_path.exists():
        logo_uri = image_data_uri(logo_path)
        logo_class = "brand-logo-compact" if compact else "brand-logo-login"
        st.markdown(
            f'<div class="{logo_class}"><img src="{logo_uri}" alt="Finora Bank"></div>',
            unsafe_allow_html=True,
        )
        return

    st.markdown(
        """
        <div class="brand-row">
          <div class="brand-mark">F</div>
          <div><div class="brand-name">FINORA BANK</div>
          <div class="brand-sub">VIRTUAL BANKING SYSTEM</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def money(value: float) -> str:
    """Turn a number into a Malaysian ringgit amount, like "RM 1,234.56"."""
    return f"RM {float(value):,.2f}"


def current_user(data: dict[str, Any]) -> dict[str, Any]:
    """Get the account data for whoever is logged in right now."""
    return data["users"][st.session_state.username]


def sign_out(message: str | None = None) -> None:
    """Log the user out and clear everything tied to their session."""
    username = st.session_state.get("username", "")
    if username:
        try:
            event_details = "Session timed out" if message == "timeout" else "User signed out"
            record_security_event(username, "Session ended", "Successful", event_details)
        except DataStoreError:
            # Signing out must still work even if the audit file cannot be written.
            pass
    for key in [
        "authenticated", "username", "last_activity", "pending_transaction",
        "demo_otp", "transaction_result", "navigation", "requested_page",
        "account_visible", "card_visible",
    ]:
        st.session_state.pop(key, None)
    if message:
        st.session_state.logout_message = message


def change_page(page: str) -> None:
    """Jump to a different page when a quick-action button is clicked."""
    # The sidebar menu is already drawn by the time this button is clicked,
    # so we can't change it right this second. Save the page we want and
    # switch to it on the next run instead.
    st.session_state.requested_page = page
    st.rerun()


def toggle_account_details() -> None:
    """Switch the sidebar balance between hidden and shown."""
    st.session_state.account_visible = not bool(st.session_state.get("account_visible", False))


def toggle_card_details() -> None:
    """Switch the card number between hidden and shown."""
    st.session_state.card_visible = not bool(st.session_state.get("card_visible", False))


# Login page and sidebar menu
def login_page() -> None:
    """Show the login form and check the username and password."""
    left, centre, right = st.columns([1, 1.25, 1])
    with centre:
        brand_header()
        st.markdown(
            """
            <div class="hero">
              <h2>Secure Online Banking</h2>
              <p>Fast, simple and protected access to your Finora account.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.session_state.pop("logout_message", None):
            st.info("Your session ended safely. Please sign in again.")

        with st.form("login_form"):
            st.subheader("Welcome back")
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("Sign in securely", type="primary", use_container_width=True)

        if submitted:
            if not username.strip() or not password:
                st.error("Please enter both username and password.")
                return
            try:
                status, message = authenticate(username, password)
                if status == "success":
                    st.session_state.authenticated = True
                    st.session_state.username = username.strip().lower()
                    st.session_state.last_activity = time.time()
                    st.session_state.navigation = "Dashboard"
                    st.rerun()
                st.error(message)
            except DataStoreError as exc:
                st.error(str(exc))

        with st.expander("Demonstration login"):
            st.code("Username: Paulina\nPassword: Finora@123")
            st.caption("The password is stored as a salted hash in the JSON data file.")
        st.caption(
            "This demo only has two fixed accounts, so there's no sign-up or "
            "'forgot password' page - that's on purpose, not missing. Use the "
            "demo login above."
        )

        with st.expander("About this project"):
            st.markdown(
                "Finora Bank is a demo banking app built with **Streamlit** and "
                "**Python**. A few things it does under the hood:\n\n"
                "- Passwords are hashed with **PBKDF2-SHA256** and a random salt "
                "- the plain password is never stored\n"
                "- Money-moving actions need a one-time **OTP** code that expires "
                "after 60 seconds\n"
                "- Login locks for 60 seconds after 3 wrong password attempts\n"
                "- Account data is saved with an **atomic write**, so a crash "
                "mid-save can't corrupt the file\n\n"
                "It's a personal/learning project - no real bank, money, or "
                "SMS provider is connected."
            )


def sidebar(user: dict[str, Any]) -> str:
    """Show the account name, balance, page menu, and sign-out button."""
    with st.sidebar:
        st.markdown("## FINORA BANK")
        st.caption("SECURE • SIMPLE • SMART")
        st.markdown(f"**{html.escape(user['full_name'])}**")
        account_visible = bool(st.session_state.get("account_visible", False))
        if account_visible:
            st.caption(f"Savings {user['account_number']}")
            st.markdown(f"### {money(user['balance'])}")
        else:
            st.caption(f"Savings •••• {user['account_number'][-4:]}")
            st.markdown("### RM ••••••")

        visibility_label = "🙈 Hide account details" if account_visible else "👁 Show account details"
        st.button(
            visibility_label,
            key="account_visibility_toggle",
            on_click=toggle_account_details,
            use_container_width=True,
        )
        st.divider()
        pages = [
            "Dashboard", "Transfer", "Pay Bills", "Credit Card",
            "Deposit", "Budget Planner", "Transactions", "Security",
        ]
        if st.session_state.get("navigation") not in pages:
            st.session_state.navigation = "Dashboard"
        page = st.radio(
            "Banking menu",
            pages,
            key="navigation",
            format_func=lambda page_name: NAVIGATION_LABELS[page_name],
            label_visibility="collapsed",
        )
        st.divider()
        if st.button("Sign out", use_container_width=True):
            sign_out()
            st.rerun()
        st.caption("Protected by OTP verification and automatic session timeout.")
    return page


# The actual banking pages (Dashboard, Transfer, and so on)
def page_title(title: str, subtitle: str) -> None:
    """Show a page title with a short description underneath it."""
    st.title(title)
    st.markdown(f"<p class='muted'>{html.escape(subtitle)}</p>", unsafe_allow_html=True)


def dashboard_page(user: dict[str, Any]) -> None:
    """Show the balance, quick-action buttons, recent activity, and charts."""
    first_name = html.escape(user["full_name"].split()[0])
    hero_image = image_data_uri(APP_DIR / "assets" / "finora_dashboard_hero.png")
    if hero_image:
        st.markdown(
            f"""
            <div class="dashboard-hero" style="background-image:
              linear-gradient(90deg, rgba(6,35,77,.98) 0%, rgba(12,64,116,.88) 42%,
              rgba(12,64,116,.08) 72%), url('{hero_image}');">
              <div class="eyebrow">SECURE DIGITAL BANKING</div>
              <h2>Welcome back, {first_name}.</h2>
              <p>Manage your money confidently with secure payments, clear insights
              and everyday banking in one place.</p>
              <div class="hero-features">
                <div class="hero-feature"><strong>Secure by design</strong>
                  <span>Password hashing, account lock and OTP.</span></div>
                <div class="hero-feature"><strong>Smart insights</strong>
                  <span>Track spending and balance trends.</span></div>
                <div class="hero-feature"><strong>Everyday convenience</strong>
                  <span>Transfer, pay and deposit securely.</span></div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div class="hero"><h2>Good day, {first_name}</h2>
            <p>Here is your financial overview and recent Finora activity.</p></div>
            """,
            unsafe_allow_html=True,
        )

    transactions = user["transactions"]
    outgoing = [t for t in transactions if float(t["amount"]) < 0]
    current_month = datetime.now().strftime("%Y-%m")
    monthly_spending = -sum(float(t["amount"]) for t in outgoing if t["date"].startswith(current_month))

    col1, col2, col3 = st.columns(3)
    col1.metric("Available balance", money(user["balance"]))
    col2.metric("This month's spending", money(monthly_spending))
    col3.metric("Card outstanding", money(user["credit_card"]["outstanding"]))

    st.subheader("Quick actions")
    q1, q2, q3, q4 = st.columns(4)
    if q1.button("Transfer money", use_container_width=True):
        change_page("Transfer")
    if q2.button("Pay a bill", use_container_width=True):
        change_page("Pay Bills")
    if q3.button("Pay card", use_container_width=True):
        change_page("Credit Card")
    if q4.button("Make deposit", use_container_width=True):
        change_page("Deposit")

    overview_tab, insights_tab = st.tabs(["Recent activity", "Financial analytics"])
    with overview_tab:
        if transactions:
            recent = pd.DataFrame(list(reversed(transactions[-5:])))
            recent["Amount"] = recent["amount"].map(money)
            recent["Balance"] = recent["balance_after"].map(money)
            st.dataframe(
                recent[["date", "type", "description", "Amount", "Balance"]].rename(
                    columns={"date": "Date", "type": "Type", "description": "Description"}
                ),
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No transactions have been recorded yet.")

    with insights_tab:
        chart1, chart2 = st.columns(2)
        with chart1:
            st.markdown("#### Spending by category")
            category = spending_summary(transactions)
            if not category.empty:
                st.bar_chart(
                    category.set_index("Category"),
                    y="Spending (RM)",
                    color=SKY_BLUE,
                    use_container_width=True,
                )
                st.caption("Total outgoing amount grouped by transaction type.")
            else:
                st.info("Complete an outgoing transaction to view spending insights.")

        with chart2:
            st.markdown("#### Balance over time")
            history = balance_history_frame(transactions)
            if not history.empty:
                st.line_chart(
                    history,
                    y="Balance (RM)",
                    color=DEEP_BLUE,
                    use_container_width=True,
                )
                st.caption("Available balance recorded after each transaction.")
            else:
                st.info("Complete a transaction to view the balance trend.")


def otp_countdown(expires_at: float, otp_id: str) -> None:
    """Show a live countdown timer for the OTP, running in the browser."""
    # We send a countdown length, not a fixed clock time, because the
    # user's computer clock might not match the server's clock.
    remaining_ms = max(0, int((expires_at - time.time()) * 1000))
    timer_id = f"otp-timer-{otp_id}"
    components.html(
        f"""
        <div style="font-family:Arial,sans-serif;padding:2px 1px 0;color:#123B6D;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <strong>OTP expires in</strong>
            <strong id="{timer_id}-text" style="font-size:20px;color:#123B6D;">60 seconds</strong>
          </div>
          <div style="height:10px;background:#DDEEF5;border-radius:999px;overflow:hidden;">
            <div id="{timer_id}-bar" style="height:100%;width:100%;background:#6EC1E4;
                 border-radius:999px;transition:width 1s linear,background .3s;"></div>
          </div>
        </div>
        <script>
          const deadline = Date.now() + {remaining_ms};
          const textElement = document.getElementById("{timer_id}-text");
          const barElement = document.getElementById("{timer_id}-bar");
          function updateTimer() {{
            const seconds = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
            textElement.textContent = seconds > 0 ? seconds + " seconds" : "Expired";
            barElement.style.width = Math.min(100, (seconds / {OTP_VALID_SECONDS}) * 100) + "%";
            if (seconds <= 10) {{
              textElement.style.color = "#D64545";
              barElement.style.background = "#D64545";
            }}
            if (seconds <= 0) clearInterval(timerInterval);
          }}
          let timerInterval;
          updateTimer();
          timerInterval = setInterval(updateTimer, 1000);
        </script>
        """,
        height=68,
    )


def session_countdown(duration_seconds: int = SESSION_TIMEOUT_SECONDS) -> None:
    """Show a browser-side session countdown from the exact duration."""
    # Use a duration instead of a server timestamp. The Streamlit server and
    # the user's computer can have slightly different clocks, which previously
    # caused a five-minute timer to begin at values such as 5:02.
    duration_ms = max(0, int(duration_seconds * 1000))
    components.html(
        f"""
        <div style="font-family:Arial,sans-serif;padding:2px 1px 0;color:#123B6D;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <strong>Session time remaining</strong>
            <strong id="session-timer-text" style="font-size:20px;color:#123B6D;">5:00</strong>
          </div>
          <div style="height:10px;background:#DDEEF5;border-radius:999px;overflow:hidden;">
            <div id="session-timer-bar" style="height:100%;width:100%;
                 background:linear-gradient(90deg,#123B6D,#6EC1E4,#8FD9C7);
                 border-radius:999px;transition:width 1s linear,background .3s;"></div>
          </div>
          <div id="session-timer-note" style="font-size:12px;color:#58778F;margin-top:7px;">
            The timer restarts when you interact with the banking app.
          </div>
        </div>
        <script>
          const sessionTotal = {SESSION_TIMEOUT_SECONDS};
          const sessionDeadline = Date.now() + {duration_ms};
          const sessionText = document.getElementById("session-timer-text");
          const sessionBar = document.getElementById("session-timer-bar");
          const sessionNote = document.getElementById("session-timer-note");
          function updateSessionTimer() {{
            const seconds = Math.max(0, Math.ceil((sessionDeadline - Date.now()) / 1000));
            const minutes = Math.floor(seconds / 60);
            const remainder = String(seconds % 60).padStart(2, "0");
            sessionText.textContent = minutes + ":" + remainder;
            sessionBar.style.width = Math.min(100, (seconds / sessionTotal) * 100) + "%";
            if (seconds <= 60) {{
              sessionText.style.color = "#D64545";
              sessionBar.style.background = "#D64545";
              sessionNote.textContent = "Your session will expire soon.";
            }}
            if (seconds <= 0) {{
              sessionText.textContent = "Expired";
              sessionNote.textContent = "Interact with the app to complete automatic sign-out.";
              clearInterval(sessionTimerInterval);
            }}
          }}
          let sessionTimerInterval;
          updateSessionTimer();
          sessionTimerInterval = setInterval(updateSessionTimer, 1000);
        </script>
        """,
        height=82,
    )


def otp_panel() -> None:
    """Show the OTP box and check the code the user types in."""
    pending = st.session_state.get("pending_transaction")
    if not pending:
        return

    # Submitting the form reloads the page. We start the 60-second timer
    # here instead of earlier, so the user still gets the full 60 seconds
    # even if that reload took a moment.
    if not pending.get("countdown_started", False):
        countdown_started_at = time.time()
        pending["created_at"] = countdown_started_at
        pending["expires_at"] = countdown_started_at + OTP_VALID_SECONDS
        pending["countdown_started"] = True

    st.divider()
    st.subheader("Secure verification")
    st.write(pending["summary"])
    remaining = max(0, int(pending["expires_at"] - time.time()))
    otp_countdown(pending["expires_at"], pending.get("otp_id", "current"))
    if remaining == 0:
        st.error("This OTP has expired. Generate a new OTP to continue.")

    with st.expander("View demonstration OTP", expanded=True):
        st.code(st.session_state.get("demo_otp", "------"), language=None)
        st.caption(
            "This code is shown here on purpose, just for the demo. A real bank "
            "would send it by SMS or a push notification, and would never show "
            "it on screen like this. That SMS/push step is what a production "
            "version of this app would plug in here instead."
        )

    with st.form("otp_form"):
        entered_otp = st.text_input("6-digit OTP", max_chars=6, placeholder="Enter verification code")
        verify_clicked = st.form_submit_button("Verify and complete", type="primary")

    cancel_col, resend_col = st.columns(2)
    if cancel_col.button("Cancel transaction", use_container_width=True):
        record_security_event(
            st.session_state.username, "OTP verification", "Cancelled", pending["kind"]
        )
        st.session_state.pop("pending_transaction", None)
        st.session_state.pop("demo_otp", None)
        st.rerun()
    if resend_col.button("Generate new OTP", use_container_width=True):
        create_pending_transaction(pending["kind"], pending["details"], pending["summary"])
        st.rerun()

    if verify_clicked:
        if not entered_otp.isdigit() or len(entered_otp) != 6:
            record_security_event(
                st.session_state.username, "OTP verification", "Failed", "Invalid OTP format"
            )
            st.error("OTP must contain exactly 6 digits.")
            return
        if time.time() > pending["expires_at"]:
            record_security_event(
                st.session_state.username, "OTP verification", "Expired", pending["kind"]
            )
            st.error("The OTP has expired. Please generate a new OTP.")
            return

        entered_hash = hashlib.sha256(entered_otp.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(entered_hash, pending["otp_hash"]):
            pending["verification_attempts"] += 1
            if pending["verification_attempts"] >= 3:
                record_security_event(
                    st.session_state.username,
                    "OTP verification",
                    "Blocked",
                    f"{pending['kind']}; 3 incorrect attempts",
                )
                st.session_state.pop("pending_transaction", None)
                st.session_state.pop("demo_otp", None)
                st.error("Too many incorrect OTP attempts. The transaction was cancelled.")
            else:
                attempts = 3 - pending["verification_attempts"]
                record_security_event(
                    st.session_state.username,
                    "OTP verification",
                    "Failed",
                    f"{pending['kind']}; {attempts} attempt(s) remaining",
                )
                st.error(f"Incorrect OTP. {attempts} attempt(s) remaining.")
            return

        try:
            result = process_transaction(st.session_state.username, pending)
            record_security_event(
                st.session_state.username,
                "OTP verification",
                "Successful",
                f"{pending['kind']}; reference {result['reference']}",
            )
            st.session_state.transaction_result = result
            st.session_state.pop("pending_transaction", None)
            st.session_state.pop("demo_otp", None)
            st.rerun()
        except (BankingError, DataStoreError) as exc:
            st.error(str(exc))


def show_transaction_result() -> None:
    """Show a "your transaction worked" message, once, right after it happens."""
    result = st.session_state.pop("transaction_result", None)
    if not result:
        return
    st.markdown(
        f"""
        <div class="success-card"><strong>{html.escape(result['message'])}</strong><br>
        Amount: {money(result['amount'])}<br>
        Reference: {html.escape(result['reference'])}<br>
        Available balance: {money(result['balance'])}</div>
        """,
        unsafe_allow_html=True,
    )


def transfer_page(user: dict[str, Any]) -> None:
    """Take the transfer details, check them, then ask for the OTP."""
    page_title("Transfer Money", "Send funds to a Finora or simulated external account.")
    show_transaction_result()
    st.metric("Available balance", money(user["balance"]))
    with st.form("transfer_form"):
        recipient_account = st.text_input("Recipient account number", placeholder="Example: 8800259999")
        amount = st.number_input("Transfer amount (RM)", min_value=0.0, step=10.0, format="%.2f")
        note = st.text_input("Payment note (optional)", max_chars=60)
        submitted = st.form_submit_button("Continue to OTP", type="primary")
    if submitted:
        try:
            if not valid_account_number(recipient_account):
                raise BankingError("Recipient account number must contain exactly 10 digits.")
            data = load_data()
            recipient_username = find_username_by_account(data, recipient_account)
            if recipient_username == st.session_state.username:
                raise BankingError("You cannot transfer money to your own account.")
            if amount <= 0:
                raise BankingError("Transfer amount must be greater than RM 0.00.")
            if amount > user["balance"]:
                raise BankingError("Insufficient balance for this transfer.")
            recipient_name = (
                data["users"][recipient_username]["full_name"]
                if recipient_username
                else f"external account •••• {recipient_account[-4:]}"
            )
            details = {
                "recipient_account": recipient_account.strip(),
                "amount": amount,
                "note": note.strip(),
            }
            summary = f"Transfer {money(amount)} to {recipient_name} (•••• {recipient_account[-4:]})."
            create_pending_transaction("Transfer", details, summary)
            st.rerun()
        except (BankingError, DataStoreError) as exc:
            st.error(str(exc))
    otp_panel()
    st.caption("Enter exactly 10 digits. Demo Finora recipient: Alex Tan • 8800259999")


def bills_page(user: dict[str, Any]) -> None:
    """Let the user pick a bill, check the details, then ask for the OTP."""
    page_title("Pay Bills", "Pay utilities and services from your savings account.")
    show_transaction_result()
    category = st.selectbox(
        "Bill category",
        list(BILLERS),
        key="bill_category",
        help="The provider list updates automatically when this category changes.",
    )
    with st.form("bill_form"):
        provider = st.selectbox(
            "Service provider",
            BILLERS[category],
            key=f"bill_provider_{category}",
        )
        customer_reference = st.text_input("Bill account / reference number", max_chars=30)
        amount = st.number_input("Payment amount (RM)", min_value=0.0, step=10.0, format="%.2f")
        submitted = st.form_submit_button("Continue to OTP", type="primary")
    if submitted:
        if not customer_reference.strip():
            st.error("Please enter the bill account or reference number.")
        elif amount <= 0:
            st.error("Payment amount must be greater than RM 0.00.")
        elif amount > user["balance"]:
            st.error("Insufficient balance for this bill payment.")
        else:
            details = {
                "category": category,
                "provider": provider,
                "customer_reference": customer_reference.strip(),
                "amount": amount,
            }
            create_pending_transaction(
                "Bill Payment", details, f"Pay {money(amount)} to {provider}."
            )
            st.rerun()
    otp_panel()


def credit_card_page(user: dict[str, Any]) -> None:
    """Show the card details and handle minimum, full, or custom payments."""
    card = user["credit_card"]
    page_title("Credit Card", "View and pay your Finora credit card securely.")
    show_transaction_result()
    c1, c2, c3 = st.columns(3)
    card_visible = bool(st.session_state.get("card_visible", False))
    displayed_card = (
        visible_card_number(card["number"])
        if card_visible
        else masked_card_number(card["number"])
    )
    with c1:
        st.markdown(
            f"""
            <div class="card-number-panel">
              <div class="card-number-label">Card</div>
              <div class="card-number-value">{html.escape(displayed_card)}</div>
              <div class="card-number-note">DEMONSTRATION CARD</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        card_button_label = "🙈 Hide card number" if card_visible else "👁 Show card number"
        st.button(
            card_button_label,
            key="card_visibility_toggle",
            on_click=toggle_card_details,
            use_container_width=True,
        )
    c2.metric("Outstanding", money(card["outstanding"]))
    c3.metric("Available credit", money(card["limit"] - card["outstanding"]))
    minimum_payment = min(card["outstanding"], round(max(50.0, card["outstanding"] * 0.10), 2)) if card["outstanding"] else 0.0

    # This has to sit outside the form. That way, picking "Custom" shows
    # its input box right away, instead of waiting for a submit click.
    option = st.radio(
        "Payment option",
        ["Minimum payment", "Full payment", "Custom amount"],
        horizontal=True,
        key="card_payment_option",
    )
    with st.form("card_form"):
        custom_amount = 0.0
        if option == "Minimum payment":
            st.info(f"Payment amount: {money(minimum_payment)}")
        elif option == "Full payment":
            st.info(f"Payment amount: {money(card['outstanding'])}")
        else:
            custom_amount = st.number_input(
                "Custom amount (RM)",
                min_value=0.0,
                step=10.0,
                format="%.2f",
            )
        submitted = st.form_submit_button("Continue to OTP", type="primary")
    if submitted:
        amount = minimum_payment if option == "Minimum payment" else card["outstanding"] if option == "Full payment" else custom_amount
        if card["outstanding"] <= 0:
            st.info("There is no outstanding card balance to pay.")
        elif amount <= 0:
            st.error("Payment amount must be greater than RM 0.00.")
        elif amount > card["outstanding"]:
            st.error("Payment cannot exceed the outstanding card balance.")
        elif amount > user["balance"]:
            st.error("Insufficient balance for this card payment.")
        else:
            create_pending_transaction(
                "Credit Card Payment",
                {"amount": amount},
                f"Pay {money(amount)} to Finora credit card {card['number']}.",
            )
            st.rerun()
    otp_panel()
    st.caption(f"Current minimum payment: {money(minimum_payment)}")


def deposit_page(user: dict[str, Any]) -> None:
    """Pretend to add money to the account. Demo only, no real deposit."""
    page_title("Make a Deposit", "Simulate adding funds to your Finora savings account.")
    show_transaction_result()
    st.warning("Demonstration mode: this does not accept or move real money.")
    with st.form("deposit_form"):
        source = st.selectbox("Deposit source", ["Cash deposit", "Cheque deposit", "External bank transfer"])
        amount = st.number_input("Deposit amount (RM)", min_value=0.0, step=50.0, format="%.2f")
        submitted = st.form_submit_button("Continue to OTP", type="primary")
    if submitted:
        if amount <= 0:
            st.error("Deposit amount must be greater than RM 0.00.")
        elif amount > 100_000:
            st.error("A single demonstration deposit cannot exceed RM 100,000.00.")
        else:
            create_pending_transaction(
                "Deposit", {"source": source, "amount": amount}, f"Deposit {money(amount)} from {source}."
            )
            st.rerun()
    otp_panel()


def budget_planner_page(user: dict[str, Any]) -> None:
    """Help the user set and monitor a monthly spending target."""
    today = datetime.now()
    month_name = today.strftime("%B %Y")
    page_title("Monthly Budget Planner", f"Plan and monitor your spending for {month_name}.")

    current_budget = float(user.get("monthly_budget", 3000.0))
    with st.form("monthly_budget_form"):
        budget_amount = st.number_input(
            "Monthly spending budget (RM)",
            min_value=0.0,
            value=current_budget,
            step=100.0,
            format="%.2f",
            help="Set RM 0.00 if you do not want a monthly limit.",
        )
        save_budget = st.form_submit_button("💾 Save monthly budget", type="primary")
    if save_budget:
        try:
            update_monthly_budget(st.session_state.username, budget_amount)
            st.session_state.budget_message = f"Budget updated to {money(budget_amount)}."
            st.rerun()
        except (BankingError, DataStoreError) as exc:
            st.error(str(exc))

    message = st.session_state.pop("budget_message", None)
    if message:
        st.success(message)

    summary = monthly_spending_summary(user.get("transactions", []), today)
    spent = float(summary["Spending (RM)"].sum()) if not summary.empty else 0.0
    remaining = current_budget - spent
    usage = spent / current_budget if current_budget > 0 else 0.0

    budget_col, spent_col, remaining_col = st.columns(3)
    budget_col.metric("Monthly budget", money(current_budget))
    spent_col.metric("Spent this month", money(spent))
    remaining_col.metric(
        "Remaining",
        money(max(remaining, 0.0)),
        delta=f"{money(abs(remaining))} over" if remaining < 0 else None,
        delta_color="inverse",
    )

    if current_budget <= 0:
        st.info("Set a monthly budget above RM 0.00 to activate progress tracking and alerts.")
    else:
        st.progress(min(usage, 1.0), text=f"{usage:.0%} of the monthly budget used")
        if usage > 1:
            st.error(f"🚨 Budget exceeded by {money(spent - current_budget)}.")
        elif usage >= 0.9:
            st.warning(f"⚠️ You have used {usage:.0%} of this month's budget.")
        elif usage >= 0.7:
            st.info(f"🔔 You have used {usage:.0%}; monitor the rest of your spending.")
        else:
            st.success(f"✅ Spending is within budget. {money(remaining)} remains.")

        days_in_month = calendar.monthrange(today.year, today.month)[1]
        days_remaining = max(days_in_month - today.day + 1, 1)
        daily_allowance = max(remaining, 0.0) / days_remaining
        st.caption(
            f"Suggested daily allowance: **{money(daily_allowance)}** for the remaining "
            f"**{days_remaining} day(s)** of {today.strftime('%B')}."
        )

    st.subheader("Spending by category")
    if summary.empty:
        st.info("No outgoing transactions have been recorded for this month yet.")
    else:
        chart_data = summary.set_index("Category")[["Spending (RM)"]]
        st.bar_chart(chart_data, color=SKY_BLUE)
        category_display = summary.copy()
        category_display["Share"] = category_display["Spending (RM)"].map(
            lambda value: f"{value / spent:.1%}" if spent else "0.0%"
        )
        category_display["Spending (RM)"] = category_display["Spending (RM)"].map(money)
        st.dataframe(category_display, hide_index=True, use_container_width=True)


def transactions_page(user: dict[str, Any]) -> None:
    """Show past transactions, let the user search/filter, and download a CSV."""
    page_title("Transaction History", "Review, filter and export your Finora account activity.")
    transactions = list(reversed(user["transactions"]))
    if not transactions:
        st.info("No transactions have been recorded yet.")
        return
    types = sorted({item["type"] for item in transactions})
    filter_col, search_col = st.columns([1, 2])
    selected_type = filter_col.selectbox("Transaction type", ["All"] + types)
    search_text = search_col.text_input("Search description or reference")
    filtered = [
        item for item in transactions
        if (selected_type == "All" or item["type"] == selected_type)
        and (not search_text.strip() or search_text.lower() in (item["description"] + item["id"]).lower())
    ]
    display = pd.DataFrame(filtered)
    if display.empty:
        st.info("No transactions match the selected filters.")
    else:
        display["Amount"] = display["amount"].map(money)
        display["Balance"] = display["balance_after"].map(money)
        st.dataframe(
            display[["date", "id", "type", "description", "Amount", "Balance"]].rename(
                columns={"date": "Date", "id": "Reference", "type": "Type", "description": "Description"}
            ),
            hide_index=True,
            use_container_width=True,
        )

    st.download_button(
        "Download filtered statement (CSV)",
        data=transactions_csv(filtered),
        file_name=f"finora_statement_{datetime.now():%Y%m%d}.csv",
        mime="text/csv",
        use_container_width=True,
    )


def security_page(user: dict[str, Any]) -> None:
    """Show what security features this demo has, and the current session status."""
    page_title("Security Centre", "Review the protection features used by this simulation.")
    st.success("Your account session is active.")
    c1, c2, c3 = st.columns(3)
    c1.metric("Password", "PBKDF2-SHA256")
    c2.metric("OTP validity", f"{OTP_VALID_SECONDS} seconds")
    c3.metric("Session timeout", f"{SESSION_TIMEOUT_SECONDS // 60} minutes")
    st.subheader("Implemented enhancements")
    enhancements = pd.DataFrame(
        [
            ("Persistent data storage", "Active", "Balances and transactions saved to JSON"),
            ("Password hashing", "Active", "Salted PBKDF2-SHA256; no plain-text password"),
            ("Balance visualisation", "Active", "Balance trend and spending category charts"),
            ("Account lock", "Active", "60-second lock after 3 failed login attempts"),
            ("Session timeout", "Active", "Automatic sign-out after 5 minutes of inactivity"),
            ("Improved OTP", "Active", "Random 6-digit code, 60-second expiry, 3 attempts"),
            ("CSV report export", "Active", "Filtered transaction statement download"),
            ("Monthly budget planner", "Active", "Monthly target, alerts and category analysis"),
            ("Security activity log", "Active", "Login, lock and OTP events saved to JSON"),
        ],
        columns=["Enhancement", "Status", "Implementation"],
    )
    st.dataframe(enhancements, hide_index=True, use_container_width=True)
    st.subheader("Live security countdowns")
    session_countdown(SESSION_TIMEOUT_SECONDS)

    pending = st.session_state.get("pending_transaction")
    if pending:
        st.markdown("##### Active OTP")
        otp_countdown(pending["expires_at"], pending.get("otp_id", "security-centre"))
        st.caption("Return to the transaction page to enter or regenerate the OTP.")
    else:
        st.info("No active OTP. Start a transfer, bill, card or deposit transaction to generate one.")

    st.subheader("Security Activity Log")
    st.caption("The latest login, account-lock, OTP and budget-security events are shown first.")
    events = list(reversed(user.get("security_log", [])))[:20]
    if not events:
        st.info("No security events have been recorded yet.")
    else:
        event_table = pd.DataFrame(events).rename(
            columns={"date": "Date", "event": "Event", "status": "Status", "details": "Details"}
        )
        st.dataframe(
            event_table[["Date", "Event", "Status", "Details"]],
            hide_index=True,
            use_container_width=True,
        )


def main_app() -> None:
    """Send a logged-in user to whichever banking page they picked."""
    # Check if the session has already timed out, before resetting the activity clock.
    if time.time() - st.session_state.get("last_activity", time.time()) > SESSION_TIMEOUT_SECONDS:
        sign_out("timeout")
        st.rerun()
    st.session_state.last_activity = time.time()

    # If a quick-action button asked for a page switch, do that now,
    # before the sidebar menu gets drawn.
    requested_page = st.session_state.pop("requested_page", None)
    if requested_page:
        st.session_state.navigation = requested_page

    try:
        data = load_data()
        user = current_user(data)
    except (DataStoreError, KeyError) as exc:
        st.error(f"Unable to open the account: {exc}")
        if st.button("Return to login"):
            sign_out()
            st.rerun()
        return

    page = sidebar(user)
    brand_header(compact=True)
    pages = {
        "Dashboard": dashboard_page,
        "Transfer": transfer_page,
        "Pay Bills": bills_page,
        "Credit Card": credit_card_page,
        "Deposit": deposit_page,
        "Budget Planner": budget_planner_page,
        "Transactions": transactions_page,
        "Security": security_page,
    }
    pages[page](user)
    st.markdown(
        "<div class='footer'>Finora Bank Virtual Banking System • Educational simulation only</div>",
        unsafe_allow_html=True,
    )


def main() -> None:
    """Set up the page, then show either the login screen or the main app."""
    st.set_page_config(
        page_title="Finora Bank",
        page_icon="🏦",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_css()
    if st.session_state.get("authenticated"):
        main_app()
    else:
        login_page()


if __name__ == "__main__":
    main()
