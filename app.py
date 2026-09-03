"""Finora Bank - secure virtual banking simulation built with Streamlit.

Run with: streamlit run app.py

This application is for education and demonstration only. It does not connect
to a real bank, payment gateway, SMS provider, or cash deposit machine.
"""

from __future__ import annotations

import csv
import base64
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
# Application configuration
# -----------------------------------------------------------------------------
APP_DIR = Path(__file__).resolve().parent
DATA_FILE = APP_DIR / "bank_data.json"
DATA_LOCK = threading.RLock()
OTP_VALID_SECONDS = 60
SESSION_TIMEOUT_SECONDS = 5 * 60
ACCOUNT_LOCK_SECONDS = 60
MAX_LOGIN_ATTEMPTS = 3
ACCOUNT_NUMBER_LENGTH = 10
DATA_SCHEMA_VERSION = 3
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
    "Transactions": "📄  Transactions",
    "Security": "🛡️  Security",
}


class BankingError(Exception):
    """A user-friendly banking validation error."""


class DataStoreError(Exception):
    """Raised when the local JSON data store cannot be read or written."""


# -----------------------------------------------------------------------------
# Security and data-storage helpers
# -----------------------------------------------------------------------------
def hash_password(password: str, salt_hex: str | None = None) -> dict[str, str]:
    """Hash a password with PBKDF2-SHA256 and a random salt.

    A salt prevents identical passwords from producing identical stored hashes.
    Only the salt and derived hash are saved; the plain password is never saved.
    """
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return {"salt": salt.hex(), "hash": derived.hex()}


def verify_password(password: str, stored: dict[str, str]) -> bool:
    """Safely compare an entered password with its stored password hash."""
    candidate = hash_password(password, stored["salt"])["hash"]
    return hmac.compare_digest(candidate, stored["hash"])


def now_text() -> str:
    """Return a readable timestamp for a transaction record."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def transaction_record(
    transaction_type: str,
    description: str,
    amount: float,
    balance_after: float,
    reference: str | None = None,
) -> dict[str, Any]:
    """Build one consistently formatted transaction dictionary."""
    return {
        "id": reference or f"FNB-{datetime.now():%Y%m%d}-{uuid.uuid4().hex[:8].upper()}",
        "date": now_text(),
        "type": transaction_type,
        "description": description,
        "amount": round(float(amount), 2),
        "balance_after": round(float(balance_after), 2),
    }


def create_seed_data() -> dict[str, Any]:
    """Create two demonstration accounts on the application's first launch."""
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
    """Atomically save bank data so an interrupted write cannot corrupt it."""
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
    """Load persistent data, creating safe demonstration data when absent."""
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

            # Migrate data created by earlier demonstration versions without
            # deleting existing balances or transaction records.
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
    """Return the username belonging to an exact account number."""
    for username, user in data["users"].items():
        if user["account_number"] == account_number.strip():
            return username
    return None


def valid_account_number(account_number: str) -> bool:
    """Return True only for an account number containing exactly 10 digits."""
    cleaned = account_number.strip()
    return cleaned.isdigit() and len(cleaned) == ACCOUNT_NUMBER_LENGTH


def card_number_digits(card_number: str) -> str:
    """Return only the numeric characters from a demonstration card number."""
    return "".join(character for character in str(card_number) if character.isdigit())


def masked_card_number(card_number: str) -> str:
    """Mask a card number while keeping its final four digits visible."""
    digits = card_number_digits(card_number)
    return f"•••• •••• •••• {digits[-4:]}"


def visible_card_number(card_number: str) -> str:
    """Group a full demonstration card number into readable blocks of four."""
    digits = card_number_digits(card_number)
    return " ".join(digits[index:index + 4] for index in range(0, len(digits), 4))


# -----------------------------------------------------------------------------
# Authentication and transaction logic (kept separate from the page layout)
# -----------------------------------------------------------------------------
def authenticate(username: str, password: str) -> tuple[str, str]:
    """Authenticate a user and persist failed-attempt/account-lock information."""
    username = username.strip().lower()
    with DATA_LOCK:
        data = load_data()
        user = data["users"].get(username)
        if user is None:
            return "invalid", "Invalid username or password."

        current_time = time.time()
        if float(user.get("locked_until", 0)) > current_time:
            remaining = int(user["locked_until"] - current_time) + 1
            return "locked", f"Account locked. Try again in {remaining} seconds."

        # A completed lock period restores the normal attempt counter.
        if user.get("locked_until", 0):
            user["locked_until"] = 0.0
            user["failed_attempts"] = 0

        if verify_password(password, user["password"]):
            user["failed_attempts"] = 0
            user["locked_until"] = 0.0
            save_data(data)
            return "success", "Login successful."

        user["failed_attempts"] = int(user.get("failed_attempts", 0)) + 1
        attempts_left = MAX_LOGIN_ATTEMPTS - user["failed_attempts"]
        if attempts_left <= 0:
            user["locked_until"] = current_time + ACCOUNT_LOCK_SECONDS
            save_data(data)
            return "locked", "Account locked for 60 seconds after 3 unsuccessful attempts."

        save_data(data)
        return "invalid", f"Invalid username or password. {attempts_left} attempt(s) remaining."


def add_transaction(user: dict[str, Any], kind: str, description: str, amount: float, ref: str) -> None:
    """Append a transaction using the user's current balance."""
    user["transactions"].append(
        transaction_record(kind, description, amount, user["balance"], reference=ref)
    )


def balance_history_frame(transactions: list[dict[str, Any]]) -> pd.DataFrame:
    """Return chronological balance data suitable for a Streamlit line chart."""
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
    """Summarise outgoing transactions by category for analytics."""
    outgoing = [item for item in transactions if float(item.get("amount", 0)) < 0]
    if not outgoing:
        return pd.DataFrame(columns=["Category", "Spending (RM)"])

    spending = pd.DataFrame(outgoing)
    spending["Spending (RM)"] = pd.to_numeric(spending["amount"], errors="coerce").abs()
    return (
        spending.groupby("type", as_index=False)["Spending (RM)"]
        .sum()
        .rename(columns={"type": "Category"})
        .sort_values("Spending (RM)", ascending=False)
    )


def transactions_csv(transactions: list[dict[str, Any]]) -> bytes:
    """Create a consistently formatted UTF-8 CSV statement."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output, fieldnames=["date", "id", "type", "description", "amount", "balance_after"]
    )
    writer.writeheader()
    writer.writerows(transactions)
    # UTF-8 BOM helps Microsoft Excel display the file correctly.
    return output.getvalue().encode("utf-8-sig")


def process_transaction(username: str, pending: dict[str, Any]) -> dict[str, Any]:
    """Validate and commit one OTP-approved transaction to the JSON file."""
    with DATA_LOCK:
        data = load_data()  # Reload to use the newest persisted balance.
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
            add_transaction(user, "Bill Payment", description, -amount, ref)

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
            # This is a simulation: no real cash or external payment is accepted.
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
    """Generate a one-use OTP and store only its hash for verification."""
    otp = f"{secrets.randbelow(1_000_000):06d}"
    st.session_state.pending_transaction = {
        "otp_id": uuid.uuid4().hex[:10],
        "kind": kind,
        "details": details,
        "summary": summary,
        "otp_hash": hashlib.sha256(otp.encode("utf-8")).hexdigest(),
        "created_at": time.time(),
        "expires_at": time.time() + OTP_VALID_SECONDS,
        "verification_attempts": 0,
    }
    # In a real system the OTP is sent by SMS. It is displayed only so this
    # offline classroom simulation can be demonstrated and tested.
    st.session_state.demo_otp = otp


# -----------------------------------------------------------------------------
# Visual helpers
# -----------------------------------------------------------------------------
def image_data_uri(path: Path) -> str | None:
    """Convert a local image into an embeddable CSS data URI."""
    if not path.exists():
        return None
    mime_type = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime_type};base64,{encoded}"


def inject_css() -> None:
    """Apply the Finora blue, sky-blue, white and mint visual identity."""
    login_background = image_data_uri(APP_DIR / "assets" / "finora_background_v2.png")
    inside_background = image_data_uri(APP_DIR / "assets" / "finora_dashboard_background.png")
    if st.session_state.get("authenticated") and inside_background:
        page_background = (
            "linear-gradient(135deg, rgba(174, 215, 234, .76) 0%, "
            "rgba(202, 230, 239, .78) 52%, rgba(177, 221, 218, .74) 100%), "
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
        </style>
        """,
        unsafe_allow_html=True,
    )


def brand_header(compact: bool = False) -> None:
    """Render the uploaded logo, with a text fallback if the file is absent."""
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
    """Format a number as Malaysian ringgit."""
    return f"RM {float(value):,.2f}"


def current_user(data: dict[str, Any]) -> dict[str, Any]:
    """Return the logged-in user record."""
    return data["users"][st.session_state.username]


def sign_out(message: str | None = None) -> None:
    """Clear all authentication and transaction state."""
    for key in [
        "authenticated", "username", "last_activity", "pending_transaction",
        "demo_otp", "transaction_result", "navigation", "requested_page",
        "account_visible", "card_visible",
    ]:
        st.session_state.pop(key, None)
    if message:
        st.session_state.logout_message = message


def change_page(page: str) -> None:
    """Navigate from a quick-action button to a sidebar page."""
    # The sidebar radio using the ``navigation`` key has already been rendered
    # when a Dashboard quick-action button is clicked. Streamlit does not allow
    # that widget's value to be changed afterward in the same run, so store the
    # request under a separate key and apply it before the next sidebar render.
    st.session_state.requested_page = page
    st.rerun()


def toggle_account_details() -> None:
    """Toggle sidebar privacy before Streamlit renders the current page."""
    st.session_state.account_visible = not bool(st.session_state.get("account_visible", False))


def toggle_card_details() -> None:
    """Toggle the demonstration card number without changing navigation."""
    st.session_state.card_visible = not bool(st.session_state.get("card_visible", False))


# -----------------------------------------------------------------------------
# Login and sidebar
# -----------------------------------------------------------------------------
def login_page() -> None:
    """Display secure login and validate credentials."""
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


def sidebar(user: dict[str, Any]) -> str:
    """Display account identity, navigation and safe logout controls."""
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
            "Deposit", "Transactions", "Security",
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


# -----------------------------------------------------------------------------
# Banking pages
# -----------------------------------------------------------------------------
def page_title(title: str, subtitle: str) -> None:
    """Render a consistent page heading."""
    st.title(title)
    st.markdown(f"<p class='muted'>{html.escape(subtitle)}</p>", unsafe_allow_html=True)


def dashboard_page(user: dict[str, Any]) -> None:
    """Show balance, quick actions, recent activity and spending analytics."""
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
    """Render a live browser-side OTP countdown without blocking Streamlit."""
    deadline_ms = int(expires_at * 1000)
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
          const deadline = {deadline_ms};
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


def otp_panel() -> None:
    """Display and verify the OTP for the active pending transaction."""
    pending = st.session_state.get("pending_transaction")
    if not pending:
        return

    st.divider()
    st.subheader("Secure verification")
    st.write(pending["summary"])
    remaining = max(0, int(pending["expires_at"] - time.time()))
    otp_countdown(pending["expires_at"], pending.get("otp_id", "current"))
    if remaining == 0:
        st.error("This OTP has expired. Generate a new OTP to continue.")

    with st.expander("View demonstration OTP", expanded=True):
        st.code(st.session_state.get("demo_otp", "------"), language=None)
        st.caption("Simulation only. A production bank would send this code through a secure channel.")

    with st.form("otp_form"):
        entered_otp = st.text_input("6-digit OTP", max_chars=6, placeholder="Enter verification code")
        verify_clicked = st.form_submit_button("Verify and complete", type="primary")

    cancel_col, resend_col = st.columns(2)
    if cancel_col.button("Cancel transaction", use_container_width=True):
        st.session_state.pop("pending_transaction", None)
        st.session_state.pop("demo_otp", None)
        st.rerun()
    if resend_col.button("Generate new OTP", use_container_width=True):
        create_pending_transaction(pending["kind"], pending["details"], pending["summary"])
        st.rerun()

    if verify_clicked:
        if not entered_otp.isdigit() or len(entered_otp) != 6:
            st.error("OTP must contain exactly 6 digits.")
            return
        if time.time() > pending["expires_at"]:
            st.error("The OTP has expired. Please generate a new OTP.")
            return

        entered_hash = hashlib.sha256(entered_otp.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(entered_hash, pending["otp_hash"]):
            pending["verification_attempts"] += 1
            if pending["verification_attempts"] >= 3:
                st.session_state.pop("pending_transaction", None)
                st.session_state.pop("demo_otp", None)
                st.error("Too many incorrect OTP attempts. The transaction was cancelled.")
            else:
                attempts = 3 - pending["verification_attempts"]
                st.error(f"Incorrect OTP. {attempts} attempt(s) remaining.")
            return

        try:
            result = process_transaction(st.session_state.username, pending)
            st.session_state.transaction_result = result
            st.session_state.pop("pending_transaction", None)
            st.session_state.pop("demo_otp", None)
            st.rerun()
        except (BankingError, DataStoreError) as exc:
            st.error(str(exc))


def show_transaction_result() -> None:
    """Show a one-time transaction receipt after successful OTP processing."""
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
    """Collect and validate a transfer before requesting OTP approval."""
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
    """Provide service selection and a validated bill-payment workflow."""
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
    """Display card details and process minimum, full or custom payments."""
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

    # Keep this selector outside the form so choosing Custom amount reruns the
    # page immediately and enables the amount input field.
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
    """Simulate a verified deposit into the logged-in account."""
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


def transactions_page(user: dict[str, Any]) -> None:
    """Show searchable transaction history and a downloadable CSV statement."""
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
    """Explain the demonstrable security controls and current session state."""
    page_title("Security Centre", "Review the protection features used by this simulation.")
    elapsed = time.time() - st.session_state.last_activity
    remaining = max(0, int(SESSION_TIMEOUT_SECONDS - elapsed))
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
        ],
        columns=["Enhancement", "Status", "Implementation"],
    )
    st.dataframe(enhancements, hide_index=True, use_container_width=True)
    st.progress(
        min(1.0, max(0.0, remaining / SESSION_TIMEOUT_SECONDS)),
        text="Session time remaining",
    )
    st.caption(f"Approximate session time remaining at page load: {remaining // 60}m {remaining % 60}s")


def main_app() -> None:
    """Route authenticated users to the selected banking page."""
    # Session timeout is checked before updating the activity timestamp.
    if time.time() - st.session_state.get("last_activity", time.time()) > SESSION_TIMEOUT_SECONDS:
        sign_out("timeout")
        st.rerun()
    st.session_state.last_activity = time.time()

    # Apply a Quick Action navigation request before the sidebar radio widget
    # is instantiated. This avoids StreamlitWidgetAlreadyInstantiatedError.
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
        "Transactions": transactions_page,
        "Security": security_page,
    }
    pages[page](user)
    st.markdown(
        "<div class='footer'>Finora Bank Virtual Banking System • Educational simulation only</div>",
        unsafe_allow_html=True,
    )


def main() -> None:
    """Configure Streamlit and start the correct authenticated view."""
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
