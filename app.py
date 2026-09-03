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
        "schema_version": 1,
        "users": {
            "paulina": {
                "full_name": "Paulina",
                "account_number": "8800251573",
                "password": hash_password("Finora@123"),
                "balance": 15420.80,
                "credit_card": {"number": "**** 4821", "limit": 10000.0, "outstanding": 1580.0},
                "failed_attempts": 0,
                "locked_until": 0.0,
                "transactions": paulina_transactions,
            },
            "alex": {
                "full_name": "Alex Tan",
                "account_number": "8800259999",
                "password": hash_password("Alex@123"),
                "balance": 8250.00,
                "credit_card": {"number": "**** 1109", "limit": 6000.0, "outstanding": 780.0},
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

            # Migrate data created by the earlier demonstration version so
            # existing balances and transaction records are not lost.
            if "chai" in data["users"] and "paulina" not in data["users"]:
                data["users"]["paulina"] = data["users"].pop("chai")
                data["users"]["paulina"]["full_name"] = "Paulina"
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
            recipient_username = find_username_by_account(data, details["recipient_account"])
            if recipient_username is None:
                raise BankingError("Recipient account number was not found.")
            if recipient_username == username:
                raise BankingError("You cannot transfer money to the same account.")
            if user["balance"] < amount:
                raise BankingError("Insufficient balance for this transfer.")

            recipient = data["users"][recipient_username]
            user["balance"] = round(user["balance"] - amount, 2)
            recipient["balance"] = round(recipient["balance"] + amount, 2)
            add_transaction(user, "Transfer", f"Transfer to {recipient['full_name']}", -amount, ref)
            add_transaction(recipient, "Transfer Received", f"Transfer from {user['full_name']}", amount, ref)

        elif kind == "Bill Payment":
            if user["balance"] < amount:
                raise BankingError("Insufficient balance for this bill payment.")
            user["balance"] = round(user["balance"] - amount, 2)
            description = f"{details['provider']} - {details['customer_reference']}"
            add_transaction(user, "Bill Payment", description, -amount, ref)

        elif kind == "Credit Card Payment":
            outstanding = float(user["credit_card"]["outstanding"])
            if amount > outstanding:
                raise BankingError("Payment cannot be higher than the outstanding card balance.")
            if user["balance"] < amount:
                raise BankingError("Insufficient balance for this credit card payment.")
            user["balance"] = round(user["balance"] - amount, 2)
            user["credit_card"]["outstanding"] = round(outstanding - amount, 2)
            add_transaction(user, "Credit Card", f"Card payment {user['credit_card']['number']}", -amount, ref)

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
    background_image = image_data_uri(APP_DIR / "assets" / "finora_background_v2.png")
    if not st.session_state.get("authenticated") and background_image:
        page_background = (
            "linear-gradient(rgba(5, 28, 65, .18), rgba(5, 45, 88, .30)), "
            f"url('{background_image}') center center / cover fixed no-repeat"
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
            padding: .60rem .70rem; border-radius: 10px; margin: .12rem 0;
        }}
        [data-testid="stSidebar"] [role="radiogroup"] label:hover {{ background: rgba(110,193,228,.18); }}
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
        div[data-testid="stMetric"] {{
            background:rgba(255,255,255,.96); border:1px solid #D8EDF6; border-radius:16px;
            padding:1rem 1.05rem; box-shadow:0 8px 24px #123B6D12;
        }}
        div[data-testid="stMetric"] label {{ color:#567286; }}
        div[data-testid="stMetricValue"] {{ color:{DEEP_BLUE}; }}
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
        "demo_otp", "transaction_result", "navigation",
    ]:
        st.session_state.pop(key, None)
    if message:
        st.session_state.logout_message = message


def change_page(page: str) -> None:
    """Navigate from a quick-action button to a sidebar page."""
    st.session_state.navigation = page
    st.rerun()


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
        st.caption(f"Savings •••• {user['account_number'][-4:]}")
        st.markdown(f"### {money(user['balance'])}")
        st.divider()
        pages = [
            "Dashboard", "Transfer", "Pay Bills", "Credit Card",
            "Deposit", "Transactions", "Security",
        ]
        if st.session_state.get("navigation") not in pages:
            st.session_state.navigation = "Dashboard"
        page = st.radio("Banking menu", pages, key="navigation", label_visibility="collapsed")
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

    overview_tab, insights_tab = st.tabs(["Recent activity", "Spending insights"])
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
        if outgoing:
            spending = pd.DataFrame(outgoing)
            spending["Spending (RM)"] = spending["amount"].abs()
            category = spending.groupby("type", as_index=True)["Spending (RM)"].sum()
            st.bar_chart(category, color=SKY_BLUE)
            st.caption("Total outgoing amount grouped by transaction type.")
        else:
            st.info("Complete an outgoing transaction to view spending insights.")


def otp_panel() -> None:
    """Display and verify the OTP for the active pending transaction."""
    pending = st.session_state.get("pending_transaction")
    if not pending:
        return

    st.divider()
    st.subheader("Secure verification")
    st.write(pending["summary"])
    remaining = max(0, int(pending["expires_at"] - time.time()))
    if remaining == 0:
        st.error("This OTP has expired. Generate a new OTP to continue.")
    else:
        st.info(f"The OTP is valid for approximately {remaining} more seconds.")

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
    page_title("Transfer Money", "Send funds securely to another Finora account.")
    show_transaction_result()
    st.metric("Available balance", money(user["balance"]))
    with st.form("transfer_form"):
        recipient_account = st.text_input("Recipient account number", placeholder="Example: 8800259999")
        amount = st.number_input("Transfer amount (RM)", min_value=0.0, step=10.0, format="%.2f")
        note = st.text_input("Payment note (optional)", max_chars=60)
        submitted = st.form_submit_button("Continue to OTP", type="primary")
    if submitted:
        try:
            data = load_data()
            recipient_username = find_username_by_account(data, recipient_account)
            if recipient_username is None:
                raise BankingError("Recipient account number was not found.")
            if recipient_username == st.session_state.username:
                raise BankingError("You cannot transfer money to your own account.")
            if amount <= 0:
                raise BankingError("Transfer amount must be greater than RM 0.00.")
            if amount > user["balance"]:
                raise BankingError("Insufficient balance for this transfer.")
            recipient_name = data["users"][recipient_username]["full_name"]
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
    st.caption("Demo recipient: Alex Tan • Account 8800259999")


def bills_page(user: dict[str, Any]) -> None:
    """Provide service selection and a validated bill-payment workflow."""
    page_title("Pay Bills", "Pay utilities and services from your savings account.")
    show_transaction_result()
    with st.form("bill_form"):
        category = st.selectbox("Bill category", list(BILLERS))
        provider = st.selectbox("Service provider", BILLERS[category])
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
    c1.metric("Card", card["number"])
    c2.metric("Outstanding", money(card["outstanding"]))
    c3.metric("Available credit", money(card["limit"] - card["outstanding"]))
    minimum_payment = min(card["outstanding"], round(max(50.0, card["outstanding"] * 0.10), 2)) if card["outstanding"] else 0.0
    with st.form("card_form"):
        option = st.radio("Payment option", ["Minimum payment", "Full payment", "Custom amount"], horizontal=True)
        custom_amount = st.number_input("Custom amount (RM)", min_value=0.0, step=10.0, format="%.2f", disabled=option != "Custom amount")
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

    output = io.StringIO()
    writer = csv.DictWriter(
        output, fieldnames=["date", "id", "type", "description", "amount", "balance_after"]
    )
    writer.writeheader()
    writer.writerows(filtered)
    st.download_button(
        "Download filtered statement (CSV)",
        data=output.getvalue().encode("utf-8"),
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
    st.markdown(
        """
        - Passwords are stored as salted hashes, not readable plain text.
        - Three failed sign-in attempts temporarily lock the account.
        - Every banking transaction requires a new six-digit OTP.
        - OTPs expire and are cancelled after three incorrect entries.
        - Account data and transaction history persist in a local JSON file.
        - An inactive authenticated session is automatically signed out.
        """
    )
    st.caption(f"Approximate session time remaining at page load: {remaining // 60}m {remaining % 60}s")


def main_app() -> None:
    """Route authenticated users to the selected banking page."""
    # Session timeout is checked before updating the activity timestamp.
    if time.time() - st.session_state.get("last_activity", time.time()) > SESSION_TIMEOUT_SECONDS:
        sign_out("timeout")
        st.rerun()
    st.session_state.last_activity = time.time()

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
