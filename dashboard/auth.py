# dashboard/auth.py
# Password login for the dashboard.
# The password comes from the DASHBOARD_PASSWORD environment variable or from a
# Streamlit secret. If neither is set, the dashboard is open (development mode).
import hmac
import os

import streamlit as st

from dashboard import ui

MAX_ATTEMPTS = 5


def configured_password():
    password = os.environ.get("DASHBOARD_PASSWORD")
    if password:
        return password
    try:
        return st.secrets.get("DASHBOARD_PASSWORD")
    except Exception:            # no secrets file configured
        return None


def check_password(supplied, expected):
    return hmac.compare_digest(supplied.encode(), expected.encode())


def require_login():
    """Stops the page until the user has signed in (when a password is configured)."""
    expected = configured_password()
    if not expected:
        st.sidebar.caption("🔓 Login disabled (development mode)")
        return

    if st.session_state.get("authed"):
        with st.sidebar:
            if st.button("Sign out"):
                st.session_state["authed"] = False
                st.session_state["attempts"] = 0
                st.rerun()
        return

    attempts = st.session_state.get("attempts", 0)
    ui.hero("🛡️ ThreatWatch", "Sign in to open the security dashboard", [])
    _, middle, _ = st.columns([1, 1.2, 1])
    with middle:
        if attempts >= MAX_ATTEMPTS:
            st.error("Too many failed attempts. Reload the page to try again.")
            st.stop()
        password = st.text_input("Password", type="password")
        if st.button("Sign in"):
            if check_password(password, expected):
                st.session_state["authed"] = True
                st.session_state["attempts"] = 0
                st.rerun()
            else:
                st.session_state["attempts"] = attempts + 1
                st.error("Incorrect password.")
    st.stop()
