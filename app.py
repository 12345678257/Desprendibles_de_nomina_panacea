import os
import re
import io
import base64
import hmac
import hashlib
from datetime import date
from typing import Optional

import pandas as pd
import streamlit as st

APP_TITLE = "Portal de Desprendibles"
DATA_DIR = "data"
USERS_CSV = os.path.join(DATA_DIR, "users.csv")

PBKDF2_ITERS = 200_000
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


# =========================
# PASSWORD HASH (PBKDF2)
# =========================
def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32)
    return f"{base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64, dk_b64 = stored.split("$", 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# =========================
# FILE HELPERS
# =========================
def month_from_date(d: date) -> str:
    return f"{d.year:04d}-{d.month:02d}"

def normalize_month_str(s: str) -> Optional[str]:
    s = (s or "").strip()
    if MONTH_RE.match(s):
        yyyy, mm = s.split("-")
        mm_i = int(mm)
        if 1 <= mm_i <= 12:
            return s
    return None

def list_available_months() -> list[str]:
    if not os.path.isdir(DATA_DIR):
        return []
    months = []
    for name in os.listdir(DATA_DIR):
        p = os.path.join(DATA_DIR, name)
        if os.path.isdir(p) and normalize_month_str(name):
            months.append(name)
    return sorted(months, reverse=True)

def pdf_path_for(month: str, cedula: str) -> str:
    return os.path.join(DATA_DIR, month, f"{cedula}.pdf")

def read_pdf_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def embed_pdf(pdf_bytes: bytes, height: int = 780):
    b64 = base64.b64encode(pdf_bytes).decode("utf-8")
    html = f"""
    <iframe
      src="data:application/pdf;base64,{b64}"
      width="100%"
      height="{height}"
      style="border:none;"
    ></iframe>
    """
    st.components.v1.html(html, height=height, scrolling=True)


# =========================
# USERS (CSV)
# =========================
@st.cache_data
def load_users_df() -> pd.DataFrame:
    if not os.path.exists(USERS_CSV):
        return pd.DataFrame(columns=["cedula", "full_name", "password_hash", "role", "is_active"])
    df = pd.read_csv(USERS_CSV, dtype=str).fillna("")
    # Normaliza
    if "is_active" not in df.columns:
        df["is_active"] = "true"
    df["is_active"] = df["is_active"].astype(str).str.lower()
    if "role" not in df.columns:
        df["role"] = "user"
    return df

def get_user(cedula: str) -> Optional[dict]:
    df = load_users_df()
    m = df[df["cedula"].astype(str) == str(cedula)]
    if m.empty:
        return None
    row = m.iloc[0].to_dict()
    # is_active a bool
    row["is_active"] = str(row.get("is_active", "true")).lower() in ("1", "true", "yes", "y")
    row["role"] = (row.get("role") or "user").strip().lower()
    return row

def admin_exists() -> bool:
    df = load_users_df()
    if df.empty:
        return False
    roles = df.get("role", pd.Series([], dtype=str)).astype(str).str.lower()
    return bool((roles == "admin").any())


# =========================
# UI
# =========================
def login_screen():
    st.title(APP_TITLE)
    st.caption("Acceso por cédula y contraseña.")

    if not os.path.exists(USERS_CSV):
        st.error("No existe data/users.csv. Debes crearlo y subirlo al repositorio.")
        st.info(
            "Crea `data/users.csv` con columnas: cedula, full_name, password_hash, role, is_active.\n"
            "Luego haz commit/push para que Streamlit Cloud lo vea."
        )
        st.stop()

    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        with st.form("login_form"):
            cedula = st.text_input("Cédula").strip()
            password = st.text_input("Contraseña", type="password")
            ok = st.form_submit_button("Ingresar", use_container_width=True)

        if ok:
            u = get_user(cedula)
            if not u:
                st.error("Usuario o contraseña inválidos.")
                return
            if not u.get("is_active", True):
                st.error("Usuario inactivo. Contacta al administrador.")
                return
            if not verify_password(password, u.get("password_hash", "")):
                st.error("Usuario o contraseña inválidos.")
                return

            st.session_state.user = {
                "cedula": u["cedula"],
                "full_name": u.get("full_name") or "",
                "role": u.get("role") or "user",
            }
            st.success("Ingreso exitoso.")
            st.rerun()

def shell_header():
    st.sidebar.markdown(f"## {APP_TITLE}")
    u = st.session_state.user
    st.sidebar.caption(f"Sesión: {u['cedula']} ({u['role'].upper()})")
    if st.sidebar.button("Cerrar sesión", use_container_width=True):
        st.session_state.user = None
        st.rerun()

def user_portal():
    st.subheader("Mis desprendibles")
    cedula = st.session_state.user["cedula"]
    full_name = st.session_state.user.get("full_name", "")
    st.caption(f"Usuario: {full_name or cedula}")

    months = list_available_months()
    if not months:
        st.info("No hay meses disponibles aún. Sube una carpeta data/YYYY-MM con PDFs al repositorio.")
        return

    month = st.selectbox("Mes", months, index=0)
    path = pdf_path_for(month, cedula)

    if not os.path.exists(path):
        st.warning("No hay desprendible para este mes (para tu cédula).")
        st.write(f"Esperado: `{path}`")
        return

    pdf_bytes = read_pdf_bytes(path)
    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown(f"### Desprendible {month}")
    with c2:
        st.download_button(
            "Descargar PDF",
            data=pdf_bytes,
            file_name=f"{cedula}_{month}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

    embed_pdf(pdf_bytes, height=780)

def admin_panel():
    st.subheader("Admin")
    st.caption("Modo simple: lectura desde repo. Para cargar nuevos PDFs/usuarios se hace por GitHub (commit/push).")

    st.markdown("### Resumen")
    users = load_users_df()
    months = list_available_months()
    st.write({
        "usuarios_en_csv": int(len(users)),
        "meses_disponibles": months,
    })

    st.divider()
    st.markdown("### Generador de hash de contraseña (para llenar users.csv)")
    with st.form("gen_hash"):
        plain = st.text_input("Contraseña a hashear", type="password")
        ok = st.form_submit_button("Generar hash", use_container_width=True)
    if ok:
        if not plain:
            st.error("Escribe una contraseña.")
        else:
            hp = hash_password(plain)
            st.success("Hash generado. Pégalo en users.csv (columna password_hash).")
            st.code(hp)

    st.divider()
    st.markdown("### Plantilla users.csv")
    st.write("Crea/edita `data/users.csv` y haz commit/push. Ejemplo de encabezado:")
    st.code("cedula,full_name,password_hash,role,is_active")

    st.markdown("### Usuarios actuales (solo lectura)")
    if not users.empty:
        show = users.copy()
        show["password_hash"] = show["password_hash"].astype(str).str[:18] + "..."
        st.dataframe(show, use_container_width=True, hide_index=True)

def main():
    st.set_page_config(page_title=APP_TITLE, layout="wide")

    if "user" not in st.session_state:
        st.session_state.user = None

    if not st.session_state.user:
        login_screen()
        return

    shell_header()
    role = st.session_state.user.get("role", "user")

    if role == "admin":
        page = st.sidebar.radio("Menú", ["Portal", "Admin"], index=0)
        if page == "Portal":
            user_portal()
        else:
            admin_panel()
    else:
        user_portal()

if __name__ == "__main__":
    main()
