import os
import re
import io
import base64
import hmac
import sqlite3
import zipfile
from datetime import datetime, date
from pathlib import Path

import streamlit as st

# =========================
# CONFIG
# =========================
APP_TITLE = "Portal de Desprendibles"
DB_PATH = Path("data") / "app.db"
STORAGE_DIR = Path("data") / "pdfs"
PBKDF2_ITERS = 200_000

CEDULA_RE = re.compile(r"(\d{5,})")  # ajusta si necesitas mínimo diferente


# =========================
# SEGURIDAD (hash estándar sin dependencias)
# =========================
import hashlib

def hash_password(password: str, salt: bytes | None = None) -> str:
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
# DB
# =========================
def get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cedula TEXT UNIQUE NOT NULL,
        full_name TEXT,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user', -- 'admin' | 'user'
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS stubs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        month TEXT NOT NULL,        -- 'YYYY-MM'
        cedula TEXT NOT NULL,
        file_path TEXT NOT NULL,    -- ruta en disco
        uploaded_at TEXT NOT NULL,
        UNIQUE(month, cedula),
        FOREIGN KEY (cedula) REFERENCES users(cedula) ON UPDATE CASCADE
    );
    """)

    conn.commit()
    conn.close()

def user_exists_admin() -> bool:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1;")
    row = cur.fetchone()
    conn.close()
    return row is not None

def create_user(cedula: str, full_name: str, password: str, role: str = "user", is_active: int = 1):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO users (cedula, full_name, password_hash, role, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (cedula, full_name, hash_password(password), role, is_active, datetime.now().isoformat(timespec="seconds")))
    conn.commit()
    conn.close()

def set_user_password(cedula: str, new_password: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash=? WHERE cedula=?", (hash_password(new_password), cedula))
    conn.commit()
    conn.close()

def set_user_active(cedula: str, is_active: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_active=? WHERE cedula=?", (is_active, cedula))
    conn.commit()
    conn.close()

def get_user(cedula: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT cedula, full_name, password_hash, role, is_active FROM users WHERE cedula=?", (cedula,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "cedula": row[0],
        "full_name": row[1],
        "password_hash": row[2],
        "role": row[3],
        "is_active": int(row[4]),
    }

def list_users():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT cedula, full_name, role, is_active, created_at FROM users ORDER BY created_at DESC;")
    rows = cur.fetchall()
    conn.close()
    return rows

def upsert_stub(month: str, cedula: str, file_path: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO stubs (month, cedula, file_path, uploaded_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(month, cedula) DO UPDATE SET
            file_path=excluded.file_path,
            uploaded_at=excluded.uploaded_at;
    """, (month, cedula, file_path, datetime.now().isoformat(timespec="seconds")))
    conn.commit()
    conn.close()

def list_months_for_cedula(cedula: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT month FROM stubs WHERE cedula=? ORDER BY month DESC;", (cedula,))
    rows = cur.fetchall()
    conn.close()
    return [r[0] for r in rows]

def get_stub_path(month: str, cedula: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT file_path FROM stubs WHERE month=? AND cedula=? LIMIT 1;", (month, cedula))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


# =========================
# UTILIDADES
# =========================
def normalize_month_str(s: str) -> str | None:
    s = (s or "").strip()
    if re.fullmatch(r"\d{4}-\d{2}", s):
        yyyy, mm = s.split("-")
        mm_i = int(mm)
        if 1 <= mm_i <= 12:
            return s
    return None

def month_from_date(d: date) -> str:
    return f"{d.year:04d}-{d.month:02d}"

def extract_cedula_from_filename(name: str) -> str | None:
    base = Path(name).stem
    m = CEDULA_RE.search(base)
    if not m:
        return None
    return m.group(1)

def safe_write_bytes(target_path: Path, data: bytes):
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_path.with_suffix(target_path.suffix + ".tmp")
    with open(tmp_path, "wb") as f:
        f.write(data)
    os.replace(tmp_path, target_path)

def is_pdf_bytes(data: bytes) -> bool:
    return data[:5] == b"%PDF-"

def embed_pdf_in_page(pdf_bytes: bytes, height: int = 700):
    b64 = base64.b64encode(pdf_bytes).decode("utf-8")
    pdf_display = f"""
        <iframe
            src="data:application/pdf;base64,{b64}"
            width="100%"
            height="{height}"
            style="border: none;"
        ></iframe>
    """
    st.components.v1.html(pdf_display, height=height, scrolling=True)

def iter_zip_pdfs(zip_bytes: bytes):
    """
    Retorna tuplas (filename, file_bytes) solo para PDFs.
    Protege contra zip-slip.
    """
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    for info in zf.infolist():
        if info.is_dir():
            continue
        # zip-slip guard
        p = Path(info.filename)
        if any(part == ".." for part in p.parts):
            continue
        if not info.filename.lower().endswith(".pdf"):
            continue
        with zf.open(info, "r") as f:
            yield info.filename, f.read()


# =========================
# UI: AUTH
# =========================
def do_logout():
    st.session_state.user = None
    st.rerun()

def login_screen():
    st.title(APP_TITLE)
    st.subheader("Ingreso")

    with st.form("login_form", clear_on_submit=False):
        cedula = st.text_input("Cédula", placeholder="Ej: 1032456789").strip()
        password = st.text_input("Contraseña", type="password")
        submitted = st.form_submit_button("Ingresar")

    if submitted:
        u = get_user(cedula)
        if not u:
            st.error("Usuario o contraseña inválidos.")
            return
        if not u["is_active"]:
            st.error("Usuario inactivo. Contacta al administrador.")
            return
        if not verify_password(password, u["password_hash"]):
            st.error("Usuario o contraseña inválidos.")
            return

        st.session_state.user = {
            "cedula": u["cedula"],
            "full_name": u["full_name"] or "",
            "role": u["role"],
        }
        st.success("Ingreso exitoso.")
        st.rerun()


def initial_admin_setup():
    st.title(APP_TITLE)
    st.subheader("Configuración inicial (crear ADMIN)")

    st.info(
        "No existe un usuario administrador. Crea el primer ADMIN ahora.\n\n"
        "Recomendación: usa una cédula/usuario de admin (por ejemplo 'admin') o tu cédula real."
    )

    with st.form("init_admin"):
        cedula = st.text_input("Usuario admin (cédula o 'admin')", value="admin").strip()
        full_name = st.text_input("Nombre completo", value="Administrador")
        p1 = st.text_input("Contraseña", type="password")
        p2 = st.text_input("Confirmar contraseña", type="password")
        ok = st.form_submit_button("Crear ADMIN")

    if ok:
        if not cedula:
            st.error("Debes ingresar un usuario (cédula).")
            return
        if p1 != p2 or not p1:
            st.error("Las contraseñas no coinciden o están vacías.")
            return
        try:
            create_user(cedula=cedula, full_name=full_name, password=p1, role="admin", is_active=1)
            st.success("Administrador creado. Ya puedes iniciar sesión.")
            st.rerun()
        except sqlite3.IntegrityError:
            st.error("Ese usuario ya existe. Intenta con otro.")


# =========================
# UI: ADMIN
# =========================
def admin_users_panel():
    st.markdown("### Usuarios")

    with st.expander("Crear usuario", expanded=True):
        with st.form("create_user"):
            cedula = st.text_input("Cédula (usuario)", placeholder="Ej: 1032456789").strip()
            full_name = st.text_input("Nombre completo", placeholder="Opcional")
            role = st.selectbox("Rol", ["user", "admin"], index=0)
            password = st.text_input("Contraseña inicial", type="password")
            active = st.checkbox("Activo", value=True)
            ok = st.form_submit_button("Crear")

        if ok:
            if not cedula or not password:
                st.error("Cédula y contraseña son obligatorias.")
                return
            try:
                create_user(cedula, full_name, password, role=role, is_active=1 if active else 0)
                st.success("Usuario creado.")
                st.rerun()
            except sqlite3.IntegrityError:
                st.error("La cédula ya existe.")

    with st.expander("Administrar usuarios (activar/desactivar, reset password)", expanded=False):
        users = list_users()
        if not users:
            st.write("No hay usuarios.")
            return

        for cedula, full_name, role, is_active, created_at in users:
            cols = st.columns([3, 3, 1.5, 1.5, 2])
            cols[0].write(f"**{cedula}**")
            cols[1].write(full_name or "")
            cols[2].write(role)
            cols[3].write("Activo" if is_active else "Inactivo")
            with cols[4]:
                c1, c2, c3 = st.columns(3)
                if c1.button("ON" if not is_active else "OFF", key=f"toggle_{cedula}"):
                    set_user_active(cedula, 1 if not is_active else 0)
                    st.rerun()
                if c2.button("Reset", key=f"reset_{cedula}"):
                    st.session_state._reset_target = cedula
                # evita borrar: mejor desactivar

        target = st.session_state.get("_reset_target")
        if target:
            st.warning(f"Resetear contraseña de: {target}")
            with st.form("reset_pass"):
                np1 = st.text_input("Nueva contraseña", type="password")
                np2 = st.text_input("Confirmar", type="password")
                ok = st.form_submit_button("Confirmar reset")
            if ok:
                if not np1 or np1 != np2:
                    st.error("Contraseñas vacías o no coinciden.")
                else:
                    set_user_password(target, np1)
                    st.success("Contraseña actualizada.")
                    st.session_state._reset_target = None
                    st.rerun()


def admin_upload_panel():
    st.markdown("### Cargar desprendibles (PDF)")

    st.info(
        "Requisitos:\n"
        "- Cada PDF debe estar nombrado como **CEDULA.pdf** (ej: 1032456789.pdf)\n"
        "- Recomendado: subir un **ZIP** con todos los PDFs del mes."
    )

    # Mes
    col1, col2 = st.columns([2, 3])
    with col1:
        d = st.date_input("Selecciona una fecha del mes a cargar", value=date.today())
    month = month_from_date(d)

    with col2:
        month_override = st.text_input("Mes (opcional) en formato YYYY-MM", value=month)
    month_norm = normalize_month_str(month_override)
    if not month_norm:
        st.error("Mes inválido. Usa formato YYYY-MM (ej: 2025-11).")
        return

    tabs = st.tabs(["Subir ZIP (recomendado)", "Subir múltiples PDFs"])
    with tabs[0]:
        zip_file = st.file_uploader("ZIP con PDFs", type=["zip"], accept_multiple_files=False)
        overwrite = st.checkbox("Sobrescribir si ya existe", value=True, key="ov_zip")

        if zip_file and st.button("Procesar ZIP"):
            zip_bytes = zip_file.read()
            processed = 0
            skipped = 0
            errors = 0

            for fname, fbytes in iter_zip_pdfs(zip_bytes):
                cedula = extract_cedula_from_filename(fname)
                if not cedula:
                    skipped += 1
                    continue
                if not is_pdf_bytes(fbytes):
                    skipped += 1
                    continue

                target = STORAGE_DIR / month_norm / f"{cedula}.pdf"
                if target.exists() and not overwrite:
                    skipped += 1
                    continue

                try:
                    safe_write_bytes(target, fbytes)
                    upsert_stub(month_norm, cedula, str(target))
                    processed += 1
                except Exception:
                    errors += 1

            st.success(f"Listo. Procesados: {processed} | Omitidos: {skipped} | Errores: {errors}")

    with tabs[1]:
        pdfs = st.file_uploader("Selecciona PDFs", type=["pdf"], accept_multiple_files=True)
        overwrite2 = st.checkbox("Sobrescribir si ya existe", value=True, key="ov_pdfs")

        if pdfs and st.button("Procesar PDFs"):
            processed = 0
            skipped = 0
            errors = 0

            for up in pdfs:
                cedula = extract_cedula_from_filename(up.name)
                if not cedula:
                    skipped += 1
                    continue

                fbytes = up.read()
                if not is_pdf_bytes(fbytes):
                    skipped += 1
                    continue

                target = STORAGE_DIR / month_norm / f"{cedula}.pdf"
                if target.exists() and not overwrite2:
                    skipped += 1
                    continue

                try:
                    safe_write_bytes(target, fbytes)
                    upsert_stub(month_norm, cedula, str(target))
                    processed += 1
                except Exception:
                    errors += 1

            st.success(f"Listo. Procesados: {processed} | Omitidos: {skipped} | Errores: {errors}")


def admin_dashboard():
    st.title(APP_TITLE)
    st.write(f"Sesión: **{st.session_state.user['cedula']}** (ADMIN)")

    if st.button("Cerrar sesión"):
        do_logout()

    st.divider()
    menu = st.sidebar.radio("Administración", ["Usuarios", "Cargar PDFs"])
    if menu == "Usuarios":
        admin_users_panel()
    else:
        admin_upload_panel()


# =========================
# UI: USER
# =========================
def user_portal():
    st.title(APP_TITLE)
    cedula = st.session_state.user["cedula"]
    full_name = st.session_state.user.get("full_name", "")

    st.write(f"Bienvenido: **{full_name or cedula}**")
    if st.button("Cerrar sesión"):
        do_logout()

    st.divider()
    months = list_months_for_cedula(cedula)
    if not months:
        st.info("Aún no hay desprendibles disponibles para tu usuario.")
        return

    month = st.selectbox("Selecciona el mes", months)
    path = get_stub_path(month, cedula)
    if not path or not Path(path).exists():
        st.error("El archivo no se encuentra en el servidor. Contacta al administrador.")
        return

    pdf_bytes = Path(path).read_bytes()

    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown(f"#### Desprendible {month}")
    with c2:
        st.download_button(
            "Descargar PDF",
            data=pdf_bytes,
            file_name=f"{cedula}_{month}.pdf",
            mime="application/pdf",
            use_container_width=True
        )

    embed_pdf_in_page(pdf_bytes, height=750)


# =========================
# MAIN
# =========================
def main():
    st.set_page_config(page_title=APP_TITLE, layout="wide")
    init_db()

    if "user" not in st.session_state:
        st.session_state.user = None

    # Setup inicial (primer admin)
    if not user_exists_admin():
        initial_admin_setup()
        return

    # Login si no hay sesión
    if not st.session_state.user:
        login_screen()
        return

    role = st.session_state.user.get("role")
    if role == "admin":
        admin_dashboard()
    else:
        user_portal()


if __name__ == "__main__":
    main()
