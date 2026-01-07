import os
import re
import io
import base64
import hmac
import zipfile
import secrets as pysecrets
from datetime import datetime, date
from typing import Optional, Tuple, List, Dict, Any

import pandas as pd
import streamlit as st
from supabase import create_client


# =========================
# CONFIG
# =========================
APP_TITLE = "Portal de Desprendibles"
PBKDF2_ITERS = 200_000
CEDULA_RE = re.compile(r"(\d{5,})")  # Ajusta si necesitas otra regla


# =========================
# PASSWORD HASH (PBKDF2)
# =========================
import hashlib

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32
    )
    return f"{base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64, dk_b64 = stored.split("$", 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32
        )
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# =========================
# HELPERS
# =========================
def normalize_month_str(s: str) -> Optional[str]:
    s = (s or "").strip()
    if re.fullmatch(r"\d{4}-\d{2}", s):
        yyyy, mm = s.split("-")
        mm_i = int(mm)
        if 1 <= mm_i <= 12:
            return s
    return None

def month_from_date(d: date) -> str:
    return f"{d.year:04d}-{d.month:02d}"

def extract_cedula_from_filename(name: str) -> Optional[str]:
    base = os.path.splitext(os.path.basename(name))[0]
    m = CEDULA_RE.search(base)
    return m.group(1) if m else None

def is_pdf_bytes(data: bytes) -> bool:
    return data[:5] == b"%PDF-"

def embed_pdf_in_page(pdf_bytes: bytes, height: int = 750):
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

def iter_zip_pdfs(zip_bytes: bytes):
    """
    Retorna (filename, file_bytes) solo PDFs.
    Incluye protección básica zip-slip.
    """
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    for info in zf.infolist():
        if info.is_dir():
            continue
        normalized = info.filename.replace("\\", "/")
        if ".." in normalized.split("/"):
            continue
        if not normalized.lower().endswith(".pdf"):
            continue
        with zf.open(info, "r") as f:
            yield info.filename, f.read()


# =========================
# SECRETS / CONFIG (ROBUSTO)
# =========================
def cfg_get(key: str, default: str = "") -> str:
    """
    Lee primero de st.secrets (Streamlit Cloud), luego de env vars.
    """
    try:
        v = st.secrets.get(key, None)
        if v is not None and str(v).strip():
            return str(v).strip()
    except Exception:
        pass
    v2 = os.getenv(key, "").strip()
    return v2 if v2 else default

def config_screen_and_stop():
    st.title(APP_TITLE)
    st.error("Faltan credenciales de Supabase para iniciar la app.")

    st.markdown("### Cómo solucionarlo (Streamlit Community Cloud)")
    st.write("1) Abre tu app → Settings → Secrets")
    st.write("2) Pega esto y guarda:")
    st.code(
        'SUPABASE_URL = "https://TU-PROYECTO.supabase.co"\n'
        'SUPABASE_SERVICE_ROLE_KEY = "TU_SERVICE_ROLE_KEY"\n'
        'SUPABASE_BUCKET = "desprendibles"\n',
        language="toml"
    )
    st.info("Después usa Reboot app. No subas secrets.toml al repositorio.")
    st.stop()


# =========================
# SUPABASE
# =========================
@st.cache_resource
def sb_client():
    url = cfg_get("SUPABASE_URL")
    key = cfg_get("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        # En vez de reventar con RuntimeError, mostramos pantalla guiada
        config_screen_and_stop()
    return create_client(url, key)

def sb_bucket() -> str:
    return cfg_get("SUPABASE_BUCKET", "desprendibles")

def sb_storage():
    return sb_client().storage.from_(sb_bucket())


# --- DB ops
def user_exists_admin() -> bool:
    sb = sb_client()
    resp = sb.table("users").select("cedula").eq("role", "admin").limit(1).execute()
    return bool(resp.data)

def get_user(cedula: str):
    sb = sb_client()
    resp = sb.table("users").select(
        "cedula,full_name,password_hash,role,is_active"
    ).eq("cedula", cedula).limit(1).execute()
    return resp.data[0] if resp.data else None

def create_user(cedula: str, full_name: str, password: str, role: str = "user", is_active: bool = True):
    sb = sb_client()
    sb.table("users").insert({
        "cedula": cedula,
        "full_name": full_name,
        "password_hash": hash_password(password),
        "role": role,
        "is_active": is_active
    }).execute()

def set_user_password(cedula: str, new_password: str):
    sb = sb_client()
    sb.table("users").update({
        "password_hash": hash_password(new_password)
    }).eq("cedula", cedula).execute()

def set_user_active(cedula: str, is_active: bool):
    sb = sb_client()
    sb.table("users").update({
        "is_active": is_active
    }).eq("cedula", cedula).execute()

def list_users():
    sb = sb_client()
    resp = sb.table("users").select(
        "cedula,full_name,role,is_active,created_at"
    ).order("created_at", desc=True).execute()
    return resp.data or []

def upsert_stub(month: str, cedula: str, storage_path: str):
    sb = sb_client()
    sb.table("stubs").upsert({
        "month": month,
        "cedula": cedula,
        "storage_path": storage_path,
        "uploaded_at": datetime.now().isoformat(timespec="seconds")
    }).execute()

def list_months_for_cedula(cedula: str):
    sb = sb_client()
    resp = sb.table("stubs").select("month").eq("cedula", cedula).order("month", desc=True).execute()
    return [r["month"] for r in (resp.data or [])]

def get_stub_storage_path(month: str, cedula: str):
    sb = sb_client()
    resp = sb.table("stubs").select("storage_path").eq("month", month).eq("cedula", cedula).limit(1).execute()
    return resp.data[0]["storage_path"] if resp.data else None

def get_stubs_for_month(month: str):
    sb = sb_client()
    resp = sb.table("stubs").select(
        "month,cedula,storage_path,uploaded_at"
    ).eq("month", month).order("cedula", desc=False).execute()
    return resp.data or []

def count_users():
    sb = sb_client()
    resp = sb.table("users").select("cedula", count="exact").execute()
    return resp.count or 0

def count_stubs():
    sb = sb_client()
    resp = sb.table("stubs").select("cedula", count="exact").execute()
    return resp.count or 0

def count_stubs_month(month: str):
    sb = sb_client()
    resp = sb.table("stubs").select("cedula", count="exact").eq("month", month).execute()
    return resp.count or 0


# --- Storage ops (robusto con fallback update)
def storage_upload_pdf(path: str, pdf_bytes: bytes, overwrite: bool = True):
    storage = sb_storage()
    f = io.BytesIO(pdf_bytes)

    # Intento 1: upload con upsert
    try:
        storage.upload(
            path=path,
            file=f,
            file_options={
                "content-type": "application/pdf",
                "cache-control": "3600",
                "upsert": "true" if overwrite else "false",
            },
        )
        return
    except Exception:
        if not overwrite:
            raise

    # Intento 2: si existe, update
    f2 = io.BytesIO(pdf_bytes)
    storage.update(
        path=path,
        file=f2,
        file_options={"content-type": "application/pdf"},
    )

def storage_download_pdf(path: str) -> bytes:
    storage = sb_storage()
    return storage.download(path)

def storage_list_folder(prefix: str):
    storage = sb_storage()
    return storage.list(
        prefix,
        {
            "limit": 1000,
            "offset": 0,
            "sortBy": {"column": "name", "order": "asc"},
        },
    )


# =========================
# AUTH UI
# =========================
def do_logout():
    st.session_state.user = None
    st.rerun()

def login_screen():
    st.title(APP_TITLE)
    st.caption("Acceso seguro por cédula y contraseña.")

    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        with st.form("login_form", clear_on_submit=False):
            cedula = st.text_input("Cédula", placeholder="Ej: 1032456789").strip()
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
            if not verify_password(password, u["password_hash"]):
                st.error("Usuario o contraseña inválidos.")
                return

            st.session_state.user = {
                "cedula": u["cedula"],
                "full_name": u.get("full_name") or "",
                "role": u.get("role") or "user",
            }
            st.success("Ingreso exitoso.")
            st.rerun()

def initial_admin_setup():
    st.title(APP_TITLE)
    st.subheader("Configuración inicial: crear ADMIN")
    st.info("No existe un usuario administrador. Crea el primer ADMIN ahora.")

    with st.form("init_admin"):
        cedula = st.text_input("Usuario admin (cédula o 'admin')", value="admin").strip()
        full_name = st.text_input("Nombre completo", value="Administrador")
        p1 = st.text_input("Contraseña", type="password")
        p2 = st.text_input("Confirmar contraseña", type="password")
        ok = st.form_submit_button("Crear ADMIN", use_container_width=True)

    if ok:
        if not cedula:
            st.error("Debes ingresar un usuario.")
            return
        if not p1 or p1 != p2:
            st.error("Las contraseñas no coinciden o están vacías.")
            return
        try:
            create_user(cedula, full_name, p1, role="admin", is_active=True)
            st.success("Administrador creado. Ya puedes iniciar sesión.")
            st.rerun()
        except Exception as e:
            st.error(f"No se pudo crear el admin: {e}")


# =========================
# ADMIN UI
# =========================
def admin_home():
    st.subheader("Resumen")
    st.caption("Visibilidad rápida de usuarios y desprendibles cargados.")
    col1, col2, col3 = st.columns(3)
    col1.metric("Usuarios", f"{count_users():,}")
    col2.metric("Desprendibles (total)", f"{count_stubs():,}")

    month_sel = month_from_date(date.today())
    month_sel = st.text_input("Mes para métricas (YYYY-MM)", value=month_sel)
    month_sel = normalize_month_str(month_sel) or month_from_date(date.today())
    col3.metric(f"Desprendibles ({month_sel})", f"{count_stubs_month(month_sel):,}")

    st.divider()
    st.markdown("#### Dónde quedan los PDFs")
    st.write(
        f"- Bucket: `{sb_bucket()}`\n"
        f"- Ruta: `YYYY-MM/<CEDULA>.pdf` (ej: `2025-11/1032456789.pdf`)\n"
        "- Metadatos: tabla `stubs`."
    )

def admin_diagnostico():
    st.subheader("Diagnóstico")
    st.caption("Verifica que Supabase DB y Storage estén accesibles desde Streamlit Cloud.")

    url_ok = bool(cfg_get("SUPABASE_URL"))
    key_ok = bool(cfg_get("SUPABASE_SERVICE_ROLE_KEY"))
    st.write("Secrets presentes:", {
        "SUPABASE_URL": url_ok,
        "SUPABASE_SERVICE_ROLE_KEY": key_ok,
        "SUPABASE_BUCKET": bool(cfg_get("SUPABASE_BUCKET")),
    })

    st.divider()
    try:
        _ = sb_client()
        st.success("Cliente Supabase: OK")
    except Exception as e:
        st.error(f"Cliente Supabase: ERROR -> {e}")
        return

    try:
        # Prueba DB
        _ = count_users()
        st.success("Acceso DB (tabla users): OK (o tabla existe y es accesible)")
    except Exception as e:
        st.error(f"Acceso DB: ERROR -> {e}")

    try:
        # Prueba Storage: listar root del bucket (vacío o no)
        _ = storage_list_folder("")
        st.success("Acceso Storage (listar bucket): OK")
    except Exception as e:
        st.error(f"Acceso Storage: ERROR -> {e}")

    st.info("Si DB falla: revisa que existan tablas `users` y `stubs`.\nSi Storage falla: revisa que exista el bucket y la key sea correcta.")

def admin_users_panel():
    st.subheader("Usuarios")

    with st.expander("Crear usuario", expanded=True):
        with st.form("create_user"):
            cedula = st.text_input("Cédula (usuario)", placeholder="Ej: 1032456789").strip()
            full_name = st.text_input("Nombre completo", placeholder="Opcional")
            role = st.selectbox("Rol", ["user", "admin"], index=0)
            password = st.text_input("Contraseña inicial", type="password")
            active = st.checkbox("Activo", value=True)
            ok = st.form_submit_button("Crear", use_container_width=True)

        if ok:
            if not cedula or not password:
                st.error("Cédula y contraseña son obligatorias.")
                return
            try:
                create_user(cedula, full_name, password, role=role, is_active=active)
                st.success("Usuario creado.")
                st.rerun()
            except Exception as e:
                st.error(f"No se pudo crear el usuario: {e}")

    st.divider()
    users = list_users()
    if not users:
        st.info("No hay usuarios.")
        return

    df = pd.DataFrame(users).rename(columns={
        "cedula": "Cédula",
        "full_name": "Nombre",
        "role": "Rol",
        "is_active": "Activo",
        "created_at": "Creado",
    })
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        target = st.text_input("Cédula a activar/desactivar")
        if st.button("Toggle Activo", use_container_width=True, disabled=not target.strip()):
            u = get_user(target.strip())
            if not u:
                st.error("No existe ese usuario.")
            else:
                set_user_active(target.strip(), not bool(u.get("is_active", True)))
                st.success("Actualizado.")
                st.rerun()

    with col2:
        target2 = st.text_input("Cédula para resetear contraseña", key="rst2")
        np1 = st.text_input("Nueva contraseña", type="password")
        np2 = st.text_input("Confirmar", type="password")
        if st.button("Reset contraseña", use_container_width=True, disabled=not target2.strip()):
            if not np1 or np1 != np2:
                st.error("Contraseñas vacías o no coinciden.")
            else:
                u = get_user(target2.strip())
                if not u:
                    st.error("No existe ese usuario.")
                else:
                    set_user_password(target2.strip(), np1)
                    st.success("Contraseña actualizada.")
                    st.rerun()

def admin_upload_panel():
    st.subheader("Cargar desprendibles (PDF)")
    st.caption("Sube un ZIP con PDFs nombrados por cédula. Verás un reporte detallado de lo cargado.")

    col1, col2 = st.columns([2, 3])
    with col1:
        d = st.date_input("Selecciona una fecha del mes", value=date.today())
    default_month = month_from_date(d)

    with col2:
        month_override = st.text_input("Mes (YYYY-MM)", value=default_month)

    month = normalize_month_str(month_override)
    if not month:
        st.error("Mes inválido. Usa YYYY-MM (ej: 2025-11).")
        return

    overwrite = st.checkbox("Sobrescribir si ya existe (upsert)", value=True)
    auto_create_missing_users = st.checkbox("Crear usuario automáticamente si no existe (inactivo)", value=False)
    auto_create_name = st.text_input("Nombre por defecto (si se autocrea)", value="Usuario")

    st.info(
        "Si una cédula NO existe en `users`, el usuario no podrá ver su PDF. "
        "Aquí se reporta y opcionalmente se puede autocrear INACTIVO."
    )

    tab1, tab2 = st.tabs(["Subir ZIP", "Subir múltiples PDFs"])

    def ensure_user(cedula: str) -> Tuple[bool, bool, Optional[str]]:
        u = get_user(cedula)
        if u:
            return True, False, None
        if not auto_create_missing_users:
            return False, False, None
        temp_pass = pysecrets.token_urlsafe(10)
        create_user(cedula, auto_create_name, temp_pass, role="user", is_active=False)
        return True, True, temp_pass

    def show_last_upload_results():
        payload = st.session_state.get("last_upload_results")
        if not payload:
            return
        st.markdown("### Resultado del último cargue")
        st.caption(f"Mes: {payload['month']} | Fecha: {payload['timestamp']} | Bucket: {sb_bucket()}")

        df = pd.DataFrame(payload["results"])
        if not df.empty:
            c1, c2, c3 = st.columns(3)
            c1.metric("Cargados", int((df["estado"] == "OK").sum()))
            c2.metric("Omitidos", int((df["estado"] == "OMITIDO").sum()))
            c3.metric("Errores", int((df["estado"] == "ERROR").sum()))
            st.dataframe(df, use_container_width=True, hide_index=True)

        if payload.get("created_users"):
            st.warning("Se autocrearon usuarios INACTIVOS. Debes asignar contraseña y activarlos en 'Usuarios'.")
            st.dataframe(pd.DataFrame(payload["created_users"]), use_container_width=True, hide_index=True)

    def run_upload(items: List[Tuple[str, bytes]]):
        results: List[Dict[str, Any]] = []
        total = len(items)
        if total == 0:
            st.warning("No se encontraron PDFs en el archivo.")
            return

        created_users = []
        progress = st.progress(0, text="Iniciando...")

        with st.status("Procesando archivos...", expanded=True) as status:
            ok = skipped = errors = 0

            for i, (fname, fbytes) in enumerate(items, start=1):
                cedula = extract_cedula_from_filename(fname)
                size_kb = round(len(fbytes) / 1024, 1)

                try:
                    if not cedula:
                        skipped += 1
                        results.append({
                            "archivo": fname, "cedula": None, "tam_kb": size_kb,
                            "estado": "OMITIDO", "motivo": "No se pudo extraer cédula del nombre",
                            "storage_path": None
                        })
                    elif not is_pdf_bytes(fbytes):
                        skipped += 1
                        results.append({
                            "archivo": fname, "cedula": cedula, "tam_kb": size_kb,
                            "estado": "OMITIDO", "motivo": "No parece ser PDF",
                            "storage_path": None
                        })
                    else:
                        user_ok, created, temp_pass = ensure_user(cedula)
                        if not user_ok:
                            skipped += 1
                            results.append({
                                "archivo": fname, "cedula": cedula, "tam_kb": size_kb,
                                "estado": "OMITIDO", "motivo": "No existe usuario (crea la cédula o habilita autocreación)",
                                "storage_path": None
                            })
                        else:
                            if created:
                                created_users.append({"cedula": cedula, "temp_password": temp_pass})

                            storage_path = f"{month}/{cedula}.pdf"
                            storage_upload_pdf(storage_path, fbytes, overwrite=overwrite)
                            upsert_stub(month, cedula, storage_path)

                            ok += 1
                            results.append({
                                "archivo": fname, "cedula": cedula, "tam_kb": size_kb,
                                "estado": "OK", "motivo": "Cargado",
                                "storage_path": storage_path
                            })
                except Exception as e:
                    errors += 1
                    results.append({
                        "archivo": fname, "cedula": cedula, "tam_kb": size_kb,
                        "estado": "ERROR", "motivo": str(e),
                        "storage_path": None
                    })

                progress.progress(int(i * 100 / total), text=f"Procesando {i}/{total}...")

            status.update(label=f"Finalizado. OK={ok}, Omitidos={skipped}, Errores={errors}", state="complete")

        progress.empty()

        st.session_state["last_upload_results"] = {
            "month": month,
            "results": results,
            "created_users": created_users,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }
        show_last_upload_results()

    show_last_upload_results()

    with tab1:
        zip_file = st.file_uploader("ZIP con PDFs", type=["zip"], accept_multiple_files=False)
        if st.button("Procesar ZIP", use_container_width=True, disabled=not zip_file):
            items = list(iter_zip_pdfs(zip_file.read()))
            run_upload(items)

    with tab2:
        pdfs = st.file_uploader("Selecciona PDFs", type=["pdf"], accept_multiple_files=True)
        if st.button("Procesar PDFs", use_container_width=True, disabled=not pdfs):
            items = [(p.name, p.read()) for p in pdfs]
            run_upload(items)

def admin_auditoria():
    st.subheader("Auditoría")
    st.caption("Revisa qué quedó en BD y qué existe en Storage para un mes.")

    default_month = month_from_date(date.today())
    month = st.text_input("Mes a auditar (YYYY-MM)", value=default_month)
    month = normalize_month_str(month)
    if not month:
        st.error("Mes inválido.")
        return

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Registros en BD (stubs)")
        rows = get_stubs_for_month(month)
        st.metric("Cantidad BD", f"{len(rows):,}")
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with col2:
        st.markdown("#### Objetos en Storage (carpeta del mes)")
        try:
            objs = storage_list_folder(month)
            st.metric("Cantidad Storage", f"{len(objs):,}")
            if objs:
                df = pd.DataFrame([{
                    "name": o.get("name"),
                    "size": (o.get("metadata") or {}).get("size"),
                    "mimetype": (o.get("metadata") or {}).get("mimetype"),
                } for o in objs])
                st.dataframe(df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"No se pudo listar Storage: {e}")


# =========================
# USER UI
# =========================
def user_portal():
    st.subheader("Mis desprendibles")
    cedula = st.session_state.user["cedula"]
    full_name = st.session_state.user.get("full_name", "")
    st.caption(f"Usuario: {full_name or cedula}")

    months = list_months_for_cedula(cedula)
    if not months:
        st.info("Aún no hay desprendibles disponibles para tu usuario.")
        return

    month = st.selectbox("Mes", months)
    storage_path = get_stub_storage_path(month, cedula)
    if not storage_path:
        st.error("No se encuentra el registro. Contacta al administrador.")
        return

    try:
        pdf_bytes = storage_download_pdf(storage_path)
    except Exception as e:
        st.error(f"No se pudo descargar el PDF: {e}")
        return

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

    embed_pdf_in_page(pdf_bytes, height=780)


# =========================
# SHELL
# =========================
def shell_header():
    st.sidebar.markdown(f"## {APP_TITLE}")
    u = st.session_state.user
    st.sidebar.caption(f"Sesión: {u['cedula']} ({u['role'].upper()})")
    if st.sidebar.button("Cerrar sesión", use_container_width=True):
        do_logout()

def admin_shell():
    shell_header()
    page = st.sidebar.radio("Menú", ["Inicio", "Cargar PDFs", "Usuarios", "Auditoría", "Diagnóstico"], index=0)

    if page == "Inicio":
        admin_home()
    elif page == "Cargar PDFs":
        admin_upload_panel()
    elif page == "Usuarios":
        admin_users_panel()
    elif page == "Auditoría":
        admin_auditoria()
    elif page == "Diagnóstico":
        admin_diagnostico()

def user_shell():
    shell_header()
    user_portal()


# =========================
# MAIN
# =========================
def main():
    st.set_page_config(page_title=APP_TITLE, layout="wide")

    # Fuerza lectura de config (si falta, muestra pantalla guiada)
    _ = sb_client()

    if "user" not in st.session_state:
        st.session_state.user = None

    # Si no hay admin, crea admin inicial
    try:
        has_admin = user_exists_admin()
    except Exception as e:
        st.error(f"No se pudo consultar la BD. Revisa Supabase tablas / keys. Detalle: {e}")
        st.stop()

    if not has_admin:
        initial_admin_setup()
        return

    if not st.session_state.user:
        login_screen()
        return

    role = st.session_state.user.get("role", "user")
    if role == "admin":
        admin_shell()
    else:
        user_shell()


if __name__ == "__main__":
    main()
