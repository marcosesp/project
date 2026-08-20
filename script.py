#!/usr/bin/env python3

import os
import re
import json
import time
import hashlib
import pwd
import socket
import subprocess
import requests
import urllib3
from threading import Timer


# ==========================================================
# CONFIGURACION
# ==========================================================

WATCH_PATH = "/home/ansible/projects/async"
AUDIT_LOG = "/var/log/audit/audit.log"
AUDIT_KEY = "ansible_audit"
EDA_URL = "https://10.0.32.220:443/eda-event-streams/api/eda/v1/external_event_stream/12a7d1ab-5976-4fd1-b226-eb97f86053c7/post/"
EDA_USER = "ansible_audit"
EDA_PASSWORD = "redhat"
STATE_FILE = "/var/lib/audit-event-forwarder/checksums.json"
urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)
pending_delete = {}


# ==========================================================
# CHECKSUM SHA256
# ==========================================================

def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(
                lambda: f.read(1024 * 1024),
                b""
            ):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

# ==========================================================
# EXTRAER CAMPOS DE AUDITD
# ==========================================================

def get(line, field):
    m = re.search(
        rf'{field}=(?:"([^"]*)"|(\S+))',
        line
    )
    return (m.group(1) or m.group(2)) if m else None
# ==========================================================
# RESOLVER USUARIO
# ==========================================================

def username(uid):
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except:
        return uid

# ==========================================================
# CARGAR ESTADO
# ==========================================================

try:
    with open(STATE_FILE) as f:
        state = json.load(f)
except:
    state = {}

# ==========================================================
# GUARDAR ESTADO
# ==========================================================

def save_state():
    os.makedirs(
        os.path.dirname(STATE_FILE),
        exist_ok=True
    )
    with open(STATE_FILE, "w") as f:
        json.dump(
            state,
            f,
            indent=2
        )

# ==========================================================
# ENVIAR EVENTO
# ==========================================================

def send_event(event_type, path, old, new, syscall):

    auid = get(syscall, "auid")
    checksum_changed = old != new
    payload = {
        "event_type": event_type,
        "host": socket.gethostname(),
        "path": path,
        "old_checksum": old,
        "new_checksum": new,
        "checksum_changed": checksum_changed,
        "user": username(auid),
        "auid": auid,
        "uid": get(syscall, "uid"),
        "pid": get(syscall, "pid"),
        "comm": get(syscall, "comm"),
        "exe": get(syscall, "exe")
    }
    print("\nEvento detectado:")
    print(
        json.dumps(
            payload,
            indent=2
        )
    )

# ======================================================
# SOLO ENVIAR SI EL CHECKSUM CAMBIO
# ======================================================

    if not checksum_changed:
        print(
            "Checksum sin cambios - "
            "Evento NO enviado a EDA"
        )
        return

# ======================================================
# ENVIAR A EDA
# ======================================================

    try:
        r = requests.post(
            EDA_URL,
            json=payload,
            auth=(
                EDA_USER,
                EDA_PASSWORD
            ),
            verify=False,
            timeout=10
        )

        print(
            "Checksum modificado - "
            "Evento enviado a EDA"
        )

        print(
            "EDA HTTP:",
            r.status_code
        )

    except Exception as e:
        print(
            "Error enviando a EDA:",
            e
        )


# ==========================================================
# CREAR BASELINE INICIAL
# ==========================================================

for root, dirs, files in os.walk(WATCH_PATH):
    for name in files:
        # Ignorar archivos temporales de Vim
        if name.endswith(
            (
                "~",
                ".swp",
                ".swo",
                ".swx"
            )
        ):
            continue
        path = os.path.abspath(
            os.path.join(
                root,
                name
            )
        )
        if path not in state:
            state[path] = sha256(path)
save_state()

# ==========================================================
# CONFIRMAR ELIMINACION
# ==========================================================

def confirmar_delete(path):
    data = pending_delete.pop(
        path,
        None
    )
    if not data:
        return
    state.pop(
        path, None
    )
    save_state()
    send_event(
        "file_deleted", path, data["old"], None, data["syscall"]
    )

# ==========================================================
# PROCESAR EVENTO AUDIT
# ==========================================================

def process_event(lines):

    # Validar key de audit

    if not any(
        AUDIT_KEY in x
        for x in lines
    ):
        return

    syscall = next(
        (
            x
            for x in lines
            if "type=SYSCALL" in x
        ),

        None
    )

    cwd_line = next(

        (
            x
            for x in lines
            if "type=CWD" in x
        ),

        None
    )

    if not syscall:
        return
    cwd = (
        get(
            cwd_line,
            "cwd"
        )
        if cwd_line
        else WATCH_PATH
    )
    paths = []

# ======================================================
# OBTENER PATHS
# ======================================================
    for line in lines:
        if "type=PATH" not in line:
            continue
        if "nametype=PARENT" in line:
            continue
        path = get(
            line,
            "name"
        )
        nametype = get(
            line,
            "nametype"
        )
        if not path:
            continue
        # Convertir path relativo a absoluto
        if not os.path.isabs(path):
            path = os.path.abspath(
                os.path.join(
                    cwd,
                    path
                )
            )
        name = os.path.basename(path)

# ==================================================
# IGNORAR TEMPORALES DE VIM
# ==================================================
        if (
            (
                name.startswith(".")
                and ".sw" in name
            )
            or name.endswith("~")
            or name.isdigit()
        ):
            continue
        paths.append(
            (
                path,
                nametype
            )
        )
    if not paths:
        return

# ======================================================
# PROCESAR PATH
# ======================================================

    for path, nametype in paths:

# ==================================================
# DELETE
# ==================================================

        if nametype == "DELETE":
            old = state.get(path)

# Vim suele borrar y volver a crear.
# Esperamos antes de considerar un delete real.

            timer = Timer(
                1.5,
                confirmar_delete,
                args=[path]
            )
            pending_delete[path] = {
                "old": old,
                "syscall": syscall,
                "timer": timer
            }

            timer.start()

# ==================================================
# CREATE
# ==================================================

        elif nametype == "CREATE":
            time.sleep(0.2)
            new = sha256(path)

# ==================================================
# DELETE + CREATE = MODIFICACION
# ==================================================

            if path in pending_delete:
                data = pending_delete.pop(path)
                data["timer"].cancel()
                old = data["old"]
                if new:
                    state[path] = new
                    save_state()
                send_event(
                    "file_modified",
                    path,
                    old,
                    new,
                    syscall
                )

# ==================================================
# CREACION REAL
# ==================================================
            else:
                old = state.get(path)
                if new:
                    state[path] = new
                    save_state()
                send_event(
                    "file_created",
                    path,
                    old,
                    new,
                    syscall
                )

# ==================================================
# MODIFICACION NORMAL
# ==================================================

        elif nametype in (
            "NORMAL",
            None
        ):
            old = state.get(path)
            time.sleep(0.2)
            new = sha256(path)
            if new:
                state[path] = new
                save_state()
                send_event(
                    "file_modified",
                    path,
                    old,
                    new,
                    syscall
                )


# ==========================================================
# LEER AUDIT.LOG
# ==========================================================

p = subprocess.Popen(

    [
        "tail",
        "-F",
        "-n",
        "0",
        AUDIT_LOG
    ],
    stdout=subprocess.PIPE,
    text=True
)
current_id = None
event = []
print(
    "Audit Event Forwarder iniciado"
)
print(
    "Directorio:",
    WATCH_PATH
)
print(
    "Audit key:",
    AUDIT_KEY
)
print(
    "EDA:",
    EDA_URL
)


# ==========================================================
# LOOP PRINCIPAL
# ==========================================================

for line in p.stdout:
    m = re.search(
        r'audit\([0-9.]+:(\d+)\)',
        line
    )
    if not m:
        continue
    event_id = m.group(1)
    if (
        current_id
        and event_id != current_id
    ):
        process_event(event)
        event = []
    current_id = event_id
    event.append(
        line.strip()
    )
