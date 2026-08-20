#!/usr/bin/env python3

import os, re, json, time, hashlib, pwd, socket, subprocess, requests, urllib3

WATCH_PATH = "/home/ansible/projects/async"
AUDIT_LOG = "/var/log/audit/audit.log"
AUDIT_KEY = "ansible_audit"

EDA_URL = "https://10.0.32.220:443/eda-event-streams/api/eda/v1/external_event_stream/12a7d1ab-5976-4fd1-b226-eb97f86053c7/post/"
EDA_USER = "ansible_audit"
EDA_PASSWORD = "redhat"

STATE_FILE = "/var/lib/audit-event-forwarder/checksums.json"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None


def get(line, field):
    m = re.search(rf'{field}=(?:"([^"]*)"|(\S+))', line)
    return (m.group(1) or m.group(2)) if m else None


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except:
        return {}


def save_state():
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def user(uid):
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except:
        return uid


state = load_state()

# Baseline inicial
for root, dirs, files in os.walk(WATCH_PATH):
    for name in files:
        path = os.path.abspath(os.path.join(root, name))

        # Ignorar temporales de Vim
        if name.endswith(("~", ".swp", ".swx", ".swo")):
            continue

        if path not in state:
            state[path] = sha256(path)

save_state()


def process_event(lines):

    if not any(AUDIT_KEY in x for x in lines):
        return

    syscall = next((x for x in lines if "type=SYSCALL" in x), None)
    cwd_line = next((x for x in lines if "type=CWD" in x), None)

    if not syscall:
        return

    cwd = get(cwd_line, "cwd") if cwd_line else WATCH_PATH

    paths = []

    for line in lines:

        if "type=PATH" not in line or "nametype=PARENT" in line:
            continue

        name = get(line, "name")
        nametype = get(line, "nametype")

        if not name:
            continue

        # Convertir PATH relativo de auditd a absoluto
        if not os.path.isabs(name):
            name = os.path.abspath(os.path.join(cwd, name))

        # Ignorar temporales de Vim
        base = os.path.basename(name)

        if base.startswith(".") and ".sw" in base:
            continue

        if base.endswith("~"):
            continue

        if base.isdigit():
            continue

        paths.append((name, nametype))

    if not paths:
        return

    types = [t for _, t in paths]

    if "DELETE" in types and "CREATE" in types:

        event_type = "file_moved"
        source = next(p for p, t in paths if t == "DELETE")
        path = next(p for p, t in paths if t == "CREATE")

    elif "DELETE" in types:

        event_type = "file_deleted"
        path = next(p for p, t in paths if t == "DELETE")
        source = None

    elif "CREATE" in types:

        event_type = "file_created"
        path = next(p for p, t in paths if t == "CREATE")
        source = None

    else:

        event_type = "file_modified"
        path = paths[-1][0]
        source = None


    old = state.get(source or path)

    time.sleep(0.5)

    if event_type == "file_deleted":

        new = None
        state.pop(path, None)

    else:

        new = sha256(path)

        if source:
            state.pop(source, None)

        if new:
            state[path] = new

    save_state()

    auid = get(syscall, "auid")

    payload = {
        "event_type": event_type,
        "host": socket.gethostname(),
        "path": path,
        "source_path": source,
        "old_checksum": old,
        "new_checksum": new,
        "checksum_changed": old != new,
        "user": user(auid),
        "auid": auid,
        "uid": get(syscall, "uid"),
        "pid": get(syscall, "pid"),
        "comm": get(syscall, "comm"),
        "exe": get(syscall, "exe")
    }

    print("\nEvento detectado:")
    print(json.dumps(payload, indent=2))

    try:
        r = requests.post(
            EDA_URL,
            json=payload,
            auth=(EDA_USER, EDA_PASSWORD),
            verify=False,
            timeout=10
        )

        print("EDA HTTP:", r.status_code)

    except Exception as e:
        print("Error enviando a EDA:", e)


p = subprocess.Popen(
    ["tail", "-F", "-n", "0", AUDIT_LOG],
    stdout=subprocess.PIPE,
    text=True
)

current_id = None
event = []

print("Audit Event Forwarder iniciado")
print("Directorio:", WATCH_PATH)

for line in p.stdout:

    m = re.search(r'audit\([0-9.]+:(\d+)\)', line)

    if not m:
        continue

    event_id = m.group(1)

    if current_id and event_id != current_id:
        process_event(event)
        event = []

    current_id = event_id
    event.append(line.strip())
