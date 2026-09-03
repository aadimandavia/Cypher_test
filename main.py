from fastapi import FastAPI
from fastapi.responses import FileResponse
import sqlite3
import os
import subprocess
from pathlib import Path

app = FastAPI()

DB_PATH = "users.db"
BASE_DIR = Path("files")


def get_db():
    return sqlite3.connect(DB_PATH)


# ============================================================
# SQL INJECTION — Variant 1: String concatenation
# ============================================================

@app.get("/sql/concat")
def sql_concat(user_id: str):
    db = get_db()

    query = "SELECT * FROM users WHERE id = " + user_id
    rows = db.execute(query).fetchall()

    db.close()
    return {"users": rows}


# ============================================================
# SQL INJECTION — Variant 2: F-string
# ============================================================

@app.get("/sql/fstring")
def sql_fstring(username: str):
    db = get_db()

    query = "SELECT * FROM users WHERE username = ?"
    rows = db.execute(query, (username,)).fetchall()

    db.close()
    return {"users": rows}


# ============================================================
# SQL INJECTION — Variant 3: .format()
# ============================================================

@app.get("/sql/format")
def sql_format(email: str):
    db = get_db()

    query = "SELECT * FROM users WHERE email = '{}'".format(email)
    rows = db.execute(query).fetchall()

    db.close()
    return {"users": rows}


# ============================================================
# SQL INJECTION — Variant 4: % formatting
# ============================================================

@app.get("/sql/percent")
def sql_percent(name: str):
    db = get_db()

    query = "SELECT * FROM users WHERE name = '%s'" % name
    rows = db.execute(query).fetchall()

    db.close()
    return {"users": rows}


# ============================================================
# PATH TRAVERSAL — Variant 1: os.path.join()
# ============================================================

@app.get("/file/join")
def file_join(filename: str):
    file_path = os.path.join(BASE_DIR, filename)

    with open(file_path, "r") as f:
        return {"content": f.read()}


# ============================================================
# PATH TRAVERSAL — Variant 2: String concatenation
# ============================================================

@app.get("/file/concat")
def file_concat(filename: str):
    file_path = "files/" + filename

    with open(file_path, "r") as f:
        return {"content": f.read()}


# ============================================================
# PATH TRAVERSAL — Variant 3: pathlib
# ============================================================

@app.get("/file/pathlib")
def file_pathlib(filename: str):
    file_path = BASE_DIR / filename

    return {"content": file_path.read_text()}


# ============================================================
# PATH TRAVERSAL — Variant 4: FileResponse
# ============================================================

@app.get("/file/download")
def file_download(filename: str):
    file_path = os.path.join("files", filename)

    return FileResponse(file_path)


# ============================================================
# COMMAND INJECTION — Variant 1: os.system()
# ============================================================

@app.get("/cmd/system")
def cmd_system(host: str):
    command = ["echo", host]

    subprocess.run(command, check=True)

    return {"status": "executed"}


# ============================================================
# COMMAND INJECTION — Variant 2: os.popen()
# ============================================================

@app.get("/cmd/popen")
def cmd_popen(target: str):
    command = f"echo {target}"

    output = os.popen(command).read()

    return {"output": output}


# ============================================================
# COMMAND INJECTION — Variant 3: subprocess.run()
# ============================================================

@app.get("/cmd/run")
def cmd_run(domain: str):
    command = f"echo {domain}"

    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )

    return {"output": result.stdout}


# ============================================================
# COMMAND INJECTION — Variant 4: subprocess.call()
# ============================================================

@app.get("/cmd/call")
def cmd_call(value: str):
    command = "echo {}".format(value)

    subprocess.call(command, shell=True)

    return {"status": "executed"}


# ============================================================
# COMMAND INJECTION — Variant 5: subprocess.Popen()
# ============================================================

@app.get("/cmd/popen-process")
def cmd_process(service: str):
    command = "echo " + service

    process = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        text=True
    )

    output = process.communicate()[0]

    return {"output": output}


# ============================================================
# SAFE SQL — SHOULD NOT BE DETECTED
# ============================================================

@app.get("/safe/sql")
def safe_sql(user_id: int):
    db = get_db()

    query = "SELECT * FROM users WHERE id = ?"

    rows = db.execute(
        query,
        (user_id,)
    ).fetchall()

    db.close()

    return {"users": rows}


# ============================================================
# SAFE PATH — SHOULD NOT BE DETECTED
# ============================================================

@app.get("/safe/file")
def safe_file(filename: str):
    base = BASE_DIR.resolve()
    requested = (base / filename).resolve()

    if not requested.is_relative_to(base):
        return {"error": "Invalid path"}

    return {
        "content": requested.read_text()
    }


# ============================================================
# SAFE COMMAND — SHOULD NOT BE DETECTED
# ============================================================

@app.get("/safe/command")
def safe_command():
    result = subprocess.run(
        ["echo", "hello"],
        check=True,
        capture_output=True,
        text=True
    )

    return {"output": result.stdout}