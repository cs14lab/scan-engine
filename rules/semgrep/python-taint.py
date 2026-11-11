# Semgrep test fixture for python-taint.yaml. Every `ruleid:` line must be
# reported and every `ok:` line must not be — `semgrep --test` fails on either
# mistake, which is what stops a rule from quietly becoming a false-positive
# generator.
#
# The annotation is parsed as `# <ok|ruleid>: <rule-id>` and nothing else: any
# explanation appended after the id is read as part of the id and the run fails
# with a rule-id mismatch. Explanations go on their own line above.

import os
import shutil
import subprocess
import uuid
from pathlib import Path

from fastapi import UploadFile
from werkzeug.utils import secure_filename

UPLOAD_DIR = "/srv/uploads"


# ── uploadfile-filename-to-filesystem-sink ─────────────────────────────

# Annotations sit on the *sink* line: taint findings are reported where the
# tainted value is used, not where it enters.
async def save_unsafe(upload: UploadFile):
    dest = os.path.join(UPLOAD_DIR, upload.filename)
    # ruleid: uploadfile-filename-to-filesystem-sink
    with open(dest, "wb") as out:
        out.write(await upload.read())


async def save_with_basename(upload: UploadFile):
    dest = os.path.join(UPLOAD_DIR, os.path.basename(upload.filename))
    # ok: uploadfile-filename-to-filesystem-sink
    with open(dest, "wb") as out:
        out.write(await upload.read())


async def save_with_path_name(upload: UploadFile):
    dest = os.path.join(UPLOAD_DIR, Path(upload.filename).name)
    # ok: uploadfile-filename-to-filesystem-sink
    Path(dest).write_bytes(await upload.read())


async def save_with_secure_filename(upload: UploadFile):
    dest = os.path.join(UPLOAD_DIR, secure_filename(upload.filename))
    # ok: uploadfile-filename-to-filesystem-sink
    shutil.copy(upload.file.name, dest)


async def save_with_generated_name(upload: UploadFile):
    dest = os.path.join(UPLOAD_DIR, str(uuid.uuid4()))
    # ok: uploadfile-filename-to-filesystem-sink
    Path(dest).write_bytes(await upload.read())


# ── json-body-field-to-filesystem-sink ─────────────────────────────────

def read_report_unsafe(payload: dict):
    name = payload.get("filename", "report.pdf")
    # ruleid: json-body-field-to-filesystem-sink
    return open(os.path.join(UPLOAD_DIR, name), "rb").read()


def read_report_safe(payload: dict):
    name = Path(payload.get("filename", "report.pdf")).name
    # ok: json-body-field-to-filesystem-sink
    return open(os.path.join(UPLOAD_DIR, name), "rb").read()


# ── secret-literal-as-env-default ──────────────────────────────────────

# ruleid: secret-literal-as-env-default
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "s3cr3t-signing-key-2024")

# ruleid: secret-literal-as-env-default
API_KEY = os.environ.get("PARTNER_API_KEY", "pk_live_9f2a4b6c8d0e")

# ok: secret-literal-as-env-default
SECRET_PLACEHOLDER = os.getenv("JWT_SECRET_KEY", "change-me-in-production")

# ok: secret-literal-as-env-default
SECRET_REQUIRED = os.environ["JWT_SECRET_KEY"]

# Not a secret-shaped name.
# ok: secret-literal-as-env-default
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO_VERBOSE")

# Too short to be a real key.
# ok: secret-literal-as-env-default
SHORT = os.getenv("API_KEY", "dev")


# ── credential-in-process-argv ─────────────────────────────────────────

def deploy_unsafe(host: str, password: str):
    # ruleid: credential-in-process-argv
    subprocess.run(["sshpass", "-p", password, "ssh", host, "uptime"])


def deploy_safe(host: str, password: str):
    # ok: credential-in-process-argv
    env = dict(os.environ, SSHPASS=password)
    subprocess.run(["sshpass", "-e", "ssh", host, "uptime"], env=env)
