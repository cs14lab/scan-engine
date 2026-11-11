# Semgrep test fixture for python-web-routes.yaml. Every `ruleid:` line must be
# reported and every `ok:` line must not be (`semgrep --test`). Annotations sit
# on the sink line; explanations go on their own line above them.

import os
import re
import urllib.request
from pathlib import Path

import aiohttp
import httpx
import requests
from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from flask import Flask, send_file, send_from_directory
from werkzeug.utils import secure_filename

app = FastAPI()
web = Flask(__name__)
DATA = "/srv/data"


# ── route-parameter-to-http-client ─────────────────────────────────────

# The rembg case: a query parameter fetched with an aiohttp session.
@app.get("/api/remove")
async def fetch_unsafe(url: str = Query(..., description="image URL")):
    async with aiohttp.ClientSession() as session:
        # ruleid: route-parameter-to-http-client
        async with session.get(url) as response:
            return await response.read()


@app.get("/api/remove-checked")
async def fetch_checked(url: str = Query(...)):
    _validate_url(url)
    async with aiohttp.ClientSession() as session:
        # ok: route-parameter-to-http-client
        async with session.get(url) as response:
            return await response.read()


@web.route("/proxy/<path:target>")
def proxy_unsafe(target):
    # ruleid: route-parameter-to-http-client
    return requests.get(target, timeout=5).content


@web.route("/preview/<target>")
def preview_unsafe(target):
    # ruleid: route-parameter-to-http-client
    return urllib.request.urlopen(target).read()


@app.post("/webhook-test")
async def webhook_unsafe(endpoint: str):
    async with httpx.AsyncClient() as client:
        # ruleid: route-parameter-to-http-client
        return (await client.post(endpoint, json={})).status_code


# An integer cannot be an address.
@app.get("/items/{item_id}")
async def item(item_id: int):
    # ok: route-parameter-to-http-client
    return httpx.get(item_id).json()


@web.route("/user/<user_id>")
def user(user_id):
    # ok: route-parameter-to-http-client
    return requests.get(int(user_id)).json()


# A dict's get() is not an HTTP call.
@web.route("/lookup/<key>")
def lookup(key):
    cache = {}
    # ok: route-parameter-to-http-client
    return cache.get(key)


# ── route-parameter-to-file-path ───────────────────────────────────────

# The changedetection.io case: a filter that keeps dots, then the directory
# argument of send_from_directory.
@web.route("/static/<string:group>/<string:filename>")
def static_unsafe(group, filename):
    filename = re.sub(r"[^\w.-]+", "", filename.lower())
    # ruleid: route-parameter-to-file-path
    return send_from_directory(os.path.join(DATA, filename), "last-screenshot.png")


# send_from_directory joins the file name safely; only the directory is a sink.
@web.route("/files/<name>")
def files_safe(name):
    # ok: route-parameter-to-file-path
    return send_from_directory(DATA, name)


@web.route("/download/<name>")
def download_unsafe(name):
    # ruleid: route-parameter-to-file-path
    return send_file(os.path.join(DATA, name))


@web.route("/download-safe/<name>")
def download_safe(name):
    # ok: route-parameter-to-file-path
    return send_file(os.path.join(DATA, secure_filename(name)))


@app.get("/report")
async def report_unsafe(path: str):
    # ruleid: route-parameter-to-file-path
    return FileResponse(os.path.join(DATA, path))


@app.get("/report-safe")
async def report_safe(path: str):
    # ok: route-parameter-to-file-path
    return FileResponse(os.path.join(DATA, os.path.basename(path)))


@app.delete("/notes/{name}")
async def delete_unsafe(name: str):
    # ruleid: route-parameter-to-file-path
    Path(DATA, name).unlink()


@app.delete("/notes-checked/{name}")
async def delete_checked(name: str):
    target = Path(DATA, name).resolve()
    target.relative_to(DATA)
    # ok: route-parameter-to-file-path
    target.unlink()


# A record looked up by the parameter is the application's own data.
@web.route("/edit/<uuid>/get-html")
def latest_html(uuid):
    watch = WATCHES.get(uuid)
    # ok: route-parameter-to-file-path
    return open(os.path.join(watch.data_dir, "latest.html")).read()


@web.route("/book/<book_id>/cover")
def cover(book_id):
    book = calibre_db.get_book(book_id)
    # ok: route-parameter-to-file-path
    return send_file(os.path.join(DATA, book.path, "cover.jpg"))


# An allow-list or a strict regex the code acts on.
@web.route("/flags/<subdir>/<svg>")
def flags(subdir, svg):
    if subdir not in ["1x1", "4x3"]:
        abort(404)
    if not re.match(r"^[a-z0-9-]+\.svg$", svg):
        abort(404)
    # ok: route-parameter-to-file-path
    return send_from_directory(f"static/flags/{subdir}", svg)


@web.route("/files/get/<path:path>")
def get_file(path):
    full = fs.safejoin(DATA, path)
    # ok: route-parameter-to-file-path
    return send_file(full)


# A lookup is not a check: the tag file is deleted whether or not the tag exists.
@web.route("/tags/delete/<uuid>")
def delete_tag(uuid):
    if TAGS.get(uuid):
        del TAGS[uuid]
    # ruleid: route-parameter-to-file-path
    os.unlink(os.path.join(DATA, uuid, "tag.json"))


@app.get("/page/{number}")
async def page(number: int):
    # ok: route-parameter-to-file-path
    return open(os.path.join(DATA, f"{number}.html")).read()


def _validate_url(url):
    if not url.startswith("https://"):
        raise ValueError(url)
