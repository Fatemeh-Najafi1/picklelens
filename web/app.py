"""picklelens web demo.

A single-file Flask app: upload a model file, get the reachability analysis,
behavior profile, ATT&CK mapping, indicators, and risk score rendered as a
page. It uses the real picklelens engine - the same static analysis as the
CLI - so nothing is ever executed or deserialized.

Safe to expose: uploads are capped, held only in memory, analysed, and
discarded; the analysis never runs the uploaded code. Stateless, so it fits a
free tier (e.g. Render) with no database.

Run locally:
    pip install -r web/requirements.txt
    python -m web.app           # http://127.0.0.1:5000
"""
from __future__ import annotations

import io
import os
import sys

from flask import Flask, request, abort

# Allow running both as `python -m web.app` and `python web/app.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from picklelens.scanner import scan_bytes, scan_file  # noqa: E402
from picklelens import report as report_mod  # noqa: E402

MAX_UPLOAD = 25 * 1024 * 1024  # 25 MB is plenty for a demo; blocks zip bombs.

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD

_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>picklelens</title><style>
:root{{--bg:#0f1115;--card:#181b21;--fg:#e6e6e6;--dim:#9aa4b2;--line:#262b33;--accent:#3b9eff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:820px;margin:0 auto;padding:48px 20px}}
h1{{font-size:30px;margin:0 0 6px}}.tag{{color:var(--dim);margin:0 0 32px;font-size:16px}}
.drop{{background:var(--card);border:2px dashed var(--line);border-radius:16px;
padding:40px;text-align:center;transition:.15s}}
.drop.hover{{border-color:var(--accent);background:#1b2129}}
input[type=file]{{display:none}}
.btn{{display:inline-block;background:var(--accent);color:#fff;font-weight:600;
padding:11px 22px;border-radius:10px;border:0;cursor:pointer;font-size:15px}}
.hint{{color:var(--dim);font-size:13px;margin-top:14px}}
.samples{{margin-top:28px;font-size:14px;color:var(--dim)}}
.samples code{{background:var(--card);border:1px solid var(--line);border-radius:5px;
padding:2px 7px;font-size:13px}}
.err{{background:#2a1416;border:1px solid #e5484d;color:#ffb4b4;padding:14px 16px;
border-radius:10px;margin-top:20px}}
footer{{margin-top:40px;color:var(--dim);font-size:13px}}
a{{color:var(--accent)}}
</style></head><body><div class="wrap">
<h1>🥒🔍 picklelens</h1>
<p class="tag">Upload an ML model file. See what it would run when loaded —
without loading it.</p>
<form method="post" action="/scan" enctype="multipart/form-data" id="f">
  <label class="drop" id="drop">
    <input type="file" name="model" id="file" required>
    <div><b>Drop a model file here</b> or <span class="btn">choose a file</span></div>
    <div class="hint">.pkl · .pt · .pth · .bin · .ckpt · .npy · .keras · .h5 ·
      up to 25 MB · analysed in memory, never executed, never stored</div>
  </label>
</form>
{error}
<div class="samples">Nothing to test with? The repo ships an inert sample
corpus under <code>samples/</code> (e.g. <code>mal_ransomware.pkl</code>).</div>
<footer>Static reachability analysis of pickle/Keras model files ·
<a href="https://github.com/Fatemeh-Najafi1/picklelens">source on GitHub</a></footer>
</div>
<script>
const drop=document.getElementById('drop'),file=document.getElementById('file'),f=document.getElementById('f');
file.addEventListener('change',()=>{{if(file.files.length)f.submit();}});
['dragover','dragenter'].forEach(e=>drop.addEventListener(e,ev=>{{ev.preventDefault();drop.classList.add('hover');}}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,ev=>{{ev.preventDefault();drop.classList.remove('hover');}}));
drop.addEventListener('drop',ev=>{{if(ev.dataTransfer.files.length){{file.files=ev.dataTransfer.files;f.submit();}}}});
</script>
</body></html>"""


@app.get("/")
def index():
    return _PAGE.format(error="")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/scan")
def scan():
    up = request.files.get("model")
    if up is None or not up.filename:
        return _PAGE.format(error='<div class="err">No file was uploaded.</div>')
    data = up.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        abort(413)

    # Route by extension into the right container handler, but always from
    # in-memory bytes - nothing is written to disk or executed.
    name = os.path.basename(up.filename)
    result = _scan_upload(name, data)

    # Reuse the exact HTML report the CLI produces, wrapped for the browser.
    body = report_mod.render([result])
    return body


def _scan_upload(name: str, data: bytes):
    """Dispatch an uploaded blob to the engine by extension, in memory."""
    import tempfile
    suffix = os.path.splitext(name)[1].lower()
    container_exts = {".pt", ".pth", ".npz", ".keras", ".h5", ".hdf5",
                      ".7z", ".npy", ".zip", ".ckpt", ".bin"}
    if suffix in container_exts:
        # Container formats need scan_file's format dispatch; give it a temp
        # path with the right suffix. The file is read, analysed, deleted.
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tf:
            tf.write(data)
            tmp = tf.name
        try:
            res = scan_file(tmp)
            res.path = name
            return res
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    res = scan_bytes(data, path=name, label=name)
    return res


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
