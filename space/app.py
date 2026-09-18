"""picklelens — Hugging Face Space (Gradio).

Upload a model file; the picklelens engine statically analyses it (never
executing or deserializing anything) and reports the verdict, risk score,
malware-behavior profile, MITRE ATT&CK mapping, indicators, and the reachable
calls that justify the verdict.

Deployed as a Gradio Space so it fits Hugging Face's free tier. The heavy
lifting is the same `picklelens` package used by the CLI — this file is only a
thin UI wrapper.
"""
from __future__ import annotations

import os
import sys
import tempfile

import gradio as gr

# On Hugging Face the `picklelens` package is pip-installed (see
# requirements.txt). When running this file straight from a checkout of the
# repo, fall back to importing it from the parent directory.
try:
    from picklelens.scanner import scan_bytes, scan_file, ScanResult
    from picklelens import report as report_mod
except ModuleNotFoundError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from picklelens.scanner import scan_bytes, scan_file, ScanResult
    from picklelens import report as report_mod

MAX_UPLOAD = 25 * 1024 * 1024
_CONTAINER_EXTS = {".pt", ".pth", ".npz", ".keras", ".h5", ".hdf5",
                   ".7z", ".npy", ".zip", ".ckpt", ".bin"}

_VERDICT_EMOJI = {
    "malicious": "🛑", "suspicious": "⚠️", "notable": "🔎",
    "clean": "✅", "error": "❓",
}


def _scan_path(path: str, display_name: str) -> ScanResult:
    suffix = os.path.splitext(path)[1].lower()
    if suffix in _CONTAINER_EXTS:
        res = scan_file(path)
    else:
        with open(path, "rb") as fh:
            res = scan_bytes(fh.read(), path=display_name, label=display_name)
    res.path = display_name
    return res


def analyze(file_path: str | None):
    """Gradio callback. Returns (summary_markdown, report_html)."""
    if not file_path:
        return "Upload a model file to begin.", ""

    size = os.path.getsize(file_path)
    if size > MAX_UPLOAD:
        return (f"⚠️ File is {size/1e6:.1f} MB; the demo cap is 25 MB.", "")

    name = os.path.basename(file_path)
    res = _scan_path(file_path, name)

    emoji = _VERDICT_EMOJI.get(res.verdict, "•")
    lines = [f"## {emoji} {res.verdict.upper()} — `{name}`",
             f"**Risk {res.risk}/100** · format: {res.format}"]
    if res.profile:
        lines.append(f"**Behavior profile:** {res.profile}")
    if res.behaviors:
        lines.append("\n**Behaviors**")
        for b in res.behaviors:
            lines.append(f"- {b.title}  _(ATT&CK {b.attck})_")
    iocs = res.iocs.to_dict()
    if iocs:
        lines.append("\n**Indicators**")
        for label, vals in iocs.items():
            shown = ", ".join(f"`{v}`" for v in vals[:6])
            lines.append(f"- {label}: {shown}")
    if res.error:
        lines.append(f"\n_{res.error}_")

    html = report_mod.render([res])
    return "\n".join(lines), html


_INTRO = """# 🥒🔍 picklelens
**Is this AI model file safe to load?**

Most model weights ship as Python *pickles* — and a pickle is a program that
runs the instant you load it. picklelens reads the file's opcode stream
*without executing it*, resolves what it would actually call (seeing through
reflection and alias tricks), and classifies the behavior — ransomware,
infostealer, reverse shell, dropper, persistence — with MITRE ATT&CK tags and
extracted indicators.

Supports `.pkl .pt .pth .bin .ckpt .npy .npz .keras .h5 .7z` · analysed in
memory, never executed, never stored · [source on GitHub](https://github.com/Fatemeh-Najafi1/picklelens)
"""


def build() -> gr.Blocks:
    with gr.Blocks(title="picklelens") as demo:
        gr.Markdown(_INTRO)
        with gr.Row():
            with gr.Column(scale=1):
                up = gr.File(label="Model file (≤ 25 MB)", type="filepath")
                btn = gr.Button("Analyze", variant="primary")
                summary = gr.Markdown()
            with gr.Column(scale=1):
                out = gr.HTML(label="Report")
        up.change(analyze, up, [summary, out])
        btn.click(analyze, up, [summary, out])
        gr.Markdown("_Tip: the repo ships an inert sample corpus under "
                    "`samples/` — try `mal_ransomware.pkl`._")
    return demo


if __name__ == "__main__":
    # HF Spaces expect the app on 7860; PORT overrides for local runs.
    build().launch(
        server_name="0.0.0.0",
        server_port=int(os.environ.get("PORT", "7860")),
        theme=gr.themes.Soft(),
    )
