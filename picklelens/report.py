"""Self-contained HTML report generation.

Produces a single static .html file (no external assets, theme-aware) that a
non-terminal audience - a teammate, a ticket, a portfolio reviewer - can open
to see each file's risk score, malware-behavior profile, ATT&CK mapping,
indicators, and the reachable calls that justify the verdict.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .scanner import ScanResult

_VERDICT_COLOR = {
    "malicious": "#e5484d", "suspicious": "#f5a623",
    "notable": "#3b9eff", "clean": "#30a46c", "error": "#a35bd4",
}


def _esc(x) -> str:
    return html.escape(str(x))


def _risk_hue(risk: int) -> str:
    return "#e5484d" if risk >= 70 else "#f5a623" if risk >= 40 else "#30a46c"


def _file_card(r: ScanResult) -> str:
    color = _VERDICT_COLOR.get(r.verdict, "#888")
    behaviors = r.behaviors
    iocs = r.iocs.to_dict()
    parts = [f'<article class="card"><header>'
             f'<span class="pill" style="background:{color}">'
             f'{_esc(r.verdict.upper())}</span>'
             f'<code class="path">{_esc(r.path)}</code>'
             f'<span class="fmt">{_esc(r.format)}</span></header>']

    if r.verdict not in ("clean", "error"):
        hue = _risk_hue(r.risk)
        prof = _esc(r.profile or "malicious behavior")
        parts.append(
            f'<div class="risk"><div class="risknum" style="color:{hue}">'
            f'{r.risk}<small>/100</small></div>'
            f'<div class="riskbar"><i style="width:{r.risk}%;background:{hue}"></i></div>'
            f'<div class="profile">{prof}</div></div>')

    if behaviors:
        parts.append('<h4>Behavior</h4><ul class="behaviors">')
        for b in behaviors:
            ev = _esc(", ".join(b.evidence[:5]))
            parts.append(
                f'<li><span class="bsev sev-{b.severity.label}">{b.severity.label}</span>'
                f'<b>{_esc(b.title)}</b> <span class="attck">ATT&amp;CK {_esc(b.attck)}</span>'
                f'<div class="ev">{ev}</div></li>')
        parts.append('</ul>')

    if iocs:
        parts.append('<h4>Indicators</h4><table class="iocs">')
        for label, vals in iocs.items():
            cells = "".join(f'<code>{_esc(v)}</code>' for v in vals[:12])
            parts.append(f'<tr><th>{_esc(label)}</th><td>{cells}</td></tr>')
        parts.append('</table>')

    findings = r.findings
    if findings:
        parts.append('<h4>Reachable calls</h4><table class="findings">')
        parts.append('<tr><th>sev</th><th>call</th><th>what</th><th>where</th></tr>')
        for f in findings[:40]:
            arrow = "calls" if f.reachable else "names"
            parts.append(
                f'<tr><td><span class="bsev sev-{f.severity.label}">'
                f'{f.severity.label}</span></td>'
                f'<td>{arrow} <code>{_esc(f.qualname)}</code></td>'
                f'<td>{_esc(f.note)}</td>'
                f'<td class="dim">{_esc(f.stream)} @ {f.position}</td></tr>')
        parts.append('</table>')

    if r.error:
        parts.append(f'<p class="err">{_esc(r.error)}</p>')
    parts.append('</article>')
    return "".join(parts)


_CSS = """
:root{--bg:#f6f6f7;--card:#fff;--fg:#1a1a1a;--dim:#6b7280;--line:#e5e7eb}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b21;
--fg:#e6e6e6;--dim:#9aa4b2;--line:#262b33}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:32px 20px}
h1{font-size:22px;margin:0 0 4px}.sub{color:var(--dim);margin:0 0 24px}
.summary{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:12px 16px;min-width:110px}.stat b{font-size:22px;display:block}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:18px 20px;margin-bottom:16px}
.card header{display:flex;align-items:center;gap:10px;flex-wrap:wrap;
border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:12px}
.pill{color:#fff;font-weight:700;font-size:11px;padding:3px 9px;border-radius:20px}
.path{font-size:13px;word-break:break-all}.fmt{color:var(--dim);font-size:12px;
margin-left:auto}
.risk{display:flex;align-items:center;gap:14px;margin:8px 0 4px}
.risknum{font-size:30px;font-weight:800}.risknum small{font-size:13px;color:var(--dim)}
.riskbar{flex:1;height:8px;background:var(--line);border-radius:6px;overflow:hidden}
.riskbar i{display:block;height:100%}.profile{font-weight:600}
h4{margin:16px 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;
color:var(--dim)}
ul.behaviors{list-style:none;padding:0;margin:0}
ul.behaviors li{padding:8px 0;border-bottom:1px solid var(--line)}
.attck{color:var(--dim);font-size:12px}.ev{color:var(--dim);font-size:12px;margin-top:2px}
.bsev{display:inline-block;font-size:10px;font-weight:700;text-transform:uppercase;
padding:2px 6px;border-radius:4px;margin-right:8px;color:#fff}
.sev-critical{background:#e5484d}.sev-high{background:#f5761a}.sev-medium{background:#f5a623}
.sev-low{background:#3b9eff}.sev-info{background:#8b8b8b}
table{width:100%;border-collapse:collapse;font-size:13px}
table th{text-align:left;color:var(--dim);font-weight:600;padding:4px 8px 4px 0;
vertical-align:top}table td{padding:4px 8px 4px 0;vertical-align:top}
.iocs code{background:var(--bg);border:1px solid var(--line);border-radius:4px;
padding:1px 5px;margin:2px;display:inline-block;font-size:12px;word-break:break-all}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.dim{color:var(--dim)}.err{color:#e5484d}
footer{color:var(--dim);font-size:12px;margin-top:24px;text-align:center}
"""


def render(results: list[ScanResult]) -> str:
    n_mal = sum(1 for r in results if r.verdict == "malicious")
    n_sus = sum(1 for r in results if r.verdict == "suspicious")
    n_clean = sum(1 for r in results if r.verdict == "clean")
    max_risk = max((r.risk for r in results), default=0)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    cards = "".join(_file_card(r) for r in
                    sorted(results, key=lambda r: -r.risk))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>picklelens report</title><style>{_CSS}</style></head><body><div class="wrap">
<h1>picklelens scan report</h1>
<p class="sub">{_esc(len(results))} file(s) analysed · {_esc(ts)}</p>
<div class="summary">
<div class="stat" style="border-color:#e5484d"><b>{n_mal}</b>malicious</div>
<div class="stat" style="border-color:#f5a623"><b>{n_sus}</b>suspicious</div>
<div class="stat" style="border-color:#30a46c"><b>{n_clean}</b>clean</div>
<div class="stat"><b>{max_risk}</b>top risk</div>
</div>
{cards}
<footer>Generated by picklelens · static reachability analysis of pickle model files</footer>
</div></body></html>"""
