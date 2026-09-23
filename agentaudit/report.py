"""Self-contained HTML report for agentaudit results.

A single static .html (no external assets, theme-aware) showing each audited
trace's verdict, risk, the betrayal findings with their provenance chains, the
injected instructions detected, and the MITRE ATT&CK tags - the human-facing
counterpart to the terminal output.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from .detect import AuditResult

_VERDICT_COLOR = {
    "betrayed": "#e5484d", "compromised": "#e5484d", "suspicious": "#f5a623",
    "notable": "#3b9eff", "clean": "#30a46c",
}
_SEV = {"critical": "#e5484d", "high": "#f5761a", "medium": "#f5a623",
        "low": "#3b9eff", "info": "#8b8b8b"}


def _esc(x) -> str:
    return html.escape(str(x))


def _card(r: AuditResult) -> str:
    color = _VERDICT_COLOR.get(r.verdict, "#888")
    parts = [f'<article class="card"><header>'
             f'<span class="pill" style="background:{color}">{_esc(r.verdict.upper())}</span>'
             f'<code class="name">{_esc(r.name)}</code></header>']

    if r.findings:
        parts.append('<ul class="findings">')
        for f in r.findings:
            sev = _SEV.get(f.severity.label, "#888")
            loc = []
            if f.action_index is not None:
                loc.append(f"action @ step {f.action_index}")
            if f.source_index is not None:
                loc.append(f"source @ step {f.source_index}")
            locs = f' <span class="loc">{_esc(" · ".join(loc))}</span>' if loc else ""
            attck = f' <span class="attck">ATT&amp;CK {_esc(f.attck)}</span>' if f.attck else ""
            ev = "".join(f'<code>{_esc(e)}</code>' for e in f.evidence)
            parts.append(
                f'<li><span class="sev" style="background:{sev}">{f.severity.label}</span>'
                f'<span class="kind">{_esc(f.kind)}</span> <b>{_esc(f.title)}</b>{attck}{locs}'
                f'<div class="detail">{_esc(f.detail)}</div>'
                f'<div class="ev">{ev}</div></li>')
        parts.append('</ul>')
    else:
        parts.append('<p class="ok">No betrayal indicators; every action traces '
                     'to trusted input.</p>')

    if r.injected_instructions:
        chips = "".join(f'<code>step {i}: {_esc(k)}</code>'
                        for i, k in r.injected_instructions)
        parts.append(f'<div class="inj"><b>Injected instructions seen:</b> {chips}</div>')

    parts.append('</article>')
    return "".join(parts)


_CSS = """
:root{--bg:#f6f6f7;--card:#fff;--fg:#1a1a1a;--dim:#6b7280;--line:#e5e7eb}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b21;--fg:#e6e6e6;
--dim:#9aa4b2;--line:#262b33}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:32px 20px}
h1{font-size:22px;margin:0 0 4px}.sub{color:var(--dim);margin:0 0 22px}
.summary{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:10px 15px;min-width:96px}.stat b{font-size:22px;display:block}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:16px 18px;margin-bottom:14px}
.card header{display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--line);
padding-bottom:10px;margin-bottom:10px}
.pill{color:#fff;font-weight:700;font-size:11px;padding:3px 9px;border-radius:20px}
.name{font-size:13px;word-break:break-all}
ul.findings{list-style:none;padding:0;margin:0}
ul.findings li{padding:9px 0;border-bottom:1px solid var(--line)}
.sev{display:inline-block;color:#fff;font-size:10px;font-weight:700;text-transform:uppercase;
padding:2px 6px;border-radius:4px;margin-right:6px}
.kind{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.04em;margin-right:6px}
.attck,.loc{color:var(--dim);font-size:12px}
.detail{color:var(--dim);font-size:13px;margin-top:3px}
.ev code,.inj code{background:var(--bg);border:1px solid var(--line);border-radius:4px;
padding:1px 6px;margin:3px 4px 0 0;display:inline-block;font-size:12px;word-break:break-all}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.ok{color:#30a46c;font-weight:600}.inj{margin-top:10px;font-size:13px}
footer{color:var(--dim);font-size:12px;margin-top:22px;text-align:center}
"""


def render(results: list[AuditResult]) -> str:
    n_bet = sum(1 for r in results if r.verdict in ("betrayed", "compromised"))
    n_sus = sum(1 for r in results if r.verdict == "suspicious")
    n_clean = sum(1 for r in results if r.verdict == "clean")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cards = "".join(_card(r) for r in results)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>agentaudit report</title><style>{_CSS}</style></head><body><div class="wrap">
<h1>agentaudit report</h1>
<p class="sub">{_esc(len(results))} trace(s) audited · {_esc(ts)}</p>
<div class="summary">
<div class="stat" style="border-color:#e5484d"><b>{n_bet}</b>betrayed</div>
<div class="stat" style="border-color:#f5a623"><b>{n_sus}</b>suspicious</div>
<div class="stat" style="border-color:#30a46c"><b>{n_clean}</b>clean</div>
</div>
{cards}
<footer>Generated by agentaudit · provenance analysis of agent execution traces</footer>
</div></body></html>"""
