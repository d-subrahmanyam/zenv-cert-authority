#!/usr/bin/env python3
"""Collect every ```mermaid block from docs/*.md into docs/diagrams.html.

The Markdown files stay the single source of truth; the generated page renders all
diagrams in one place (open it in a browser, no server needed).

    python3 scripts/build-diagram-viewer.py
"""
import html
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
ORDER = ["use-cases.md", "flows.md", "architecture.md"]
BLOCK = re.compile(r"^(#{1,3}) (.+?)$|^```mermaid\n(.*?)^```", re.M | re.S)

sections = []
for name in ORDER:
    text = (DOCS / name).read_text()
    heading = name
    for m in BLOCK.finditer(text):
        if m.group(2):
            heading = m.group(2).strip()
        else:
            sections.append((name, heading, m.group(3)))

nav = "\n".join(
    f'<a href="#d{i}">{html.escape(h)}</a>' for i, (_, h, _) in enumerate(sections)
)
body = "\n".join(
    f'<section id="d{i}"><h2>{html.escape(h)}</h2><p class="src">{html.escape(f)}</p>'
    f'<pre class="mermaid">{html.escape(src)}</pre></section>'
    for i, (f, h, src) in enumerate(sections)
)

page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zenv CA Diagrams</title>
<style>
:root {{ --bg:#f6f7f9; --fg:#1b1f24; --muted:#5d6673; --card:#fff; --border:#dde1e7; --accent:#2556d8; }}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{ --bg:#0f1216; --fg:#e6e9ee; --muted:#9aa4b2; --card:#171b21; --border:#2b323c; --accent:#6b93ff; }} }}
:root[data-theme="dark"] {{ --bg:#0f1216; --fg:#e6e9ee; --muted:#9aa4b2; --card:#171b21; --border:#2b323c; --accent:#6b93ff; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui,sans-serif; }}
header {{ padding:20px 16px 8px; max-width:1100px; margin:0 auto; }}
header h1 {{ margin:0; font-size:1.4rem; }}
header p {{ color:var(--muted); margin:4px 0 0; }}
nav {{ display:flex; flex-wrap:wrap; gap:6px 14px; padding:8px 16px 16px; max-width:1100px; margin:0 auto; }}
nav a {{ color:var(--accent); text-decoration:none; font-size:.9rem; }}
main {{ max-width:1100px; margin:0 auto; padding:0 16px 40px; }}
section {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:16px; margin-bottom:18px; overflow-x:auto; }}
section h2 {{ margin:0; font-size:1.05rem; }}
.src {{ margin:2px 0 10px; color:var(--muted); font-size:.8rem; font-family:ui-monospace,monospace; }}
.mermaid {{ background:transparent; margin:0; }}
</style></head>
<body>
<header><h1>Zenv DMZ CA: diagrams</h1>
<p>Generated from the Mermaid blocks in docs/*.md by scripts/build-diagram-viewer.py. Formal UML (PlantUML) sources: docs/uml/*.puml.</p></header>
<nav>{nav}</nav>
<main>{body}</main>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js"></script>
<script>
const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
mermaid.initialize({{ startOnLoad: true, theme: dark ? 'dark' : 'default', securityLevel: 'strict' }});
</script>
</body></html>
"""
out = DOCS / "diagrams.html"
out.write_text(page)
print(f"wrote {out.relative_to(ROOT)} with {len(sections)} diagrams")
