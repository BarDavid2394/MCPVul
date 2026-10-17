"""Render a standalone HTML view of a live scan's serialized findings."""
from html import escape
import json


def render_html(report):
    def esc(value):
        return escape(str(value), quote=True)

    info = report['scan_info']
    errors = info.get('parse_errors', [])
    findings = report['findings']
    status = 'Scan incomplete' if errors else ('Findings detected' if findings else 'No findings in selected scope')
    cards = []
    for finding in findings:
        details = []
        for label, value in (
            ('Matched evidence', finding.get('matched_text')),
            ('Source excerpt', finding.get('code_snippet')),
            ('Data-flow evidence', finding.get('metadata', {}).get('evidence')),
        ):
            if value:
                text = json.dumps(value, indent=2, ensure_ascii=False) if isinstance(value, dict) else value
                details.append(f'<details open><summary>{label}</summary><pre>{esc(text)}</pre></details>')
        location = f"{finding['file_path']}:{finding['line_number']}"
        if finding.get('function_name'):
            location += ' · ' + finding['function_name']
        cards.append(f'''<article class="finding">
<div class="tags"><strong>{esc(finding.get('rule_id') or finding.get('attack_id') or '')}</strong>
<span>{esc(finding['severity'])}</span><span>Confidence: {esc(finding.get('confidence', 'unknown'))}</span></div>
<h2>{esc(finding['title'])}</h2><p class="location">{esc(location)}</p>
<p>{esc(finding['description'])}</p>{''.join(details)}
<p><strong>Recommendation:</strong> {esc(finding.get('recommendation') or 'Review the evidence in context.')}</p>
<small>{'Eligible for targeted remediation' if finding.get('fixable') else 'Manual review required'}</small>
</article>''')
    error_html = ('<aside><h2>Scan errors</h2><ul>' + ''.join(f'<li>{esc(e)}</li>' for e in errors) + '</ul></aside>') if errors else ''
    coverage = ('<aside>No tool definitions were recognized. Tool-specific coverage may be incomplete.</aside>'
                if not info.get('tools_analyzed') else '')
    empty = '<p>No findings were produced. Review the scan errors above.</p>' if errors else '<p>No findings in the selected scope.</p>'
    severity = ' · '.join(f'{name}: {count}' for name, count in report['summary']['by_severity'].items()) or 'No severity counts'
    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP Security Scanner — Scan report</title>
<style>
:root{font-family:system-ui,sans-serif;color:#e8eef8;background:#101827;color-scheme:dark}
body{max-width:1100px;margin:auto;padding:32px}header{border-bottom:1px solid #34435d;padding-bottom:24px}
h1{font-size:32px;margin:10px 0}h2{font-size:20px}p{line-height:1.6}small,.location,.meta{color:#becbe0}
.location{overflow-wrap:anywhere}.stats{display:flex;flex-wrap:wrap;gap:16px;margin:24px 0}
.stat{background:#1b2940;border-radius:10px;padding:18px;min-width:135px}.stat strong{display:block;font-size:28px}
.finding{border:1px solid #394a65;border-left:4px solid #efb86b;padding:24px;border-radius:10px;margin:20px 0}
.tags{display:flex;gap:14px;flex-wrap:wrap;color:#8ee0d1}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0c1220;padding:16px;border-radius:8px}
summary{cursor:pointer;padding:8px 0}aside{background:#392f21;border:1px solid #806b40;padding:18px;margin:20px 0;border-radius:8px}
footer{border-top:1px solid #34435d;margin-top:28px;padding-top:16px;color:#becbe0}
@media(max-width:600px){body{padding:16px}.finding{padding:16px}.stat{min-width:95px}}
@media print{:root{color:black;background:white;color-scheme:light}pre,.stat{background:#eee}.finding{break-inside:avoid}small,.location,.meta,footer{color:#333}}
</style></head><body>''' + f'''
<header><p class="meta">MCP Security Scanner · Catalog {esc(report['catalog_version'])}</p>
<h1>{esc(status)}</h1><p class="location"><strong>Target:</strong> {esc(info['target'])}</p>
<p class="meta">Generated: {esc(report['timestamp'])} · Scope: {esc(info.get('check') or 'All rules')}</p></header>
<div class="stats"><div class="stat"><strong>{info['files_scanned']}</strong>Files scanned</div>
<div class="stat"><strong>{info['tools_analyzed']}</strong>Tools recognized</div>
<div class="stat"><strong>{len(findings)}</strong>Findings</div>
<div class="stat"><strong>{len(errors)}</strong>Scan errors</div></div>
<p>{esc(severity)}</p>{error_html}{coverage}{''.join(cards) or empty}
<footer>Results from this scan of the supplied path. Source was statically analyzed; the target server was not executed.
Findings are heuristic evidence. No findings do not prove safety. No automatic fixes were applied.</footer>
</body></html>'''
