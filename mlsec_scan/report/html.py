"""
HTML-отчёт для mlsec-scan.

Генерирует один self-contained HTML-файл со всей информацией о сканировании:
- шапка: модель, время, длительность
- сводка: сколько модулей, сколько критичных
- каждый модуль: статус, findings, рекомендации
- графики (если есть) — встроены как base64

Использование:
    from mlsec_scan.report.html import write_html_report
    write_html_report(report, Path("report.html"))
"""

import base64
from datetime import datetime
from pathlib import Path

from jinja2 import Template

from mlsec_scan.core.scanner import ScanReport

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>mlsec-scan report — {{ model_name }}</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #f5f7fa;
    color: #1f2937;
    margin: 0;
    padding: 32px 16px;
    line-height: 1.5;
  }
  .container { max-width: 960px; margin: 0 auto; }
  .header {
    background: #ffffff;
    border-radius: 12px;
    padding: 24px 28px;
    margin-bottom: 20px;
    border-left: 6px solid #3b82f6;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
  }
  .header h1 { margin: 0 0 6px; font-size: 24px; color: #111827; }
  .header .meta { color: #6b7280; font-size: 14px; }
  .header .meta span { margin-right: 16px; }
  .summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
  }
  .card {
    background: #ffffff;
    border-radius: 10px;
    padding: 16px 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
  }
  .card .label { color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  .card .value { font-size: 28px; font-weight: 600; margin-top: 4px; }
  .card.critical .value { color: #dc2626; }
  .card.high .value { color: #ea580c; }
  .card.ok .value { color: #16a34a; }

  .module {
    background: #ffffff;
    border-radius: 12px;
    padding: 22px 26px;
    margin-bottom: 16px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    border-left: 6px solid #9ca3af;
  }
  .module.vulnerable { border-left-color: #dc2626; }
  .module.resistant { border-left-color: #16a34a; }
  .module.unknown { border-left-color: #eab308; }
  .module.error { border-left-color: #a855f7; }

  .module-header {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 12px;
  }
  .module-name { font-size: 18px; font-weight: 600; }
  .module-status {
    font-size: 13px;
    padding: 3px 10px;
    border-radius: 20px;
    font-weight: 500;
  }
  .status-vulnerable { background: #fee2e2; color: #991b1b; }
  .status-resistant { background: #dcfce7; color: #166534; }
  .status-unknown { background: #fef9c3; color: #854d0e; }
  .status-error { background: #f3e8ff; color: #6b21a8; }
  .module-duration { color: #9ca3af; font-size: 12px; margin-left: 8px; }

  .finding { margin: 10px 0; padding-left: 14px; border-left: 3px solid #e5e7eb; }
  .finding .title { font-weight: 500; }
  .finding .desc { color: #4b5563; font-size: 14px; margin-top: 3px; }
  .finding.sev-critical, .finding.sev-high { border-left-color: #dc2626; }
  .finding.sev-medium { border-left-color: #ea580c; }
  .finding.sev-low { border-left-color: #eab308; }
  .finding.sev-info { border-left-color: #3b82f6; }

  .recommendations {
    margin-top: 12px;
    padding: 12px 16px;
    background: #f9fafb;
    border-radius: 8px;
    font-size: 14px;
  }
  .recommendations .title { font-weight: 600; margin-bottom: 6px; }
  .recommendations ul { margin: 0; padding-left: 20px; }

  .plot { margin-top: 16px; max-width: 100%; border-radius: 8px; }

  .footer {
    text-align: center;
    color: #9ca3af;
    font-size: 12px;
    margin-top: 32px;
  }
  .footer a { color: #6b7280; }
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>mlsec-scan report</h1>
    <div class="meta">
      <span><strong>Модель:</strong> {{ model_name }}</span>
      <span><strong>Время:</strong> {{ timestamp }}</span>
      <span><strong>Длительность:</strong> {{ duration }}s</span>
    </div>
  </div>

  <div class="summary">
    <div class="card">
      <div class="label">Модулей</div>
      <div class="value">{{ modules_count }}</div>
    </div>
    <div class="card critical">
      <div class="label">Critical</div>
      <div class="value">{{ critical_count }}</div>
    </div>
    <div class="card high">
      <div class="label">High</div>
      <div class="value">{{ high_count }}</div>
    </div>
    <div class="card ok">
      <div class="label">Resistant</div>
      <div class="value">{{ resistant_count }}</div>
    </div>
  </div>

  {% for result in results %}
  <div class="module {{ result.status }}">
    <div class="module-header">
      <div>
        <span class="module-name">{{ result.module_name }}</span>
        <span class="module-duration">{{ result.duration }}s</span>
      </div>
      <span class="module-status status-{{ result.status }}">{{ result.status }}</span>
    </div>

    {% for finding in result.findings %}
    <div class="finding sev-{{ finding.severity }}">
      <div class="title">{{ finding.title }}</div>
      <div class="desc">{{ finding.description }}</div>
    </div>
    {% endfor %}

    {% if result.recommendations %}
    <div class="recommendations">
      <div class="title">Рекомендации</div>
      <ul>
        {% for rec in result.recommendations %}
        <li>{{ rec }}</li>
        {% endfor %}
      </ul>
    </div>
    {% endif %}

    {% if result.plot_base64 %}
    <img class="plot" src="data:image/png;base64,{{ result.plot_base64 }}" alt="plot">
    {% endif %}
  </div>
  {% endfor %}

  <div class="footer">
    Сгенерировано <a href="https://github.com/Vaks911/mlsec-scan">mlsec-scan</a> · {{ generated }}
  </div>

</div>
</body>
</html>
"""


def report_to_dict(report: ScanReport) -> dict:
    """Превращает ScanReport в структуру для Jinja2."""
    results = []
    for r in report.results:
        plot_b64 = None
        plot_path = r.raw_data.get("plot_path")
        if plot_path and Path(plot_path).exists():
            with open(plot_path, "rb") as f:
                plot_b64 = base64.b64encode(f.read()).decode("ascii")

        results.append(
            {
                "module_name": r.module_name,
                "status": r.status,
                "duration": round(r.duration_sec, 2),
                "findings": [
                    {
                        "title": f.title,
                        "severity": f.severity,
                        "description": f.description,
                    }
                    for f in r.findings
                ],
                "recommendations": r.recommendations,
                "plot_base64": plot_b64,
            }
        )

    return {
        "model_name": report.model_name,
        "timestamp": report.timestamp,
        "duration": round(report.total_duration_sec, 2),
        "modules_count": len(report.results),
        "critical_count": report.critical_count,
        "high_count": report.high_count,
        "resistant_count": sum(1 for r in report.results if r.status == "resistant"),
        "results": results,
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def write_html_report(report: ScanReport, output_path: Path) -> None:
    """
    Пишет HTML-отчёт на диск.

    Args:
        report: ScanReport после сканирования.
        output_path: путь к файлу (например, report.html).
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    template = Template(HTML_TEMPLATE)
    data = report_to_dict(report)
    html = template.render(**data)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n✅ HTML-отчёт сохранён: {output_path}")
