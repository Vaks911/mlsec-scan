"""
JSON-отчёт для mlsec-scan.

Формат вывода — совместим с CI/CD: один файл, машиночитаемый,
с полями для парсинга (severity, status, findings).

Использование:
    from mlsec_scan.report.json import write_json_report
    write_json_report(report, Path("report.json"))
"""

import json
from dataclasses import asdict
from pathlib import Path

from mlsec_scan.core.scanner import ScanReport


def report_to_dict(report: ScanReport) -> dict:
    """Превращает ScanReport в словарь (готов к json.dump)."""
    return {
        "tool": "mlsec-scan",
        "version": "0.1.0",
        "model": report.model_name,
        "timestamp": report.timestamp,
        "duration_sec": round(report.total_duration_sec, 2),
        "summary": report.summary(),
        "results": [
            {
                "module": r.module_name,
                "status": r.status,
                "duration_sec": round(r.duration_sec, 2),
                "findings": [
                    {
                        "title": f.title,
                        "severity": f.severity,
                        "description": f.description,
                        "metric_value": f.metric_value,
                    }
                    for f in r.findings
                ],
                "recommendations": r.recommendations,
                "raw_data": r.raw_data,
            }
            for r in report.results
        ],
    }


def write_json_report(report: ScanReport, output_path: Path) -> None:
    """
    Пишет JSON-отчёт на диск.

    Args:
        report: ScanReport после сканирования.
        output_path: путь к файлу (например, report.json).
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = report_to_dict(report)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"\n✅ JSON-отчёт сохранён: {output_path}")
