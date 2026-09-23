"""
Command-line interface для mlsec-scan.
"""

from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mlsec_scan import __version__
from mlsec_scan.config import ScanConfig

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="mlsec-scan")
def cli():
    """
    MLSecOps scanner for machine learning models.

    Проверяет устойчивость ML-модели к adversarial, poisoning,
    extraction и backdoor атакам.
    """
    pass


@cli.command()
def version():
    """Показать версию mlsec-scan."""
    console.print(f"[bold cyan]mlsec-scan[/bold cyan] [green]v{__version__}[/green]")


@cli.command("list-modules")
def list_modules_cmd():
    """Показать список доступных модулей проверки."""
    from mlsec_scan.modules import adversarial  # noqa: F401
    from mlsec_scan.modules import poisoning  # noqa: F401
    from mlsec_scan.core import registry
    from mlsec_scan.modules import extraction  # noqa: F401

    modules = registry.list_modules()

    if not modules:
        console.print("[yellow]Пока не зарегистрировано ни одного модуля.[/yellow]")
        return

    table = Table(title="Доступные модули mlsec-scan")
    table.add_column("Имя", style="cyan")
    table.add_column("Описание", style="white")

    for name in modules:
        module = registry.get_module(name)
        table.add_row(name, module.description or "—")

    console.print(table)


@cli.command()
@click.option(
    "--model",
    "model_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Путь к чекпоинту модели (.ckpt, .pth, .onnx).",
)
@click.option(
    "--model-type",
    type=click.Choice(["auto", "patchcore", "resnet", "onnx"]),
    default="auto",
    help="Тип модели. По умолчанию auto.",
)
@click.option(
    "--detector-path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Путь к проекту defect-detection (для PatchCore).",
)
@click.option(
    "--data",
    "data_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Путь к папке с тестовыми данными.",
)
@click.option(
    "--train-data",
    "train_data_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Путь к train/good/ — для проверки на poisoning.",
)
@click.option(
    "--modules",
    default="adversarial",
    help="Список модулей через запятую. Например: adversarial,poisoning,extraction",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Путь к файлу отчёта (для --format json).",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["console", "json", "html"]),
    default="console",
    help="Формат отчёта.",
)
@click.option(
    "--eps",
    type=float,
    default=0.05,
    help="Epsilon для adversarial атак.",
)
@click.option(
    "--extraction-queries",
    type=int,
    default=150,
    help="Количество запросов к модели для extraction-проверки.",
)
@click.option("--verbose", is_flag=True, help="Подробный вывод.")
def scan(
    model_path,
    model_type,
    detector_path,
    data_path,
    train_data_path,
    modules,
    output_path,
    output_format,
    eps,
    extraction_queries,
    verbose,
):
    """
    Запустить сканирование ML-модели.
    """
    from mlsec_scan.modules import adversarial  # noqa: F401
    from mlsec_scan.modules import poisoning  # noqa: F401
    from mlsec_scan.modules import extraction  # noqa: F401
    from mlsec_scan.core import Scanner, TestDataset, registry
    from mlsec_scan.core.adapters import PatchCoreAdapter

    console.print("[bold cyan]mlsec-scan[/bold cyan] — запуск сканирования\n")

    module_names = [m.strip() for m in modules.split(",") if m.strip()]

    config = ScanConfig(
        model_path=model_path,
        model_type=model_type,
        data_path=data_path,
        train_data_path=train_data_path,
        enabled_modules=module_names,
        adversarial_eps=eps,
        extraction_n_queries=extraction_queries,
        output_path=output_path,
        output_format=output_format,
        verbose=verbose,
    )
    config.validate()

    # Автоопределение типа модели
    if config.model_type == "auto":
        if str(config.model_path).endswith(".ckpt"):
            config.model_type = "patchcore"
        elif str(config.model_path).endswith(".onnx"):
            config.model_type = "onnx"
        else:
            config.model_type = "resnet"

    console.print(f"[bold]Модель:[/bold] {config.model_path}")
    console.print(f"[bold]Тип:[/bold] {config.model_type}")

    if config.model_type == "patchcore":
        if detector_path is None:
            console.print("[red]Ошибка: для PatchCore нужен --detector-path[/red]")
            raise SystemExit(1)
        adapter = PatchCoreAdapter(
            model_path=str(config.model_path),
            detector_path=str(detector_path),
        )
    else:
        console.print(
            f"[red]Тип модели '{config.model_type}' пока не поддерживается.[/red]"
        )
        raise SystemExit(1)

    console.print(f"[bold]Данные:[/bold] {config.data_path}")
    dataset = TestDataset(config.data_path)
    summary = dataset.summary()
    console.print(
        f"  → {summary['total']} картинок "
        f"({summary['normal']} норм, {summary['defect']} дефектов)\n"
    )

    modules_to_run = []
    for name in config.enabled_modules:
        try:
            modules_to_run.append(registry.get_module(name))
        except ValueError as e:
            console.print(f"[red]Ошибка: {e}[/red]")
            raise SystemExit(1)

    scanner = Scanner(modules=modules_to_run, config=config)
    report = scanner.scan(model=adapter, dataset=dataset)

    _print_report(report)
    _save_report_if_needed(report, config)


def _print_report(report):
    """Печатает финальный отчёт в консоль."""
    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]MLSEC-SCAN REPORT[/bold cyan]\n"
            f"Модель:       {report.model_name}\n"
            f"Время:        {report.timestamp}\n"
            f"Длительность: {report.total_duration_sec}s\n"
            f"Критичных:    {report.critical_count}\n"
            f"High:         {report.high_count}",
            border_style="cyan",
        )
    )

    for result in report.results:
        console.print()
        status_color = {
            "vulnerable": "red",
            "resistant": "green",
            "unknown": "yellow",
            "error": "magenta",
        }.get(result.status, "white")

        console.print(
            f"[bold]{result.module_name.upper()}[/bold]  "
            f"[{status_color}]{result.status}[/{status_color}]  "
            f"[dim]({result.duration_sec}s)[/dim]"
        )

        for finding in result.findings:
            sev_color = {
                "critical": "red",
                "high": "red",
                "medium": "yellow",
                "low": "cyan",
                "info": "blue",
            }.get(finding.severity, "white")

            console.print(f"  [{sev_color}]●[/{sev_color}] {finding.title}")
            console.print(f"    [dim]{finding.description}[/dim]")

        if result.recommendations:
            console.print("  [bold]Рекомендации:[/bold]")
            for rec in result.recommendations:
                console.print(f"    → {rec}")


def _save_report_if_needed(report, config):
    """Сохраняет отчёт в файл, если задан --output и --format."""
    if config.output_path is None:
        return

    if config.output_format == "json":
        from mlsec_scan.report.json import write_json_report

        write_json_report(report, config.output_path)
    elif config.output_format == "html":
        console.print(
            "[yellow]HTML-формат пока не реализован. "
            "Используйте --format json или console.[/yellow]"
        )
    # console — печатается всегда выше, файл не нужен


if __name__ == "__main__":
    cli()
