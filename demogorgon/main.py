"""Demogorgon — Entry point.

Usage:
    python -m demogorgon <target_url> [options]

Options:
    --headless          Run browser in headless mode (default: True)
    --proxy URL         Route traffic through a proxy (e.g., Burp Suite)
    --rate-limit SECS  Delay between requests (default: 1.0)
    --max-iterations N  Max reasoning iterations (default: 50)
    --output DIR        Output directory (default: hunt_output)
    --v3                Use V3 autonomous researcher (executive controller)
    --benchmark         Run benchmark mode against target
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from rich.console import Console

console = Console()


async def main():
    parser = argparse.ArgumentParser(description="Demogorgon — Autonomous Bug Bounty Hunter")
    parser.add_argument("target", help="Target URL to hunt")
    parser.add_argument("--headless", action="store_true", default=True,
                        help="Run browser in headless mode")
    parser.add_argument("--no-headless", dest="headless", action="store_false",
                        help="Run browser with GUI")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--rate-limit", type=float, default=1.0,
                        help="Seconds between requests")
    parser.add_argument("--max-iterations", type=int, default=50,
                        help="Maximum reasoning iterations")
    parser.add_argument("--output", default="hunt_output",
                        help="Output directory")
    parser.add_argument("--v3", action="store_true", default=False,
                        help="Use V3 autonomous researcher (executive controller)")
    parser.add_argument("--benchmark", action="store_true", default=False,
                        help="Run benchmark mode against target")

    args = parser.parse_args()

    if args.v3:
        from demogorgon.researcher_v3 import ResearcherV3

        researcher = ResearcherV3(
            target_url=args.target,
            headless=args.headless,
            proxy=args.proxy,
            rate_limit=args.rate_limit,
            max_experiments=args.max_iterations,
            output_dir=args.output,
        )

        try:
            result = await researcher.start()

            console.print("\n[bold green]=== HUNT SUMMARY (V3) ===[/bold green]")
            console.print(f"  Target: {result['target']}")
            console.print(f"  Experiments: {result['iterations']}")
            console.print(f"  Findings: {result['findings']}")

            if result["finding_details"]:
                console.print("\n[bold red]=== FINDINGS ===[/bold red]")
                for f in result["finding_details"]:
                    console.print(f"  [{f['severity'].upper()}] {f['title']}")
                    console.print(f"    Endpoint: {f['endpoint']}")
                    console.print()

            console.print(f"\n{result['coverage']}")
            console.print(f"\n{result['evaluator']}")

        except KeyboardInterrupt:
            console.print("\n[yellow]Hunt interrupted by user[/yellow]")
            await researcher._cleanup()
        except Exception as e:
            console.print(f"\n[red]Hunt failed: {e}[/red]")
            await researcher._cleanup()
            raise

    elif args.benchmark:
        from demogorgon.benchmark.runner import BenchmarkRunner
        from demogorgon.researcher_v3 import ResearcherV3

        async def run_benchmark(target_url):
            r = ResearcherV3(
                target_url=target_url,
                headless=True,
                proxy=args.proxy,
                rate_limit=args.rate_limit,
                max_experiments=args.max_iterations,
                output_dir=f"{args.output}_benchmark",
            )
            result = await r.start()
            return result["finding_details"]

        runner = BenchmarkRunner(output_dir=f"{args.output}_benchmark")
        results = await runner.run_all(run_benchmark)

        for r in results:
            status = "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]"
            console.print(f"\n{r.target}: {status}")
            console.print(f"  Coverage: {r.coverage:.0%}")
            console.print(f"  TP: {r.true_positives} FP: {r.false_positives} FN: {r.false_negatives}")
            console.print(f"  Runtime: {r.runtime:.1f}s")

        report = runner.get_regression_report()
        console.print(f"\n[bold]Regression Report:[/bold]")
        console.print(f"  Regressions: {len(report.get('regressions', []))}")
        console.print(f"  Improvements: {len(report.get('improvements', []))}")

    else:
        from demogorgon.researcher import Researcher
        from demogorgon.llm_client import LLMClient

        try:
            llm = LLMClient()
        except Exception as e:
            console.print(f"[red]Failed to initialize LLM client: {e}[/red]")
            console.print("[yellow]Make sure OPENROUTER_API_KEY is set in .env[/yellow]")
            sys.exit(1)

        console.print("[cyan]Testing LLM connection...[/cyan]")
        try:
            result = await llm.complete([
                {"role": "system", "content": "Reply with one word: CONNECTED"},
                {"role": "user", "content": "ping"},
            ])
            if "CONNECTED" in result.upper():
                console.print("[green]LLM connected successfully[/green]")
            else:
                console.print(f"[yellow]LLM responded: {result[:50]}[/yellow]")
        except Exception as e:
            console.print(f"[red]LLM connection failed: {e}[/red]")
            sys.exit(1)

        researcher = Researcher(
            target_url=args.target,
            llm_client=llm,
            headless=args.headless,
            proxy=args.proxy,
            rate_limit=args.rate_limit,
            max_iterations=args.max_iterations,
            output_dir=args.output,
        )

        try:
            memory = await researcher.start()

            console.print("\n[bold green]=== HUNT SUMMARY ===[/bold green]")
            summary = memory.get_summary()
            console.print(f"  Target: {summary['target']}")
            console.print(f"  Runtime: {summary['runtime_seconds']:.0f}s")
            console.print(f"  Endpoints discovered: {summary['endpoints_discovered']}")
            console.print(f"  Endpoints tested: {summary['endpoints_tested']}")
            console.print(f"  Hypotheses: {summary['hypotheses']}")
            console.print(f"  Findings: {summary['findings']}")
            console.print(f"  Evidence items: {summary['evidence_items']}")

            if memory.findings:
                console.print("\n[bold red]=== FINDINGS ===[/bold red]")
                for f in memory.findings:
                    console.print(f"  [{f.severity.value.upper()}] {f.title}")
                    console.print(f"    Endpoint: {f.method} {f.endpoint}")
                    console.print(f"    Impact: {f.impact}")
                    console.print()

                from pathlib import Path
                report_path = Path(args.output) / "REPORT.md"
                report_lines = [f"# Demogorgon Hunt Report\n"]
                report_lines.append(f"**Target:** {summary['target']}\n")
                report_lines.append(f"**Runtime:** {summary['runtime_seconds']:.0f}s\n")
                report_lines.append(f"**Endpoints:** {summary['endpoints_discovered']} discovered, {summary['endpoints_tested']} tested\n")
                report_lines.append(f"**Findings:** {summary['findings']}\n\n")
                for i, f in enumerate(memory.findings, 1):
                    report_lines.append(f"## {i}. [{f.severity.value.upper()}] {f.title}\n")
                    report_lines.append(f"- **Endpoint:** `{f.method} {f.endpoint}`")
                    report_lines.append(f"- **Vuln Class:** {f.vuln_class}")
                    report_lines.append(f"- **Evidence:** {f.evidence}")
                    report_lines.append(f"- **Impact:** {f.impact}")
                    if f.reproduction:
                        report_lines.append(f"- **Reproduction:**")
                        for step in f.reproduction:
                            report_lines.append(f"  1. {step}")
                    report_lines.append("")
                report_path.write_text("\n".join(report_lines))
                console.print(f"\n[cyan]Report saved to {report_path}[/cyan]")

        except KeyboardInterrupt:
            console.print("\n[yellow]Hunt interrupted by user[/yellow]")
            await researcher._cleanup()
        except Exception as e:
            console.print(f"\n[red]Hunt failed: {e}[/red]")
            await researcher._cleanup()
            raise


if __name__ == "__main__":
    asyncio.run(main())
