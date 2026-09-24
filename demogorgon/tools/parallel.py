"""Parallel — concurrent request batches for faster endpoint probing.

10-50x faster than sequential testing. Limits concurrency to avoid
overwhelming targets. Supports race-condition detection via parallel replay.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ParallelResult:
    """Result of a parallel batch execution."""
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    duration: float = 0.0
    results: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def rps(self) -> float:
        return self.total / self.duration if self.duration > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "duration": self.duration,
            "rps": self.rps,
            "errors": self.errors[:10],
        }


class ParallelExecutor:
    """Runs HTTP requests (or arbitrary coroutines) concurrently with a semaphore."""

    def __init__(self, max_concurrency: int = 10, rate_limit_delay: float = 0.0):
        self.max_concurrency = max(1, min(max_concurrency, 50))
        self.rate_limit_delay = rate_limit_delay
        self._sem = asyncio.Semaphore(self.max_concurrency)

    async def _run_one(self, coro, index: int) -> dict[str, Any]:
        async with self._sem:
            if self.rate_limit_delay > 0:
                await asyncio.sleep(self.rate_limit_delay)
            start = time.time()
            try:
                result = await coro
                elapsed = time.time() - start
                if isinstance(result, dict):
                    return {
                        "index": index,
                        "ok": not result.get("error"),
                        "elapsed": elapsed,
                        "data": result,
                    }
                return {"index": index, "ok": True, "elapsed": elapsed, "data": result}
            except Exception as e:
                return {
                    "index": index,
                    "ok": False,
                    "elapsed": time.time() - start,
                    "error": str(e),
                }

    async def gather(
        self,
        tasks: list[Any],
        timeout: float | None = None,
    ) -> ParallelResult:
        """Run a list of coroutines concurrently.

        Args:
            tasks: List of awaitables (e.g. http.request(...) coroutines)
            timeout: Optional overall timeout in seconds
        """
        batch = ParallelResult(total=len(tasks))
        if not tasks:
            return batch

        start = time.time()
        wrapped = [self._run_one(t, i) for i, t in enumerate(tasks)]
        try:
            if timeout:
                raw = await asyncio.wait_for(
                    asyncio.gather(*wrapped, return_exceptions=True),
                    timeout=timeout,
                )
            else:
                raw = await asyncio.gather(*wrapped, return_exceptions=True)
        except asyncio.TimeoutError:
            batch.errors.append(f"Batch timed out after {timeout}s")
            batch.duration = time.time() - start
            return batch

        for item in raw:
            if isinstance(item, Exception):
                batch.failed += 1
                batch.errors.append(str(item))
            elif isinstance(item, dict) and item.get("ok"):
                batch.succeeded += 1
                batch.results.append(item)
            else:
                batch.failed += 1
                if isinstance(item, dict):
                    batch.errors.append(item.get("error", "unknown"))
                else:
                    batch.errors.append(str(item))

        batch.duration = time.time() - start
        return batch

    async def probe_endpoints(
        self,
        http,
        urls: list[str],
        method: str = "GET",
        headers: dict | None = None,
        timeout: float = 60.0,
    ) -> ParallelResult:
        """Probe a batch of URLs concurrently and return structured results."""
        tasks = [
            http.request(method, url, headers=headers)
            for url in urls
        ]
        return await self.gather(tasks, timeout=timeout)

    async def race_replay(
        self,
        http,
        request_factory: Callable[[], Any],
        count: int = 10,
        timeout: float = 15.0,
    ) -> dict[str, Any]:
        """Fire N identical requests in parallel to detect race conditions.

        Returns timing stats and response-code distribution for comparison.
        """
        count = max(2, min(count, 30))
        tasks = [request_factory() for _ in range(count)]
        batch = await self.gather(tasks, timeout=timeout)

        statuses: dict[str, int] = {}
        timings: list[float] = []
        for r in batch.results:
            data = r.get("data") or {}
            code = str(data.get("status_code", "unknown"))
            statuses[code] = statuses.get(code, 0) + 1
            timings.append(r.get("elapsed", 0.0))

        # High timing variance can indicate race windows
        if timings:
            avg = sum(timings) / len(timings)
            variance = sum((t - avg) ** 2 for t in timings) / len(timings)
            stdev = variance ** 0.5
        else:
            avg = stdev = 0.0

        # Divergent status codes under identical requests = suspicious
        suspicious = len(statuses) > 1

        return {
            "race_suspected": suspicious,
            "status_distribution": statuses,
            "avg_latency": avg,
            "latency_stdev": stdev,
            "count": count,
            "errors": batch.errors[:5],
        }


def create_parallel_executor(max_concurrency: int = 10) -> ParallelExecutor:
    return ParallelExecutor(max_concurrency=max_concurrency)
