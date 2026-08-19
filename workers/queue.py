"""
Controlled Concurrency & Background Worker Queue
------------------------------------------------
Manages concurrent async URL analysis, threat intelligence enrichments,
and rate-limited background task execution using thread pools.
"""

import concurrent.futures
from typing import Callable, Any, List, Dict, Optional
from config import MAX_CONCURRENT_ENRICHMENTS


class WorkerPool:
    """ThreadPoolExecutor wrapper for background tasks and concurrent forensic enrichments."""

    def __init__(self, max_workers: int = MAX_CONCURRENT_ENRICHMENTS):
        self.max_workers = max_workers
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="PhishGuardWorker")

    def submit_task(self, fn: Callable[..., Any], *args, **kwargs) -> concurrent.futures.Future:
        """Submit a one-off background task."""
        return self._executor.submit(fn, *args, **kwargs)

    def map_concurrent(self, fn: Callable[[Any], Any], items: List[Any], timeout: Optional[float] = None) -> List[Any]:
        """Execute a function concurrently over a list of items with optional timeout."""
        if not items:
            return []
        futures = [self._executor.submit(fn, item) for item in items]
        results = []
        for future in concurrent.futures.as_completed(futures, timeout=timeout):
            try:
                results.append(future.result())
            except Exception as e:
                results.append({"error": str(e), "success": False})
        return results

    def shutdown(self, wait: bool = False):
        self._executor.shutdown(wait=wait)


# Global worker pool singleton
GLOBAL_WORKER_POOL = WorkerPool()
