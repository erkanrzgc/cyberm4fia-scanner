"""
cyberm4fia-scanner - Concurrency Utilities
Provides multi-threading wrappers for payload execution to drastically speed up scans.
"""
import concurrent.futures
import threading

from utils.request import get_thread_count, ScanCancelled
from utils.colors import log_info


def run_concurrent_tasks(tasks, max_workers=None):
    """
    Executes a list of zero-argument callables concurrently.
    
    Args:
        tasks (list): List of zero-argument functions (e.g. lambdas or partials).
        max_workers (int, optional): Max threads to use. Defaults to Config.THREADS.
        
    Returns:
        list: Flattened list of all findings.
    """
    if not tasks:
        return []

    workers = max_workers or get_thread_count()
    findings = []
    findings_lock = threading.Lock()

    def _worker(task):
        try:
            result = task()
            if result:
                with findings_lock:
                    if isinstance(result, list):
                        findings.extend(result)
                    else:
                        findings.append(result)
        except ScanCancelled:
            raise
        except Exception:
            pass

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            list(executor.map(_worker, tasks))
    except ScanCancelled:
        log_info("[-] Scan cancelled during concurrent execution. Stopping threads...")
    
    return findings
