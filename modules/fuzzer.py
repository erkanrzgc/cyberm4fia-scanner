"""
cyberm4fia-scanner - Advanced Fuzzer Module
Recursive Directory & File Fuzzing with Auto-Calibration
"""

import sys
import os
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_success, log_warning, log_error
from utils.request import smart_request, lock


class FuzzerState:
    def __init__(self):
        self.found_paths = set()
        self.directories_to_scan = []
        self.scanned_directories = set()
        self.soft_404_signatures = []
        self.redirect_count = 0
        self.total_checked = 0
        self.blanket_redirect = False  # True if target redirects everything
        self.blanket_403 = False  # True if WAF blocks everything (Cloudflare)


def auto_calibrate(url, delay):
    """Detect custom 'Soft 404' pages, blanket-redirect, AND WAF blanket-403."""
    log_info(f"Auto-calibrating fuzzer for {url} ...")
    soft_404_lens = []
    redirect_hits = 0
    forbidden_hits = 0
    probe_count = 5

    for _ in range(probe_count):
        random_str = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=12)
        )
        fake_url = urljoin(url, f"/{random_str}")
        try:
            resp = smart_request("get", fake_url, delay=delay, allow_redirects=False)
            if resp.status_code == 200:
                soft_404_lens.append(len(resp.content))
            elif resp.status_code in (301, 302, 307, 308):
                redirect_hits += 1
            elif resp.status_code == 403:
                forbidden_hits += 1
        except Exception:
            pass

    blanket_redirect = redirect_hits >= (probe_count * 0.6)
    blanket_403 = forbidden_hits >= (probe_count * 0.6)

    if soft_404_lens:
        avg = sum(soft_404_lens) // len(soft_404_lens)
        log_warning(
            "Target returns 200 OK for non-existent pages (Soft 404). "
            f"Calibrating filter by length ~{avg}."
        )
        soft_404_lens = list(range(avg - 50, avg + 51))

    if blanket_redirect:
        log_warning(
            "Target blanket-redirects all unknown paths (e.g. SPA/Vercel). "
            "Redirect results will be suppressed."
        )

    if blanket_403:
        log_warning(
            "WAF/Cloudflare detected: blanket 403 for all paths. "
            "Extension fuzzing disabled, recursion limited."
        )

    return soft_404_lens, blanket_redirect, blanket_403


def check_url(
    base_url,
    word,
    delay,
    extensions,
    soft_404_lens,
    blanket_redirect,
    blanket_403=False,
):
    """Check a base path and its extensions."""
    results = []

    # If WAF blocks everything, only test base path (skip extensions)
    paths_to_test = [word]
    if not blanket_403 and not word.endswith("/"):
        for ext in extensions:
            paths_to_test.append(f"{word}.{ext}")

    for p in paths_to_test:
        full_url = urljoin(base_url, p)
        try:
            resp = smart_request("get", full_url, delay=delay, allow_redirects=False)
            code = resp.status_code
            size = len(resp.content)

            # Filter standard 404/400
            if code in (404, 400):
                continue

            # Filter soft 404s (within tolerance)
            if code == 200 and size in soft_404_lens:
                continue

            # Filter blanket redirects (SPA / Vercel / Next.js)
            if blanket_redirect and code in (301, 302, 307, 308):
                continue

            # Filter blanket 403s (WAF/Cloudflare)
            if blanket_403 and code == 403:
                continue

            results.append((full_url, code, size))

        except Exception:
            pass

    return results


def scan_fuzzer(
    url,
    wordlist_path,
    threads=10,
    delay=0,
    recursive=True,
    extensions=None,
    max_depth=3,
):
    """Main Recursive Fuzzer function"""
    if extensions is None:
        extensions = [
            "php",
            "txt",
            "bak",
            "html",
            "htm",
            "asp",
            "aspx",
            "jsp",
            "json",
            "xml",
            "yml",
            "yaml",
            "env",
            "config",
            "conf",
            "log",
            "sql",
            "old",
            "orig",
            "swp",
            "zip",
            "tar.gz",
            "gz",
        ]

    if not os.path.exists(wordlist_path):
        log_error(f"Wordlist not found: {wordlist_path}")
        return []

    log_info(f"Starting Fuzzing on {url}")

    # Calibration
    soft_404_lens, blanket_redirect, blanket_403 = auto_calibrate(url, delay)

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [
            line.strip() for line in f if line.strip() and not line.startswith("#")
        ]

    state = FuzzerState()
    state.blanket_redirect = blanket_redirect
    state.blanket_403 = blanket_403
    if not url.endswith("/"):
        url += "/"
    state.directories_to_scan.append((url, 0))  # (dir_url, depth)

    all_found_results = []

    while state.directories_to_scan:
        current_dir, depth = state.directories_to_scan.pop(0)
        if current_dir in state.scanned_directories:
            continue
        if depth > max_depth:
            continue

        state.scanned_directories.add(current_dir)
        log_info(
            f"Fuzzing directory: {current_dir} | Depth: {depth}/{max_depth} | Threads: {threads}"
        )

        dir_found_paths = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [
                executor.submit(
                    check_url,
                    current_dir,
                    w,
                    delay,
                    extensions,
                    soft_404_lens,
                    blanket_redirect,
                    blanket_403,
                )
                for w in words
            ]

            for future in as_completed(futures):
                try:
                    results = future.result()
                    for path, code, size in results:
                        if path in state.found_paths:
                            continue

                        state.found_paths.add(path)
                        dir_found_paths.append(
                            {"path": path, "code": code, "size": size}
                        )

                        with lock:
                            if code == 200:
                                log_success(f"Found: {path} [200] (Size: {size})")
                                # Only recurse into 200 directories (not redirects!)
                                if recursive and path.endswith("/"):
                                    state.directories_to_scan.append((path, depth + 1))
                            elif code in (301, 302, 307, 308):
                                # Never recurse into redirects — they are not real dirs
                                if not blanket_redirect:
                                    log_info(f"Redirect: {path} [{code}]")
                            elif code == 403:
                                log_warning(f"Forbidden: {path} [403]")
                                # Don't recurse into 403 dirs when WAF blocks everything
                                if (
                                    recursive
                                    and not blanket_403
                                    and not path.endswith(".php")
                                    and not path.endswith(".html")
                                    and depth < max_depth - 1
                                ):
                                    state.directories_to_scan.append(
                                        (
                                            path + "/"
                                            if not path.endswith("/")
                                            else path,
                                            depth + 1,
                                        )
                                    )
                            else:
                                log_info(f"Found: {path} [{code}] (Size: {size})")
                except Exception:
                    pass

        all_found_results.extend(dir_found_paths)

    log_success(f"Fuzzing completed. Total paths found: {len(all_found_results)}")
    return all_found_results
