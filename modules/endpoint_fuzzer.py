"""
cyberm4fia-scanner - API Fuzzer & Endpoint Hunter
High-speed asynchronous directory and API endpoint discovery tool.
"""

import sys
import asyncio
import httpx
import string
import random

from utils.colors import log_info, log_success, log_warning, log_error
from utils.request import get_global_headers, get_proxy, is_ssl_verification_enabled
from utils.request import ScanExceptions
from utils.response_fingerprint import (
    BaselineSet,
    compute_fingerprint,
    compute_baseline_set,
)

# Calibration probes — three random, two deeply nested, two unusual
# extensions, and one with a query string. Tuned to surface SPA/catch-all
# fallbacks that vary the URL inside ``<base href>`` or ``canonical``.
_CALIBRATION_TEMPLATES = (
    ("random_a", "{rand}"),
    ("random_b", "{rand}{rand}"),
    ("random_c", "{rand}-test-{rand}"),
    ("nested_a", "{rand}/{rand}/{rand}"),
    ("nested_b", "api/v9/{rand}/details"),
    ("ext_json", "{rand}.json"),
    ("ext_map", "{rand}.js.map"),
    ("queryed", "{rand}?q={rand}&id=999999"),
)


class EndpointFuzzer:
    def __init__(self, target_url, wordlist_path, delay=0, threads=50):
        self.target_url = target_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.delay = delay
        self.threads = threads
        self.found_endpoints = []
        self.soft_404_baseline: BaselineSet = BaselineSet(fingerprints=())
        self.soft_403_baseline: BaselineSet = BaselineSet(fingerprints=())
        self.soft_redirect_baseline: BaselineSet = BaselineSet(fingerprints=())
        # Legacy length-only signatures kept for backwards compatibility with
        # external callers that may inspect these attributes.
        self.soft_404_signatures = []
        self.soft_403_signatures = []
        self.soft_redirect_signatures = []

        # Load wordlist
        self.words = []
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                self.words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            log_info(f"Loaded {len(self.words)} paths from {wordlist_path}")
        except FileNotFoundError:
            log_error(f"Wordlist not found: {wordlist_path}")
            
    def _generate_random_string(self, length=12):
        """Generate a random string for 404 calibration"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
        
    async def _calibrate(self, client):
        """Probe for soft-404 / SPA fallback / catch-all behaviour.

        Fires 8 calibration probes (random, nested, alt-extension, query) and
        builds a fingerprint baseline per status family. Matching uses content
        fingerprinting (title + DOM skeleton + simhash) rather than raw length,
        so SPA templates that embed the request URL in ``<base href>`` are
        still recognised as catch-all hits.
        """
        log_info("Calibrating Fuzzer for Soft-404 / SPA fallback detection...")

        buckets_200: list[tuple[str, dict]] = []
        buckets_403: list[tuple[str, dict]] = []
        buckets_3xx: list[tuple[str, dict]] = []

        # Pull the homepage once — if it shares the same template as the fake
        # probes, we want it folded into the baseline so other modules can
        # detect "this finding's response is the homepage" later.
        try:
            home_resp = await client.get(self.target_url + "/")
            if home_resp.status_code == 200:
                buckets_200.append((home_resp.text, dict(home_resp.headers)))
        except ScanExceptions:
            pass
        except Exception:
            pass

        for _, tmpl in _CALIBRATION_TEMPLATES:
            probe = tmpl.format(rand=self._generate_random_string())
            test_url = f"{self.target_url}/{probe}"
            try:
                resp = await client.get(test_url)
            except ScanExceptions:
                continue
            try:
                body = resp.text
                headers = dict(resp.headers)
            except Exception:
                continue
            length = len(body)
            if resp.status_code == 200:
                buckets_200.append((body, headers))
                self.soft_404_signatures.append(length)
            elif resp.status_code == 403:
                buckets_403.append((body, headers))
                self.soft_403_signatures.append(length)
            elif resp.status_code in (301, 302, 307, 308):
                buckets_3xx.append((body, headers))
                self.soft_redirect_signatures.append(length)

        self.soft_404_baseline = compute_baseline_set(buckets_200)
        self.soft_403_baseline = compute_baseline_set(buckets_403)
        self.soft_redirect_baseline = compute_baseline_set(buckets_3xx)

        if buckets_200:
            log_warning(
                f"Soft-404 detected ({len(buckets_200)} probes returned 200). "
                "Fingerprint baseline built — catch-all hits will be filtered."
            )
        if buckets_403:
            log_warning(
                f"Soft-403 detected ({len(buckets_403)} probes). Uniform 403s will be filtered."
            )
        if buckets_3xx:
            log_warning(
                f"Soft-redirect detected ({len(buckets_3xx)} probes). Uniform 3xx will be filtered."
            )
        if not (buckets_200 or buckets_403 or buckets_3xx):
            log_info("Target handles 404s correctly — no calibration baseline needed.")

    def _is_soft_404(self, resp):
        """Decide if a response is really a soft 404/403/redirect.

        Compares the response's fingerprint (title + DOM skeleton + simhash)
        against the calibration baseline for the matching status family.
        """
        try:
            body = resp.text
            headers = dict(resp.headers)
        except Exception:
            return False
        fp = compute_fingerprint(body, headers)

        if resp.status_code == 200 and self.soft_404_baseline.fingerprints:
            if self.soft_404_baseline.matches(fp):
                return True

        if resp.status_code == 403 and self.soft_403_baseline.fingerprints:
            if self.soft_403_baseline.matches(fp, length_band=0.10):
                return True

        if resp.status_code in (301, 302, 307, 308) and self.soft_redirect_baseline.fingerprints:
            if self.soft_redirect_baseline.matches(fp):
                return True

        return False

    async def _fuzz_worker(self, client, queue):
        """Worker task that consumes the queue and sends requests"""
        while not queue.empty():
            word = await queue.get()
            # Clean up word
            word = word.lstrip('/')
            test_url = f"{self.target_url}/{word}"
            
            try:
                # Obey delay
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                    
                resp = await client.get(test_url)
                
                # Check for successful discovery
                if resp.status_code in [200, 204, 301, 302, 307, 308, 401, 403]:
                    # Skip trailing-slash redirects (Next.js/Vercel normalization)
                    if resp.status_code in (301, 307, 308):
                        location = resp.headers.get("location", "")
                        # Normalize: if redirect only adds or removes trailing slash, skip
                        if location.rstrip("/") == test_url.rstrip("/") or \
                           location == test_url + "/" or \
                           location == test_url.rstrip("/"):
                            continue

                    # Filter out soft 404s
                    if not self._is_soft_404(resp):
                        log_success(f"[HTTP {resp.status_code}] Found: /{word} (Size: {len(resp.content)} bytes)")
                        self.found_endpoints.append({
                            "url": test_url,
                            "path": f"/{word}",
                            "status": resp.status_code,
                            "size": len(resp.content)
                        })
                        
            except ScanExceptions:
                pass  # Ignore connection errors during fuzzing
                
            finally:
                queue.task_done()

    async def run(self):
        """Main async runner"""
        if not self.words:
            return []
            
        log_info(f"🚀 Starting High-Speed API Fuzzer on {self.target_url}...")
        
        # Configure the HTTP client
        proxy = get_proxy()
        proxy_settings = proxy if proxy else None
        
        headers = get_global_headers()
        if "User-Agent" not in headers:
            headers["User-Agent"] = "cyberm4fia-fuzzer/4.0"
            
        limits = httpx.Limits(max_connections=self.threads, max_keepalive_connections=self.threads)
        
        async with httpx.AsyncClient(verify=is_ssl_verification_enabled(), proxy=proxy_settings, headers=headers, limits=limits, follow_redirects=False, timeout=5.0) as client:
            
            # Step 1: Calibrate context to avoid false positives
            await self._calibrate(client)
            
            # Step 2: Create Queue
            queue = asyncio.Queue()
            for word in self.words:
                queue.put_nowait(word)
                
            # Step 3: Spawn workers
            workers = []
            for _ in range(min(self.threads, len(self.words))):
                worker = asyncio.create_task(self._fuzz_worker(client, queue))
                workers.append(worker)
                
            # Step 4: Wait for completion
            await queue.join()
            
            # Cancel workers
            for worker in workers:
                worker.cancel()
                
        log_info(f"Taramayı bitirdim ustam! Toplamda {len(self.found_endpoints)} geçerli servis/sayfa yakaladım.")
        return self.found_endpoints

def scan_fuzzer_async(url, wordlist_path, delay=0, threads=50, *, return_fuzzer=False):
    """Synchronous wrapper for the async fuzzer.

    Pass ``return_fuzzer=True`` to receive ``(endpoints, fuzzer)`` so callers
    can inspect ``fuzzer.soft_404_baseline`` and reuse it for SPA-fallback
    filtering elsewhere in the pipeline.
    """
    fuzzer = EndpointFuzzer(url, wordlist_path, delay, threads)
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    endpoints = loop.run_until_complete(fuzzer.run())
    if return_fuzzer:
        return endpoints, fuzzer
    return endpoints

if __name__ == "__main__":
    if len(sys.argv) > 2:
        res = scan_fuzzer_async(sys.argv[1], sys.argv[2])
        print(f"\\nTotal Found: {len(res)}")
    else:
        print("Usage: python3 endpoint_fuzzer.py <url> <wordlist_path>")
