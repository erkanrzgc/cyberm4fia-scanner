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

class EndpointFuzzer:
    def __init__(self, target_url, wordlist_path, delay=0, threads=50):
        self.target_url = target_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.delay = delay
        self.threads = threads
        self.found_endpoints = []
        self.soft_404_signatures = []
        self.soft_403_signatures = []  # Detect uniform 403 = generic "not found"
        
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
        """Detect Soft-404 pages (pages that return 200 OK but are actually 'Not Found' errors)"""
        log_info("Calibrating Fuzzer for Soft-404 detection...")
        
        # Test 3 random non-existent paths
        for _ in range(3):
            random_path = self._generate_random_string()
            test_url = f"{self.target_url}/{random_path}"
            try:
                resp = await client.get(test_url)
                # If a random page returns 200 OK, it's a soft 404
                if resp.status_code == 200:
                    # Save the response length or hash as a signature
                    content_length = len(resp.text)
                    self.soft_404_signatures.append(content_length)
                elif resp.status_code == 403:
                    # Uniform 403 for random paths = generic "forbidden" page, not real 403
                    content_length = len(resp.text)
                    self.soft_403_signatures.append(content_length)
            except ScanExceptions:
                pass
                
        if self.soft_404_signatures:
            log_warning(f"Soft-404 detected! Target returns 200 OK for missing pages. Calibration lengths: {self.soft_404_signatures}")
        if self.soft_403_signatures:
            log_warning(f"Soft-403 detected! Target returns uniform 403 for random paths — these will be filtered.")
        if not self.soft_404_signatures and not self.soft_403_signatures:
            log_info("Target handles 404s correctly.")
            
    def _is_soft_404(self, resp):
        """Check if a response is actually a soft 404/403 based on calibration"""
        content_length = len(resp.text)

        # Soft-404: 200 OK but same body as calibration 404 probe
        if resp.status_code == 200:
            for sig in self.soft_404_signatures:
                if abs(content_length - sig) < 50:
                    return True

        # Soft-403: uniform 403 with same body as calibration 403 probe
        if resp.status_code == 403 and self.soft_403_signatures:
            for sig in self.soft_403_signatures:
                if abs(content_length - sig) < 100:
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

def scan_fuzzer_async(url, wordlist_path, delay=0, threads=50):
    """Synchronous wrapper for the async fuzzer"""
    fuzzer = EndpointFuzzer(url, wordlist_path, delay, threads)
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
    return loop.run_until_complete(fuzzer.run())

if __name__ == "__main__":
    if len(sys.argv) > 2:
        res = scan_fuzzer_async(sys.argv[1], sys.argv[2])
        print(f"\\nTotal Found: {len(res)}")
    else:
        print("Usage: python3 endpoint_fuzzer.py <url> <wordlist_path>")
