"""
cyberm4fia-scanner - Cloud Storage Enumeration Module
Discovers exposed AWS S3, Azure Blob, and GCP Buckets
"""

import sys
import os
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_success, log_warning, log_error
from utils.request import smart_request


# ─────────────────────────────────────────────────────
# Permutation Engine
# ─────────────────────────────────────────────────────
PERMUTATIONS = [
    "{base}",
    "{base}-dev",
    "{base}-staging",
    "{base}-prod",
    "{base}-backup",
    "{base}-assets",
    "{base}-uploads",
    "{base}-media",
    "{base}-static",
    "{base}-data",
    "{base}-logs",
    "{base}-private",
    "{base}-public",
    "{base}-test",
    "{base}-internal",
    "{base}-cdn",
    "{base}-api",
    "{base}-app",
    "{base}-web",
    "{base}-files",
    "{base}-db",
    "{base}-config",
    "{base}-archive",
    "dev-{base}",
    "staging-{base}",
    "prod-{base}",
    "backup-{base}",
    "test-{base}",
]

# ─────────────────────────────────────────────────────
# Cloud providers
# ─────────────────────────────────────────────────────
PROVIDERS = {
    "aws_s3": {
        "name": "AWS S3",
        "url_template": "https://{bucket}.s3.amazonaws.com",
        "region_urls": ["https://{bucket}.s3.{region}.amazonaws.com"],
        "regions": [
            "us-east-1",
            "us-west-2",
            "eu-west-1",
            "eu-central-1",
            "ap-southeast-1",
            "ap-northeast-1",
        ],
    },
    "azure_blob": {
        "name": "Azure Blob",
        "url_template": "https://{bucket}.blob.core.windows.net",
    },
    "gcp": {
        "name": "Google Cloud Storage",
        "url_template": "https://storage.googleapis.com/{bucket}",
    },
    "digitalocean": {
        "name": "DigitalOcean Spaces",
        "url_template": "https://{bucket}.nyc3.digitaloceanspaces.com",
    },
}


def generate_bucket_names(domain):
    """Generate permutations of bucket names from target domain."""
    parsed = urlparse(domain)
    hostname = parsed.hostname or domain
    # Extract base name: 'app.example.com' → ['app', 'example', 'app-example', 'app.example']
    parts = hostname.replace("www.", "").split(".")
    bases = set()
    bases.add(parts[0])  # subdomain or main
    if len(parts) >= 2:
        bases.add(parts[-2])  # domain name
        bases.add(f"{parts[0]}-{parts[-2]}")
        bases.add(f"{parts[-2]}-{parts[0]}")
    # Also full domain without TLD
    bases.add(".".join(parts[:-1]) if len(parts) > 1 else parts[0])

    bucket_names = set()
    for base in bases:
        for perm in PERMUTATIONS:
            bucket_names.add(perm.format(base=base))

    return list(bucket_names)


def check_bucket(bucket_name, provider_key, provider_info, delay):
    """Check if a cloud storage bucket exists and is accessible."""
    results = []
    urls_to_check = []

    main_url = provider_info["url_template"].format(bucket=bucket_name)
    urls_to_check.append(main_url)

    # For AWS, also try regional URLs
    if "region_urls" in provider_info:
        for region_tpl in provider_info["region_urls"]:
            for region in provider_info.get("regions", []):
                urls_to_check.append(
                    region_tpl.format(bucket=bucket_name, region=region)
                )

    for url in urls_to_check:
        try:
            resp = smart_request("get", url, delay=delay, timeout=5)
            code = resp.status_code
            body = resp.text[:500].lower()

            if code == 200:
                # Check for directory listing (ListBucket)
                if "<listbucketresult" in body or "<contents>" in body:
                    results.append(
                        {
                            "type": "cloud_bucket",
                            "provider": provider_info["name"],
                            "bucket": bucket_name,
                            "url": url,
                            "access": "PUBLIC_LIST",
                            "severity": "CRITICAL",
                            "description": f"Open {provider_info['name']} bucket with directory listing enabled",
                        }
                    )
                elif "<error>" not in body and "accessdenied" not in body:
                    results.append(
                        {
                            "type": "cloud_bucket",
                            "provider": provider_info["name"],
                            "bucket": bucket_name,
                            "url": url,
                            "access": "PUBLIC_READ",
                            "severity": "HIGH",
                            "description": f"{provider_info['name']} bucket is publicly readable",
                        }
                    )
            elif code == 403:
                # Bucket exists but is private — still worth knowing
                results.append(
                    {
                        "type": "cloud_bucket",
                        "provider": provider_info["name"],
                        "bucket": bucket_name,
                        "url": url,
                        "access": "EXISTS_PRIVATE",
                        "severity": "INFO",
                        "description": f"{provider_info['name']} bucket exists (private)",
                    }
                )
                break  # No need to try other regions

            # If 404 / NoSuchBucket → skip
        except Exception:
            pass

    return results


def try_upload(url, delay):
    """Attempt a PUT upload to check write permissions."""
    try:
        test_content = "cyberm4fia-scanner-WRITE-TEST"
        test_url = f"{url}/cyberm4fia-write-test.txt"
        resp = smart_request("put", test_url, data=test_content, delay=delay, timeout=5)
        if resp.status_code in (200, 201):
            return True
    except Exception:
        pass
    return False


def scan_cloud_storage(url, delay=0, threads=15):
    """Main entry point for cloud storage enumeration."""
    log_info("Starting Cloud Storage Enumeration...")

    bucket_names = generate_bucket_names(url)
    log_info(f"Generated {len(bucket_names)} bucket permutations")

    all_findings = []

    for provider_key, provider_info in PROVIDERS.items():
        log_info(f"Scanning {provider_info['name']}...")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(
                    check_bucket, name, provider_key, provider_info, delay
                ): name
                for name in bucket_names
            }

            for future in as_completed(futures):
                try:
                    results = future.result()
                    for finding in results:
                        all_findings.append(finding)
                        severity = finding["severity"]
                        if severity == "CRITICAL":
                            log_success(
                                f"[CRITICAL] {finding['provider']}: "
                                f"{finding['bucket']} → {finding['access']} "
                                f"({finding['url']})"
                            )
                        elif severity == "HIGH":
                            log_warning(
                                f"[HIGH] {finding['provider']}: "
                                f"{finding['bucket']} → {finding['access']} "
                                f"({finding['url']})"
                            )
                        else:
                            log_info(
                                f"{finding['provider']}: "
                                f"{finding['bucket']} → {finding['access']}"
                            )
                except Exception:
                    pass

    # Try write test on open buckets
    for finding in all_findings:
        if finding["access"] in ("PUBLIC_LIST", "PUBLIC_READ"):
            if try_upload(finding["url"], delay):
                finding["access"] = "PUBLIC_WRITE"
                finding["severity"] = "CRITICAL"
                finding["description"] += " — WRITE ACCESS CONFIRMED!"
                log_success(
                    f"[CRITICAL] WRITE ACCESS on {finding['provider']}: "
                    f"{finding['bucket']}"
                )

    log_success(f"Cloud Enum completed. Found {len(all_findings)} bucket(s).")
    return all_findings
