"""
cyberm4fia-scanner - Cloud Storage Enumeration Module
Discovers exposed AWS S3, Azure Blob, and GCP Buckets,
container registries (Docker Hub, Quay, GHCR, ECR, GCR, ACR),
and CI/CD platform exposures (Jenkins, GitLab, TeamCity, ArgoCD).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from utils.colors import log_info, log_success, log_warning, log_error, Colors
from utils.request import smart_request
from utils.request import ScanExceptions

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
        except ScanExceptions:
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
    except ScanExceptions:
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
                except ScanExceptions:
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


# ─────────────────────────────────────────────────────
# Container Registry Leak Detection
# ─────────────────────────────────────────────────────

CONTAINER_REGISTRIES = {
    "docker_hub": {
        "name": "Docker Hub",
        "search_url": "https://hub.docker.com/v2/search/repositories/?query={keyword}&page_size=25",
        "image_url": "https://hub.docker.com/v2/repositories/{org}/{image}/tags/?page_size=10",
        "org_url": "https://hub.docker.com/v2/repositories/{org}/?page_size=25",
    },
    "quay": {
        "name": "Quay.io (Red Hat)",
        "search_url": "https://quay.io/api/v1/repository?public=true&namespace={keyword}&popularity=true",
        "repo_url": "https://quay.io/api/v1/repository/{org}/{image}",
    },
    "ghcr": {
        "name": "GitHub Container Registry",
        "api_url": "https://api.github.com/orgs/{org}/packages?package_type=container",
    },
    "ecr_public": {
        "name": "Amazon ECR Public",
        "search_url": "https://gallery.ecr.aws/?searchTerm={keyword}",
    },
    "gcr": {
        "name": "Google Container Registry",
        "registry_url": "https://gcr.io/v2/{project}/tags/list",
    },
    "acr": {
        "name": "Azure Container Registry",
        "registry_pattern": "{keyword}.azurecr.io",
    },
}


def _check_container_registry(registry_key, registry_info, keyword, delay):
    findings = []

    if registry_key == "docker_hub":
        try:
            url = registry_info["search_url"].format(keyword=keyword)
            resp = smart_request("get", url, delay=delay, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                for item in results[:10]:
                    findings.append({
                        "type": "container_registry",
                        "registry": "Docker Hub",
                        "name": item.get("repo_name", ""),
                        "description": item.get("short_description", "")[:200],
                        "pull_count": item.get("pull_count", 0),
                        "star_count": item.get("star_count", 0),
                        "confidence": "tentative",
                        "severity": "MEDIUM",
                    })
                if findings:
                    log_success(f"[Docker Hub] Found {len(findings)} image(s) for '{keyword}'")
        except ScanExceptions:
            pass
        except Exception:
            pass

    elif registry_key == "quay":
        try:
            url = registry_info["search_url"].format(keyword=keyword)
            resp = smart_request("get", url, delay=delay, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                repos = data.get("repositories", [])
                for repo in repos[:10]:
                    findings.append({
                        "type": "container_registry",
                        "registry": "Quay.io",
                        "namespace": repo.get("namespace", ""),
                        "name": repo.get("name", ""),
                        "description": repo.get("description", "")[:200],
                        "confidence": "tentative",
                        "severity": "MEDIUM",
                    })
                if findings:
                    log_success(f"[Quay.io] Found {len(findings)} repo(s) for '{keyword}'")
        except ScanExceptions:
            pass
        except Exception:
            pass

    elif registry_key == "acr":
        host = f"{keyword}.azurecr.io"
        try:
            url = f"https://{host}/v2/"
            resp = smart_request("get", url, delay=delay, timeout=8)
            if resp.status_code in (200, 401):
                findings.append({
                    "type": "container_registry",
                    "registry": "Azure Container Registry",
                    "host": host,
                    "status": resp.status_code,
                    "confidence": "firm" if resp.status_code == 401 else "tentative",
                    "severity": "HIGH" if resp.status_code == 200 else "MEDIUM",
                    "description": f"ACR exists at {host} (HTTP {resp.status_code})",
                })
                log_success(f"[ACR] Registry exists: {host} → {resp.status_code}")
        except ScanExceptions:
            pass

    return findings


def scan_container_registries(domain, delay=0, threads=5):
    """
    Check public container registries for target-owned images.
    Searches Docker Hub, Quay.io, ACR for images matching the domain.

    Args:
        domain: Target domain string
        delay: Request delay
        threads: Thread pool workers

    Returns:
        list of findings dicts
    """
    parsed = urlparse(domain)
    hostname = parsed.hostname or domain
    parts = hostname.replace("www.", "").split(".")
    keywords = []
    if len(parts) >= 2:
        keywords.append(parts[-2])
        keywords.append(parts[0])
        keywords.append(parts[-2].lower())
    keywords.append(hostname)

    print(f"\n{Colors.BOLD}{Colors.CYAN}──── CONTAINER REGISTRY LEAK DETECTION ────{Colors.END}")
    log_info(f"Searching container registries for: {', '.join(set(keywords))}")

    all_findings = []
    registries_to_check = ["docker_hub", "quay", "acr"]

    for registry_key in registries_to_check:
        registry_info = CONTAINER_REGISTRIES[registry_key]
        log_info(f"[*] Searching {registry_info['name']}...")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(
                    _check_container_registry, registry_key, registry_info, kw, delay
                ): kw
                for kw in set(keywords)
            }
            for future in as_completed(futures):
                try:
                    results = future.result()
                    all_findings.extend(results)
                except Exception:
                    pass

    log_success(f"Container registry scan complete. {len(all_findings)} image/repo(s) found.")
    print(f"{Colors.BOLD}{Colors.CYAN}──── CONTAINER REGISTRY COMPLETE ────{Colors.END}\n")
    return all_findings


# ─────────────────────────────────────────────────────
# CI/CD Platform Exposure Detection
# ─────────────────────────────────────────────────────

CICD_PLATFORMS = {
    "jenkins": {
        "name": "Jenkins",
        "paths": [
            "/script", "/asynchPeople/", "/computer/",
            "/jnlpJars/jenkins-cli.jar", "/login",
            "/api/json?tree=jobs[name,color,url]",
        ],
        "body_pattern": r"(?:Jenkins|jenkins|Dashboard \[Jenkins\])",
        "severity_if_unauth": "CRITICAL",
        "severity_if_auth": "HIGH",
    },
    "gitlab": {
        "name": "GitLab Self-Hosted",
        "paths": [
            "/users/sign_in", "/api/v4/version",
            "/explore", "/help",
            "/-/snippets/",
        ],
        "body_pattern": r"(?:GitLab|gitlab)",
        "severity_if_unauth": "HIGH",
        "severity_if_auth": "MEDIUM",
    },
    "teamcity": {
        "name": "TeamCity",
        "paths": [
            "/login.html", "/agent.html",
            "/admin/admin.html", "/overview.html",
        ],
        "body_pattern": r"(?:TeamCity|teamcity)",
        "severity_if_unauth": "CRITICAL",
        "severity_if_auth": "HIGH",
    },
    "argocd": {
        "name": "Argo CD",
        "paths": [
            "/api/version", "/applications",
            "/login", "/settings",
        ],
        "body_pattern": r"(?:Argo CD|argocd)",
        "severity_if_unauth": "HIGH",
        "severity_if_auth": "MEDIUM",
    },
    "droneci": {
        "name": "Drone CI",
        "paths": ["/api/info", "/login", "/repos"],
        "body_pattern": r"(?:Drone|drone)",
        "severity_if_unauth": "MEDIUM",
        "severity_if_auth": "LOW",
    },
    "spinnaker": {
        "name": "Spinnaker",
        "paths": ["/gate/info", "/applications", "/pipelines"],
        "body_pattern": r"(?:Spinnaker|spinnaker)",
        "severity_if_unauth": "HIGH",
        "severity_if_auth": "MEDIUM",
    },
    "buildkite": {
        "name": "Buildkite",
        "paths": ["/docs", "/plugins", "/integrations"],
        "body_pattern": r"(?:Buildkite|buildkite)",
        "severity_if_unauth": "LOW",
        "severity_if_auth": "INFO",
    },
}


def _check_cicd_platform(platform_key, platform_info, target_url, delay):
    findings = []
    base = target_url.rstrip("/")

    for path in platform_info["paths"]:
        try:
            check_url = f"{base}{path}"
            resp = smart_request("get", check_url, delay=delay, timeout=8)

            if resp.status_code in (200, 302):
                body_text = resp.text[:5000]

                import re
                matched = re.search(platform_info["body_pattern"], body_text,
                                    re.IGNORECASE) if platform_info.get("body_pattern") else True

                if matched or resp.status_code == 200:
                    findings.append({
                        "type": "cicd_exposure",
                        "platform": platform_info["name"],
                        "url": check_url,
                        "status": resp.status_code,
                        "endpoint": path,
                        "confidence": "firm",
                        "severity": platform_info.get("severity_if_unauth", "MEDIUM"),
                        "description": f"{platform_info['name']} detected at {check_url}",
                    })
                    log_success(
                        f"[{platform_info['name']}] Detected at {check_url} "
                        f"→ HTTP {resp.status_code}"
                    )
                    break  # One confirmed endpoint is enough

            elif resp.status_code == 401:
                findings.append({
                    "type": "cicd_exposure",
                    "platform": platform_info["name"],
                    "url": check_url,
                    "status": resp.status_code,
                    "endpoint": path,
                    "confidence": "firm",
                    "severity": platform_info.get("severity_if_auth", "LOW"),
                    "description": f"{platform_info['name']} exists at {check_url} (auth required)",
                })
                log_info(
                    f"[{platform_info['name']}] Exists: {check_url} "
                    f"→ HTTP {resp.status_code} (auth gated)"
                )
                break

        except ScanExceptions:
            pass
        except Exception:
            pass

    return findings


def scan_cicd_exposure(url, delay=0, threads=5):
    """
    Detect exposed CI/CD platforms (Jenkins, GitLab, TeamCity, Argo CD, etc.).

    Args:
        url: Target URL
        delay: Request delay
        threads: Thread pool workers

    Returns:
        list of findings dicts
    """
    print(f"\n{Colors.BOLD}{Colors.CYAN}──── CI/CD PLATFORM EXPOSURE ────{Colors.END}")
    log_info(f"Probing CI/CD platforms on {url}...")

    all_findings = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(
                _check_cicd_platform, key, info, url, delay
            ): key
            for key, info in CICD_PLATFORMS.items()
        }
        for future in as_completed(futures):
            try:
                results = future.result()
                all_findings.extend(results)
            except Exception:
                pass

    log_success(f"CI/CD scan complete. {len(all_findings)} platform(s) detected.")
    print(f"{Colors.BOLD}{Colors.CYAN}──── CI/CD EXPOSURE COMPLETE ────{Colors.END}\n")
    return all_findings
