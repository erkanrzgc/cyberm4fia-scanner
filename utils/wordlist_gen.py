"""
cyberm4fia-scanner - CeWL-Style Wordlist Generator
Generates site-specific wordlists by crawling and extracting words
"""

import os
import re
from collections import Counter
from urllib.parse import urlparse, urljoin

from utils.colors import log_info, log_success
from utils.request import smart_request
from utils.request import ScanExceptions

def extract_words(html, min_length=4, max_length=30):
    """Extract meaningful words from HTML content."""
    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", html)
    # Remove script/style content
    text = re.sub(
        r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE
    )
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
    # Remove special characters but keep hyphens and underscores
    text = re.sub(r"[^a-zA-Z0-9\-_\s]", " ", text)
    # Split into words
    words = text.split()
    # Filter by length
    return [w.lower() for w in words if min_length <= len(w) <= max_length]

def extract_emails(html):
    """Extract email addresses from page."""
    return re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html)

def extract_paths(html, base_url):
    """Extract URL paths for directory names."""
    paths = set()
    # Find href and src attributes
    for match in re.findall(
        r'(?:href|src|action)=["\']([^"\']+)["\']', html, re.IGNORECASE
    ):
        try:
            parsed = urlparse(urljoin(base_url, match))
            path_parts = parsed.path.strip("/").split("/")
            for part in path_parts:
                part = part.strip()
                if (
                    part
                    and 3 <= len(part) <= 30
                    and not part.endswith((".js", ".css", ".png", ".jpg", ".gif"))
                ):
                    paths.add(part.lower())
        except ScanExceptions:
            pass
    return paths

def extract_meta_keywords(html):
    """Extract meta keywords and description words."""
    words = []
    # Meta keywords
    match = re.search(
        r'<meta[^>]+name=["\']keywords["\'][^>]+content=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    if match:
        words.extend(match.group(1).replace(",", " ").split())

    # Meta description
    match = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    if match:
        words.extend(match.group(1).split())

    # Title
    match = re.search(r"<title>([^<]+)</title>", html, re.IGNORECASE)
    if match:
        words.extend(match.group(1).split())

    return [w.lower().strip() for w in words if len(w) >= 3]

def generate_mutations(words):
    """Generate common password mutations from words."""
    mutations = set()
    for word in words:
        mutations.add(word)
        mutations.add(word.capitalize())
        mutations.add(word.upper())
        # Common suffixes
        for suffix in ["1", "12", "123", "1234", "!", "@", "#", "2024", "2025", "2026"]:
            mutations.add(word + suffix)
            mutations.add(word.capitalize() + suffix)
        # Common prefixes
        for prefix in ["the", "my", "admin"]:
            mutations.add(prefix + word)
            mutations.add(prefix + word.capitalize())
    return mutations

def generate_wordlist(
    url,
    depth=2,
    min_word_length=4,
    include_mutations=True,
    output_file=None,
    delay=0,
    max_pages=50,
):
    """
    Generate a wordlist from target website content.
    Crawls pages and extracts words, paths, emails, and meta content.
    """
    log_info(f"Generating wordlist from {url} (depth: {depth})...")

    parsed = urlparse(url)
    base_domain = parsed.netloc

    visited = set()
    to_visit = [(url, 0)]
    all_words = Counter()
    all_paths = set()
    all_emails = set()

    while to_visit and len(visited) < max_pages:
        current_url, current_depth = to_visit.pop(0)
        if current_url in visited or current_depth > depth:
            continue
        visited.add(current_url)

        try:
            resp = smart_request("get", current_url, delay=delay, timeout=8)
            html = resp.text

            # Extract words
            words = extract_words(html, min_length=min_word_length)
            all_words.update(words)

            # Extract paths
            paths = extract_paths(html, current_url)
            all_paths.update(paths)

            # Extract emails
            emails = extract_emails(html)
            all_emails.update(emails)

            # Extract meta keywords
            meta_words = extract_meta_keywords(html)
            all_words.update(meta_words)

            # Find links for crawling
            if current_depth < depth:
                for match in re.findall(
                    r'href=["\']([^"\']+)["\']', html, re.IGNORECASE
                ):
                    try:
                        link = urljoin(current_url, match)
                        link_parsed = urlparse(link)
                        if link_parsed.netloc == base_domain and link not in visited:
                            to_visit.append((link, current_depth + 1))
                    except ScanExceptions:
                        pass

            log_info(f"Processed: {current_url} ({len(words)} words)")

        except ScanExceptions:
            pass

    # Build final wordlist
    final_words = set()

    # Add top words (by frequency)
    for word, count in all_words.most_common(500):
        final_words.add(word)

    # Add path components
    final_words.update(all_paths)

    # Add domain-specific words
    domain_parts = (
        base_domain.replace(".", " ").replace("-", " ").replace("_", " ").split()
    )
    for part in domain_parts:
        if len(part) >= 3:
            final_words.add(part.lower())

    # Generate mutations if requested
    if include_mutations:
        base_words = list(final_words)[:100]  # Mutate top 100 words
        mutations = generate_mutations(base_words)
        final_words.update(mutations)

    # Sort
    sorted_words = sorted(final_words)

    # Save to file
    if output_file:
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            for word in sorted_words:
                f.write(word + "\n")
        log_success(f"Wordlist saved: {output_file} ({len(sorted_words)} words)")

    log_success(
        f"Wordlist generated: {len(sorted_words)} words, "
        f"{len(all_paths)} paths, {len(all_emails)} emails "
        f"from {len(visited)} pages"
    )

    return {
        "words": sorted_words,
        "paths": list(all_paths),
        "emails": list(all_emails),
        "total": len(sorted_words),
    }
