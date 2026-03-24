"""
cyberm4fia-scanner - Template Manager
Download, import, list, and manage YAML vulnerability templates.
"""

import os
import subprocess
import yaml

from utils.colors import Colors, log_info, log_success, log_warning, log_error
from utils.request import ScanExceptions
from modules.template_engine import TEMPLATE_DIR, validate_template


class TemplateManager:
    """Manage YAML vulnerability templates."""

    COMMUNITY_REPO = "https://github.com/projectdiscovery/nuclei-templates.git"
    COMMUNITY_DIR = os.path.join(TEMPLATE_DIR, "community")

    def __init__(self):
        if not os.path.exists(TEMPLATE_DIR):
            os.makedirs(TEMPLATE_DIR)

    def list_templates(self, severity_filter=None, tags_filter=None):
        """List available templates with optional filtering."""
        templates = []

        for root, _, files in os.walk(TEMPLATE_DIR):
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r") as f:
                            tpl = yaml.safe_load(f)
                            if not tpl or "id" not in tpl:
                                continue

                            info = tpl.get("info", {})
                            sev = info.get("severity", "info").lower()
                            tags = info.get("tags", [])

                            if severity_filter and sev not in [s.lower() for s in severity_filter]:
                                continue
                            if tags_filter and not any(t in tags for t in tags_filter):
                                continue

                            templates.append({
                                "id": tpl["id"],
                                "name": info.get("name", "Unknown"),
                                "severity": sev,
                                "tags": tags,
                                "author": info.get("author", "unknown"),
                                "path": filepath,
                            })
                    except ScanExceptions:
                        pass

        return templates

    def import_template(self, source_path):
        """
        Validate and import a YAML template file.
        
        Args:
            source_path: Path to the .yaml template file.
            
        Returns:
            (success, message) tuple.
        """
        if not os.path.exists(source_path):
            return False, f"File not found: {source_path}"

        try:
            with open(source_path, "r") as f:
                tpl = yaml.safe_load(f)
        except ScanExceptions as e:
            return False, f"YAML parse error: {e}"

        is_valid, errors = validate_template(tpl)
        if not is_valid:
            return False, f"Validation failed: {', '.join(errors)}"

        # Copy to templates directory
        dest_name = f"{tpl['id']}.yaml"
        dest_path = os.path.join(TEMPLATE_DIR, dest_name)

        with open(dest_path, "w") as f:
            yaml.dump(tpl, f, default_flow_style=False)

        log_success(f"Template imported: {tpl['id']} → {dest_path}")
        return True, f"Imported as {dest_name}"

    def download_community_templates(self, shallow=True):
        """
        Download community templates from nuclei-templates repo.
        
        Args:
            shallow: If True, performs a shallow clone (saves bandwidth).
        """
        print(f"\n{Colors.BOLD}{Colors.CYAN}[*] Downloading community templates...{Colors.END}")

        if os.path.exists(self.COMMUNITY_DIR):
            log_info("Community templates directory exists. Updating...")
            return self.update_templates()

        try:
            cmd = ["git", "clone"]
            if shallow:
                cmd.extend(["--depth", "1"])
            cmd.extend([self.COMMUNITY_REPO, self.COMMUNITY_DIR])

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )

            if result.returncode == 0:
                # Count templates
                count = sum(
                    1 for root, _, files in os.walk(self.COMMUNITY_DIR)
                    for f in files if f.endswith((".yaml", ".yml"))
                )
                log_success(f"Downloaded {count} community templates!")
                return True, count
            else:
                log_error(f"Git clone failed: {result.stderr[:200]}")
                return False, 0

        except FileNotFoundError:
            log_error("Git is not installed. Cannot download community templates.")
            return False, 0
        except subprocess.TimeoutExpired:
            log_error("Download timed out after 5 minutes.")
            return False, 0

    def update_templates(self):
        """Update community templates via git pull."""
        if not os.path.exists(self.COMMUNITY_DIR):
            log_warning("Community templates not downloaded. Use download first.")
            return False, 0

        try:
            result = subprocess.run(
                ["git", "pull"],
                cwd=self.COMMUNITY_DIR,
                capture_output=True, text=True, timeout=120
            )

            if result.returncode == 0:
                log_success("Community templates updated!")
                return True, 0
            else:
                log_error(f"Git pull failed: {result.stderr[:200]}")
                return False, 0

        except ScanExceptions as e:
            log_error(f"Update failed: {e}")
            return False, 0

    def stats(self):
        """Get template statistics."""
        templates = self.list_templates()
        severity_counts = {}
        tag_counts = {}

        for tpl in templates:
            sev = tpl["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            for tag in tpl.get("tags", []):
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        return {
            "total": len(templates),
            "severity": severity_counts,
            "top_tags": dict(sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        }

    def print_summary(self):
        """Print a formatted summary of available templates."""
        stats = self.stats()

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 45}")
        print(f"  📋 Template Engine Statistics")
        print(f"{'═' * 45}{Colors.END}")
        print(f"  Total templates: {stats['total']}")

        if stats["severity"]:
            print(f"\n  By Severity:")
            sev_colors = {"critical": Colors.RED, "high": Colors.RED, "medium": Colors.YELLOW, "low": Colors.GREEN, "info": Colors.BLUE}
            for sev, count in stats["severity"].items():
                color = sev_colors.get(sev, Colors.END)
                print(f"    {color}{sev.upper():<12}{Colors.END} {count}")

        if stats["top_tags"]:
            print(f"\n  Top Tags:")
            for tag, count in list(stats["top_tags"].items())[:5]:
                print(f"    {tag:<15} {count}")
        print()
