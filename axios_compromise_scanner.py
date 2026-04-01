#!/usr/bin/env python3
"""
Standalone scanner for the March 2026 axios npm supply-chain compromise.

References used to build IOCs and checks:
- StepSecurity incident write-up (malicious versions + attack behavior)
- Huntress incident write-up (package hashes + host/network/file IOCs)

This script is intentionally standalone (stdlib only) and can be run as:

  python3 axios_compromise_scanner.py --root .

Exit codes:
  0 = no findings
  1 = findings detected
  2 = script/runtime error
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List

MALICIOUS_AXIOS_VERSIONS = {"1.14.1", "0.30.4"}
MALICIOUS_DEPENDENCY = "plain-crypto-js"
SUSPICIOUS_PLAIN_CRYPTO_VERSIONS = {"4.2.1"}

# Published IOC hashes from Huntress for malicious npm packages.
MALICIOUS_SHA1 = {
    "axios@1.14.1": "2553649f2322049666871cea80a5d0d6adc700ca",
    "axios@0.30.4": "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71",
    "plain-crypto-js@4.2.1": "07d889e2dadce6f3910dcbc253317d28ca61c766",
}

NETWORK_IOCS = {
    "domains": ["sfrclak.com"],
    "ip_addresses": ["142.11.206.73"],
    "urls": ["http://sfrclak.com:8000/6202033"],
    "post_bodies": [
        "packages.npm.org/product0",
        "packages.npm.org/product1",
        "packages.npm.org/product2",
    ],
    "user_agent": "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)",
}

FILE_IOCS = [
    "/Library/Caches/com.apple.act.mond",
    r"%PROGRAMDATA%\\wt.exe",
    r"%PROGRAMDATA%\\system.bat",
    r"%TEMP%\\6202033.vbs",
    r"%TEMP%\\6202033.ps1",
    "/tmp/ld.py",
]

LOCKFILE_CANDIDATES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".turbo",
    ".cache",
    "dist",
    "build",
    "coverage",
}


@dataclass
class Finding:
    severity: str
    category: str
    path: str
    summary: str
    details: str


@dataclass
class ScanReport:
    scanned_root: str
    findings: List[Finding]

    @property
    def compromised(self) -> bool:
        return any(f.severity in {"critical", "high"} for f in self.findings)

    def to_json(self) -> str:
        return json.dumps(
            {
                "scanned_root": self.scanned_root,
                "compromised": self.compromised,
                "finding_count": len(self.findings),
                "findings": [asdict(f) for f in self.findings],
                "iocs": {
                    "malicious_versions": {
                        "axios": sorted(MALICIOUS_AXIOS_VERSIONS),
                        MALICIOUS_DEPENDENCY: sorted(SUSPICIOUS_PLAIN_CRYPTO_VERSIONS),
                    },
                    "malicious_sha1": MALICIOUS_SHA1,
                    "network": NETWORK_IOCS,
                    "filesystem": FILE_IOCS,
                },
            },
            indent=2,
        )


def iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name


def safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def check_lockfile_for_versions(path: Path, findings: List[Finding]) -> None:
    text = safe_read(path)
    if not text:
        return

    def add_axios_finding(version: str) -> None:
        findings.append(
            Finding(
                severity="critical",
                category="dependency",
                path=str(path),
                summary=f"Potential malicious axios version referenced: {version}",
                details=(
                    "Lockfile contains a known malicious axios version from the March 2026 compromise. "
                    "Treat this environment as potentially compromised and rotate credentials."
                ),
            )
        )

    # Prefer structured parsing for JSON lockfiles where available.
    if path.suffix == ".json":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None

        if isinstance(parsed, dict):
            def recurse(obj: object) -> None:
                if isinstance(obj, dict):
                    if obj.get("name") == "axios" and str(obj.get("version", "")) in MALICIOUS_AXIOS_VERSIONS:
                        add_axios_finding(str(obj["version"]))
                    for key, value in obj.items():
                        if key == "axios" and isinstance(value, dict):
                            version = str(value.get("version", "")).strip()
                            if version in MALICIOUS_AXIOS_VERSIONS:
                                add_axios_finding(version)
                        recurse(value)
                elif isinstance(obj, list):
                    for item in obj:
                        recurse(item)

            recurse(parsed)

    for version in MALICIOUS_AXIOS_VERSIONS:
        pattern = rf"axios(?:@|\s|/)?{re.escape(version)}"
        if re.search(pattern, text):
            add_axios_finding(version)

    if re.search(r"plain-crypto-js", text):
        sev = "critical" if re.search(r"plain-crypto-js[^\n]*4\.2\.1", text) else "high"
        findings.append(
            Finding(
                severity=sev,
                category="dependency",
                path=str(path),
                summary="Suspicious plain-crypto-js dependency reference detected",
                details=(
                    "plain-crypto-js appeared in the axios compromise chain and should not be present in normal axios installs."
                ),
            )
            )


def check_generic_json_for_indicators(path: Path, findings: List[Finding]) -> None:
    text = safe_read(path)
    if not text:
        return

    matched = False

    # Structured parse for JSON content.
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, (dict, list)):
        def recurse(obj: object) -> None:
            nonlocal matched
            if isinstance(obj, dict):
                if obj.get("name") == "axios" and str(obj.get("version", "")) in MALICIOUS_AXIOS_VERSIONS:
                    version = str(obj.get("version", "")).strip()
                    findings.append(
                        Finding(
                            severity="critical",
                            category="json-indicator",
                            path=str(path),
                            summary=f"JSON indicator references malicious axios version: {version}",
                            details="Structured JSON parsing identified a known malicious axios version field.",
                        )
                    )
                    matched = True
                for key, value in obj.items():
                    if key == "axios" and isinstance(value, dict):
                        version = str(value.get("version", "")).strip()
                        if version in MALICIOUS_AXIOS_VERSIONS:
                            findings.append(
                                Finding(
                                    severity="critical",
                                    category="json-indicator",
                                    path=str(path),
                                    summary=f"JSON indicator references malicious axios version: {version}",
                                    details="Structured JSON parsing identified axios object with malicious version.",
                                )
                            )
                            matched = True
                    recurse(value)
            elif isinstance(obj, list):
                for item in obj:
                    recurse(item)

        recurse(parsed)

    # Regex pass is always applied as an additional safety net.
    regex_hit = False
    for version in MALICIOUS_AXIOS_VERSIONS:
        if re.search(rf"axios(?:@|\s|/)?{re.escape(version)}", text) or re.search(
            rf"\"axios\"\\s*:\\s*\\{{[^\\}}]*\"version\"\\s*:\\s*\"{re.escape(version)}\"",
            text,
        ):
            regex_hit = True
            findings.append(
                Finding(
                    severity="critical",
                    category="json-indicator",
                    path=str(path),
                    summary=f"Regex indicator references malicious axios version: {version}",
                    details="Regex scanning of JSON text matched a known malicious axios version pattern.",
                )
            )

    if re.search(r"plain-crypto-js", text):
        regex_hit = True
        findings.append(
            Finding(
                severity="high",
                category="json-indicator",
                path=str(path),
                summary="Regex indicator references plain-crypto-js in JSON file",
                details="Regex scanning found plain-crypto-js token in JSON content; investigate dependency chain.",
            )
        )

    # Avoid silent no-op for JSON files that had no indicators.
    _ = matched or regex_hit


def check_installed_node_modules(root: Path, findings: List[Finding]) -> None:
    axios_pkg = root / "node_modules" / "axios" / "package.json"
    if axios_pkg.exists():
        try:
            data = json.loads(safe_read(axios_pkg) or "{}")
        except json.JSONDecodeError:
            data = {}
        version = str(data.get("version", "")).strip()
        if version in MALICIOUS_AXIOS_VERSIONS:
            findings.append(
                Finding(
                    severity="critical",
                    category="installed-package",
                    path=str(axios_pkg),
                    summary=f"Installed axios version is malicious: {version}",
                    details="Known compromised version discovered directly in node_modules.",
                )
            )

    plain_crypto_dir = root / "node_modules" / MALICIOUS_DEPENDENCY
    if plain_crypto_dir.exists():
        details = (
            "Directory exists. Huntress notes presence of node_modules/plain-crypto-js can indicate compromise, "
            "even if package contents look benign after self-cleanup."
        )
        pkg = plain_crypto_dir / "package.json"
        version = ""
        if pkg.exists():
            try:
                version = str(json.loads(safe_read(pkg) or "{}").get("version", "")).strip()
            except json.JSONDecodeError:
                pass
        if version in SUSPICIOUS_PLAIN_CRYPTO_VERSIONS:
            sev = "critical"
            details += f" package.json reports suspicious version {version}."
        else:
            sev = "high"
            if version:
                details += f" package.json reports version {version}; this can be spoofed post-infection."
        findings.append(
            Finding(
                severity=sev,
                category="installed-package",
                path=str(plain_crypto_dir),
                summary="Suspicious dependency directory detected: node_modules/plain-crypto-js",
                details=details,
            )
        )


def check_host_iocs(findings: List[Finding]) -> None:
    expanded_paths = [
        Path("/Library/Caches/com.apple.act.mond"),
        Path("/tmp/ld.py"),
    ]

    if os.name == "nt":
        for env_var, leaf in [
            ("PROGRAMDATA", "wt.exe"),
            ("PROGRAMDATA", "system.bat"),
            ("TEMP", "6202033.vbs"),
            ("TEMP", "6202033.ps1"),
        ]:
            base = os.environ.get(env_var)
            if base:
                expanded_paths.append(Path(base) / leaf)

    for p in expanded_paths:
        if p.exists():
            findings.append(
                Finding(
                    severity="critical",
                    category="host-artifact",
                    path=str(p),
                    summary="Known axios-compromise filesystem IOC detected",
                    details="IOC path exists on disk and maps to published malware artifacts.",
                )
            )


def run_scan(root: Path) -> ScanReport:
    findings: List[Finding] = []

    for path in iter_files(root):
        if path.name in LOCKFILE_CANDIDATES:
            check_lockfile_for_versions(path, findings)
        elif path.suffix == ".json":
            check_generic_json_for_indicators(path, findings)

    check_installed_node_modules(root, findings)
    check_host_iocs(findings)

    return ScanReport(scanned_root=str(root.resolve()), findings=findings)


def print_human_report(report: ScanReport) -> None:
    print("=" * 78)
    print("Axios 2026 Supply-Chain Compromise Scanner")
    print("=" * 78)
    print(f"Scanned root: {report.scanned_root}")
    print(f"Findings: {len(report.findings)}")
    print(f"Compromised (heuristic): {'YES' if report.compromised else 'NO'}")

    if report.findings:
        print("\nFindings:")
        for idx, finding in enumerate(report.findings, start=1):
            print(f"  {idx}. [{finding.severity.upper()}] {finding.summary}")
            print(f"     Category: {finding.category}")
            print(f"     Path:     {finding.path}")
            print(f"     Details:  {finding.details}")

    print("\nRecommended response if findings are present:")
    print("  1) Assume credential exposure on affected hosts; rotate secrets immediately.")
    print("  2) Rebuild affected systems from known-good images (avoid in-place cleanup).")
    print("  3) Pin axios to safe versions (1.14.0 or 0.30.3) and reinstall with --ignore-scripts.")
    print("  4) Block network IOC: sfrclak.com / 142.11.206.73 / port 8000.")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Standalone scanner for the March 2026 axios npm compromise."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Root directory to scan for lockfiles/node_modules (default: current dir)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON report",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in dummy payload tests and exit",
    )
    return parser.parse_args(argv)


def run_self_test() -> int:
    test_results = []

    def record(name: str, passed: bool, details: str = "") -> None:
        test_results.append((name, passed, details))

    with tempfile.TemporaryDirectory(prefix="axios-scan-test-") as tmp:
        root = Path(tmp)

        # Test 1: clean workspace should not be marked compromised.
        clean = run_scan(root)
        record(
            "clean_workspace",
            clean.compromised is False and len(clean.findings) == 0,
            f"findings={len(clean.findings)} compromised={clean.compromised}",
        )

        # Test 2: malicious axios version in lockfile should be detected.
        lock = root / "package-lock.json"
        lock.write_text(
            json.dumps({"dependencies": {"axios": {"version": "1.14.1"}}}),
            encoding="utf-8",
        )
        compromised = run_scan(root)
        has_axios = any("axios version" in f.summary.lower() for f in compromised.findings)
        record(
            "lockfile_malicious_axios",
            compromised.compromised is True and has_axios,
            f"findings={len(compromised.findings)}",
        )

        # Test 3: suspicious dependency directory should be detected.
        plain_crypto_pkg = root / "node_modules" / "plain-crypto-js"
        plain_crypto_pkg.mkdir(parents=True, exist_ok=True)
        (plain_crypto_pkg / "package.json").write_text(
            json.dumps({"name": "plain-crypto-js", "version": "4.2.1"}),
            encoding="utf-8",
        )
        compromised2 = run_scan(root)
        has_plain_crypto = any("plain-crypto-js" in f.summary for f in compromised2.findings)
        record(
            "node_modules_plain_crypto",
            compromised2.compromised is True and has_plain_crypto,
            f"findings={len(compromised2.findings)}",
        )

    print("Self-test results:")
    failures = 0
    for name, passed, details in test_results:
        status = "PASS" if passed else "FAIL"
        print(f"  - {name}: {status} {details}")
        if not passed:
            failures += 1
    print(f"Summary: {len(test_results) - failures}/{len(test_results)} tests passed")
    return 0 if failures == 0 else 2


def main(argv: List[str]) -> int:
    try:
        args = parse_args(argv)
        if args.self_test:
            return run_self_test()

        root = Path(args.root)
        if not root.exists() or not root.is_dir():
            print(f"[error] --root does not exist or is not a directory: {root}", file=sys.stderr)
            return 2

        report = run_scan(root)

        if args.json:
            print(report.to_json())
        else:
            print_human_report(report)

        return 1 if report.compromised else 0
    except KeyboardInterrupt:
        print("\n[error] interrupted", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[error] scanner failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
