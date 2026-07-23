#!/usr/bin/env python3
"""
guac-analyzer.py -- Metal3 Go-repo vulnerability scanner via GUAC + bom.

WHAT IT DOES
  For each Metal3 Go repository under ./repos it detects the release version from
  git tags, generates an SPDX SBOM with kubernetes-sigs/bom (native pkg:golang
  purls + full dependency graph), patches the SBOM root package purl, ingests it
  into GUAC, then queries, enriches (NVD/OSV) and reports the vulnerabilities,
  attributed to each repo.

USAGE
  python3 guac-analyzer.py [--keep-forwards]

FLAGS
  --keep-forwards   Leave the kubectl port-forwards (graphql:8080, visualizer:3000)
                    running after the scan so the printed visualizer URLs work.

ENVIRONMENT
  BOM_BIN      Path to the `bom` binary (default: `bom` on PATH).
  BOM_FORCE=1  Force SBOM regeneration instead of reusing the ./bom-output cache.

REQUIREMENTS
  bom, guacone, kubectl, git; a GUAC deployment in the `guac` namespace; and
  guac_common.py in the same directory.

CLEANUP
  rm -rf bom-output/      regenerate SBOMs on next run
  rm -rf guac-reports/    clear generated reports
  Clean GUAC DB (drop leftover data from other scans) before a run:
    kubectl rollout restart deployment -n guac graphql-server
"""

import json, subprocess, time, os, re
from typing import List, Dict, Tuple
from pathlib import Path
from collections import defaultdict

from guac_common import (start_port_forwards, stop_port_forwards, enrich_vuln,
                         query_certify_vuln, ingest_sbom, parse_vuln_edge,
                         build_record, print_tier)


class GuacScanner:
    def __init__(self, keep_forwards: bool = False):
        self.guac_url = "http://localhost:8080/query"
        self.bom_bin = os.environ.get("BOM_BIN", "bom")
        self.keep_forwards = keep_forwards
        self.repos = {
            "baremetal-operator": "./repos/baremetal-operator",
            "cluster-api-provider-metal3": "./repos/cluster-api-provider-metal3",
            "ip-address-manager": "./repos/ip-address-manager",
            "ironic-standalone-operator": "./repos/ironic-standalone-operator",
            "ironic-ipa-downloader": "./repos/ironic-ipa-downloader",
        }
        self.pids = []
        self.nvd_cache = {}
        self.sbom_packages = defaultdict(set)   # repo -> {package name}
        self.repo_versions = {}
        self.pkg_purls = {}
        self.visualizer_uris = {}
        self.reports_dir = Path("./guac-reports")
        self.sbom_dir = Path("./bom-output")
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.sbom_dir.mkdir(parents=True, exist_ok=True)

    def check_bom(self) -> bool:
        try:
            if subprocess.run([self.bom_bin, "version"],
                              capture_output=True, timeout=15).returncode == 0:
                print(f"Using bom ({self.bom_bin})")
                return True
        except FileNotFoundError:
            print(f"ERROR: '{self.bom_bin}' not found. "
                  f"Install: go install sigs.k8s.io/bom/cmd/bom@latest, or set BOM_BIN.")
        except Exception as e:
            print(f"ERROR: could not run bom: {e}")
        return False

    def get_repo_version(self, repo_name: str, repo_path: str) -> str:
        """Resolve a version, preferring highest semver tag, then newest tag,
        then `git describe`, then a short-SHA pseudo-version. Avoids "unknown"
        for repos (e.g. ironic-ipa-downloader) with no semver release tags."""
        try:
            out = subprocess.run(["git", "-C", repo_path, "tag", "-l"],
                capture_output=True, text=True, timeout=10).stdout
            tags = [t for t in out.strip().split('\n') if t]
            semver = [t for t in tags if re.match(r'^v\d+\.\d+\.\d+$', t)]
            if semver:
                return sorted(semver, key=lambda x: tuple(map(int, x[1:].split('.'))))[-1][1:]
            if tags:
                r = subprocess.run(
                    ["git", "-C", repo_path, "for-each-ref", "--sort=-creatordate",
                     "--format=%(refname:short)", "refs/tags"],
                    capture_output=True, text=True, timeout=10)
                newest = [t for t in r.stdout.strip().split('\n') if t]
                if newest:
                    return newest[0].lstrip('v')
            r = subprocess.run(["git", "-C", repo_path, "describe", "--tags", "--always"],
                capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                return r.stdout.strip().lstrip('v')
            r = subprocess.run(["git", "-C", repo_path, "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                return f"0.0.0-{r.stdout.strip()}"
        except Exception as e:
            print(f"ERROR: version detection failed for {repo_name}: {e}")
        return "unknown"

    def detect_package_type(self, repo_path: str) -> Tuple[str, str]:
        """Return (type, go-module) -- golang with its module path if go.mod
        exists, else python/dockerfile/unknown (module None)."""
        if Path(f"{repo_path}/go.mod").exists():
            try:
                with open(f"{repo_path}/go.mod") as f:
                    for line in f:
                        if line.startswith("module "):
                            return "golang", line.replace("module ", "").strip()
            except Exception:
                pass
            return "golang", None
        if Path(f"{repo_path}/requirements.txt").exists():
            return "python", None
        if Path(f"{repo_path}/Dockerfile").exists():
            return "dockerfile", None
        return "unknown", None

    def generate_sbom(self, repo_path: str, repo_name: str, version: str) -> str:
        """Generate (or reuse) an SPDX-JSON SBOM with `bom generate` and record
        its package names. Reuse skips bom's slow module resolution; delete
        ./bom-output or set BOM_FORCE=1 to rebuild."""
        sbom_file = str(self.sbom_dir / f"{repo_name}-{version}.spdx.json")
        cached = (os.environ.get("BOM_FORCE") != "1"
                  and Path(sbom_file).exists() and Path(sbom_file).stat().st_size > 0)
        if cached:
            print(f"  (reusing cached SBOM {sbom_file})")
        else:
            try:
                subprocess.run(
                    [self.bom_bin, "generate", "--dirs", repo_path, "--name", repo_name,
                     "--namespace", f"https://metal3.io/{repo_name}",
                     "--format", "json", "--output", sbom_file],
                    capture_output=True, text=True, check=True, timeout=300)
            except subprocess.CalledProcessError as e:
                print(f"ERROR: bom failed for {repo_name}: {(e.stderr or '')[:200]}")
                return None
            except Exception as e:
                print(f"ERROR: bom failed for {repo_name}: {e}")
                return None
        try:
            with open(sbom_file) as f:
                sbom = json.load(f)
        except Exception as e:
            print(f"ERROR: could not read SBOM for {repo_name}: {e}")
            return None
        for pkg in sbom.get('packages', []):
            self.sbom_packages[repo_name].add(pkg.get('name', '').lower())
        return sbom_file

    def patch_sbom_purl(self, sbom_file: str, repo_name: str, version: str,
                        pkg_type: str, module: str) -> bool:
        """Add a version + purl to the SPDX root package (documentDescribes
        target). bom leaves it empty; GUAC needs it for a queryable top-level
        purl. Dependency packages already carry their own purls."""
        try:
            with open(sbom_file) as f:
                sbom = json.load(f)
            purl = (f"pkg:golang/{module}@{version}" if pkg_type == "golang" and module
                    else f"pkg:github/metal3-io/{repo_name}@{version}")
            describes = sbom.get('documentDescribes', [])
            root_id = describes[0] if describes else None

            patched = False
            for pkg in sbom.get('packages', []):
                is_root = (root_id and pkg.get('SPDXID') == root_id) or \
                          (not root_id and pkg.get('name') == repo_name)
                if is_root:
                    pkg['versionInfo'] = version
                    refs = pkg.get('externalRefs') or []
                    if not any(r.get('referenceType') == 'purl' for r in refs):
                        refs.append({'referenceCategory': 'PACKAGE-MANAGER',
                                     'referenceLocator': purl, 'referenceType': 'purl'})
                    pkg['externalRefs'] = refs
                    patched = True
                    break
            if not patched:
                print(f"  WARNING: no root package matched for {repo_name}; ingesting unpatched")
            with open(sbom_file, 'w') as f:
                json.dump(sbom, f, indent=2)
            return True
        except Exception as e:
            print(f"ERROR: SBOM patching failed for {repo_name}: {e}")
            return False

    def get_visualizer_uri(self, purl: str, repo_name: str) -> str:
        """Ask guacone for the visualizer deep link (?path=...) for a purl."""
        try:
            r = subprocess.run(["guacone", "query", "vuln", "uri", purl],
                capture_output=True, text=True, timeout=30)
            m = re.search(r'(http://localhost:3000/\?path=[\w,]+)', r.stdout + r.stderr)
            if m:
                return m.group(1)
        except Exception as e:
            print(f"  visualizer URI failed for {repo_name}: {str(e)[:60]}")
        return ""

    def process_vulns(self, vuln_edges: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """Turn CertifyVuln edges into enriched actionable records, filtering out
        dev-only and auto-updated distro packages (noise for Go source scans)."""
        actionable, filtered, seen = [], [], set()
        distro = ['tzdata', 'perl', 'util-linux', 'gzip', 'openssl', 'bash', 'curl',
                  'wget', 'coreutils', 'tar']
        dev = ['test', '-dev', 'pytest', 'mock', 'junit', 'dev-', '@types/', '-tools', 'sphinx']

        for edge in vuln_edges:
            parsed = parse_vuln_edge(edge)
            if not parsed:
                continue
            cve_id, full_name, name_lc, version = parsed
            key = (cve_id, full_name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            if any(p in name_lc for p in dev):
                filtered.append({'cve': cve_id, 'package': full_name, 'version': version, 'reason': 'Dev-only'})
                continue
            if any(name_lc.startswith(d) for d in distro):
                filtered.append({'cve': cve_id, 'package': full_name, 'version': version, 'reason': 'Distro'})
                continue
            actionable.append(build_record(cve_id, full_name, name_lc, version,
                                            enrich_vuln(cve_id, self.nvd_cache)))
        return actionable, filtered

    def attribute(self, actionable: List[Dict]) -> Dict[str, List[Dict]]:
        """Group vulns by repo. A shared dependency is attributed to every repo
        whose SBOM contains that package; anything unmatched goes to 'other'."""
        by_repo = defaultdict(list)
        for v in actionable:
            pkg = v['package'].lower()
            matched = False
            for repo in self.repos:
                pkgs = self.sbom_packages.get(repo, set())
                if pkg in pkgs or pkg == repo.lower() or pkg.endswith("/" + repo.lower()):
                    by_repo[repo].append(v)
                    matched = True
            if not matched:
                by_repo['other'].append(v)
        return by_repo

    def scan(self):
        if not self.check_bom():
            return
        self.pids, ready = start_port_forwards(self.guac_url)
        if not ready:
            stop_port_forwards(self.pids, self.keep_forwards)
            return

        print(f"\nScanning {len(self.repos)} Metal3 repos with bom...\n")
        for repo_name, repo_path in self.repos.items():
            if not Path(repo_path).exists():
                print(f"N/A: {repo_name} (not found)")
                continue
            print(f"\n=== {repo_name} ===")
            version = self.get_repo_version(repo_name, repo_path)
            self.repo_versions[repo_name] = version
            pkg_type, module = self.detect_package_type(repo_path)
            sbom = self.generate_sbom(repo_path, repo_name, version)
            if not sbom or not self.patch_sbom_purl(sbom, repo_name, version, pkg_type, module):
                continue
            self.pkg_purls[repo_name] = (f"pkg:golang/{module}@{version}"
                if pkg_type == "golang" and module
                else f"pkg:github/metal3-io/{repo_name}@{version}")
            ingest_sbom(self.guac_url, sbom, repo_name)

        print("\nWaiting for GUAC to process ingestions...")
        time.sleep(3)
        print("Querying visualizer URLs...")
        for repo_name, purl in self.pkg_purls.items():
            uri = self.get_visualizer_uri(purl, repo_name)
            if uri:
                self.visualizer_uris[repo_name] = uri

        print("Querying GUAC for vulnerabilities...\n")
        vulns = query_certify_vuln(self.guac_url)
        if not vulns:
            print("ERROR: no vulnerabilities found in GUAC")
            stop_port_forwards(self.pids, self.keep_forwards)
            return

        print(f"Found {len(vulns)} vulnerability records\n")
        actionable, filtered = self.process_vulns(vulns)
        self.report(self.attribute(actionable), actionable, filtered)
        stop_port_forwards(self.pids, self.keep_forwards)

    def report(self, by_repo: Dict, all_actionable: List[Dict], all_filtered: List[Dict]):
        consolidated = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'sbom_tool': 'kubernetes-sigs/bom',
            'repos_scanned': len(self.repos),
            'total_vulns': len(all_actionable),
            'total_filtered': len(all_filtered),
            'by_repo': dict(by_repo),
            'all_actionable': all_actionable,
        }
        with open(self.reports_dir / 'metal3-bom-guac-vulns-consolidated.json', 'w') as f:
            json.dump(consolidated, f, indent=2)
        for repo in by_repo:
            if repo == 'other':
                continue
            version = self.repo_versions.get(repo, 'unknown')
            with open(self.reports_dir / f"metal3-bom-{repo}-{version}-vulns.json", 'w') as f:
                json.dump({'timestamp': consolidated['timestamp'], 'repository': repo,
                           'sbom_tool': 'kubernetes-sigs/bom', 'version': version,
                           'total_vulns': len(by_repo[repo]), 'vulnerabilities': by_repo[repo]}, f, indent=2)

        print(f"\n{'='*70}\n VULNERABILITY REPORT (bom)\n{'='*70}")
        print(f"Total: {len(all_actionable)} found | {len(all_filtered)} filtered\n")
        for repo in sorted(by_repo):
            if repo == 'other':
                continue
            vulns = by_repo[repo]
            tiers = {'critical': [], 'urgent_go': [], 'high_ghsa': [], 'other': []}
            for v in vulns:
                score = v.get('score') if isinstance(v.get('score'), (int, float)) else None
                if score is not None and score >= 9.0:
                    tiers['critical'].append(v)
                elif v.get('is_go'):
                    tiers['urgent_go'].append(v)
                elif v.get('is_ghsa'):
                    tiers['high_ghsa'].append(v)
                else:
                    tiers['other'].append(v)
            print(f"  {repo.upper()} @ {self.repo_versions.get(repo, 'unknown')}:  ({len(vulns)} total)")
            print_tier("CRITICAL", tiers['critical'], cap=len(tiers['critical']) or 1)
            print_tier("URGENT Go", tiers['urgent_go'])
            print_tier("HIGH GHSA", tiers['high_ghsa'])
            print_tier("MEDIUM/OTHER", tiers['other'])

        if by_repo.get('other'):
            print(f"\n  UNATTRIBUTED ({len(by_repo['other'])} total):")
            print_tier("MEDIUM/OTHER", by_repo['other'])

        print(f"\n Reports: {self.reports_dir}/")
        if self.visualizer_uris:
            print("Visualizer URLs:")
            for repo in sorted(self.visualizer_uris):
                print(f"\n--> {repo}: {self.visualizer_uris[repo]}\n")
        print()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Metal3 GUAC vulnerability scanner (bom)")
    parser.add_argument("--keep-forwards", action="store_true",
                        help="leave kubectl port-forwards running after the scan")
    args = parser.parse_args()

    scanner = GuacScanner(keep_forwards=args.keep_forwards)
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print("\nInterrupted")
        stop_port_forwards(scanner.pids, keep=False)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        stop_port_forwards(scanner.pids, keep=False)
