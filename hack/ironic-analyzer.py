#!/usr/bin/env python3
"""
ironic-analyzer.py -- ironic-image container vulnerability scanner via GUAC + Syft.

WHAT IT DOES
  ironic-image is a Python (OpenStack) + OS-package container, not a Go module
  tree, so the SBOM is generated from the built image. The scanner selects one
  or more image tags from Quay.io (deduped by manifest digest), resolves the
  external repo pins from the Dockerfile for context, generates an SPDX SBOM per
  image with Syft, ingests each into GUAC, then reports per image plus a combined
  summary. Findings are isolated per image by (package, version).

  Syft is the default: kubernetes-sigs/bom cataloged no pip packages for this
  image (see --compare), so it misses ironic's Python vulnerabilities.

USAGE
  python3 ironic-analyzer.py <Dockerfile> [options]

FLAGS
  --quay-repo REPO   Quay repository (default: metal3-io/ironic)
  --guac-url URL     GUAC GraphQL endpoint (default: http://localhost:8080/query)
  --sbom-tool T      syft (default) or bom
  --output DIR       Output directory (default: .ironic-image-scan)
  --keep-forwards    Leave kubectl port-forwards running after the scan
  --latest N         Scan the N newest unique-digest tags (default: 3)
  --tags a,b,c       Scan explicit tag names (best for release-* tags)
  --since-hours H    Scan tags modified within H hours (digest-deduped)
  --compare          Generate SBOMs with both bom and syft for the newest image
                     and print a package-type comparison, then exit (no ingest)

ENVIRONMENT
  BOM_BIN      Path to the `bom` binary (used with --sbom-tool bom / --compare).
  BOM_FORCE=1  Force SBOM regeneration instead of reusing the cache.

REQUIREMENTS
  syft (or bom), guacone, kubectl, git; a GUAC deployment in the `guac`
  namespace; and guac_common.py in the same directory.

CLEANUP
  rm -rf .ironic-image-scan/    remove cached SBOMs and reports
  Clean GUAC DB before a run:
    kubectl rollout restart deployment -n guac graphql-server
"""

import json, subprocess, time, requests, os, argparse, re
from pathlib import Path
from typing import Dict, Tuple, Optional, List
from collections import defaultdict
from email.utils import parsedate_to_datetime

from guac_common import (start_port_forwards, stop_port_forwards, enrich_vuln,
                         query_certify_vuln, ingest_sbom, parse_vuln_edge,
                         build_record, print_tier)


class IronicImageScanner:
    def __init__(self, dockerfile_path: str, quay_repo: str = "metal3-io/ironic",
                 guac_url: str = "http://localhost:8080/query", sbom_tool: str = "syft",
                 output_dir: str = ".ironic-image-scan", keep_forwards: bool = False,
                 latest_n: int = 3, tags_arg: str = "", since_hours: float = 0):
        self.dockerfile_path = dockerfile_path
        self.quay_repo = quay_repo
        self.guac_url = guac_url
        self.sbom_tool = sbom_tool
        self.bom_bin = os.environ.get("BOM_BIN", "bom")
        self.keep_forwards = keep_forwards
        self.latest_n = latest_n
        self.tags_arg = tags_arg
        self.since_hours = since_hours
        self.work_dir = Path(output_dir)
        self.reports_dir = self.work_dir / "reports"
        self.version_dir = self.work_dir / "versioncheck"
        for d in (self.work_dir, self.reports_dir, self.version_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.pids = []
        self.nvd_cache = {}
        self.images = []                        # selected image dicts
        self.image_pkgs = defaultdict(set)      # tag -> {(name, version)}
        self.image_reports = defaultdict(list)  # tag -> [vuln, ...]
        self.external_repo_versions = {}

    def check_tool(self) -> bool:
        binary = self.bom_bin if self.sbom_tool == "bom" else "syft"
        try:
            if subprocess.run([binary, "version"], capture_output=True, timeout=15).returncode == 0:
                print(f"Using SBOM tool: {self.sbom_tool} ({binary})")
                return True
        except FileNotFoundError:
            print(f"ERROR: '{binary}' not found on PATH.")
        except Exception as e:
            print(f"ERROR: could not run {binary}: {e}")
        return False

    @staticmethod
    def _ts(last_modified: str) -> float:
        """Quay's last_modified is an RFC-1123 string; parse to epoch for sorting."""
        try:
            return parsedate_to_datetime(last_modified).timestamp()
        except Exception:
            return 0.0

    def _img(self, t: Dict) -> Dict:
        name = t['name']
        return {'tag': name, 'image_ref': f"quay.io/{self.quay_repo}:{name}",
                'digest': t.get('manifest_digest'), 'last_modified': t.get('last_modified'),
                'url': f"https://quay.io/repository/{self.quay_repo}?tab=tags&tag={name}"}

    def select_images(self) -> List[Dict]:
        """Pick image tags to scan. Explicit --tags wins; otherwise skip digest
        tags, sort newest-first, dedupe by manifest digest (many names alias one
        image), and take those within --since-hours or the newest --latest N."""
        print("\nQuerying Quay.io for image tags...")
        try:
            r = requests.get(
                f"https://quay.io/api/v1/repository/{self.quay_repo}/tag/"
                f"?limit=100&page=1&onlyActiveTags=true", timeout=15)
            r.raise_for_status()
            tags = r.json().get('tags', [])
        except Exception as e:
            print(f"  ERROR: failed to fetch tags: {e}")
            return []

        if self.tags_arg:
            wanted = [t.strip() for t in self.tags_arg.split(',') if t.strip()]
            by_name = {t['name']: t for t in tags if t.get('name')}
            missing = [w for w in wanted if w not in by_name]
            if missing:
                print(f"  WARNING: tags not found: {', '.join(missing)}")
            return [self._img(by_name[w]) for w in wanted if w in by_name]

        cand = [t for t in tags if t.get('name') and not t['name'].startswith('sha256')]
        cand.sort(key=lambda t: self._ts(t.get('last_modified', '')), reverse=True)
        seen, unique = set(), []
        for t in cand:
            d = t.get('manifest_digest')
            if d and d in seen:
                continue
            seen.add(d)
            unique.append(t)

        if self.since_hours:
            cutoff = time.time() - self.since_hours * 3600
            unique = [t for t in unique if self._ts(t.get('last_modified', '')) >= cutoff]
        else:
            unique = unique[:self.latest_n]
        return [self._img(t) for t in unique]

    def extract_external_repos(self) -> Dict[str, Tuple[str, str]]:
        """Read the pinned (commit, branch) for ironic/ngs/sushy from the
        Dockerfile ARG *_SOURCE lines."""
        print("\nExtracting external repo pins from Dockerfile...")
        try:
            with open(self.dockerfile_path) as f:
                content = f.read()
        except Exception as e:
            print(f"  ERROR: could not read Dockerfile: {e}")
            return {}
        versions = {}
        for repo_key, marker in [('ironic', 'IRONIC'), ('ngs', 'NGS'), ('sushy', 'SUSHY')]:
            m = re.search(rf'^ARG {marker}_SOURCE=([a-f0-9]+)\s+#\s+(.+)$', content, re.MULTILINE)
            if m:
                versions[repo_key] = (m.group(1), m.group(2).strip())
                print(f"  {marker}: {m.group(1)} ({m.group(2).strip()})")
        return versions

    def resolve_commits_to_versions(self, extracted: Dict[str, Tuple[str, str]]) -> Dict[str, str]:
        """Clone each external repo at its pinned branch and `git describe` the
        pinned commit into a human version (reporting context only)."""
        print("\nResolving external repo versions (from current Dockerfile)...")
        repos_map = {
            'ironic': 'https://opendev.org/openstack/ironic.git',
            'ngs': 'https://opendev.org/openstack/networking-generic-switch.git',
            'sushy': 'https://opendev.org/openstack/sushy.git',
        }
        resolved = {}
        for repo_key, (commit_sha, branch) in extracted.items():
            if repo_key not in repos_map:
                continue
            repo_dir = self.version_dir / repo_key
            if repo_dir.exists():
                subprocess.run(["rm", "-rf", str(repo_dir)], capture_output=True)
            try:
                subprocess.run(
                    ["git", "clone", "-q", "-b", branch, "--filter=blob:none",
                     repos_map[repo_key], str(repo_dir)],
                    check=True, capture_output=True, timeout=60)
                r = subprocess.run(["git", "-C", str(repo_dir), "describe", "--tags", commit_sha],
                    capture_output=True, text=True, check=True, timeout=10)
                resolved[repo_key] = r.stdout.strip()
                print(f"  {repo_key}: {r.stdout.strip()}")
            except Exception as e:
                print(f"  {repo_key}: FAILED ({str(e)[:80]})")
                resolved[repo_key] = "unknown"
        return resolved

    def generate_sbom(self, image_ref: str, tag: str) -> Optional[str]:
        """Generate (or reuse) an SPDX-JSON SBOM for one image and record its
        (name, version) set for per-image isolation. BOM_FORCE=1 rebuilds."""
        sbom_file = str(self.work_dir / f"ironic-image-{tag}-{self.sbom_tool}.spdx.json")
        print(f"\nGenerating SBOM for {tag} ({self.sbom_tool})...")
        cached = (os.environ.get("BOM_FORCE") != "1"
                  and Path(sbom_file).exists() and Path(sbom_file).stat().st_size > 0)
        if cached:
            print(f"  (reusing cached SBOM {sbom_file})")
        else:
            cmd = ([self.bom_bin, "generate", "--image", image_ref, "--format", "json",
                    "--output", sbom_file] if self.sbom_tool == "bom"
                   else ["syft", image_ref, "-o", f"spdx-json={sbom_file}"])
            try:
                subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
            except subprocess.CalledProcessError as e:
                print(f"  ERROR: SBOM generation failed: {(e.stderr or '')[:200]}")
                return None
            except Exception as e:
                print(f"  ERROR: SBOM generation failed: {e}")
                return None
        try:
            with open(sbom_file) as f:
                sbom = json.load(f)
        except Exception as e:
            print(f"  ERROR: could not read SBOM: {e}")
            return None
        for pkg in sbom.get('packages', []):
            name = pkg.get('name', '').lower()
            if name:
                self.image_pkgs[tag].add((name, pkg.get('versionInfo', '')))
        print(f"  SBOM generated: {len(sbom.get('packages', []))} packages")
        return sbom_file

    def patch_sbom_root(self, sbom_file: str, tag: str) -> bool:
        """Add an OCI purl + version to the SPDX root package. bom uses
        documentDescribes; Syft omits it and records a DESCRIBES relationship
        from the document to the root package instead."""
        try:
            with open(sbom_file) as f:
                sbom = json.load(f)
            purl = f"pkg:oci/{self.quay_repo}@{tag}"
            describes = sbom.get('documentDescribes', [])
            root_id = describes[0] if describes else None
            if not root_id:
                for rel in sbom.get('relationships', []) or []:
                    if rel.get('relationshipType') == 'DESCRIBES' and \
                            rel.get('spdxElementId') == 'SPDXRef-DOCUMENT':
                        root_id = rel.get('relatedSpdxElement')
                        break
            patched = False
            for pkg in sbom.get('packages', []):
                is_root = (root_id and pkg.get('SPDXID') == root_id) or \
                          (not root_id and pkg.get('name') in ('ironic-image', self.quay_repo, tag))
                if is_root:
                    pkg['versionInfo'] = tag
                    refs = pkg.get('externalRefs') or []
                    if not any(r.get('referenceType') == 'purl' for r in refs):
                        refs.append({'referenceCategory': 'PACKAGE-MANAGER',
                                     'referenceLocator': purl, 'referenceType': 'purl'})
                    pkg['externalRefs'] = refs
                    patched = True
                    break
            if not patched:
                print("  WARNING: no root package matched; ingesting unpatched")
            with open(sbom_file, 'w') as f:
                json.dump(sbom, f, indent=2)
            return True
        except Exception as e:
            print(f"  ERROR: SBOM patching failed: {e}")
            return False

    def process_vulns(self, vuln_edges: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """Enrich and dedupe CertifyVuln edges, keeping only packages present in
        some scanned image's SBOM. Per-image attribution happens in scan()."""
        actionable, filtered, seen = [], [], set()
        dev = ['test', '-dev', 'pytest', 'mock', 'junit', 'dev-', '@types/', '-tools', 'sphinx']
        union = set().union(*self.image_pkgs.values()) if self.image_pkgs else set()

        for edge in vuln_edges:
            parsed = parse_vuln_edge(edge)
            if not parsed:
                continue
            cve_id, full_name, name_lc, version = parsed
            if union and (name_lc, version) not in union:
                continue
            key = (cve_id, name_lc, version)
            if key in seen:
                continue
            seen.add(key)
            if any(p in name_lc for p in dev):
                filtered.append({'cve': cve_id, 'package': full_name, 'version': version, 'reason': 'Dev-only'})
                continue
            actionable.append(build_record(cve_id, full_name, name_lc, version,
                                            enrich_vuln(cve_id, self.nvd_cache)))
        return actionable, filtered

    @staticmethod
    def _tiers(vulns: List[Dict]) -> Dict[str, List[Dict]]:
        """Bucket vulns into CVSS critical/high, then Go/GHSA, then other."""
        tiers = {'critical': [], 'high': [], 'urgent_go': [], 'high_ghsa': [], 'other': []}
        for v in vulns:
            score = v.get('score') if isinstance(v.get('score'), (int, float)) else None
            if score is not None and score >= 9.0:
                tiers['critical'].append(v)
            elif score is not None and score >= 7.0:
                tiers['high'].append(v)
            elif v.get('is_go'):
                tiers['urgent_go'].append(v)
            elif v.get('is_ghsa'):
                tiers['high_ghsa'].append(v)
            else:
                tiers['other'].append(v)
        for t in ('critical', 'high'):
            tiers[t].sort(key=lambda x: x.get('score') or 0, reverse=True)
        return tiers

    def report(self, all_actionable: List[Dict], filtered: List[Dict]):
        combined = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'sbom_tool': self.sbom_tool, 'quay_repo': self.quay_repo,
            'external_repos_current_dockerfile': self.external_repo_versions,
            'total_unique_vulns': len(all_actionable), 'total_filtered': len(filtered),
            'images': [],
        }
        for img in self.images:
            vulns = self.image_reports.get(img['tag'], [])
            combined['images'].append({
                'tag': img['tag'], 'image_ref': img['image_ref'], 'digest': img['digest'],
                'last_modified': img['last_modified'],
                'total_vulns': len(vulns), 'vulnerabilities': vulns})
        report_file = self.reports_dir / f"ironic-image-multi-{self.sbom_tool}-vulns.json"
        with open(report_file, 'w') as f:
            json.dump(combined, f, indent=2)

        print(f"\n{'='*70}\n IRONIC-IMAGE VULNERABILITY REPORT ({self.sbom_tool})\n{'='*70}")
        print(f"Repo: quay.io/{self.quay_repo}  |  images scanned: {len(self.images)}")
        if self.external_repo_versions:
            print("External repos (from current Dockerfile):")
            for repo, version in self.external_repo_versions.items():
                print(f"  {repo}: {version}")
        print(f"\nUnique vulns across images: {len(all_actionable)} | {len(filtered)} filtered")

        for img in self.images:
            vulns = self.image_reports.get(img['tag'], [])
            print(f"\n  {img['tag']}  ({len(vulns)} total)")
            tiers = self._tiers(vulns)
            print_tier("CRITICAL", tiers['critical'], cap=len(tiers['critical']) or 1)
            print_tier("HIGH", tiers['high'])
            print_tier("URGENT Go", tiers['urgent_go'])
            print_tier("HIGH GHSA", tiers['high_ghsa'])
            print_tier("MEDIUM/OTHER", tiers['other'])

        print(f"\n Report: {report_file}")
        print(" GUAC Visualizer: http://localhost:3000 -- search a package name or CVE id\n")

    # --- bom-vs-syft comparison (answers "how well does bom work") ---------

    def _purl_counts(self, sbom_file: str) -> Tuple[Dict[str, int], int]:
        """Count purls per ecosystem (pypi/rpm/deb/...) in an SBOM."""
        try:
            with open(sbom_file) as f:
                sbom = json.load(f)
        except Exception:
            return {}, 0
        counts = defaultdict(int)
        pkgs = sbom.get('packages', [])
        for p in pkgs:
            for ref in p.get('externalRefs', []) or []:
                if ref.get('referenceType') == 'purl':
                    m = re.match(r'pkg:([a-zA-Z0-9.\-]+)[/@]', ref.get('referenceLocator', ''))
                    if m:
                        counts[m.group(1)] += 1
        return counts, len(pkgs)

    def _tool_available(self, binary: str) -> bool:
        b = self.bom_bin if binary == "bom" else binary
        try:
            return subprocess.run([b, "version"], capture_output=True, timeout=15).returncode == 0
        except Exception:
            print(f"ERROR: '{b}' not found on PATH (needed for --compare).")
            return False

    def compare(self):
        """Generate SBOMs with both bom and Syft for the newest image and print a
        per-ecosystem package-count breakdown."""
        if not (self._tool_available("bom") and self._tool_available("syft")):
            return
        imgs = self.select_images()
        if not imgs:
            return
        img = imgs[0]
        results = {}
        for tool in ("bom", "syft"):
            self.sbom_tool = tool
            sbom = self.generate_sbom(img['image_ref'], img['tag'])
            if sbom:
                results[tool] = self._purl_counts(sbom)

        print(f"\n{'='*70}\n SBOM TOOL COMPARISON: {img['tag']}\n{'='*70}")
        ecosystems = sorted({e for _, (c, _) in results.items() for e in c})
        print(f"{'ecosystem':<14}{'bom':>10}{'syft':>10}")
        print("-" * 34)
        for eco in ecosystems:
            b = results.get('bom', ({}, 0))[0].get(eco, 0)
            s = results.get('syft', ({}, 0))[0].get(eco, 0)
            print(f"{eco:<14}{b:>10}{s:>10}")
        print("-" * 34)
        print(f"{'TOTAL pkgs':<14}{results.get('bom', ({}, 0))[1]:>10}{results.get('syft', ({}, 0))[1]:>10}")
        print("\nNear-zero bom pypi vs non-zero syft => bom misses ironic's Python vulns.\n")

    def scan(self):
        print("IRONIC-IMAGE VULNERABILITY SCANNER")
        if not self.check_tool():
            return
        self.images = self.select_images()
        if not self.images:
            print("ERROR: no images selected")
            return
        print(f"\nSelected {len(self.images)} image(s):")
        for img in self.images:
            print(f"  {img['tag']}  ({img['last_modified']})")

        extracted = self.extract_external_repos()
        self.external_repo_versions = self.resolve_commits_to_versions(extracted) if extracted else {}

        self.pids, ready = start_port_forwards(self.guac_url)
        if not ready:
            stop_port_forwards(self.pids, self.keep_forwards)
            return

        for img in self.images:
            sbom = self.generate_sbom(img['image_ref'], img['tag'])
            if not sbom or not self.patch_sbom_root(sbom, img['tag']):
                print(f"  skipping {img['tag']} (SBOM failed)")
                continue
            ingest_sbom(self.guac_url, sbom, img['tag'])

        print("\nWaiting for GUAC to process ingestions...")
        time.sleep(3)
        print("Querying GUAC for vulnerabilities...\n")
        vulns = query_certify_vuln(self.guac_url)
        if not vulns:
            print("  No vulnerability records found")
            self.report([], [])
            stop_port_forwards(self.pids, self.keep_forwards)
            return
        print(f"Found {len(vulns)} vulnerability records")
        actionable, filtered = self.process_vulns(vulns)

        # Attribute each vuln to every scanned image whose SBOM has that (name, version).
        for v in actionable:
            key = (v['name_lc'], v['version'])
            for img in self.images:
                if key in self.image_pkgs[img['tag']]:
                    self.image_reports[img['tag']].append(v)

        self.report(actionable, filtered)
        stop_port_forwards(self.pids, self.keep_forwards)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="ironic-image GUAC vulnerability scanner (multi-image)")
    parser.add_argument('dockerfile', help='Path to the ironic-image Dockerfile')
    parser.add_argument('--quay-repo', default='metal3-io/ironic', help='Quay.io repository')
    parser.add_argument('--guac-url', default='http://localhost:8080/query', help='GUAC GraphQL URL')
    parser.add_argument('--sbom-tool', choices=['bom', 'syft'], default='syft',
                        help='SBOM generator (default: syft; bom misses pip packages)')
    parser.add_argument('--output', default='.ironic-image-scan', help='Output directory')
    parser.add_argument('--keep-forwards', action='store_true',
                        help='leave kubectl port-forwards running after the scan')
    parser.add_argument('--latest', type=int, default=3, metavar='N',
                        help='scan the N newest unique-digest tags (default: 3)')
    parser.add_argument('--tags', default='', metavar='a,b,c',
                        help='explicit comma-separated tag names to scan')
    parser.add_argument('--since-hours', type=float, default=0, metavar='H',
                        help='scan tags modified within H hours (digest-deduped)')
    parser.add_argument('--compare', action='store_true',
                        help='compare bom vs syft package coverage on the newest image, then exit')
    args = parser.parse_args()

    if not Path(args.dockerfile).exists():
        print(f"ERROR: Dockerfile not found: {args.dockerfile}")
        raise SystemExit(1)

    scanner = IronicImageScanner(args.dockerfile, args.quay_repo, args.guac_url,
                                 args.sbom_tool, args.output, args.keep_forwards,
                                 args.latest, args.tags, args.since_hours)
    try:
        if args.compare:
            scanner.compare()
        else:
            scanner.scan()
    except KeyboardInterrupt:
        print("\nInterrupted")
        stop_port_forwards(scanner.pids, keep=False)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        stop_port_forwards(scanner.pids, keep=False)
