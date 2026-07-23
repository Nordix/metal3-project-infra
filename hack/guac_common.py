#!/usr/bin/env python3
"""
guac_common.py -- shared helpers for the GUAC vulnerability scanners.

This is a library, not a runnable script. It is imported by guac-analyzer.py
(Metal3 Go repos) and ironic-analyzer.py (ironic-image container) and holds the
logic that must behave identically for both:
  - kubectl port-forward setup / teardown
  - external vuln enrichment (NVD for CVSS, OSV for severity + fix version)
  - the GUAC CertifyVuln GraphQL query and SBOM ingestion (with retry)
  - CertifyVuln edge parsing, actionable-record building, and report formatting

This is an importable module and must sit in the same directory as the scanners that import it.
"""

import subprocess, time, requests, os, signal
from typing import Dict, List, Optional, Tuple


# --- port forwarding -------------------------------------------------------

def start_port_forwards(guac_url: str, namespace: str = "guac",
                        services=(("graphql-server", "8080"), ("visualizer", "3000"))
                        ) -> Tuple[List[int], bool]:
    """Start kubectl port-forwards and wait until the GUAC endpoint answers.

    Returns (pids, ready). kubectl stderr is captured so its connection-reset
    noise doesn't clutter the scan output. `ready` is False if GUAC never
    responded within the retry window.
    """
    print("\nStarting port forwards...")
    pids = [subprocess.Popen(["kubectl", "port-forward", "-n", namespace,
            f"svc/{s}", f"{p}:{p}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).pid
            for s, p in services]
    time.sleep(2)
    for _ in range(5):
        try:
            requests.post(guac_url, json={"query": "{__typename}"}, timeout=2)
            print("GUAC API ready")
            return pids, True
        except Exception:
            time.sleep(1)
    print("ERROR: GUAC did not become ready")
    return pids, False


def stop_port_forwards(pids: List[int], keep: bool = False):
    """Terminate the port-forward processes, or leave them running (and print how
    to stop them) when keep=True."""
    if keep:
        if pids:
            print("\nLeaving port-forwards running (--keep-forwards):")
            print("  visualizer -> http://localhost:3000")
            print("  graphql    -> http://localhost:8080")
            print(f"  Stop them with: kill {' '.join(map(str, pids))}")
        return
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass


# --- enrichment (NVD / OSV) ------------------------------------------------

def normalize_vuln_id(vid: str) -> str:
    """Uppercase only the scheme prefix for NVD/OSV lookups. GUAC lowercases ids,
    but GHSA suffixes contain lowercase letters that must be preserved
    (GHSA-hrxh-..., GO-2026-..., CVE-..., PYSEC-...)."""
    if '-' not in vid:
        return vid.upper()
    prefix, rest = vid.split('-', 1)
    return f"{prefix.upper()}-{rest}"


def parse_osv(record: Dict) -> Dict:
    """Pull severity + fixed version from an OSV /v1/vulns/{id} record. OSV's
    `severity` is a CVSS-vector list rather than a label, so the label comes from
    database_specific; fix versions come from affected[].ranges[].events[].fixed."""
    sev = (record.get('database_specific', {}) or {}).get('severity', 'UNKNOWN')
    fixed = []
    for aff in record.get('affected', []) or []:
        for rng in aff.get('ranges', []) or []:
            for ev in rng.get('events', []) or []:
                if ev.get('fixed'):
                    fixed.append(ev['fixed'])
    return {'severity': sev or 'UNKNOWN',
            'fixed': ', '.join(dict.fromkeys(fixed)) if fixed else None}


def enrich_vuln(cve_id: str, cache: Dict) -> Dict:
    """Enrich a vuln id externally (GUAC's certifiers crash): NVD for CVSS on
    CVEs, OSV for severity fallback and the fixed version. Memoized in the
    caller's cache dict. NVD is limited to ~5 req/30s without an API key."""
    if not cve_id or cve_id in cache:
        return cache.get(cve_id, {'severity': 'UNKNOWN', 'score': None, 'source': 'none', 'fixed': None})

    result = {'severity': 'UNKNOWN', 'score': None, 'source': 'none', 'fixed': None}
    vid = normalize_vuln_id(cve_id)

    if vid.startswith('CVE-'):
        try:
            r = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={vid}", timeout=5)
            if r.status_code == 200:
                vulns = r.json().get('vulnerabilities', [])
                if vulns:
                    metrics = vulns[0].get('cve', {}).get('metrics', {})
                    for k in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        c = metrics.get(k, [{}])[0].get('cvssData', {})
                        if c:
                            result.update({'severity': c.get('baseSeverity', 'UNKNOWN'),
                                           'score': c.get('baseScore'), 'source': 'NVD'})
                            break
        except Exception:
            pass
        time.sleep(0.6)

    # Look advisories up by id via GET /v1/vulns/{id}; POST /v1/query is for
    # package/commit queries and returns nothing for a bare id.
    try:
        r = requests.get(f"https://api.osv.dev/v1/vulns/{vid}", timeout=5)
        if r.status_code == 200:
            osv = parse_osv(r.json())
            result['fixed'] = osv.get('fixed')
            if result['severity'] == 'UNKNOWN':
                result['severity'] = osv.get('severity', 'UNKNOWN')
            if result['source'] == 'none':
                result['source'] = 'OSV'
    except Exception:
        pass

    if result['severity'] == 'UNKNOWN':
        lc = cve_id.lower()
        if lc.startswith('go-'):
            result['severity'] = 'HIGH'
        elif lc.startswith(('ghsa-', 'pysec-')):
            result['severity'] = 'MEDIUM'

    time.sleep(0.2)
    cache[cve_id] = result
    return result


# --- GUAC query / ingest ---------------------------------------------------

CERTIFY_VULN_QUERY = {"query": """{
  CertifyVulnList(certifyVulnSpec: {}) {
    edges {
      node {
        package { namespaces { namespace names { id name versions { id version qualifiers { key value } } } } }
        vulnerability { id vulnerabilityIDs { id vulnerabilityID } }
      }
    }
  }
}"""}


def query_certify_vuln(guac_url: str) -> List[Dict]:
    """Fetch all CertifyVuln edges from GUAC."""
    try:
        r = requests.post(guac_url, json=CERTIFY_VULN_QUERY, timeout=60)
        if r.status_code == 200:
            data = r.json()
            if 'errors' in data:
                print(f"  GraphQL errors: {data['errors']}")
                return []
            return data.get('data', {}).get('CertifyVulnList', {}).get('edges', [])
    except Exception as e:
        print(f"ERROR: GUAC query failed: {e}")
    return []


def ingest_sbom(guac_url: str, sbom_file: str, label: str, attempts: int = 3) -> bool:
    """Ingest an SBOM via guacone, retrying on timeout/failure since the single
    port-forward connection can drop under load."""
    for i in range(1, attempts + 1):
        try:
            subprocess.run(["guacone", "collect", "--gql-addr", guac_url,
                "--add-vuln-on-ingest", "--add-eol-on-ingest", "--add-license-on-ingest",
                "files", sbom_file], capture_output=True, text=True, check=True, timeout=600)
            print(f"-> Ingested {sbom_file}")
            return True
        except subprocess.TimeoutExpired:
            print(f"  timeout ingesting {label} (attempt {i}/{attempts})")
        except subprocess.CalledProcessError as e:
            tail = (e.stderr or e.stdout or '').strip().splitlines()
            print(f"  ingest error {label} (attempt {i}/{attempts}): {tail[-1][:200] if tail else str(e)[:200]}")
        except Exception as e:
            print(f"  ingest error {label} (attempt {i}/{attempts}): {str(e)[:200]}")
        if i < attempts:
            time.sleep(3 * i)
    print(f"ERROR: Ingestion failed for {label} after {attempts} attempts")
    return False


# --- vuln record handling --------------------------------------------------

def parse_vuln_edge(edge: Dict) -> Optional[Tuple[str, str, str, str]]:
    """Extract (cve_id, full_name, short_name_lc, version) from a CertifyVuln
    edge. Returns None for GUAC "novuln" markers or edges missing a package.

    full_name rebuilds the module path (namespace + name, e.g. golang.org/x/net)
    so it matches the package names recorded from SBOMs.
    """
    node = edge.get('node', {})
    vuln_ids = node.get('vulnerability', {}).get('vulnerabilityIDs', [])
    if not vuln_ids:
        return None
    cve_id = vuln_ids[0].get('vulnerabilityID', '')
    if not cve_id or cve_id.lower() == 'novuln':
        return None
    ns_list = node.get('package', {}).get('namespaces', [])
    if not ns_list:
        return None
    ns = ns_list[0].get('namespace', '') or ''
    names = ns_list[0].get('names', [])
    if not names:
        return None
    short = names[0].get('name', '')
    version = names[0].get('versions', [{}])[0].get('version', 'unknown')
    full = f"{ns}/{short}" if ns else short
    return cve_id, full, short.lower(), version


def build_record(cve_id: str, full_name: str, name_lc: str, version: str, nvd: Dict) -> Dict:
    """Assemble an actionable-vuln dict from a parsed edge and its enrichment."""
    lc = cve_id.lower()
    return {'cve': cve_id, 'package': full_name, 'name_lc': name_lc, 'version': version,
            'severity': nvd.get('severity'), 'score': nvd.get('score'),
            'source': nvd.get('source'), 'fixed': nvd.get('fixed'),
            'is_go': lc.startswith('go-'), 'is_ghsa': lc.startswith('ghsa-'),
            'is_ubuntu': lc.startswith(('ubuntu-', 'usn-'))}


# --- report formatting -----------------------------------------------------

def fmt_vuln(v: Dict) -> str:
    """Format one vuln line: id - package:version (CVSS) -> update to: fix."""
    line = f"       {v['cve']} - {v['package']}:{v['version']}"
    if isinstance(v.get('score'), (int, float)):
        line += f" (CVSS: {v['score']})"
    line += f"  -> update to: {v['fixed']}" if v.get('fixed') else "  -> no fixed version published"
    return line


def print_tier(label: str, items: List[Dict], cap: int = 5):
    """Print a severity tier, capped, with an '... and N more' tail."""
    if not items:
        return
    print(f"    {label}: {len(items)}")
    for v in items[:cap]:
        print(fmt_vuln(v))
    if len(items) > cap:
        print(f"       ... and {len(items) - cap} more")
