#!/usr/bin/env python3
"""Check upstream component releases and recent CVEs; report anything new.

Reads component-watch/state.json, compares against live GitHub releases
and NVD CVE search results, writes findings to component-watch/findings.md
(if any) and updates the state file.
"""
import json
import os
import time
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

COMPONENTS = {
    "OpenVPN": "OpenVPN/openvpn",
    "OpenSSL": "openssl/openssl",
    "curl": "curl/curl",
    "stubby": "getdnsapi/stubby",
    "inadyn": "troglobit/inadyn",
    "miniupnpd": "miniupnp/miniupnp",
    "json-c": "json-c/json-c",
}

CVE_KEYWORDS = ["openssl", "openvpn", "curl", "dnsmasq", "busybox", "json-c", "stubby", "inadyn", "miniupnp"]

# Signals that a CVE is actually about the product (not merely mentioning it).
# NVD keyword search is noisy: it matches any CVE whose description contains
# the word. A CVE is only reported when either:
#   (a) one of its reference URLs points at the vendor (site or GitHub repo), or
#   (b) the product name appears in the description's first sentence.
# New CVEs usually have no CPE configurations yet (NVD "Awaiting Analysis"),
# so CPE filtering cannot be used here.
CVE_SIGNALS = {
    "openssl": {"refs": ["openssl.org", "openssl-library.org", "github.com/openssl/openssl"], "name": "openssl"},
    "openvpn": {"refs": ["openvpn.net", "github.com/openvpn/openvpn"], "name": "openvpn"},
    "curl": {"refs": ["curl.se", "haxx.se", "github.com/curl/curl"], "name": "curl"},
    "dnsmasq": {"refs": ["thekelleys.org.uk", "github.com/imp/dnsmasq"], "name": "dnsmasq"},
    "busybox": {"refs": ["busybox.net", "github.com/mirror/busybox"], "name": "busybox"},
    "json-c": {"refs": ["github.com/json-c/json-c"], "name": "json-c"},
    "stubby": {"refs": ["github.com/getdnsapi/stubby", "getdnsapi.org"], "name": "stubby"},
    "inadyn": {"refs": ["github.com/troglobit/inadyn", "troglobit.com"], "name": "inadyn"},
    "miniupnp": {"refs": ["github.com/miniupnp/miniupnp", "miniupnp.free.fr"], "name": "miniupnp"},
}

STATE_FILE = "component-watch/state.json"
FINDINGS_FILE = "component-watch/findings.md"
LOOKBACK_DAYS = 7


def gh_api(url):
    token = os.environ.get("GH_TOKEN", "")
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "component-watch",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def nvd_search(keyword, start, end):
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "pubStartDate": start,
        "pubEndDate": end,
        "resultsPerPage": 20,
    })
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "component-watch"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def cve_affects_product(cve, signals):
    """True if the CVE is actually about the product (see CVE_SIGNALS)."""
    if not signals:
        return False
    # (a) reference URL points at the vendor
    for ref in cve.get("references", []):
        url = ref.get("url", "").lower()
        if any(s in url for s in signals["refs"]):
            return True
    # (b) product name in the description's first sentence
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            first_sentence = desc.split(".")[0].lower()
            if signals["name"] in first_sentence:
                return True
            break
    return False


def main():
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
    except FileNotFoundError:
        state = {"releases": {}, "cves": []}
    state.setdefault("releases", {})
    state.setdefault("cves", [])

    findings = []
    seen_cves = set(state["cves"])

    # Releases
    for name, repo in COMPONENTS.items():
        try:
            data = gh_api(f"https://api.github.com/repos/{repo}/releases/latest")
            tag = data.get("tag_name", "")
            url = data.get("html_url", "")
            prev = state["releases"].get(name)
            if not tag:
                print(f"WARN: {name}: no tag_name in response")
                continue
            if prev is None:
                print(f"{name}: baseline {tag}")
            elif tag != prev:
                findings.append(f"- New {name} release: `{tag}` (was `{prev}`) — {url}")
            state["releases"][name] = tag
        except Exception as e:
            print(f"WARN: {name} release check failed: {e}")

    # CVEs (NVD, last LOOKBACK_DAYS days)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=LOOKBACK_DAYS)
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    start_s, end_s = start.strftime(fmt), end.strftime(fmt)
    for kw in CVE_KEYWORDS:
        signals = CVE_SIGNALS.get(kw, {})
        try:
            data = nvd_search(kw, start_s, end_s)
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id or cve_id in seen_cves:
                    continue
                if not cve_affects_product(cve, signals):
                    continue
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                findings.append(f"- New CVE for `{kw}`: **{cve_id}** — {desc[:200]} {url}")
                seen_cves.add(cve_id)
        except Exception as e:
            print(f"WARN: CVE search '{kw}' failed: {e}")
        time.sleep(7)  # NVD unauthenticated rate limit: 5 req / 30s

    # Prune CVE list to keep state file small (keep last 200)
    state["cves"] = sorted(seen_cves)[-200:]

    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")

    if findings:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with open(FINDINGS_FILE, "w") as f:
            f.write(f"# Component watch — {today}\n\n")
            f.write("New upstream releases / CVEs since last check:\n\n")
            f.write("\n".join(findings))
            f.write("\n")
        print(f"{len(findings)} finding(s)")
    else:
        if os.path.exists(FINDINGS_FILE):
            os.remove(FINDINGS_FILE)
        print("No new findings")


if __name__ == "__main__":
    main()
