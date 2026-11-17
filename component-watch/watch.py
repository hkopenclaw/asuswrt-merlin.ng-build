#!/usr/bin/env python3
"""Check upstream component releases and recent CVEs; maintain one rolling issue.

Reads component-watch/state.json, compares against live GitHub releases
and NVD CVE search results, and updates a SINGLE rolling GitHub issue in
this repo (instead of opening a new issue per run).

Rolling issue:
  - Title: "[component-watch] Component releases and CVEs — rolling status"
  - Label: "component-watch" (created automatically if missing)
  - Body: fully rewritten on every run (last-run timestamp, this run's new
    releases/CVEs, already-known tracked state, footer). A run with nothing
    new still rewrites the body (fresh timestamp, "nothing new" status) so
    the user can see the watch is alive, but never creates a new issue and
    never adds a comment.

Legacy per-run issues (#1, #2, #3, ...) have no label, so they are never
matched as the rolling issue. If more than one labelled rolling issue is
ever found (e.g. duplicates created by hand), the newest is updated and a
pointer comment is left on the older ones; none are closed automatically.
"""
import json
import os
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timedelta, timezone

COMPONENTS = {
    "OpenVPN": "OpenVPN/openvpn",
    "OpenSSL": "openssl/openssl",
    "curl": "curl/curl",
    "stubby": "getdnsapi/stubby",
    "inadyn": "troglobit/inadyn",
    "miniupnpd": "miniupnp/miniupnp",
    "json-c": "json-c/json-c",
    "expat": "libexpat/libexpat",
    "zlib": "madler/zlib",
}

# GitLab-hosted components. Unlike GitHub's /releases/latest (single
# latest release), the GitLab releases API returns a list, newest first,
# so each entry also carries a tag prefix: only releases whose tag starts
# with the prefix are tracked. This matters for libxml2: the fork is on
# the 2.13 branch (2.15 bumped the SONAME to libxml2.so.16 and removed
# ELF symbol versioning, so 2.15.x cannot be used), so only 2.13.x
# releases are tracked — a future v2.13.10 security backport would be
# actionable, while 2.15.x releases are not.
GITLAB_COMPONENTS = {
    "libxml2": {"project": "GNOME/libxml2", "prefix": "v2.13."},
}

CVE_KEYWORDS = ["openssl", "openvpn", "curl", "dnsmasq", "busybox", "json-c", "stubby", "inadyn", "miniupnp", "expat", "zlib", "libxml2"]

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
    "expat": {"refs": ["libexpat.org", "github.com/libexpat/libexpat"], "name": "expat"},
    "zlib": {"refs": ["zlib.net", "github.com/madler/zlib"], "name": "zlib"},
    "libxml2": {"refs": ["gitlab.gnome.org/GNOME/libxml2", "xmlsoft.org"], "name": "libxml2"},
}

STATE_FILE = "component-watch/state.json"
ISSUE_BODY_FILE = "component-watch/issue-body.md"
LOOKBACK_DAYS = 7

ROLLING_TITLE = "[component-watch] Component releases and CVEs — rolling status"
ROLLING_LABEL = "component-watch"
ROLLING_LABEL_COLOR = "0E8A16"
ROLLING_LABEL_DESC = "Component-watch rolling status issue"


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


def gitlab_api(url):
    """Unauthenticated GitLab API GET (public projects need no token)."""
    headers = {"User-Agent": "component-watch"}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def gitlab_latest_release(project, prefix):
    """Latest GitLab release whose tag starts with `prefix`.

    The GitLab releases API returns a list, newest first. Returns
    (tag, url, released_at) or (\"\", \"\", \"\") when no release matches.
    """
    encoded = urllib.parse.quote(project, safe="")
    url = (f"https://gitlab.gnome.org/api/v4/projects/{encoded}"
           f"/releases?per_page=30")
    releases = gitlab_api(url)
    for rel in releases:
        tag = rel.get("tag_name", "")
        if tag and tag.startswith(prefix):
            page = (f"https://gitlab.gnome.org/{project}"
                    f"/-/releases/{urllib.parse.quote(tag, safe='')}")
            return tag, page, rel.get("released_at", "")
    return "", "", ""


def gh_api_request(method, url, payload=None):
    """GitHub API call with a JSON body (POST/PATCH). Returns parsed JSON."""
    token = os.environ.get("GH_TOKEN", "")
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "component-watch",
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
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


def cve_severity(cve):
    """Best available CVSS base score + severity, or ('', '') if unknown.

    Prefers CVSS v3.1, then v3.0, then v2.0. New CVEs often have no metrics
    yet (NVD "Awaiting Analysis"), so empty is a normal result.
    """
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore", "")
            sev = data.get("baseSeverity", "")
            return (str(score), sev)
    return ("", "")


def render_body(run_time, new_releases, new_cves, state):
    """Render the rolling issue body from this run's findings + full state."""
    lines = []
    lines.append("# Component watch — rolling status")
    lines.append("")
    n_rel = len(new_releases)
    n_cve = len(new_cves)
    if n_rel or n_cve:
        summary = f"{n_rel} new release(s), {n_cve} new CVE(s) since last check."
    else:
        summary = "nothing new since last check."
    lines.append(f"Last run: {run_time} — {summary}")
    lines.append("")

    lines.append("## New releases")
    if new_releases:
        for r in new_releases:
            line = f"- **{r['name']}**: `{r['old']}` → `{r['new']}` — {r['url']}"
            if r.get("published_at"):
                line += f" (published {r['published_at'][:10]})"
            lines.append(line)
    else:
        lines.append("_None since last check._")
    lines.append("")

    lines.append("## New CVEs")
    if new_cves:
        for c in new_cves:
            sev = ""
            if c.get("score"):
                sev = f", CVSS {c['score']}"
                if c.get("severity"):
                    sev += f" {c['severity']}"
            lines.append(f"- **{c['id']}** (`{c['keyword']}`{sev}) — {c['desc'][:200]} {c['url']}")
    else:
        lines.append("_None since last check._")
    lines.append("")

    lines.append("## Already known / tracked")
    lines.append("Current tracked releases:")
    for name in COMPONENTS:
        tag = state["releases"].get(name, "(unknown)")
        lines.append(f"- {name}: `{tag}`")
    for name in GITLAB_COMPONENTS:
        tag = state["releases"].get(name, "(unknown)")
        lines.append(f"- {name}: `{tag}`")
    lines.append("")
    cve_list = state.get("cves", [])
    lines.append(f"Tracked CVEs: {len(cve_list)} total.")
    if cve_list:
        lines.append("<details>")
        lines.append("<summary>Full CVE list</summary>")
        lines.append("")
        for cve_id in sorted(cve_list):
            lines.append(f"- {cve_id}")
        lines.append("")
        lines.append("</details>")
    lines.append("")

    lines.append("---")
    lines.append("_This issue is maintained automatically by the component-watch workflow (daily, 00:00 UTC). It is rewritten on every run; do not edit it by hand — your edits will be overwritten._")
    lines.append("_Older per-run issues (#1, #2, #3) are superseded by this rolling issue._")
    lines.append("")
    return "\n".join(lines)


def repo_base_url():
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not repo or "/" not in repo:
        raise RuntimeError("GITHUB_REPOSITORY env var not set (expected owner/repo)")
    return f"https://api.github.com/repos/{repo}"


def ensure_label(base):
    """Create the rolling-issue label if it does not exist yet."""
    try:
        gh_api_request("POST", f"{base}/labels", {
            "name": ROLLING_LABEL,
            "color": ROLLING_LABEL_COLOR,
            "description": ROLLING_LABEL_DESC,
        })
        print(f"Created label '{ROLLING_LABEL}'")
    except urllib.error.HTTPError as e:
        if e.code == 422:
            # Already exists.
            pass
        else:
            raise


def find_rolling_issues(base):
    """Open issues carrying the rolling label whose title starts with
    '[component-watch]'. Returns a list of issue dicts, sorted by number.
    Pull requests are excluded. Legacy per-run issues have no label, so
    they are never matched here."""
    url = (f"{base}/issues?labels={urllib.parse.quote(ROLLING_LABEL)}"
           f"&state=open&per_page=100")
    issues = gh_api(url)
    found = []
    for issue in issues:
        if "pull_request" in issue:
            continue
        title = issue.get("title", "")
        if title.startswith("[component-watch]"):
            found.append(issue)
    found.sort(key=lambda i: i["number"])
    return found


def update_rolling_issue(base, body):
    """Find-or-create the rolling issue and rewrite its body.

    Returns the issue number. Never creates a duplicate: the rolling issue
    is identified by label + title prefix, so repeated runs update the
    same issue. If several labelled issues exist, the newest is updated
    and a pointer comment is left on the older ones (none are closed)."""
    ensure_label(base)
    found = find_rolling_issues(base)
    if not found:
        issue = gh_api_request("POST", f"{base}/issues", {
            "title": ROLLING_TITLE,
            "body": body,
            "labels": [ROLLING_LABEL],
        })
        print(f"Created rolling issue #{issue['number']}")
        return issue["number"]
    target = found[-1]
    gh_api_request("PATCH", f"{base}/issues/{target['number']}", {"body": body})
    print(f"Updated rolling issue #{target['number']}")
    for older in found[:-1]:
        gh_api_request("POST", f"{base}/issues/{older['number']}/comments", {
            "body": (f"Superseded by the rolling status issue "
                     f"#{target['number']} — this duplicate will no longer be updated."),
        })
        print(f"Left pointer comment on duplicate rolling issue #{older['number']}")
    return target["number"]


def main():
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
    except FileNotFoundError:
        state = {"releases": {}, "cves": []}
    state.setdefault("releases", {})
    state.setdefault("cves", [])

    new_releases = []
    new_cves = []
    seen_cves = set(state["cves"])

    # Releases
    for name, repo in COMPONENTS.items():
        try:
            data = gh_api(f"https://api.github.com/repos/{repo}/releases/latest")
            tag = data.get("tag_name", "")
            url = data.get("html_url", "")
            published = data.get("published_at", "")
            prev = state["releases"].get(name)
            if not tag:
                print(f"WARN: {name}: no tag_name in response")
                continue
            if prev is None:
                print(f"{name}: baseline {tag}")
            elif tag != prev:
                new_releases.append({
                    "name": name, "old": prev, "new": tag,
                    "url": url, "published_at": published,
                })
            state["releases"][name] = tag
        except Exception as e:
            print(f"WARN: {name} release check failed: {e}")

    # Releases (GitLab-hosted; prefix-filtered, see GITLAB_COMPONENTS)
    for name, spec in GITLAB_COMPONENTS.items():
        try:
            tag, url, published = gitlab_latest_release(
                spec["project"], spec["prefix"])
            prev = state["releases"].get(name)
            if not tag:
                print(f"WARN: {name}: no release matching "
                      f"prefix {spec['prefix']!r}")
                continue
            if prev is None:
                print(f"{name}: baseline {tag}")
            elif tag != prev:
                new_releases.append({
                    "name": name, "old": prev, "new": tag,
                    "url": url, "published_at": published,
                })
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
                score, severity = cve_severity(cve)
                url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                new_cves.append({
                    "id": cve_id, "keyword": kw, "score": score,
                    "severity": severity, "desc": desc, "url": url,
                })
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

    run_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = render_body(run_time, new_releases, new_cves, state)
    os.makedirs(os.path.dirname(ISSUE_BODY_FILE), exist_ok=True)
    with open(ISSUE_BODY_FILE, "w") as f:
        f.write(body)
    print(f"{len(new_releases)} new release(s), {len(new_cves)} new CVE(s)")

    # Update the rolling issue (skip silently when no token, e.g. local run).
    if not os.environ.get("GH_TOKEN", ""):
        print("No GH_TOKEN — skipping rolling issue update (body written to "
              f"{ISSUE_BODY_FILE})")
        return
    try:
        base = repo_base_url()
    except RuntimeError as e:
        print(f"WARN: {e} — skipping rolling issue update")
        return
    update_rolling_issue(base, body)


if __name__ == "__main__":
    main()
