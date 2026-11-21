#!/usr/bin/env python3
"""Generate a GitHub release draft for an RT-AC68U Merlin build.

The script does the mechanical assembly; it does NOT decide the final
wording. Review the draft, delete build-only lines, group related
commits, and check every link before publishing.

Usage:
    python3 gen-release.py <old_ref> <new_ref> [--trx PATH] [--run N]
                           [--note PATH] [--fork DIR] [--out DIR]

  <old_ref>, <new_ref>   fork commits bracketing the release, e.g.
                         9410e685 (386.14_8) and 10953156b7 (386.14_9).
  --trx PATH             the built .trx file. A copy renamed to
                         RT-AC68U_386.14_<new>.trx plus a matching
                         RT-AC68U_386.14_<new>.md5 are written to --out.
  --run N                GitHub Actions workflow run number, for the
                         Build line. The workflow commit is fetched from
                         the public API; on failure a TODO is printed.
  --note PATH            the fwcheck note file for the new version
                         (e.g. fwcheck/386_14_9_note-amended.txt).
                         Its bullets are cross-checked against
                         Changelog-386.txt so fixes omitted from the
                         changelog are not lost.
  --fork DIR             fork clone (default: the usual VM location).
  --out DIR              output dir (default: ./release-386.14_<new>/).

Outputs (in --out):
  RELEASE-BODY-DRAFT.md  the release body draft (also printed to stdout)
  COMMIT-INVENTORY.md    every commit in old_ref..new_ref, with links,
                         so nothing in the range is silently dropped
  RT-AC68U_386.14_<new>.trx / .md5   (only with --trx)

Change descriptions come from the new version's Changelog-386.txt entry
(the version-bump commit), supplemented by fwcheck-note bullets that the
changelog does not cover. Each line is matched to commit(s) by keyword
overlap with the commit subject; ambiguous or unmatched lines are marked
TODO in the draft instead of guessed.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request

FORK_DEFAULT = os.path.expanduser(
    "~/workspace/phase2-research/work-port/fork")
REPO = "hkopenclaw/asuswrt-merlin.ng"
BUILD_REPO = "hkopenclaw/asuswrt-merlin.ng-build"

NOTE_BLOCK = (
    "  - NOTE: This is NOT an official Asuswrt-Merlin release.\n"
    "          It is an unofficial build based on 386.14_2, with\n"
    "          security updates and selected feature backports.\n"
)

# Words that carry no matching value; everything else in a change line
# or a commit subject is a potential keyword.
STOPWORDS = {
    "to", "the", "a", "an", "and", "or", "of", "on", "in", "for", "with",
    "now", "from", "before", "after", "update", "updated", "fix", "fixed",
    "change", "changed", "use", "uses", "using", "add", "added", "show",
    "shows", "history", "dialog", "reads", "read", "this", "that", "is",
}


def run_git(fork, *args):
    """Run git in the fork clone; return stdout (stripped of trailing NL)."""
    out = subprocess.run(
        ["git", "-C", fork, *args],
        capture_output=True, text=True, check=True)
    return out.stdout


def full_sha(fork, ref):
    return run_git(fork, "rev-parse", ref).strip()


def short_sha(full):
    return full[:10]


def commit_url(full):
    return "https://github.com/%s/commit/%s" % (REPO, full)


def link(full):
    return "([%s](%s))" % (short_sha(full), commit_url(full))


def version_at(fork, ref):
    """EXTENDNO at a ref, e.g. '9' for 386.14_9."""
    text = run_git(fork, "show", "%s:release/src-rt/version.conf" % ref)
    m = re.search(r"^EXTENDNO=(\d+)\s*$", text, re.M)
    if not m:
        raise SystemExit("cannot find EXTENDNO at %s" % ref)
    return m.group(1)


def changelog_entry(fork, ref, new_ver):
    """Return (date, [change lines]) for 386.14_<new_ver> in Changelog."""
    text = run_git(fork, "show", "%s:Changelog-386.txt" % ref)
    lines = text.splitlines()
    header_re = re.compile(r"^386\.14_%s \(([^)]+)\)" % re.escape(new_ver))
    start = None
    date = None
    for i, line in enumerate(lines):
        m = header_re.match(line)
        if m:
            start = i
            date = m.group(1)
            break
    if start is None:
        raise SystemExit(
            "no 386.14_%s entry in Changelog-386.txt at %s "
            "(was the version bump done?)" % (new_ver, ref))
    changes = []
    for line in lines[start + 1:]:
        if line.startswith("386.14_"):  # next version's entry
            break
        if line.startswith("  - NOTE:"):
            continue  # the fixed NOTE block is emitted once, below
        if line.startswith("  - "):
            changes.append(line[4:].strip())
    return date, changes


def note_bullets(path):
    """Bullets ('- ...') from a fwcheck note file."""
    bullets = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("- "):
                bullets.append(line[2:].strip())
    return bullets


def keywords(text):
    """Distinctive lowercase words of a change line or commit subject.

    A trailing '.' is stripped from each token: a change line usually
    ends in a full stop ("tor to 0.4.9.17.") while a commit subject does
    not, and without this the version token would never match.
    """
    words = re.findall(r"[A-Za-z0-9][A-Za-z0-9_.\-+]*", text.lower())
    out = set()
    for w in words:
        w = w.rstrip(".")
        if w not in STOPWORDS and len(w) > 1:
            out.add(w)
    return out


def version_tokens(text):
    """Version-like tokens, e.g. {'8.23.0'} for 'curl to 8.23.0'."""
    return set(re.findall(r"\d+\.\d+(?:\.\d+)*", text))


CAT_PREFIX = re.compile(r"^(UPDATED|FIXED|CHANGED|REVERTED):\s*", re.I)
CAT_WORD = re.compile(r"^(updated|fixed|reverted|changed)\b\s*", re.I)


def split_category(text):
    """Strip an explicit category prefix/word; return (category, text).

    Changelog lines already carry one ("UPDATED: curl to 8.23.0.");
    fwcheck-note bullets sometimes do ("Reverted the mobile ...").
    Returns (None, text) when the line carries no category.
    """
    m = CAT_PREFIX.match(text)
    if m:
        return m.group(1).upper(), text[m.end():]
    m = CAT_WORD.match(text)
    if m:
        rest = text[m.end():]
        return m.group(1).upper(), rest[:1].upper() + rest[1:]
    return None, text


def category_from_subject(subject):
    """Category implied by a commit subject's leading verb, or None."""
    low = subject.lower()
    if low.startswith("fix"):
        return "FIXED"
    if low.startswith("revert"):
        return "REVERTED"
    if low.startswith("update") or low.startswith("updated"):
        return "UPDATED"
    return None


def wrap_change(cat, text):
    """A change line wrapped to ~60 columns, as in the 386.14_8/9 bodies.

    First line carries the "  - CAT: " prefix; continuation lines are
    indented to align under the text start (the prefix width). Link
    lines are not wrapped.
    """
    import textwrap
    prefix = "  - %s: " % cat
    wrapped = textwrap.wrap(
        text + ".", width=60, initial_indent=prefix,
        subsequent_indent=" " * len(prefix),
        break_long_words=False, break_on_hyphens=False)
    return wrapped


def links(fulls):
    """Commit links in one pair of parens: ([a](url), [b](url))."""
    inner = ", ".join("[%s](%s)" % (short_sha(f), commit_url(f))
                      for f in fulls)
    return "(%s)" % inner


def category_for(text):
    """Body category (UPDATED/FIXED/CHANGED/REVERTED) from the wording."""
    low = text.lower()
    if low.startswith("revert") or "revert" in low:
        return "REVERTED"
    if low.startswith("fix") or " fixed" in low or " fix " in low:
        return "FIXED"
    if "update" in low:
        return "UPDATED"
    return "CHANGED"


def match_commits(change, commits):
    """Return (matched, ambiguous) for a change line.

    When the change names version numbers, every commit in the range
    carrying one of those numbers (and sharing a keyword with the
    change) matches -- a line can cover two commits, e.g. nano 7.2
    plus ncurses 6.3. Matches are ordered by where their version
    number appears in the change line, so nano comes before ncurses.
    Otherwise the commits with the highest keyword overlap match.
    ambiguous is True only when several commits tie on keyword overlap
    and a human must choose; version-number matches are not ambiguous.
    """
    want = keywords(change)
    versions = version_tokens(change)
    if versions:
        matched = []
        for c in commits:
            shared = version_tokens(c["subject"]) & versions
            if shared and keywords(c["subject"]) & want:
                # Position of the earliest shared version number in the
                # change line, for ordering.
                pos = min(change.find(v) for v in shared)
                matched.append((pos, c))
        if matched:
            matched.sort(key=lambda p: p[0])
            return [c for _, c in matched], False
    scored = [(len(want & keywords(c["subject"])), c) for c in commits]
    scored = [(s, c) for s, c in scored if s]
    if not scored:
        return [], False
    best = max(s for s, _ in scored)
    matched = [c for s, c in scored if s == best]
    return matched, len(matched) > 1


def fetch_run(run_no):
    """Workflow run head_sha + date from the public API, or (None, None).

    run_no is the run NUMBER the Actions UI shows (e.g. 28), not the
    run id. Run numbers are per workflow, so match both the number and
    the workflow name. Returns (None, None) on any failure (including
    the API rate limit); the caller prints a TODO instead.
    When GITHUB_TOKEN is set (as in CI), it is sent as a Bearer token,
    which raises the API rate limit from 60 to 5000 requests/hour.
    """
    url = ("https://api.github.com/repos/%s/actions/runs?per_page=30"
           % BUILD_REPO)
    req = urllib.request.Request(url)
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
        for run in d.get("workflow_runs", []):
            if (run.get("run_number") == int(run_no)
                    and run.get("name") == "Build Merlin firmware "
                    "(386 models)"):
                return run.get("head_sha"), (run.get("created_at") or "")[:10]
        return None, None
    except Exception as e:  # noqa: BLE001 - API may be rate-limited
        print("warning: could not fetch workflow run %s: %s"
              % (run_no, e), file=sys.stderr)
        return None, None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("old_ref")
    ap.add_argument("new_ref")
    ap.add_argument("--trx")
    ap.add_argument("--run")
    ap.add_argument("--note")
    ap.add_argument("--fork", default=FORK_DEFAULT)
    ap.add_argument("--out")
    args = ap.parse_args()

    fork = args.fork
    old_full = full_sha(fork, args.old_ref)
    new_full = full_sha(fork, args.new_ref)
    new_ver = version_at(fork, args.new_ref)
    old_ver = version_at(fork, args.old_ref)
    date, changelog_lines = changelog_entry(fork, args.new_ref, new_ver)

    # Commits in the range, oldest first.
    raw = run_git(fork, "log", "--format=%H|%h|%ad|%s", "--date=short",
                  "%s..%s" % (old_full, new_full))
    commits = []
    for line in reversed(raw.splitlines()):
        if not line.strip():
            continue
        full, short, when, subject = line.split("|", 3)
        commits.append({"full": full, "short": short,
                        "date": when, "subject": subject})
    if not commits:
        raise SystemExit("no commits in %s..%s" % (old_full, new_full))

    # Change list: changelog entry first, then note bullets the changelog
    # does not already cover (keyword overlap decides coverage).
    changes = list(changelog_lines)
    covered = set()
    for line in changes:
        covered |= keywords(line)
    if args.note:
        for bullet in note_bullets(args.note):
            if keywords(bullet) & covered:
                continue  # already in the changelog entry
            changes.append(bullet + "  [from fwcheck note]")
            covered |= keywords(bullet)

    # Build the body.
    body = []
    body.append("386.14_%s (%s) - UNOFFICIAL custom build" % (new_ver, date))
    body.append(NOTE_BLOCK.rstrip("\n"))
    todos = []
    for change in changes:
        cat, text = split_category(
            change.replace("  [from fwcheck note]", ""))
        text = text.rstrip(".").strip()
        matched, ambiguous = match_commits(text, commits)
        if not matched:
            if cat is None:
                cat = category_for(text)
            body.extend(wrap_change(cat, text))
            body.append("             [TODO: link - no matching commit]")
            todos.append(change)
        else:
            if cat is None:
                cat = (category_from_subject(matched[0]["subject"])
                       or category_for(text))
            body.extend(wrap_change(cat, text))
            body.append("             " +
                        links([c["full"] for c in matched]))
            if ambiguous:
                body.append("             [TODO: check - %d candidate "
                            "commits]" % len(matched))
                todos.append(change)
    body.append("")
    body.append("Source: %s @ %s (branch 386.14_x)." % (REPO, new_full))
    if args.run:
        wf_sha, wf_date = fetch_run(args.run)
        if wf_sha:
            body.append("Build: %s, workflow run #%s (%s), workflow commit %s."
                        % (BUILD_REPO, args.run, wf_date, wf_sha))
        else:
            body.append("Build: %s, workflow run #%s (TODO: workflow commit)."
                        % (BUILD_REPO, args.run))
    else:
        body.append("Build: %s, workflow run #TODO (TODO: date, workflow "
                    "commit)." % BUILD_REPO)
    body_text = "\n".join(body) + "\n"

    out_dir = args.out or ("release-386.14_%s" % new_ver)
    os.makedirs(out_dir, exist_ok=True)

    draft_path = os.path.join(out_dir, "RELEASE-BODY-DRAFT.md")
    with open(draft_path, "w", encoding="utf-8") as f:
        f.write(body_text)

    inv_path = os.path.join(out_dir, "COMMIT-INVENTORY.md")
    with open(inv_path, "w", encoding="utf-8") as f:
        f.write("# Commits in %s..%s (%d)\n\n"
                % (short_sha(old_full), short_sha(new_full), len(commits)))
        f.write("Old version 386.14_%s, new version 386.14_%s.\n\n"
                % (old_ver, new_ver))
        for c in commits:
            f.write("- %s %s %s\n  %s\n"
                    % (c["date"], c["short"], c["subject"],
                       commit_url(c["full"])))

    # Assets.
    if args.trx:
        trx_name = "RT-AC68U_386.14_%s.trx" % new_ver
        dst = os.path.join(out_dir, trx_name)
        shutil.copyfile(args.trx, dst)
        h = hashlib.md5()
        with open(dst, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        md5 = h.hexdigest()
        md5_path = os.path.join(out_dir, trx_name.replace(".trx", ".md5"))
        with open(md5_path, "w", encoding="utf-8") as f:
            f.write("%s  %s\n" % (md5, trx_name))
        # Sanity: the copy must hash identically to the source.
        h2 = hashlib.md5()
        with open(args.trx, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h2.update(chunk)
        assert h2.hexdigest() == md5, "trx copy hash mismatch"
        print("assets: %s (%d bytes), %s (%d bytes)"
              % (trx_name, os.path.getsize(dst),
                 os.path.basename(md5_path), os.path.getsize(md5_path)))

    print(body_text)
    print("---")
    print("range: %s..%s (%d commits, 386.14_%s -> 386.14_%s)"
          % (short_sha(old_full), short_sha(new_full), len(commits),
             old_ver, new_ver))
    print("draft: %s" % draft_path)
    print("inventory: %s" % inv_path)
    if todos:
        print("TODO lines needing a human decision (%d):" % len(todos))
        for t in todos:
            print("  - %s" % t)
    else:
        print("no lines need a human decision")


if __name__ == "__main__":
    main()
