#!/usr/bin/env python3
"""Fail if any relative link or heading anchor in the repo's Markdown is dead.

External (http/https/mailto) links are not fetched; this check is offline and
deterministic so it can run in CI on every push. Anchors follow GitHub's slug
rules: lowercase, punctuation stripped, spaces to hyphens.
"""
import glob
import os
import re
import sys

FENCE = re.compile(r"```.*?```", re.S)
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
HEAD = re.compile(r"^#{1,6}\s+(.*)$", re.M)


def slug(heading):
    h = heading.strip().lower().replace("`", "")
    return re.sub(r"[^\w\- ]", "", h).replace(" ", "-")


def anchors(text):
    return {slug(h) for h in HEAD.findall(FENCE.sub("", text))}


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)
    broken = 0
    for md in sorted(glob.glob("**/*.md", recursive=True)):
        text = FENCE.sub("", open(md, encoding="utf-8").read())
        own = anchors(text)
        for url in LINK.findall(text):
            if url.startswith(("http://", "https://", "mailto:")):
                continue
            path, _, frag = url.partition("#")
            if not path:
                if frag and frag not in own:
                    print(f"{md}: dead anchor #{frag}")
                    broken += 1
                continue
            target = os.path.normpath(os.path.join(os.path.dirname(md), path))
            if not os.path.exists(target):
                print(f"{md}: missing file {url}")
                broken += 1
            elif frag and target.endswith(".md"):
                if frag not in anchors(open(target, encoding="utf-8").read()):
                    print(f"{md}: dead anchor {url}")
                    broken += 1
    print(f"link check: {broken} broken")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
