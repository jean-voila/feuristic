#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Notify IndexNow search engines (Bing, Yandex, Seznam, Naver) of updated pages.

Reads the deployed sitemap and submits the pages modified since yesterday
(commit dates may be in a timezone ahead of UTC), or every page with --all.
The key file is published at the site root.
"""

import argparse
import datetime
import json
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlsplit

KEY = "fd549dd5f9d144bf76eb7ccb157d2a3d"
SITEMAP = "{http://www.sitemaps.org/schemas/sitemap/0.9}"


def changed_pages(sitemap, since):
    root = ET.fromstring(sitemap)  # noqa: S314 - our own build output
    for url in root.iter(f"{SITEMAP}url"):
        if since is None or url.findtext(f"{SITEMAP}lastmod", "") >= since:
            yield url.findtext(f"{SITEMAP}loc")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site_url")
    parser.add_argument("--sitemap", required=True, help="sitemap.xml of the deployed build")
    parser.add_argument("--all", action="store_true", help="submit every page")
    args = parser.parse_args()
    with open(args.sitemap, encoding="utf-8") as f:
        yesterday = datetime.date.today() - datetime.timedelta(days=1)
        pages = list(changed_pages(f.read(), None if args.all else yesterday.isoformat()))
    if not pages:
        print("No recently modified page.")
        return
    payload = {
        "host": urlsplit(args.site_url).hostname,
        "key": KEY,
        "keyLocation": urljoin(args.site_url, f"{KEY}.txt"),
        "urlList": pages,
    }
    request = urllib.request.Request(
        "https://api.indexnow.org/indexnow",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed HTTPS endpoint
        print(f"IndexNow accepted {len(pages)} URLs: HTTP {response.status}")


if __name__ == "__main__":
    main()
