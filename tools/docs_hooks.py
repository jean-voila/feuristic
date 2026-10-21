# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Page metadata and links between the documentation and source repository."""

import html
import json
import posixpath
import re
from pathlib import Path
from urllib.parse import quote, urljoin

REPOSITORY = "https://github.com/jean-voila/feuristic"
ROOT = Path(__file__).resolve().parent.parent


def on_page_markdown(markdown, page, config, files):
    def rewrite(match):
        target = match.group(2)
        if ":" in target or target.startswith(("#", "/")):
            return match.group(0)
        path, separator, fragment = target.partition("#")
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(page.file.src_uri), path))
        if resolved.startswith("../"):
            source = resolved[3:]
            if (ROOT / source).exists():
                target = f"{REPOSITORY}/blob/main/{quote(source, safe='/')}"
                if separator:
                    target += "#" + fragment
        return match.group(1) + target + match.group(3)

    return re.sub(r"(\]\()([^\s)]+)(\))", rewrite, markdown)


def on_page_context(context, page, config, nav):
    description = page.meta.get("description")
    if not description:
        text = re.sub(r"<[^>]+>", " ", page.content)
        text = " ".join(html.unescape(text).split())
        description = text[:180].rsplit(" ", 1)[0] or config.site_description
    page.meta["description"] = description
    context["page_description"] = description
    context["social_image"] = urljoin(config.site_url, "assets/social.png")
    context["structured_data"] = json.dumps(
        {
            "@context": "https://schema.org",
            "@type": "SoftwareSourceCode",
            "name": "Feuristic",
            "description": config.site_description,
            "url": config.site_url,
            "codeRepository": REPOSITORY,
            "license": "https://www.gnu.org/licenses/gpl-3.0.html",
            "programmingLanguage": ["MicroPython", "C", "Rust"],
            "runtimePlatform": "Trezor Safe 3 T2B1 and T3B1",
            "isAccessibleForFree": True,
        },
        ensure_ascii=False,
    ).replace("<", "\\u003c")
    return context
