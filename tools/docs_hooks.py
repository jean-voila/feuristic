# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Page metadata and links between the documentation and source repository."""

import functools
import html
import json
import posixpath
import re
import subprocess
from pathlib import Path
from urllib.parse import quote, urljoin

REPOSITORY = "https://github.com/jean-voila/feuristic"
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOCALE = "en"
OG_LOCALES = {"en": "en_US", "fr": "fr_FR"}
# Material writes relative hreflang links; theme/main.html writes absolute ones.
MATERIAL_HREFLANG = re.compile(r'\s*<link rel="alternate" href="[^"]*" hreflang="[^"]*">')


@functools.cache
def version():
    source = (ROOT / "src/feuristic/version.py").read_text(encoding="utf-8")
    return re.search(r'^VERSION = "([^"]+)"', source, re.M).group(1)


@functools.cache
def commit_dates():
    """Date of the last commit touching each documentation source."""
    try:
        log = subprocess.run(
            ["git", "log", "--format=%x00%cs", "--name-only", "--", "docs"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return {}
    dates, date = {}, None
    for line in log.splitlines():
        if line.startswith("\0"):
            date = line[1:]
        elif line:
            dates.setdefault(line, date)
    return dates


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


def translations(page, config, locale):
    """Absolute URLs of the real translations of a page, by language."""
    hreflang = {
        code: urljoin(config.site_url, alternate.url)
        for code, alternate in page.file.alternates.items()
        if code == locale or (alternate.locale == code and alternate.abs_src_path != page.file.abs_src_path)
    }
    if len(hreflang) < 2:
        return {}
    hreflang["x-default"] = hreflang[DEFAULT_LOCALE]
    return hreflang


def page_description(content, config):
    text = re.sub(r"<h1\b.*?</h1>|<a class=\"headerlink\".*?</a>", " ", content, flags=re.S)
    text = " ".join(html.unescape(re.sub(r"<[^>]+>", " ", text)).split())
    if len(text) > 160:
        text = text[:157].rsplit(" ", 1)[0] + "…"
    return text or config.site_description


def structured_data(page, config, locale, home):
    website = {
        "@type": "WebSite",
        "@id": urljoin(config.site_url, "#website"),
        "name": config.site_name,
        "url": config.site_url,
        "inLanguage": list(OG_LOCALES),
    }
    software = {
        "@type": "SoftwareApplication",
        "@id": urljoin(config.site_url, "#software"),
        "name": config.site_name,
        "description": config.site_description,
        "url": config.site_url,
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "Trezor Safe 3 (T2B1, T3B1)",
        "softwareVersion": version(),
        "downloadUrl": f"{REPOSITORY}/releases/latest",
        "license": "https://www.gnu.org/licenses/gpl-3.0.html",
        "isAccessibleForFree": True,
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "EUR"},
        "sameAs": [REPOSITORY],
    }
    if home:
        graph = [
            website,
            software,
            {
                "@type": "SoftwareSourceCode",
                "name": config.site_name,
                "codeRepository": REPOSITORY,
                "license": software["license"],
                "programmingLanguage": ["MicroPython", "C", "Rust"],
                "runtimePlatform": "Trezor Safe 3 T2B1 and T3B1",
                "targetProduct": {"@id": software["@id"]},
            },
        ]
    else:
        title = page.meta.get("title") or page.title
        article = {
            "@type": "TechArticle",
            "headline": title,
            "description": page.meta["description"],
            "url": page.canonical_url,
            "inLanguage": page.meta.get("content_language", locale),
            "isPartOf": {"@id": website["@id"]},
            "about": {"@id": software["@id"]},
            "dateModified": page.update_date,
        }
        home_url = urljoin(config.site_url, "" if locale == DEFAULT_LOCALE else f"{locale}/")
        breadcrumb = {
            "@type": "BreadcrumbList",
            "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": config.site_name, "item": home_url},
                {"@type": "ListItem", "position": 2, "name": title, "item": page.canonical_url},
            ],
        }
        graph = [website, software, article, breadcrumb]
    data = {"@context": "https://schema.org", "@graph": graph}
    return json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")


def on_page_content(content, page, config, files):
    # Runs before the sitemap is rendered, unlike on_page_context.
    locale = config.plugins["i18n"].current_language
    content_locale = page.meta.get("content_language", page.file.locale)
    page.update_date = commit_dates().get(f"docs/{page.file.src_uri}", page.update_date)
    page.meta.setdefault("description", page_description(content, config))
    # Untranslated pages are copied into every language. Only the copy in the
    # language of their content is indexed; the others point to it.
    page.meta["duplicate"] = content_locale != locale and content_locale in page.file.alternates
    if page.meta["duplicate"]:
        page.canonical_url = urljoin(config.site_url, page.file.alternates[content_locale].url)
        page.meta["hreflang"] = {}
    else:
        page.meta["hreflang"] = translations(page, config, locale)
    return content


def on_page_context(context, page, config, nav):
    locale = context["i18n_page_locale"]
    content_locale = page.meta.get("content_language", page.file.locale)
    home = page.file.src_uri in ("index.md", "index.fr.md")
    context["page_description"] = page.meta["description"]
    context["project_home"] = home
    context["og_locale"] = OG_LOCALES[content_locale]
    context["og_locale_alternates"] = [
        OG_LOCALES[code] for code in page.meta["hreflang"] if code in OG_LOCALES and code != locale
    ]
    # The language plugin publishes assets/social.fr.png as fr/assets/social.png.
    prefix = "" if locale == DEFAULT_LOCALE else f"{locale}/"
    context["social_image"] = urljoin(config.site_url, f"{prefix}assets/social.png")
    if not page.meta["duplicate"]:
        context["structured_data"] = structured_data(page, config, locale, home)
    return context


def on_post_page(output, page, config):
    head, separator, body = output.partition("</head>")
    return MATERIAL_HREFLANG.sub("", head) + separator + body
