<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Documentation and artwork

Build or preview the site without the ARM toolchain:

```sh
uv sync --frozen --only-group docs
uv run --no-sync mkdocs serve
uv run --no-sync mkdocs build --strict
```

The Documentation workflow builds every change and deploys `main` through
GitHub Actions to GitHub Pages. Pull requests build without deployment rights.
The source repository can remain private while its Pages site is public.

Page titles and descriptions belong in Markdown front matter. Repository-file
references are resolved by `tools/docs_hooks.py`; internal documentation links
remain ordinary Markdown. The site uses local assets and system fonts.

Editable visual sources live in `assets/design/feuristic.sketch`. Open the
named artboards in Sketch to edit text, colors, device shapes and diagrams.
Exports under `docs/assets/` are used by the README and documentation.
The device drawing is an illustration of Safe 3 geometry, not a product photo.
Screens are recorded from the firmware emulator using disposable identities.

To regenerate the artwork with Sketch installed, run the command documented in
[the artwork directory](../../assets/design/README.md). Preserve the exported
artboard names so existing links continue to work.
