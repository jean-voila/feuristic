# Feuristic artwork

`feuristic.sketch` contains editable text, vector shapes, device illustrations
and interface compositions. Exports are committed under `docs/assets/`.

The Safe 3 drawing follows the [official product views](https://trezor.io/trezor-safe-3):
the tapered body, glossy upper face and single split two-button bar. It is an
independent illustration, not a manufacturer photograph. Screen images are
actual T2B1 emulator captures with disposable test identities.

With Sketch installed, regenerate from the repository root:

```sh
python3 tools/export_artwork.py
```

Or open the Sketch file, edit the named artboards and export SVG/PNG at 1×.
The publication assets use the GPL-3.0-only project license.
