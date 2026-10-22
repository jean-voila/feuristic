// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
const sketch = require("sketch");
module.exports = function (root) {
    const output = root + "/docs/assets";
    const pixels = JSON.parse(
        String(
            NSString.stringWithContentsOfFile_encoding_error(
                root + "/assets/design/screen-pixels.json",
                NSUTF8StringEncoding,
                null,
            ),
        ),
    );
    const { Document, Page, Artboard, ShapePath, Text } = sketch;
    const C = {
        paper: "#F3F3EB",
        ink: "#102D23",
        green: "#315E46",
        lime: "#D2EF75",
        metal: "#B7BDB7",
        body: "#202521",
        glass: "#090D0B",
        white: "#EDF5E9",
        mute: "#607169",
    };
    const doc = new Document();
    const page = doc.pages[0];
    page.name = "feuristic";
    function rect(parent, name, x, y, w, h, fill, radius = 0, border = null) {
        const a = new ShapePath({
            parent,
            name,
            frame: { x, y, width: w, height: h },
            style: {
                fills: fill ? [fill] : [],
                borders: border ? [{ color: border, thickness: 1.5 }] : [],
            },
        });
        if (radius) a.points.forEach((p) => (p.cornerRadius = radius));
        return a;
    }
    function path(parent, name, d, x, y, w, h, fill, border = null, width = 1) {
        const a = ShapePath.fromSVGPath(d);
        a.parent = parent;
        a.name = name;
        a.frame = { x, y, width: w, height: h };
        a.style = {
            fills: fill ? [fill] : [],
            borders: border ? [{ color: border, thickness: width }] : [],
        };
        return a;
    }
    function text(
        parent,
        name,
        value,
        x,
        y,
        w,
        size = 32,
        color = C.ink,
        weight = 5,
    ) {
        return new Text({
            parent,
            name,
            text: value,
            frame: { x, y, width: w, height: size * 2.6 },
            fixedWidth: true,
            style: {
                fontFamily: "Helvetica Neue",
                fontSize: size,
                fontWeight: weight,
                textColor: color,
                lineHeight: size * 1.25,
            },
        });
    }
    function board(name, x, y, w, h, bg = C.paper) {
        const b = new Artboard({
            parent: page,
            name,
            frame: { x, y, width: w, height: h },
        });
        rect(b, "Background", 0, 0, w, h, bg);
        return b;
    }
    function mark(parent, x, y, s) {
        rect(parent, "Mark background", x, y, s, s, C.ink, s * 0.2);
        // Rounded shoulder and a crossbar on both sides distinguish the lowercase f.
        path(
            parent,
            "Lowercase f",
            "M 49 101 V 61 H 34 V 47 H 49 V 43 C 49 24 60 17 77 17 C 84 17 90 18 96 21 L 92 36 C 88 34 85 33 80 33 C 71 33 66 37 66 45 V 47 H 88 V 61 H 66 V 101 Z",
            x + (34 / 128) * s,
            y + (17 / 128) * s,
            (62 / 128) * s,
            (84 / 128) * s,
            C.lime,
        );
    }
    const silhouette =
        "M 36 0 H 284 Q 320 0 320 36 V 350 C 320 410 273 512 241 562 Q 225 590 202 590 H 118 Q 95 590 79 562 C 47 512 0 410 0 350 V 36 Q 0 0 36 0 Z";
    function screen(parent, name, x, y, w) {
        const p = pixels[name],
            s = w / p.width;
        rect(parent, "OLED black", x, y, w, p.height * s, C.glass);
        p.runs.forEach((v, i) =>
            rect(
                parent,
                "OLED " + name + " row " + v[1] + " run " + i,
                x + v[0] * s,
                y + v[1] * s,
                v[2] * s,
                s,
                C.white,
            ),
        );
    }
    function device(parent, x, y, w, screenName) {
        const s = w / 320,
            h = 590 * s;
        path(
            parent,
            "Safe 3 aluminium edge",
            silhouette,
            x - 3 * s,
            y - 2 * s,
            w + 6 * s,
            h + 4 * s,
            C.metal,
        );
        path(
            parent,
            "Safe 3 tapered enclosure",
            silhouette,
            x,
            y,
            w,
            h,
            C.body,
        );
        path(
            parent,
            "Glossy upper face",
            "M 36 0 H 284 Q 320 0 320 36 V 286 H 0 V 36 Q 0 0 36 0 Z",
            x + 3 * s,
            y + 3 * s,
            w - 6 * s,
            281 * s,
            C.glass,
        );
        rect(
            parent,
            "Two-button bar",
            x + 30 * s,
            y + 316 * s,
            260 * s,
            39 * s,
            "#303832",
            20 * s,
            "#080C09",
        );
        rect(
            parent,
            "Left-right button seam",
            x + 159 * s,
            y + 318 * s,
            1.5 * s,
            35 * s,
            "#0A110D",
        );
        if (screenName)
            screen(parent, screenName, x + 39 * s, y + 125 * s, 242 * s);
        else {
            text(
                parent,
                "OLED project name",
                "FEURISTIC",
                x + 42 * s,
                y + 145 * s,
                240 * s,
                24 * s,
                C.white,
                6,
            );
            text(
                parent,
                "OLED instruction",
                "Press any button...",
                x + 42 * s,
                y + 183 * s,
                245 * s,
                15 * s,
                C.white,
                4,
            );
        }
    }
    function banner(name, x, y, w, h) {
        const b = board(name, x, y, w, h),
            s = w / 1600;
        mark(b, 76 * s, 66 * s, 64 * s);
        const word = text(
            b,
            "Project name",
            "feuristic",
            70 * s,
            244 * s,
            1035 * s,
            220 * s,
            C.ink,
            11,
        );
        word.style.fontFamily = "Avenir Next";
        rect(b, "Dot background", 832 * s, 272 * s, 62 * s, 62 * s, C.paper);
        new ShapePath({
            parent: b,
            name: "Lime i dot",
            shapeType: ShapePath.ShapeType.Oval,
            frame: { x: 835 * s, y: 275 * s, width: 56 * s, height: 56 * s },
            style: { fills: ["#C4E525"], borders: [] },
        });
        text(
            b,
            "Supported hardware",
            name.endsWith(".fr")
                ? "Firmware personnalisé pour Trezor Safe 3"
                : "Custom firmware for Trezor Safe 3",
            78 * s,
            502 * s,
            1030 * s,
            42 * s,
            C.ink,
            4,
        );

        const protocols = text(
            b,
            "Protocol list",
            "FIDO2  ·  OpenPGP  ·  PIV  ·  OTP  ·  AES-GCM",
            80 * s,
            590 * s,
            1010 * s,
            27 * s,
            C.ink,
            4,
        );
        protocols.style.kerning = 2 * s;
        const circle = new ShapePath({
            parent: b,
            name: "Hardware outline",
            shapeType: ShapePath.ShapeType.Oval,
            frame: { x: 1062 * s, y: 174 * s, width: 434 * s, height: 434 * s },
            style: {
                fills: [],
                borders: [{ color: C.green, thickness: 1 * s }],
            },
        });
        path(
            b,
            "Accent arc",
            "M 0 0 A 263 263 0 0 1 0 410",
            1438 * s,
            174 * s,
            104 * s,
            410 * s,
            null,
            "#C4E525",
            22 * s,
        );
        path(
            b,
            "Upper left registration",
            "M 0 75 V 0 H 75",
            1112 * s,
            76 * s,
            75 * s,
            75 * s,
            null,
            C.ink,
            1.2 * s,
        );
        path(
            b,
            "Lower right registration",
            "M 0 22 H 34 V 0",
            1500 * s,
            625 * s,
            34 * s,
            22 * s,
            null,
            C.ink,
            1.2 * s,
        );
        for (let gx = 1050; gx < 1560; gx += 9)
            rect(
                b,
                "Registration dot " + gx,
                gx * s,
                379 * s,
                2 * s,
                1 * s,
                C.ink,
            );
        device(b, 1160 * s, 106 * s, 280 * s, "home-en");
        return b;
    }
    const hero = banner("overview", 0, 0, 1600, 800);
    const social = banner("social", 1740, 0, 1200, 630);
    const heroFr = banner("overview.fr", 0, 2000, 1600, 800);
    const ui = board("interface", 0, 1000, 1600, 900);
    text(ui, "Title", "On-device interface", 70, 50, 1000, 58, C.ink, 6);
    text(
        ui,
        "Context",
        "English and French · two-button navigation",
        74,
        134,
        1100,
        28,
        C.green,
        4,
    );
    [
        ["home-en", "English", 150],
        ["home-fr", "Français", 670],
        ["authentication-fr", "Authentication", 1190],
    ].forEach((v) => {
        device(ui, v[2], 242, 240, v[0]);
        text(
            ui,
            "Screen caption " + v[0],
            v[1],
            v[2] - 30,
            750,
            350,
            28,
            C.ink,
            5,
        );
    });
    const usb = board("usb-modes", 1740, 1000, 1440, 600);
    text(usb, "Title", "USB interfaces", 64, 55, 1100, 58, C.ink, 6);
    [
        ["Normal", "FIDO HID + CCID", "Passkeys and smart card", 64],
        ["Time sync", "CDC-ACM", "Serial clock synchronisation", 540],
        ["QR import", "FAT12 mass storage", "PNG and baseline JPEG", 1010],
    ].forEach((v) => {
        rect(usb, v[0] + " accent", v[3], 230, 54, 7, C.green);
        text(usb, v[0] + " title", v[0], v[3], 262, 390, 37, C.ink, 6);
        text(usb, v[0] + " interface", v[1], v[3], 330, 400, 28, C.ink, 5);
        text(usb, v[0] + " purpose", v[2], v[3], 390, 390, 22, C.mute, 4);
    });
    text(
        usb,
        "Mode rule",
        "Temporary modes suspend FIDO and CCID; completion returns to Normal.",
        64,
        508,
        1320,
        25,
        C.green,
        4,
    );
    const logo = board("mark", 3120, 0, 128, 128, "#00000000");
    logo.background.enabled = false;
    logo.background.includedInExport = false;
    mark(logo, 0, 0, 128);
    [hero, heroFr, social, ui, usb, logo].forEach((b) => {
        // Keep editable text in Sketch, but freeze the wordmark geometry in SVG.
        // Browser font substitution otherwise exposes the original i dot below lime.
        const exported = b.duplicate();
        const word = exported.layers.find((layer) => layer.type === "Text" && layer.text === "feuristic");
        if (word) {
            const outlines = sketch.fromNative(word.sketchObject.layersByConvertingToOutlines()[0]);
            exported.layers = exported.layers.map((layer) => layer.id === word.id ? outlines : layer);
        }
        sketch.export(exported, {
            output,
            formats: b.name === "social" ? "png" : "svg",
            scales: "1",
            overwriting: true,
            "save-for-web": true,
        });
        exported.remove();
    });
    const fiber = sketch.Async.createFiber();
    doc.save(root + "/assets/design/feuristic.sketch", {}, (err) => {
        fiber.cleanup();
        if (err) throw err;
        console.log("Saved editable feuristic artwork.");
    });
};
