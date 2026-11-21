#!/usr/bin/env python3
"""Generate src/libinjection/xss_data.rs from libinjection's XSS detector.

Usage:
    curl -fsSLO https://raw.githubusercontent.com/libinjection/libinjection/v4.0.2/src/libinjection_xss.c
    python3 scripts/gen_libinjection_xss_data.py libinjection_xss.c > src/libinjection/xss_data.rs

v4.0.2 is the libinjection that ModSecurity v3 vendors (others/libinjection).
The output must be byte-identical to the committed file; CI does not run this,
so regenerate and diff when moving to another libinjection version.
"""
import re
import sys

HEADER = """\
// @generated from libinjection v4.0.2 src/libinjection_xss.c
// (github.com/libinjection/libinjection). Do not edit by hand.
// Copyright 2012-2016 Nick Galbreath, 2021 LibInjection. BSD 3-Clause license.
//
// `GS_HEX_DECODE_MAP` is `gsHexDecodeMap`; `BLACKATTREVENT`, `BLACKATTR` and
// `BLACKTAG` are the C tables of the same names, in the same order (the C code
// scans them linearly and stops at the first hit).

use super::xss::{Attribute, TYPE_ATTR_INDIRECT, TYPE_ATTR_URL, TYPE_BLACK, TYPE_STYLE};
"""

ATTR_TYPES = {"TYPE_BLACK", "TYPE_ATTR_URL", "TYPE_STYLE", "TYPE_ATTR_INDIRECT"}


def strip_comments(src: str) -> str:
    # No string literal in the file contains "/*" or "//", so a plain scan is
    # enough.
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def block(src: str, opener: str) -> str:
    parts = src.split(opener, 1)
    assert len(parts) == 2, opener
    return parts[1].split("};", 1)[0]


def rust_bytes(s: str) -> str:
    # Printable ASCII without lower-case letters: `cstrcasecmp_with_null` in
    # xss.rs relies on the latter.
    assert all(0x20 <= ord(c) < 0x7F and c not in '"\\' for c in s), s
    assert s == s.upper(), s
    return 'b"' + s + '"'


def stringtypes(src: str, name: str) -> list:
    body = block(src, f"stringtype_t {name}[] = {{")
    entries = re.findall(r'\{\s*"([^"]*)"\s*,\s*(\w+)\s*\}', body)
    assert re.search(r"\{\s*NULL\s*,\s*TYPE_NONE\s*\}\s*$", body.strip()), name
    assert entries, name
    for _, kind in entries:
        assert kind in ATTR_TYPES, kind
    return entries


def main(path: str) -> None:
    src = strip_comments(open(path, encoding="latin-1").read())

    hexmap = [int(v) for v in re.findall(r"\d+", block(src, "gsHexDecodeMap[256] = {"))]
    assert len(hexmap) == 256, len(hexmap)

    events = stringtypes(src, "BLACKATTREVENT")
    attrs = stringtypes(src, "BLACKATTR")

    tag_body = block(src, "BLACKTAG[] = {")
    tags = re.findall(r'"([^"]*)"', tag_body)
    assert tag_body.strip().endswith("NULL"), "BLACKTAG terminator"
    assert tags

    out = [HEADER, "#[rustfmt::skip]", "pub(super) static GS_HEX_DECODE_MAP: [i32; 256] = ["]
    for row in range(0, 256, 16):
        vals = ", ".join(str(v) for v in hexmap[row : row + 16])
        out.append(f"    {vals}, // {row}")
    out.append("];")
    for name, entries in (("BLACKATTREVENT", events), ("BLACKATTR", attrs)):
        out.append("")
        out.append("#[rustfmt::skip]")
        out.append(f"pub(super) static {name}: [(&[u8], Attribute); {len(entries)}] = [")
        for word, kind in entries:
            out.append(f"    ({rust_bytes(word)}, {kind}),")
        out.append("];")
    out.append("")
    out.append("#[rustfmt::skip]")
    out.append(f"pub(super) static BLACKTAG: [&[u8]; {len(tags)}] = [")
    for tag in tags:
        out.append(f"    {rust_bytes(tag)},")
    out.append("];")
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
