//! XSS detection: a line-by-line port of libinjection's XSS detector
//! (`src/libinjection_xss.c`, libinjection v4.0.2,
//! <https://github.com/libinjection/libinjection>, BSD-3-Clause). That is the
//! version ModSecurity v3 vendors (`others/libinjection` on `v3/master`) and
//! calls from `src/operators/detect_xss.cc`.
//!
//! libinjection is Copyright 2012-2016 Nick Galbreath and 2021 LibInjection,
//! under the BSD 3-Clause license (`COPYING` in the libinjection repository).
//!
//! The input is tokenized with libinjection's HTML5 tokenizer (`html5.rs`)
//! five times: as page text, and as if it started inside an unquoted,
//! single-, double- and back-quoted attribute value. It is XSS when any pass
//! produces a doctype, a blacklisted tag (`BLACKTAG`, or a name starting with
//! `svg`/`xsl`), a blacklisted attribute (`BLACKATTREVENT` after `on`,
//! `xmlns*`, `xlink*`, `BLACKATTR`) with a value, a URL attribute whose value
//! starts with `data`, `view-source`, `java` or `vbscript` (after numeric HTML
//! entity decoding), or a comment that looks like an IE or XML construct. The
//! tables are in `xss_data.rs`, generated from `libinjection_xss.c`.
//!
//! The port keeps the C structure and names so the two can be compared side by
//! side, including the C behaviour that decides verdicts:
//!
//! - `cstrcasecmp_with_null` skips NUL bytes in the input and upper-cases only
//!   `a`-`z`; against `BLACKATTREVENT` it compares at most the table name's
//!   length, so `onclickfoo` counts as `onclick`.
//! - `htmlencode_startswith` compares `(char)cb`, so a decoded entity above
//!   0xFF matches on its low byte (`&#x141;` is `A`).
//! - `char` is signed (as on x86-64). Every comparison involved is against
//!   ASCII, so bytes >= 0x80 behave the same either way: they are never
//!   letters and `is_black_url` skips them as leading whitespace.
//!
//! libinjection has no XSS fingerprint. Like ModSecurity (which stores the
//! input as `TX.0`), a detection reports no fingerprint.

use super::html5::{
    libinjection_h5_init, libinjection_h5_next, Html5Flags, Html5Type, LIBINJECTION_RESULT_FALSE,
    LIBINJECTION_RESULT_TRUE,
};
use super::xss_data::{BLACKATTR, BLACKATTREVENT, BLACKTAG, GS_HEX_DECODE_MAP};
use super::DetectionResult;

/// `attribute_t`.
pub(super) type Attribute = u8;
pub(super) const TYPE_NONE: Attribute = 0;
/// ban always
pub(super) const TYPE_BLACK: Attribute = 1;
/// attribute value takes a URL-like object
pub(super) const TYPE_ATTR_URL: Attribute = 2;
pub(super) const TYPE_STYLE: Attribute = 3;
/// attribute *name* is given in *value*
pub(super) const TYPE_ATTR_INDIRECT: Attribute = 4;

/// Check if the input contains XSS (`libinjection_xss`).
#[inline]
pub fn is_xss(input: &str) -> bool {
    libinjection_xss(input.as_bytes()) != LIBINJECTION_RESULT_FALSE
}

/// Detect XSS in input (`libinjection_xss`). libinjection reports no
/// fingerprint for XSS, so a detection carries none.
pub fn detect_xss(input: &str) -> DetectionResult {
    if is_xss(input) {
        DetectionResult {
            is_injection: true,
            fingerprint: None,
        }
    } else {
        DetectionResult::safe()
    }
}

/// `IS_HEX_ENTITY_PREFIX(src)`.
fn is_hex_entity_prefix(src: &[u8]) -> bool {
    src[2] == b'x' || src[2] == b'X'
}

/// `html_decode_char_at`: decode one byte or one numeric HTML entity
/// (`&#65;`, `&#x41`, the `;` is optional) at the start of `src`. Returns the
/// value and the number of bytes consumed; -1 only for empty input.
fn html_decode_char_at(src: &[u8]) -> (i32, usize) {
    let len = src.len();
    if len == 0 {
        return (-1, 0);
    }

    let mut consumed = 1;
    // check if it starts with '&' and
    // len >=3 or src[2] == 'x'/'X' and len >=4
    // if not, return the character itself
    if src[0] != b'&' || len < 3 || (is_hex_entity_prefix(src) && len < 4) {
        return (i32::from(src[0]), consumed);
    }

    // check if the second character is '#'
    // if not, return '&' (we don't handle named entities here)
    if src[1] != b'#' {
        return (i32::from(b'&'), consumed);
    }

    let mut val: i32;
    let mut i: usize;
    if is_hex_entity_prefix(src) {
        let ch = GS_HEX_DECODE_MAP[usize::from(src[3])];
        if ch == 256 {
            // degenerate case  '&#[?]'
            return (i32::from(b'&'), consumed);
        }
        val = ch;
        i = 4;
        while i < len {
            let ch = src[i];
            if ch == b';' {
                consumed = i + 1;
                return (val, consumed);
            }
            let ch = GS_HEX_DECODE_MAP[usize::from(ch)];
            if ch == 256 {
                consumed = i;
                return (val, consumed);
            }
            val = (val * 16) + ch;
            if val > 0x1000FF {
                return (i32::from(b'&'), consumed);
            }
            i += 1;
        }
        consumed = i;
        (val, consumed)
    } else {
        i = 2;
        let ch = src[i];
        if !ch.is_ascii_digit() {
            return (i32::from(b'&'), consumed);
        }
        val = i32::from(ch - b'0');
        i += 1;
        while i < len {
            let ch = src[i];
            if ch == b';' {
                consumed = i + 1;
                return (val, consumed);
            }
            if !ch.is_ascii_digit() {
                consumed = i;
                return (val, consumed);
            }
            val = (val * 10) + i32::from(ch - b'0');
            if val > 0x1000FF {
                return (i32::from(b'&'), consumed);
            }
            i += 1;
        }
        consumed = i;
        (val, consumed)
    }
}

/// `cstrcasecmp_with_null`: 0 when the first `n` bytes of `b`, with NUL bytes
/// dropped and `a`-`z` upper-cased, equal the whole of `a` (an upper-case C
/// string); 1 otherwise.
fn cstrcasecmp_with_null(a: &[u8], b: &[u8], n: usize) -> i32 {
    // Shortcuts that give the loop's answer without running it. `a` holds no
    // NUL and no lower-case letter, so per byte the loop's test is
    // `eq_ignore_ascii_case`, and every NUL in `b` is a byte of `b` that
    // consumes nothing from `a`.
    let b = &b[..n];
    if n < a.len() {
        // At most n bytes of `a` can be consumed; its NUL is never reached.
        return 1;
    }
    if n == a.len() {
        // A NUL in `b` would leave `a` unfinished; eq_ignore_ascii_case
        // fails on it too.
        return if a.eq_ignore_ascii_case(b) { 0 } else { 1 };
    }
    if memchr::memchr(0, b).is_none() {
        // Longer than `a` with nothing to skip.
        return 1;
    }

    let mut ai = 0;
    // `a[ai++]` on the C string: its terminating NUL is 0.
    let mut next_a = || {
        let ca = a.get(ai).copied().unwrap_or(0);
        ai += 1;
        ca
    };
    for &cb in b {
        if cb == b'\0' {
            continue;
        }

        let ca = next_a();

        let cb = cb.to_ascii_uppercase();

        if ca != cb {
            return 1;
        }
    }
    if next_a() == b'\0' {
        0
    } else {
        1
    }
}

/// `htmlencode_startswith`: does the HTML-encoded `b` start with the
/// upper-case `a`, ignoring case, leading whitespace and control characters,
/// and embedded NULs and newlines?
fn htmlencode_startswith(a: &[u8], b: &[u8]) -> bool {
    let mut a = a;
    let mut b = b;
    let mut first = true;
    while !b.is_empty() {
        if a.is_empty() {
            return true;
        }
        let (mut cb, consumed) = html_decode_char_at(b);
        b = &b[consumed..];

        if first && cb <= 32 {
            // ignore all leading whitespace and control characters
            continue;
        }
        first = false;

        if cb == 0 {
            // always ignore null characters in user input
            continue;
        }

        if cb == 10 {
            // always ignore vertical tab characters in user input
            // who allows this??
            continue;
        }

        if (i32::from(b'a')..=i32::from(b'z')).contains(&cb) {
            // upcase
            cb -= 0x20;
        }

        // C: `*a != (char)cb`, the low byte of the decoded value.
        if a[0] != cb as u8 {
            // mismatch
            return false;
        }
        a = &a[1..];
    }

    a.is_empty()
}

fn is_black_tag(s: &[u8]) -> bool {
    let len = s.len();
    if len < 3 {
        return false;
    }

    for black in BLACKTAG.iter() {
        if cstrcasecmp_with_null(black, s, len) == 0 {
            return true;
        }
    }

    // anything SVG related
    if s[..3].eq_ignore_ascii_case(b"svg") {
        return true;
    }

    // Anything XSL(t) related
    if s[..3].eq_ignore_ascii_case(b"xsl") {
        return true;
    }

    false
}

fn is_black_attr(s: &[u8]) -> Attribute {
    let len = s.len();
    if len < 2 {
        return TYPE_NONE;
    }

    if len >= 5 {
        // JavaScript on.* event handlers
        if s[..2].eq_ignore_ascii_case(b"on") {
            // start comparing from the third char
            let s_without_on = &s[2..];
            let s_without_on_len = len - 2;
            for (name, atype) in BLACKATTREVENT.iter() {
                // determine the maximum length to compare
                let max_len = s_without_on_len.min(name.len());
                if cstrcasecmp_with_null(name, s_without_on, max_len) == 0 {
                    return *atype;
                }
            }
        }

        // XMLNS can be used to create arbitrary tags
        if cstrcasecmp_with_null(b"XMLNS", s, 5) == 0 || cstrcasecmp_with_null(b"XLINK", s, 5) == 0
        {
            return TYPE_BLACK;
        }
    }

    for (name, atype) in BLACKATTR.iter() {
        if cstrcasecmp_with_null(name, s, len) == 0 {
            return *atype;
        }
    }

    TYPE_NONE
}

fn is_black_url(s: &[u8]) -> bool {
    const DATA_URL: &[u8] = b"DATA";
    const VIEWSOURCE_URL: &[u8] = b"VIEW-SOURCE";

    // obsolete but interesting signal
    const VBSCRIPT_URL: &[u8] = b"VBSCRIPT";

    // covers JAVA, JAVASCRIPT, + colon
    const JAVASCRIPT_URL: &[u8] = b"JAVA";

    // skip whitespace
    //
    // C: `*s <= 32 || *s >= 127` on a signed char. High-bit bytes are skipped
    // too, since they are not ASCII, and Opera sometimes uses UTF-8
    // whitespace. Also in EUC-JP some of the high bytes are just ignored.
    let skip = s
        .iter()
        .position(|&c| (c as i8) > 32 && (c as i8) < 127)
        .unwrap_or(s.len());
    let s = &s[skip..];

    htmlencode_startswith(DATA_URL, s)
        || htmlencode_startswith(VIEWSOURCE_URL, s)
        || htmlencode_startswith(JAVASCRIPT_URL, s)
        || htmlencode_startswith(VBSCRIPT_URL, s)
}

/// `libinjection_is_xss`: one pass of the tokenizer from the state `flags`.
fn libinjection_is_xss(s: &[u8], flags: Html5Flags) -> i32 {
    let mut h5 = libinjection_h5_init(s, flags);
    let mut attr = TYPE_NONE;
    let mut parser_result;

    loop {
        parser_result = libinjection_h5_next(&mut h5);
        if parser_result != LIBINJECTION_RESULT_TRUE {
            break;
        }
        let token = h5.token();

        if h5.token_type != Html5Type::ATTR_VALUE {
            attr = TYPE_NONE;
        }

        match h5.token_type {
            Html5Type::DOCTYPE => return LIBINJECTION_RESULT_TRUE,
            Html5Type::TAG_NAME_OPEN => {
                if is_black_tag(token) {
                    return LIBINJECTION_RESULT_TRUE;
                }
            }
            Html5Type::ATTR_NAME => {
                attr = is_black_attr(token);
            }
            Html5Type::ATTR_VALUE => {
                // IE6,7,8 parsing works a bit differently so a whole <script>
                // or other black tag might be hiding inside an attribute value
                // under HTML 5 parsing (http://html5sec.org/#102). The C code
                // has the check for "<" commented out.
                match attr {
                    TYPE_NONE => {}
                    TYPE_BLACK => return LIBINJECTION_RESULT_TRUE,
                    TYPE_ATTR_URL => {
                        if is_black_url(token) {
                            return LIBINJECTION_RESULT_TRUE;
                        }
                    }
                    TYPE_STYLE => return LIBINJECTION_RESULT_TRUE,
                    TYPE_ATTR_INDIRECT => {
                        // an attribute name is specified in a _value_
                        if is_black_attr(token) != TYPE_NONE {
                            return LIBINJECTION_RESULT_TRUE;
                        }
                    }
                    _ => unreachable!("attribute_t has five values"),
                }
                attr = TYPE_NONE;
            }
            Html5Type::TAG_COMMENT => {
                // IE uses a "`" as a tag ending char
                if memchr::memchr(b'`', token).is_some() {
                    return LIBINJECTION_RESULT_TRUE;
                }

                // IE conditional comment
                if token.len() > 3 {
                    if token[0] == b'[' && token[1..3].eq_ignore_ascii_case(b"if") {
                        return LIBINJECTION_RESULT_TRUE;
                    }
                    if token[..3].eq_ignore_ascii_case(b"xml") {
                        return LIBINJECTION_RESULT_TRUE;
                    }
                }

                if token.len() > 5 {
                    // IE <?import pseudo-tag
                    if cstrcasecmp_with_null(b"IMPORT", token, 6) == 0 {
                        return LIBINJECTION_RESULT_TRUE;
                    }

                    // XML Entity definition
                    if cstrcasecmp_with_null(b"ENTITY", token, 6) == 0 {
                        return LIBINJECTION_RESULT_TRUE;
                    }
                }
            }
            _ => {}
        }
    }
    parser_result
}

/// `libinjection_xss`: the five passes. Non-zero (true or, in C, an error) is
/// XSS, as `detect_xss.cc` tests it.
fn libinjection_xss(s: &[u8]) -> i32 {
    // Not in C, and it cannot change the result: without `<` the tokenizer
    // never reaches a tag, comment or doctype state (only `h5_state_data`
    // enters them, on `<`), and without `=` no attribute value follows an
    // attribute name, so `attr` is always TYPE_NONE when a value is checked.
    // Most benign input (text, User-Agents, JSON) skips the five passes.
    if memchr::memchr2(b'<', b'=', s).is_none() {
        return LIBINJECTION_RESULT_FALSE;
    }

    for flags in [
        Html5Flags::DATA_STATE,
        Html5Flags::VALUE_NO_QUOTE,
        Html5Flags::VALUE_SINGLE_QUOTE,
        Html5Flags::VALUE_DOUBLE_QUOTE,
        Html5Flags::VALUE_BACK_QUOTE,
    ] {
        let result = libinjection_is_xss(s, flags);
        if result != LIBINJECTION_RESULT_FALSE {
            return result;
        }
    }

    LIBINJECTION_RESULT_FALSE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_tag() {
        assert!(is_xss("<script>alert(1)</script>"));
        assert!(is_xss("<SCRIPT>alert(1)</SCRIPT>"));
        assert!(is_xss("<script src=evil.js>"));
        assert!(is_xss("<script/src=evil.js>"));
        // NULs inside a tag name are ignored.
        assert!(is_xss("<scr\0ipt>"));
    }

    #[test]
    fn test_event_handlers() {
        assert!(is_xss("<img src=x onerror=alert(1)>"));
        assert!(is_xss("<body onload=alert(1)>"));
        assert!(is_xss("<svg onload=alert(1)>"));
        assert!(is_xss("<input onfocus=alert(1) autofocus>"));
        // A prefix of the attribute is enough.
        assert!(is_xss("<b onclickfoo=1>"));
    }

    #[test]
    fn test_javascript_url() {
        assert!(is_xss("<a href=javascript:alert(1)>click</a>"));
        assert!(is_xss("<a href=\"javascript:alert(1)\">click</a>"));
        assert!(is_xss("<a href=\"&#106;ava&#x73;cript:alert(1)\">"));
        assert!(is_xss("<a href=\" \x01java\nscript:x\">"));
        // `(char)cb`: only the low byte of a decoded entity counts.
        assert!(is_xss("<a href=\"&#x14A;ava:x\">"));
    }

    #[test]
    fn test_attribute_context() {
        // Starting inside a quoted attribute value.
        assert!(is_xss("x\" onmouseover=\"alert(1)"));
        assert!(is_xss("' style='x"));
        assert!(is_xss("`src=javascript:x"));
    }

    #[test]
    fn test_comments_and_doctype() {
        assert!(is_xss("<!DOCTYPE html>"));
        assert!(is_xss("<!--[if IE]><x><![endif]-->"));
        assert!(is_xss("<?import namespace=x>"));
        assert!(is_xss("<!ENTITY x SYSTEM 'y'>"));
        assert!(is_xss("<!-- ` -->"));
    }

    #[test]
    fn test_safe_input() {
        assert!(!is_xss(""));
        assert!(!is_xss("hello world"));
        assert!(!is_xss(
            "This is normal text without any special characters"
        ));
        assert!(!is_xss("12345"));
        assert!(!is_xss("user@example.com"));
        assert!(!is_xss("<p>Normal paragraph</p>"));
        assert!(!is_xss("<a href=\"https://example.com/\">link</a>"));
        assert!(!is_xss("a < b and c > d"));
        // libinjection is an HTML tokenizer, not a JavaScript scanner.
        assert!(!is_xss("javascript:alert(1)"));
        assert!(!is_xss("document.write('x')"));
        // Entities are only decoded inside URL attribute values.
        assert!(!is_xss("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn test_html_decode_char_at() {
        assert_eq!(html_decode_char_at(b""), (-1, 0));
        assert_eq!(html_decode_char_at(b"a"), (97, 1));
        assert_eq!(html_decode_char_at(b"&#65;x"), (65, 5));
        assert_eq!(html_decode_char_at(b"&#65x"), (65, 4));
        assert_eq!(html_decode_char_at(b"&#x41;"), (65, 6));
        assert_eq!(html_decode_char_at(b"&#x"), (38, 1));
        assert_eq!(html_decode_char_at(b"&amp;"), (38, 1));
        assert_eq!(html_decode_char_at(b"&#99999999"), (38, 1));
    }

    #[test]
    fn test_cstrcasecmp_with_null() {
        assert_eq!(cstrcasecmp_with_null(b"SCRIPT", b"sc\0ript", 7), 0);
        assert_eq!(cstrcasecmp_with_null(b"SCRIPT", b"scrip", 5), 1);
        assert_eq!(cstrcasecmp_with_null(b"SCRIPT", b"scripts", 7), 1);
    }
}
