//! HTML5 tokenizer: a line-by-line port of libinjection's
//! `src/libinjection_html5.c` (libinjection v4.0.2,
//! <https://github.com/libinjection/libinjection>, BSD-3-Clause), the
//! tokenizer `@detectXSS` (`xss.rs`) runs over its input.
//!
//! libinjection is Copyright 2012-2016 Nick Galbreath and 2021 LibInjection,
//! under the BSD 3-Clause license (`COPYING` in the libinjection repository).
//!
//! It is not a conforming HTML5 tokenizer: it follows the spec's state names
//! loosely and adds the IE and old-browser leniencies libinjection cares about.
//! The port keeps the C state functions, names and control flow, and the C
//! quirks that decide which tokens come out:
//!
//! - `h5_is_white` is `strchr(" \t\n\v\f\r", ch)`, which also matches NUL, so a
//!   NUL ends an attribute name or unquoted value (but not a tag name, which
//!   checks for NUL first).
//! - `h5_skip_white` also skips NUL, `\v` and `\r`.
//! - Byte comparisons are against ASCII ranges only, so the signedness of C's
//!   `char` makes no difference here.
//!
//! The current state is a function pointer, as in C (`ptr_html5_state`).

/// `enum html5_type`: the kind of the token `libinjection_h5_next` produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub(super) enum Html5Type {
    DATA_TEXT,
    TAG_NAME_OPEN,
    TAG_NAME_CLOSE,
    TAG_NAME_SELFCLOSE,
    // Declared in C but never produced.
    #[allow(dead_code)]
    TAG_DATA,
    TAG_CLOSE,
    ATTR_NAME,
    ATTR_VALUE,
    TAG_COMMENT,
    DOCTYPE,
}

/// `enum html5_flags`: the state the tokenizer starts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub(super) enum Html5Flags {
    DATA_STATE,
    VALUE_NO_QUOTE,
    VALUE_SINGLE_QUOTE,
    VALUE_DOUBLE_QUOTE,
    VALUE_BACK_QUOTE,
}

use Html5Type::*;

/// `injection_result_t` values (`libinjection_error.h`).
pub(super) const LIBINJECTION_RESULT_FALSE: i32 = 0;
pub(super) const LIBINJECTION_RESULT_TRUE: i32 = 1;
pub(super) const LIBINJECTION_RESULT_ERROR: i32 = -1;

const CHAR_EOF: i32 = -1;
const CHAR_NULL: u8 = 0;
const CHAR_BANG: u8 = 33;
const CHAR_DOUBLE: u8 = 34;
const CHAR_PERCENT: u8 = 37;
const CHAR_SINGLE: u8 = 39;
const CHAR_DASH: u8 = 45;
const CHAR_SLASH: u8 = 47;
const CHAR_EQUALS: u8 = 61;
const CHAR_GT: u8 = 62;
const CHAR_QUESTION: u8 = 63;
const CHAR_RIGHTB: u8 = 93;
const CHAR_TICK: u8 = 96;
const CHAR_LT: u8 = 60;

/// `ptr_html5_state`.
type PtrHtml5State = for<'a, 'b> fn(&'b mut H5State<'a>) -> i32;

/// `h5_state_t`. `token_start` is an offset into `s` rather than a pointer.
pub(super) struct H5State<'a> {
    pub(super) s: &'a [u8],
    pub(super) len: usize,
    pub(super) pos: usize,
    is_close: bool,
    state: Option<PtrHtml5State>,
    pub(super) token_start: usize,
    pub(super) token_len: usize,
    pub(super) token_type: Html5Type,
}

impl<'a> H5State<'a> {
    /// The current token's bytes.
    pub(super) fn token(&self) -> &'a [u8] {
        &self.s[self.token_start..self.token_start + self.token_len]
    }
}

/// `libinjection_h5_init`.
pub(super) fn libinjection_h5_init(s: &[u8], flags: Html5Flags) -> H5State<'_> {
    let state: PtrHtml5State = match flags {
        Html5Flags::DATA_STATE => h5_state_data,
        Html5Flags::VALUE_NO_QUOTE => h5_state_before_attribute_name,
        Html5Flags::VALUE_SINGLE_QUOTE => h5_state_attribute_value_single_quote,
        Html5Flags::VALUE_DOUBLE_QUOTE => h5_state_attribute_value_double_quote,
        Html5Flags::VALUE_BACK_QUOTE => h5_state_attribute_value_back_quote,
    };
    H5State {
        s,
        len: s.len(),
        pos: 0,
        is_close: false,
        state: Some(state),
        token_start: 0,
        token_len: 0,
        // memset(0): DATA_TEXT is 0.
        token_type: DATA_TEXT,
    }
}

/// `libinjection_h5_next`: 1 with the next token in `hs`, 0 at the end.
pub(super) fn libinjection_h5_next(hs: &mut H5State<'_>) -> i32 {
    match hs.state {
        None => LIBINJECTION_RESULT_ERROR,
        Some(state) => state(hs),
    }
}

/// `strchr(" \t\n\v\f\r", ch) != NULL`: NUL is in the set too.
fn h5_is_white(ch: u8) -> bool {
    matches!(ch, 0 | b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

/// The next non-whitespace byte, or `CHAR_EOF`.
fn h5_skip_white(hs: &mut H5State<'_>) -> i32 {
    while hs.pos < hs.len {
        let ch = hs.s[hs.pos];
        match ch {
            0x00 | 0x20 | 0x09 | 0x0A | 0x0B | 0x0C | 0x0D => {
                hs.pos += 1;
            }
            _ => return i32::from(ch),
        }
    }
    CHAR_EOF
}

fn h5_state_eof(_hs: &mut H5State<'_>) -> i32 {
    0
}

fn h5_state_data(hs: &mut H5State<'_>) -> i32 {
    if hs.len < hs.pos {
        return LIBINJECTION_RESULT_ERROR;
    }
    let idx = memchr::memchr(CHAR_LT, &hs.s[hs.pos..hs.len]).map(|i| hs.pos + i);
    match idx {
        None => {
            hs.token_start = hs.pos;
            hs.token_len = hs.len - hs.pos;
            hs.token_type = DATA_TEXT;
            hs.state = Some(h5_state_eof);
            if hs.token_len == 0 {
                return 0;
            }
        }
        Some(idx) => {
            hs.token_start = hs.pos;
            hs.token_type = DATA_TEXT;
            hs.token_len = idx - hs.pos;
            hs.pos = idx + 1;
            hs.state = Some(h5_state_tag_open);
            if hs.token_len == 0 {
                return h5_state_tag_open(hs);
            }
        }
    }
    1
}

/// 12 2.4.8
fn h5_state_tag_open(hs: &mut H5State<'_>) -> i32 {
    if hs.pos >= hs.len {
        return 0;
    }
    let ch = hs.s[hs.pos];
    if ch == CHAR_BANG {
        hs.pos += 1;
        h5_state_markup_declaration_open(hs)
    } else if ch == CHAR_SLASH {
        hs.pos += 1;
        hs.is_close = true;
        h5_state_end_tag_open(hs)
    } else if ch == CHAR_QUESTION {
        hs.pos += 1;
        h5_state_bogus_comment(hs)
    } else if ch == CHAR_PERCENT {
        // this is not in spec.. alternative comment format used
        // by IE <= 9 and Safari < 4.0.3
        hs.pos += 1;
        h5_state_bogus_comment2(hs)
    } else if ch.is_ascii_alphabetic() {
        h5_state_tag_name(hs)
    } else if ch == CHAR_NULL {
        // IE-ism  NULL characters are ignored
        h5_state_tag_name(hs)
    } else {
        // user input mistake in configuring state
        if hs.pos == 0 {
            return h5_state_data(hs);
        }
        hs.token_start = hs.pos - 1;
        hs.token_len = 1;
        hs.token_type = DATA_TEXT;
        hs.state = Some(h5_state_data);
        1
    }
}

/// 12.2.4.9
fn h5_state_end_tag_open(hs: &mut H5State<'_>) -> i32 {
    if hs.pos >= hs.len {
        return 0;
    }
    let ch = hs.s[hs.pos];
    if ch == CHAR_GT {
        return h5_state_data(hs);
    } else if ch.is_ascii_alphabetic() {
        return h5_state_tag_name(hs);
    }

    hs.is_close = false;
    h5_state_bogus_comment(hs)
}

fn h5_state_tag_name_close(hs: &mut H5State<'_>) -> i32 {
    hs.is_close = false;
    hs.token_start = hs.pos;
    hs.token_len = 1;
    hs.token_type = TAG_NAME_CLOSE;
    hs.pos += 1;
    if hs.pos < hs.len {
        hs.state = Some(h5_state_data);
    } else {
        hs.state = Some(h5_state_eof);
    }

    1
}

/// 12.2.4.10
fn h5_state_tag_name(hs: &mut H5State<'_>) -> i32 {
    let mut pos = hs.pos;
    while pos < hs.len {
        let ch = hs.s[pos];
        if ch == 0 {
            // special non-standard case
            // allow nulls in tag name
            // some old browsers apparently allow and ignore them
            pos += 1;
        } else if h5_is_white(ch) {
            hs.token_start = hs.pos;
            hs.token_len = pos - hs.pos;
            hs.token_type = TAG_NAME_OPEN;
            hs.pos = pos + 1;
            hs.state = Some(h5_state_before_attribute_name);
            return 1;
        } else if ch == CHAR_SLASH {
            hs.token_start = hs.pos;
            hs.token_len = pos - hs.pos;
            hs.token_type = TAG_NAME_OPEN;
            hs.pos = pos + 1;
            hs.state = Some(h5_state_self_closing_start_tag);
            return 1;
        } else if ch == CHAR_GT {
            hs.token_start = hs.pos;
            hs.token_len = pos - hs.pos;
            if hs.is_close {
                hs.pos = pos + 1;
                hs.is_close = false;
                hs.token_type = TAG_CLOSE;
                hs.state = Some(h5_state_data);
            } else {
                hs.pos = pos;
                hs.token_type = TAG_NAME_OPEN;
                hs.state = Some(h5_state_tag_name_close);
            }
            return 1;
        } else {
            pos += 1;
        }
    }

    hs.token_start = hs.pos;
    hs.token_len = hs.len - hs.pos;
    hs.token_type = TAG_NAME_OPEN;
    hs.state = Some(h5_state_eof);
    1
}

/// 12.2.4.34
fn h5_state_before_attribute_name(hs: &mut H5State<'_>) -> i32 {
    // C: a `goto tail_call` loop instead of recursing through
    // h5_state_self_closing_start_tag.
    loop {
        let ch = h5_skip_white(hs);
        if ch == CHAR_EOF {
            return 0;
        } else if ch == i32::from(CHAR_SLASH) {
            hs.pos += 1;
            if hs.pos < hs.len && hs.s[hs.pos] != CHAR_GT {
                continue;
            }
            return h5_state_self_closing_start_tag(hs);
        } else if ch == i32::from(CHAR_GT) {
            hs.state = Some(h5_state_data);
            hs.token_start = hs.pos;
            hs.token_len = 1;
            hs.token_type = TAG_NAME_CLOSE;
            hs.pos += 1;
            return 1;
        } else {
            return h5_state_attribute_name(hs);
        }
    }
}

fn h5_state_attribute_name(hs: &mut H5State<'_>) -> i32 {
    let mut pos = hs.pos + 1;
    while pos < hs.len {
        let ch = hs.s[pos];
        if h5_is_white(ch) {
            hs.token_start = hs.pos;
            hs.token_len = pos - hs.pos;
            hs.token_type = ATTR_NAME;
            hs.state = Some(h5_state_after_attribute_name);
            hs.pos = pos + 1;
            return 1;
        } else if ch == CHAR_SLASH {
            hs.token_start = hs.pos;
            hs.token_len = pos - hs.pos;
            hs.token_type = ATTR_NAME;
            hs.state = Some(h5_state_self_closing_start_tag);
            hs.pos = pos + 1;
            return 1;
        } else if ch == CHAR_EQUALS {
            hs.token_start = hs.pos;
            hs.token_len = pos - hs.pos;
            hs.token_type = ATTR_NAME;
            hs.state = Some(h5_state_before_attribute_value);
            hs.pos = pos + 1;
            return 1;
        } else if ch == CHAR_GT {
            hs.token_start = hs.pos;
            hs.token_len = pos - hs.pos;
            hs.token_type = ATTR_NAME;
            hs.state = Some(h5_state_tag_name_close);
            hs.pos = pos;
            return 1;
        } else {
            pos += 1;
        }
    }
    // EOF
    hs.token_start = hs.pos;
    hs.token_len = hs.len - hs.pos;
    hs.token_type = ATTR_NAME;
    hs.state = Some(h5_state_eof);
    hs.pos = hs.len;
    1
}

/// 12.2.4.36
fn h5_state_after_attribute_name(hs: &mut H5State<'_>) -> i32 {
    let c = h5_skip_white(hs);
    if c == CHAR_EOF {
        0
    } else if c == i32::from(CHAR_SLASH) {
        hs.pos += 1;
        h5_state_self_closing_start_tag(hs)
    } else if c == i32::from(CHAR_EQUALS) {
        hs.pos += 1;
        h5_state_before_attribute_value(hs)
    } else if c == i32::from(CHAR_GT) {
        h5_state_tag_name_close(hs)
    } else {
        h5_state_attribute_name(hs)
    }
}

/// 12.2.4.37
fn h5_state_before_attribute_value(hs: &mut H5State<'_>) -> i32 {
    let c = h5_skip_white(hs);

    if c == CHAR_EOF {
        hs.state = Some(h5_state_eof);
        return 0;
    }

    if c == i32::from(CHAR_DOUBLE) {
        h5_state_attribute_value_double_quote(hs)
    } else if c == i32::from(CHAR_SINGLE) {
        h5_state_attribute_value_single_quote(hs)
    } else if c == i32::from(CHAR_TICK) {
        // NON STANDARD IE
        h5_state_attribute_value_back_quote(hs)
    } else {
        h5_state_attribute_value_no_quote(hs)
    }
}

fn h5_state_attribute_value_quote(hs: &mut H5State<'_>, qchar: u8) -> i32 {
    // skip initial quote in normal case.
    // don't do this "if (pos == 0)" since it means we have started
    // in a non-data state.  given an input of '><foo
    // we want to make 0-length attribute name
    if hs.pos > 0 {
        hs.pos += 1;
    }

    let idx = memchr::memchr(qchar, &hs.s[hs.pos..hs.len]).map(|i| hs.pos + i);
    match idx {
        None => {
            hs.token_start = hs.pos;
            hs.token_len = hs.len - hs.pos;
            hs.token_type = ATTR_VALUE;
            hs.state = Some(h5_state_eof);
        }
        Some(idx) => {
            hs.token_start = hs.pos;
            hs.token_len = idx - hs.pos;
            hs.token_type = ATTR_VALUE;
            hs.state = Some(h5_state_after_attribute_value_quoted_state);
            hs.pos += hs.token_len + 1;
        }
    }
    1
}

fn h5_state_attribute_value_double_quote(hs: &mut H5State<'_>) -> i32 {
    h5_state_attribute_value_quote(hs, CHAR_DOUBLE)
}

fn h5_state_attribute_value_single_quote(hs: &mut H5State<'_>) -> i32 {
    h5_state_attribute_value_quote(hs, CHAR_SINGLE)
}

fn h5_state_attribute_value_back_quote(hs: &mut H5State<'_>) -> i32 {
    h5_state_attribute_value_quote(hs, CHAR_TICK)
}

fn h5_state_attribute_value_no_quote(hs: &mut H5State<'_>) -> i32 {
    let mut pos = hs.pos;
    while pos < hs.len {
        let ch = hs.s[pos];
        if h5_is_white(ch) {
            hs.token_type = ATTR_VALUE;
            hs.token_start = hs.pos;
            hs.token_len = pos - hs.pos;
            hs.pos = pos + 1;
            hs.state = Some(h5_state_before_attribute_name);
            return 1;
        } else if ch == CHAR_GT {
            hs.token_type = ATTR_VALUE;
            hs.token_start = hs.pos;
            hs.token_len = pos - hs.pos;
            hs.pos = pos;
            hs.state = Some(h5_state_tag_name_close);
            return 1;
        }
        pos += 1;
    }
    // EOF
    hs.state = Some(h5_state_eof);
    hs.token_start = hs.pos;
    hs.token_len = hs.len - hs.pos;
    hs.token_type = ATTR_VALUE;
    1
}

/// 12.2.4.41
fn h5_state_after_attribute_value_quoted_state(hs: &mut H5State<'_>) -> i32 {
    if hs.pos >= hs.len {
        return 0;
    }
    let ch = hs.s[hs.pos];
    if h5_is_white(ch) {
        hs.pos += 1;
        h5_state_before_attribute_name(hs)
    } else if ch == CHAR_SLASH {
        hs.pos += 1;
        h5_state_self_closing_start_tag(hs)
    } else if ch == CHAR_GT {
        hs.token_start = hs.pos;
        hs.token_len = 1;
        hs.token_type = TAG_NAME_CLOSE;
        hs.pos += 1;
        hs.state = Some(h5_state_data);
        1
    } else {
        h5_state_before_attribute_name(hs)
    }
}

/// 12.2.4.43 (partially inlined into `h5_state_before_attribute_name`).
fn h5_state_self_closing_start_tag(hs: &mut H5State<'_>) -> i32 {
    if hs.pos >= hs.len {
        return 0;
    }
    let ch = hs.s[hs.pos];
    if ch == CHAR_GT {
        hs.token_start = hs.pos - 1;
        hs.token_len = 2;
        hs.token_type = TAG_NAME_SELFCLOSE;
        hs.state = Some(h5_state_data);
        hs.pos += 1;
        1
    } else {
        h5_state_before_attribute_name(hs)
    }
}

/// 12.2.4.44
fn h5_state_bogus_comment(hs: &mut H5State<'_>) -> i32 {
    let idx = memchr::memchr(CHAR_GT, &hs.s[hs.pos..hs.len]).map(|i| hs.pos + i);
    match idx {
        None => {
            hs.token_start = hs.pos;
            hs.token_len = hs.len - hs.pos;
            hs.pos = hs.len;
            hs.state = Some(h5_state_eof);
        }
        Some(idx) => {
            hs.token_start = hs.pos;
            hs.token_len = idx - hs.pos;
            hs.pos = idx + 1;
            hs.state = Some(h5_state_data);
        }
    }

    hs.token_type = TAG_COMMENT;
    1
}

/// 12.2.4.44 ALT
fn h5_state_bogus_comment2(hs: &mut H5State<'_>) -> i32 {
    let mut pos = hs.pos;
    loop {
        let idx = memchr::memchr(CHAR_PERCENT, &hs.s[pos..hs.len]).map(|i| pos + i);
        let idx = match idx {
            Some(idx) if idx + 1 < hs.len => idx,
            _ => {
                hs.token_start = hs.pos;
                hs.token_len = hs.len - hs.pos;
                hs.pos = hs.len;
                hs.token_type = TAG_COMMENT;
                hs.state = Some(h5_state_eof);
                return 1;
            }
        };

        if hs.s[idx + 1] != CHAR_GT {
            pos = idx + 1;
            continue;
        }

        // ends in %>
        hs.token_start = hs.pos;
        hs.token_len = idx - hs.pos;
        hs.pos = idx + 2;
        hs.state = Some(h5_state_data);
        hs.token_type = TAG_COMMENT;
        return 1;
    }
}

/// 8.2.4.45
fn h5_state_markup_declaration_open(hs: &mut H5State<'_>) -> i32 {
    let remaining = hs.len - hs.pos;
    let s = &hs.s[hs.pos..];
    if remaining >= 7 && s[..7].eq_ignore_ascii_case(b"DOCTYPE") {
        // case insensitive
        h5_state_doctype(hs)
    } else if remaining >= 7 && &s[..7] == b"[CDATA[" {
        // upper case required
        hs.pos += 7;
        h5_state_cdata(hs)
    } else if remaining >= 2 && s[0] == b'-' && s[1] == b'-' {
        hs.pos += 2;
        h5_state_comment(hs)
    } else {
        h5_state_bogus_comment(hs)
    }
}

/// 12.2.4.48 - 12.2.4.51: comments end at EOF, `-->` or `-!>` (NULs between
/// the first dash and the second character are skipped).
fn h5_state_comment(hs: &mut H5State<'_>) -> i32 {
    let end = hs.len;
    let mut pos = hs.pos;
    loop {
        let idx = memchr::memchr(CHAR_DASH, &hs.s[pos..hs.len]).map(|i| pos + i);

        // did not find anything or has less than 3 chars left
        // (C: idx > s + len - 3)
        let idx = match idx {
            Some(idx) if idx + 3 <= hs.len => idx,
            _ => {
                hs.state = Some(h5_state_eof);
                hs.token_start = hs.pos;
                hs.token_len = hs.len - hs.pos;
                hs.token_type = TAG_COMMENT;
                return 1;
            }
        };
        let mut offset = 1;

        // skip all nulls
        while idx + offset < end && hs.s[idx + offset] == 0 {
            offset += 1;
        }
        if idx + offset == end {
            hs.state = Some(h5_state_eof);
            hs.token_start = hs.pos;
            hs.token_len = hs.len - hs.pos;
            hs.token_type = TAG_COMMENT;
            return 1;
        }

        let ch = hs.s[idx + offset];
        if ch != CHAR_DASH && ch != CHAR_BANG {
            pos = idx + 1;
            continue;
        }

        offset += 1;
        if idx + offset == end {
            hs.state = Some(h5_state_eof);
            hs.token_start = hs.pos;
            hs.token_len = hs.len - hs.pos;
            hs.token_type = TAG_COMMENT;
            return 1;
        }

        let ch = hs.s[idx + offset];
        if ch != CHAR_GT {
            pos = idx + 1;
            continue;
        }
        offset += 1;

        // ends in --> or -!>
        hs.token_start = hs.pos;
        hs.token_len = idx - hs.pos;
        hs.pos = idx + offset;
        hs.state = Some(h5_state_data);
        hs.token_type = TAG_COMMENT;
        return 1;
    }
}

fn h5_state_cdata(hs: &mut H5State<'_>) -> i32 {
    let mut pos = hs.pos;
    loop {
        let idx = memchr::memchr(CHAR_RIGHTB, &hs.s[pos..hs.len]).map(|i| pos + i);

        // did not find anything or has less than 3 chars left
        match idx {
            Some(idx) if idx + 3 <= hs.len => {
                if hs.s[idx + 1] == CHAR_RIGHTB && hs.s[idx + 2] == CHAR_GT {
                    hs.state = Some(h5_state_data);
                    hs.token_start = hs.pos;
                    hs.token_len = idx - hs.pos;
                    hs.pos = idx + 3;
                    hs.token_type = DATA_TEXT;
                    return 1;
                } else {
                    pos = idx + 1;
                }
            }
            _ => {
                hs.state = Some(h5_state_eof);
                hs.token_start = hs.pos;
                hs.token_len = hs.len - hs.pos;
                hs.token_type = DATA_TEXT;
                return 1;
            }
        }
    }
}

/// 8.2.4.52
fn h5_state_doctype(hs: &mut H5State<'_>) -> i32 {
    hs.token_start = hs.pos;
    hs.token_type = DOCTYPE;

    let idx = memchr::memchr(CHAR_GT, &hs.s[hs.pos..hs.len]).map(|i| hs.pos + i);
    match idx {
        None => {
            hs.state = Some(h5_state_eof);
            hs.token_len = hs.len - hs.pos;
        }
        Some(idx) => {
            hs.state = Some(h5_state_data);
            hs.token_len = idx - hs.pos;
            hs.pos = idx + 1;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(input: &[u8], flags: Html5Flags) -> Vec<(Html5Type, Vec<u8>)> {
        let mut hs = libinjection_h5_init(input, flags);
        let mut out = Vec::new();
        while libinjection_h5_next(&mut hs) == LIBINJECTION_RESULT_TRUE {
            out.push((hs.token_type, hs.token().to_vec()));
        }
        out
    }

    fn t(ty: Html5Type, v: &str) -> (Html5Type, Vec<u8>) {
        (ty, v.as_bytes().to_vec())
    }

    // Cases from libinjection v4.0.2 tests/test-html5-*.txt.
    #[test]
    fn tag_with_attributes() {
        assert_eq!(
            tokens(b"<a href=\"x\" onclick=y>z</a>", Html5Flags::DATA_STATE),
            vec![
                t(TAG_NAME_OPEN, "a"),
                t(ATTR_NAME, "href"),
                t(ATTR_VALUE, "x"),
                t(ATTR_NAME, "onclick"),
                t(ATTR_VALUE, "y"),
                t(TAG_NAME_CLOSE, ">"),
                t(DATA_TEXT, "z"),
                t(TAG_CLOSE, "a"),
            ]
        );
    }

    #[test]
    fn comments_and_doctype() {
        assert_eq!(
            tokens(b"<!-- x --!><!DOCTYPE html><?pi?>", Html5Flags::DATA_STATE),
            vec![
                t(TAG_COMMENT, " x -"),
                t(DOCTYPE, "DOCTYPE html"),
                t(TAG_COMMENT, "pi?"),
            ]
        );
    }

    #[test]
    fn nul_ends_attribute_name_but_not_tag_name() {
        assert_eq!(
            tokens(b"<sc\0ript a\0b>", Html5Flags::DATA_STATE),
            vec![
                t(TAG_NAME_OPEN, "sc\0ript"),
                t(ATTR_NAME, "a"),
                t(ATTR_NAME, "b"),
                t(TAG_NAME_CLOSE, ">"),
            ]
        );
    }

    #[test]
    fn starts_inside_a_quoted_value() {
        assert_eq!(
            tokens(b"x' onload=y", Html5Flags::VALUE_SINGLE_QUOTE),
            vec![
                t(ATTR_VALUE, "x"),
                t(ATTR_NAME, "onload"),
                t(ATTR_VALUE, "y"),
            ]
        );
    }
}
