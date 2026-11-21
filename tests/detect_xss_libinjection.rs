//! `@detectXSS` gives libinjection's verdict.
//!
//! ModSecurity v3 implements the operator with libinjection
//! (`src/operators/detect_xss.cc` calls `libinjection_xss`). The engine used a
//! set of regexes and keyword lists instead, which flagged text such as
//! `online=1` or `javascript:alert(1)` that libinjection clears and missed
//! constructs it flags, such as `<div style=...>` or `<!DOCTYPE`. It is now a
//! port of libinjection v4.0.2. Every verdict below is what C libinjection
//! v4.0.2 returns for the same input.

use zentinel_modsec::libinjection::xss::{detect_xss, is_xss};
use zentinel_modsec::ModSecurity;

/// Inputs C libinjection flags.
const TRUE_POSITIVES: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=//evil.example>",
    "<a href=\"javascript:alert(1)\">x</a>",
    // Numeric entities are decoded in URL attributes, and leading whitespace,
    // control characters and embedded tabs and newlines are skipped.
    "<a href=\"&#106;&#97;&#118;&#97;script:alert(1)\">x</a>",
    "<a href=\" &#x6A;ava\tscript:alert(1)\">x</a>",
    "<object data=\"data:text/html;base64,PHNjcmlwdD4=\">",
    "<div style=\"background:url(x)\">",
    "<b onmouseover=alert(1)>hi</b>",
    "<body onpageshow=alert(1)>",
    "<form><button formaction=javascript:alert(1)>",
    "<set attributeName=\"onmouseover\" to=\"alert(1)\"/>",
    "<x xmlns:xlink=\"http://www.w3.org/1999/xlink\">",
    "<xsl:stylesheet>",
    "<meta http-equiv=refresh content=0>",
    "<link rel=stylesheet href=x>",
    // NUL bytes inside a tag name are ignored.
    "<scr\0ipt>alert(1)</script>",
    // Breaking out of an attribute value: the input is also parsed as if it
    // started inside an unquoted, single-, double- or back-quoted value.
    "\"><script>alert(1)</script>",
    "' onfocus='alert(1)' autofocus='",
    "\" onmouseover=\"alert(1)",
    "onerror=alert(1)",
    "src=javascript:alert(1)",
    "style=color:red",
    // Doctype, IE conditional comments, `<?import`, XML entity definitions.
    "<!DOCTYPE html>",
    "<!--[if IE]><script>alert(1)</script><![endif]-->",
    "<?import namespace=\"t\">",
    "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
];

/// Inputs C libinjection clears: text without HTML, URLs, JSON, User-Agents,
/// and harmless markup.
const BENIGN: &[&str] = &[
    "",
    "hello world",
    "The quick brown fox jumps over the lazy dog.",
    "Price: 5 < 10 and 10 > 5",
    "a<b",
    "1 + 1 = 2",
    "user@example.com",
    "O'Reilly",
    "say \"hi\"",
    "it's `code`",
    "key=value&other=thing",
    "a=1; b=2",
    "https://example.com/path?q=search+terms&page=2#frag",
    "http://localhost:8080/api/v1/users/42",
    "{\"name\":\"Alice\",\"tags\":[\"a\",\"b\"],\"age\":30,\"html\":false}",
    "[1,2,3]",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl/8.4.0",
    "<p>Normal paragraph</p>",
    "<b>bold</b> and <i>italic</i>",
    "<a href=\"https://example.com/\">link</a>",
    "<img src=\"/logo.png\" alt=\"logo\">",
    "<div class=\"row\" id=main>text</div>",
    "<br/>",
    "<!-- a comment -->",
];

/// Inputs the old approximation flagged and C libinjection clears.
/// libinjection tokenizes HTML; it does not look for JavaScript, and it does
/// not decode entities outside URL attribute values.
const OLD_FALSE_POSITIVES: &[&str] = &[
    "online=1",
    "only=yes",
    "javascript:alert(1)",
    "document.cookie",
    "eval(atob('x'))",
    "window.location='x'",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
];

#[test]
fn true_positives_are_flagged() {
    for input in TRUE_POSITIVES {
        assert!(is_xss(input), "missed: {input:?}");
        let result = detect_xss(input);
        assert!(result.is_injection, "missed: {input:?}");
        // libinjection has no XSS fingerprint.
        assert_eq!(result.fingerprint, None);
    }
}

#[test]
fn benign_inputs_are_clear() {
    for input in BENIGN.iter().chain(OLD_FALSE_POSITIVES) {
        assert!(!is_xss(input), "flagged: {input:?}");
        assert!(!detect_xss(input).is_injection, "flagged: {input:?}");
    }
}

#[test]
fn user_agents_with_plus_decoded_are_clear() {
    // CRS decodes with t:urlDecodeUni, which turns '+' into a space.
    for input in BENIGN {
        let decoded = input.replace('+', " ");
        assert!(!is_xss(&decoded), "flagged: {decoded:?}");
    }
}

#[test]
fn detect_xss_rule_on_args() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS \"@detectXSS\" \
        \"id:100,phase:2,pass,nolog,capture,t:none,t:urlDecodeUni\"";
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let run = |query: &str| {
        let mut tx = msc.new_transaction();
        tx.process_uri(&format!("/?{query}"), "GET", "HTTP/1.1")
            .unwrap();
        tx.add_request_header("Host", "example.com").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        tx.matched_data()
            .iter()
            .find(|m| m.rule_id.as_deref() == Some("100"))
            .cloned()
    };

    let hit = run("q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E").expect("XSS in q");
    assert_eq!(hit.variable, "ARGS:q");
    // As in ModSecurity (`detect_xss.cc` stores the input as TX.0), the
    // match is the whole transformed value.
    assert_eq!(
        hit.matched_portion.as_deref(),
        Some("<img src=x onerror=alert(1)>")
    );

    assert!(run("q=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E").is_some());
    assert!(run("q=javascript:alert(1)").is_none());
    assert!(run("q=online%3D1&next=https%3A%2F%2Fexample.com%2F").is_none());
}
