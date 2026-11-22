//! A key selection whose regular expression does not compile matches no key,
//! as in ModSecurity v3. The rule set says so at load, naming the rule and the
//! expression, wherever the expression is written: a rule's target or
//! exclusion, `SecRuleUpdateTargetById`, or a `ctl:` target exclusion.

mod common;

use zentinel_modsec::ModSecurity;

fn load_log(rules: &str) -> String {
    let (loaded, log) = common::capture_log(|| ModSecurity::from_string(rules));
    loaded.expect("rules with an invalid key selection still load");
    log
}

#[test]
fn a_target_that_does_not_compile_is_reported_with_its_rule() {
    let log = load_log(
        "SecRuleEngine On\n\
         SecRule ARGS:/bad(/ \"@contains x\" \"id:11,phase:2,pass\"\n",
    );
    assert!(log.contains("this target inspects nothing"), "{log}");
    assert!(log.contains("rule_id=11") && log.contains("bad("), "{log}");
}

#[test]
fn an_exclusion_that_does_not_compile_is_reported_once_per_rule() {
    let log = load_log(
        "SecRuleEngine On\n\
         SecRule ARGS|ARGS_NAMES|!ARGS:/bad(/ \"@contains x\" \"id:12,phase:2,pass\"\n",
    );
    assert_eq!(
        log.matches("the exclusion leaves nothing out").count(),
        1,
        "{log}"
    );
    assert!(log.contains("rule_id=12"), "{log}");
}

#[test]
fn an_update_target_that_does_not_compile_is_reported() {
    let log = load_log(
        "SecRuleEngine On\n\
         SecRule ARGS \"@contains x\" \"id:13,phase:2,pass\"\n\
         SecRuleUpdateTargetById 13 \"!ARGS:/also(bad/\"\n",
    );
    assert!(log.contains("the exclusion leaves nothing out"), "{log}");
    assert!(
        log.contains("SecRuleUpdateTargetById") && log.contains("also(bad"),
        "{log}"
    );
}

#[test]
fn a_ctl_target_that_does_not_compile_is_reported_once() {
    let log = load_log(
        "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@beginsWith /a\" \"id:14,phase:1,pass,nolog,ctl:ruleRemoveTargetById=20;ARGS:/ctl(bad/\"\n\
         SecRule REQUEST_URI \"@beginsWith /b\" \"id:15,phase:1,pass,nolog,ctl:ruleRemoveTargetById=20;ARGS:/ctl(bad/\"\n",
    );
    assert_eq!(
        log.matches("will leave nothing out").count(),
        1,
        "one warning for the same directive: {log}"
    );
    assert!(
        log.contains("rules_affected=2") && log.contains("ctl(bad"),
        "{log}"
    );
}

#[test]
fn expressions_that_compile_are_not_reported() {
    let log = load_log(
        "SecRuleEngine On\n\
         SecRule ARGS:/^user/|!ARGS:/^user_id$/ \"@contains x\" \"id:16,phase:2,pass,ctl:ruleRemoveTargetById=17;ARGS:/^tok/\"\n",
    );
    assert!(!log.contains("does not compile"), "{log}");
}
