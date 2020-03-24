// These tests require serde for insta
#![cfg(feature = "with_serde")]

use std::fs;

use apple_crash_report_parser::AppleCrashReport;

fn load_fixture(name: &str) -> String {
    fs::read_to_string(format!("tests/fixtures/{}.txt", name)).unwrap()
}

#[test]
fn test_bruno() {
    let fixture = load_fixture("bruno");
    let report: AppleCrashReport = fixture.parse().unwrap();
    insta::assert_yaml_snapshot!("bruno", &report);
}

#[test]
fn test_handcrafted() {
    let fixture = load_fixture("handcrafted");
    let report: AppleCrashReport = fixture.parse().unwrap();
    insta::assert_yaml_snapshot!("handcrafted", &report);
}

#[test]
fn test_xcdyoutubekit_54() {
    let fixture = load_fixture("XCDYouTubeKit-54");
    let report: AppleCrashReport = fixture.parse().unwrap();
    insta::assert_yaml_snapshot!("XCDYouTubeKit-54", &report);
}
