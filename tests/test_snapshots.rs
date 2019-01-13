use std::fs;

use apple_crash_report_parser::AppleCrashReport;
use insta::assert_serialized_snapshot_matches;


fn load_fixture(name: &str) -> String {
    fs::read_to_string(format!("tests/fixtures/{}.txt", name)).unwrap()
}

#[test]
fn test_bruno() {
    let fixture = load_fixture("bruno");
    let report: AppleCrashReport = fixture.parse().unwrap();
    assert_serialized_snapshot_matches!("bruno", &report);
}

#[test]
fn test_handcrafted() {
    let fixture = load_fixture("handcrafted");
    let report: AppleCrashReport = fixture.parse().unwrap();
    assert_serialized_snapshot_matches!("handcrafted", &report);
}

#[test]
fn test_xcdyoutubekit_54() {
    let fixture = load_fixture("XCDYouTubeKit-54");
    let report: AppleCrashReport = fixture.parse().unwrap();
    assert_serialized_snapshot_matches!("XCDYouTubeKit-54", &report);
}