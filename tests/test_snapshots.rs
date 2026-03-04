// These tests require serde for insta
#![cfg(feature = "with_serde")]

use std::fs;

use apple_crash_report_parser::AppleCrashReport;

fn load_fixture(name: &str) -> String {
    fs::read_to_string(format!("tests/fixtures/{name}.txt")).unwrap()
}

// Regression test for https://github.com/getsentry/symbolicator/issues/1884
// Xcode 16+ crash reports use 4 fractional digits in the Date/Time field
// (e.g. "2025-01-01 12:00:00.1234 +0000") which the parser must accept.
#[test]
fn test_xcode16_timestamp_precision() {
    let fixture = load_fixture("xcode16");
    let report: AppleCrashReport = fixture.parse().expect(
        "should parse crash reports with 4-digit fractional seconds in Date/Time",
    );
    assert!(report.timestamp.is_some());
}

macro_rules! test_snapshots {
    ( $( $test:ident => $fixture:literal ),+ $(,)? ) => {
        $(
            #[test]
            fn $test() {
                let fixture = load_fixture($fixture);
                let report: AppleCrashReport = fixture.parse().unwrap();
                insta::assert_yaml_snapshot!($fixture, &report);
            }
        )*
    };
}

test_snapshots!(
    test_bruno => "bruno",
    test_handcrafted => "handcrafted",
    test_xcdyoutubekit_54 => "XCDYouTubeKit-54",
    // Regression test for #5: Spaces in image names
    test_spaces => "spaces",
);
