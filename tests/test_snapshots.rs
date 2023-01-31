// These tests require serde for insta
#![cfg(feature = "with_serde")]

use std::fs;

use apple_crash_report_parser::AppleCrashReport;

fn load_fixture(name: &str) -> String {
    fs::read_to_string(format!("tests/fixtures/{name}.txt")).unwrap()
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
