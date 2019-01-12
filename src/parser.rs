use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read};

use chrono::{DateTime, FixedOffset, Utc};
use failure::Fail;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Serialize, Serializer};
use uuid::Uuid;

lazy_static! {
    static ref KEY_VALUE_RE: Regex = Regex::new(
        r#"(?x)
        ^\s*(.*?)\s*:\s*(.*?)\s*$
    "#
    )
    .unwrap();
    static ref THREAD_RE: Regex = Regex::new(
        r#"(?x)
        ^Thread\ ([0-9]+)(\ Crashed)?:\s*(.+?)?\s*$
    "#
    )
    .unwrap();
    static ref THREAD_STATE_RE: Regex = Regex::new(
        r#"(?x)
        ^Thread\ ([0-9]+)\ crashed\ with\ .*?\ Thread\ State:\s*$
    "#
    )
    .unwrap();
    static ref REGISTER_RE: Regex = Regex::new(
        r#"(?x)
        \s*
        ([a-z0-9]+):\s+
        (0x[0-9a-fA-F]+)\s*
    "#
    )
    .unwrap();
    static ref FRAME_RE: Regex = Regex::new(
        r#"(?x)
        ^
            [0-9]+ \s+
            (\S+) \s+
            (0x[0-9a-fA-F]+)\s+
            .*
        $
    "#
    )
    .unwrap();
    static ref BINARY_IMAGE_RE: Regex = Regex::new(
        r#"(?x)
        ^
            \s*
            (0x[0-9a-fA-F]+) \s*
            -
            \s*
            (0x[0-9a-fA-F]+) \s+
            \+?(.+)\s+
            (\S+?)\s+
            (?:\(([^)]+?)\))?\s+
            <([^>]+?)>\s+
            (.*?)
        $
    "#
    )
    .unwrap();
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Addr(u64);

impl Serialize for Addr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        format!("0x{:x}", self.0).serialize(serializer)
    }
}

#[derive(Debug, Serialize, Default)]
pub struct AppleCrashReport {
    incident_identifier: Uuid,
    code_type: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    metadata: BTreeMap<String, String>,
    threads: Vec<Thread>,
    binary_images: Vec<BinaryImage>,
}

#[derive(Debug, Serialize)]
pub struct BinaryImage {
    addr: Addr,
    size: u64,
    image_uuid: Uuid,
    arch: String,
    version: Option<String>,
    name: String,
    path: String,
}

#[derive(Debug, Serialize)]
pub struct Frame {
    package: String,
    instruction_addr: Addr,
}

#[derive(Debug, Serialize)]
pub struct Thread {
    id: u64,
    name: Option<String>,
    frames: Vec<Frame>,
    crashed: bool,
    registers: BTreeMap<String, Addr>,
}

enum ParsingState {
    Header,
    Thread,
    BinaryImages,
    ThreadState,
}

#[derive(Fail, Debug)]
pub enum ParseError {
    #[fail(display = "io error during parsing")]
    Io(#[cause] io::Error),
    #[fail(display = "invalid incident identifer")]
    InvalidIncidentIdentifier(#[cause] uuid::parser::ParseError),
    #[fail(display = "invalid timestamp")]
    InvalidTimestamp(#[cause] chrono::ParseError),
}

impl std::str::FromStr for AppleCrashReport {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<AppleCrashReport, ParseError> {
        AppleCrashReport::from_line_iter(s.lines().map(|x| Ok(Cow::Borrowed(x))))
    }
}

impl AppleCrashReport {
    /// Consumes a reader and parses it.
    pub fn from_reader<R: Read>(r: R) -> Result<AppleCrashReport, ParseError> {
        let reader = BufReader::new(r);
        AppleCrashReport::from_line_iter(reader.lines().map(|x| x.map(Cow::Owned)))
    }

    fn from_line_iter<'a, I: Iterator<Item = Result<Cow<'a, str>, io::Error>>>(
        iter: I,
    ) -> Result<AppleCrashReport, ParseError> {
        let mut state = ParsingState::Header;
        let mut thread = None;
        let mut registers = BTreeMap::new();

        let mut rv = AppleCrashReport::default();

        for line in iter {
            let line = line.map_err(ParseError::Io)?;
            let line = line.trim();

            state = match state {
                ParsingState::Header => {
                    if let Some(thread) = thread.take() {
                        rv.threads.push(thread);
                    }
                    if line.is_empty() {
                        continue;
                    } else if line.starts_with("Binary Images:") {
                        ParsingState::BinaryImages
                    } else if THREAD_STATE_RE.is_match(&line) {
                        ParsingState::ThreadState
                    } else if let Some(caps) = THREAD_RE.captures(&line) {
                        thread = Some(Thread {
                            id: caps[1].parse().unwrap(),
                            name: caps.get(3).map(|m| m.as_str().to_string()),
                            frames: vec![],
                            crashed: caps.get(2).is_some(),
                            registers: BTreeMap::new(),
                        });
                        ParsingState::Thread
                    } else if let Some(caps) = KEY_VALUE_RE.captures(&line) {
                        match &caps[1] {
                            "Incident Identifier" => {
                                rv.incident_identifier = caps[2]
                                    .parse()
                                    .map_err(ParseError::InvalidIncidentIdentifier)?;
                            }
                            "Code Type" => {
                                rv.code_type = Some(caps[2].to_string());
                            }
                            "Date/Time" => {
                                let timestamp = DateTime::<FixedOffset>::parse_from_str(
                                    &caps[2],
                                    "%Y-%m-%d %H:%M:%S %z",
                                )
                                .map_err(ParseError::InvalidTimestamp)?;
                                rv.timestamp = Some(timestamp.with_timezone(&Utc));
                            }
                            _ => {
                                rv.metadata.insert(caps[1].to_string(), caps[2].to_string());
                            }
                        }
                        ParsingState::Header
                    } else {
                        ParsingState::Header
                    }
                }
                ParsingState::ThreadState => {
                    if line.is_empty() {
                        ParsingState::Header
                    } else {
                        for caps in REGISTER_RE.captures_iter(&line) {
                            registers.insert(
                                caps[1].to_string(),
                                Addr(u64::from_str_radix(&caps[2][2..], 16).unwrap()),
                            );
                        }
                        ParsingState::ThreadState
                    }
                }
                ParsingState::Thread => {
                    if let Some(caps) = FRAME_RE.captures(&line) {
                        thread.as_mut().unwrap().frames.push(Frame {
                            package: caps[1].to_string(),
                            instruction_addr: Addr(u64::from_str_radix(&caps[2][2..], 16).unwrap()),
                        });
                        ParsingState::Thread
                    } else {
                        ParsingState::Header
                    }
                }
                ParsingState::BinaryImages => {
                    if let Some(caps) = BINARY_IMAGE_RE.captures(&line) {
                        let addr = u64::from_str_radix(&caps[1][2..], 16).unwrap();
                        rv.binary_images.push(BinaryImage {
                            addr: Addr(addr),
                            size: u64::from_str_radix(&caps[2][2..], 16).unwrap() - addr,
                            image_uuid: caps[6]
                                .parse()
                                .map_err(ParseError::InvalidIncidentIdentifier)?,
                            arch: caps[4].to_string(),
                            version: caps.get(5).map(|x| x.as_str().to_string()),
                            name: caps[3].to_string(),
                            path: caps[7].to_string(),
                        });
                        ParsingState::BinaryImages
                    } else {
                        ParsingState::Header
                    }
                }
            }
        }

        if let Some(thread) = thread.take() {
            rv.threads.push(thread);
        }

        if !registers.is_empty() {
            for thread in rv.threads.iter_mut() {
                if thread.crashed {
                    thread.registers = registers;
                    break;
                }
            }
        }

        Ok(rv)
    }
}

#[test]
fn test_basic_parsing() {
    let report: AppleCrashReport = r#"
Incident Identifier: 5C32DF84-31A0-43E7-87D0-239F7F594940
CrashReporter Key:   TODO
Hardware Model:      MacBookPro14,3
Process:         YetAnotherMac [49028]
Path:            /Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/MacOS/YetAnotherMac
Identifier:      com.YourCompany.YetAnotherMac
Version:         4.21.1
Code Type:       X86-64
Parent Process:  launchd [1]

Date/Time:       2019-01-09 17:42:22 +0000
OS Version:      Mac OS X 10.14.0 (18A391)
Report Version:  104

Exception Type:  SIGSEGV
Exception Codes: SEGV_MAPERR at 0x88
Crashed Thread:  5

Thread 0:
0   libsystem_kernel.dylib              0x00007fff61bc6c2a 0x7fff61bc6000 + 3114
1   CoreFoundation                      0x00007fff349f505e 0x7fff349b9000 + 245854
2   CoreFoundation                      0x00007fff349f45ad 0x7fff349b9000 + 243117
3   CoreFoundation                      0x00007fff349f3ce4 0x7fff349b9000 + 240868
4   HIToolbox                           0x00007fff33c8d895 0x7fff33c83000 + 43157
5   HIToolbox                           0x00007fff33c8d5cb 0x7fff33c83000 + 42443
6   HIToolbox                           0x00007fff33c8d348 0x7fff33c83000 + 41800
7   AppKit                              0x00007fff31f4a95b 0x7fff31f30000 + 108891
8   AppKit                              0x00007fff31f496fa 0x7fff31f30000 + 104186
9   AppKit                              0x00007fff31f4375d 0x7fff31f30000 + 79709
10  YetAnotherMac                       0x0000000108b7092b 0x10864e000 + 5384491
11  YetAnotherMac                       0x0000000108b702a6 0x10864e000 + 5382822
12  libdyld.dylib                       0x00007fff61a8e085 0x7fff61a77000 + 94341    

Thread 1 Crashed: Test Thread Name
0   libsystem_kernel.dylib              0x00007fff61bc85be 0x7fff61bc6000 + 9662
1   libsystem_pthread.dylib             0x00007fff61c7f415 0x7fff61c7d000 + 9237
2   ???                                 0x0000000054485244 0x0 + 0

Thread 1 crashed with X86-64 Thread State:
   rip: 0x00000001090a0132    rbp: 0x0000700015a616d0    rsp: 0x0000700015a613f0    rax: 0x20261bb4775b008f 
   rbx: 0x0000000000000000    rcx: 0x00000001288266c0    rdx: 0x0000000000000001    rdi: 0x0000000000000000 
   rsi: 0x0000000000000000     r8: 0x0000000000000003     r9: 0x0000000000000010    r10: 0x0000000000000000 
   r11: 0x00000000ffffffff    r12: 0x0000000000000008    r13: 0x000000011e800b00    r14: 0x0000000000000001 
   r15: 0x0000000000000000 rflags: 0x0000000000010206     cs: 0x000000000000002b     fs: 0x0000000000000000 
    gs: 0x0000000000000000 

Binary Images:
       0x10864e000 -        0x10ee0ffff +YetAnotherMac x86_64 (400.9.4 - 1.0.0) <2d903291397d3d14bfca52c7fb8c5e00> /Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/MacOS/YetAnotherMac
       0x112bb2000 -        0x112dc3fff  libPhysX3PROFILE.dylib x86_64 (0.0.0 - 0.0.0) <6deccee4a0523ea4bb67957b06f53ad1> /Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3PROFILE.dylib
       0x112fc0000 -        0x112ff5fff  libPhysX3CookingPROFILE.dylib x86_64 (0.0.0 - 0.0.0) <5e012a646cc536f19b4da0564049169b> /Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3CookingPROFILE.dylib
       0x113013000 -        0x11317afff  libPhysX3CommonPROFILE.dylib x86_64 (0.0.0 - 0.0.0) <9c19854471943de6b67e4cc27eed2eab> /Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3CommonPROFILE.dylib
       0x1131fa000 -        0x113200fff  libPxFoundationPROFILE.dylib x86_64 (400.9.0 - 1.0.0) <890f0997f90435449af7cf011f09a06e> /Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPxFoundationPROFILE.dylib
    "#.parse().unwrap();

    let json = serde_json::to_string_pretty(&report).unwrap();
    assert_eq!(json, "{\n  \"incident_identifier\": \"5c32df84-31a0-43e7-87d0-239f7f594940\",\n  \"code_type\": \"X86-64\",\n  \"timestamp\": \"2019-01-09T17:42:22Z\",\n  \"metadata\": {\n    \"CrashReporter Key\": \"TODO\",\n    \"Crashed Thread\": \"5\",\n    \"Exception Codes\": \"SEGV_MAPERR at 0x88\",\n    \"Exception Type\": \"SIGSEGV\",\n    \"Hardware Model\": \"MacBookPro14,3\",\n    \"Identifier\": \"com.YourCompany.YetAnotherMac\",\n    \"OS Version\": \"Mac OS X 10.14.0 (18A391)\",\n    \"Parent Process\": \"launchd [1]\",\n    \"Path\": \"/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/MacOS/YetAnotherMac\",\n    \"Process\": \"YetAnotherMac [49028]\",\n    \"Report Version\": \"104\",\n    \"Version\": \"4.21.1\"\n  },\n  \"threads\": [\n    {\n      \"id\": 0,\n      \"name\": null,\n      \"frames\": [\n        {\n          \"package\": \"libsystem_kernel.dylib\",\n          \"instruction_addr\": \"0x7fff61bc6c2a\"\n        },\n        {\n          \"package\": \"CoreFoundation\",\n          \"instruction_addr\": \"0x7fff349f505e\"\n        },\n        {\n          \"package\": \"CoreFoundation\",\n          \"instruction_addr\": \"0x7fff349f45ad\"\n        },\n        {\n          \"package\": \"CoreFoundation\",\n          \"instruction_addr\": \"0x7fff349f3ce4\"\n        },\n        {\n          \"package\": \"HIToolbox\",\n          \"instruction_addr\": \"0x7fff33c8d895\"\n        },\n        {\n          \"package\": \"HIToolbox\",\n          \"instruction_addr\": \"0x7fff33c8d5cb\"\n        },\n        {\n          \"package\": \"HIToolbox\",\n          \"instruction_addr\": \"0x7fff33c8d348\"\n        },\n        {\n          \"package\": \"AppKit\",\n          \"instruction_addr\": \"0x7fff31f4a95b\"\n        },\n        {\n          \"package\": \"AppKit\",\n          \"instruction_addr\": \"0x7fff31f496fa\"\n        },\n        {\n          \"package\": \"AppKit\",\n          \"instruction_addr\": \"0x7fff31f4375d\"\n        },\n        {\n          \"package\": \"YetAnotherMac\",\n          \"instruction_addr\": \"0x108b7092b\"\n        },\n        {\n          \"package\": \"YetAnotherMac\",\n          \"instruction_addr\": \"0x108b702a6\"\n        },\n        {\n          \"package\": \"libdyld.dylib\",\n          \"instruction_addr\": \"0x7fff61a8e085\"\n        }\n      ],\n      \"crashed\": false,\n      \"registers\": {}\n    },\n    {\n      \"id\": 1,\n      \"name\": \"Test Thread Name\",\n      \"frames\": [\n        {\n          \"package\": \"libsystem_kernel.dylib\",\n          \"instruction_addr\": \"0x7fff61bc85be\"\n        },\n        {\n          \"package\": \"libsystem_pthread.dylib\",\n          \"instruction_addr\": \"0x7fff61c7f415\"\n        },\n        {\n          \"package\": \"???\",\n          \"instruction_addr\": \"0x54485244\"\n        }\n      ],\n      \"crashed\": true,\n      \"registers\": {\n        \"cs\": \"0x2b\",\n        \"fs\": \"0x0\",\n        \"gs\": \"0x0\",\n        \"r10\": \"0x0\",\n        \"r11\": \"0xffffffff\",\n        \"r12\": \"0x8\",\n        \"r13\": \"0x11e800b00\",\n        \"r14\": \"0x1\",\n        \"r15\": \"0x0\",\n        \"r8\": \"0x3\",\n        \"r9\": \"0x10\",\n        \"rax\": \"0x20261bb4775b008f\",\n        \"rbp\": \"0x700015a616d0\",\n        \"rbx\": \"0x0\",\n        \"rcx\": \"0x1288266c0\",\n        \"rdi\": \"0x0\",\n        \"rdx\": \"0x1\",\n        \"rflags\": \"0x10206\",\n        \"rip\": \"0x1090a0132\",\n        \"rsi\": \"0x0\",\n        \"rsp\": \"0x700015a613f0\"\n      }\n    }\n  ],\n  \"binary_images\": [\n    {\n      \"addr\": \"0x10864e000\",\n      \"size\": 108797951,\n      \"image_uuid\": \"2d903291-397d-3d14-bfca-52c7fb8c5e00\",\n      \"arch\": \"x86_64\",\n      \"version\": \"400.9.4 - 1.0.0\",\n      \"name\": \"YetAnotherMac\",\n      \"path\": \"/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/MacOS/YetAnotherMac\"\n    },\n    {\n      \"addr\": \"0x112bb2000\",\n      \"size\": 2170879,\n      \"image_uuid\": \"6deccee4-a052-3ea4-bb67-957b06f53ad1\",\n      \"arch\": \"x86_64\",\n      \"version\": \"0.0.0 - 0.0.0\",\n      \"name\": \"libPhysX3PROFILE.dylib\",\n      \"path\": \"/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3PROFILE.dylib\"\n    },\n    {\n      \"addr\": \"0x112fc0000\",\n      \"size\": 221183,\n      \"image_uuid\": \"5e012a64-6cc5-36f1-9b4d-a0564049169b\",\n      \"arch\": \"x86_64\",\n      \"version\": \"0.0.0 - 0.0.0\",\n      \"name\": \"libPhysX3CookingPROFILE.dylib\",\n      \"path\": \"/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3CookingPROFILE.dylib\"\n    },\n    {\n      \"addr\": \"0x113013000\",\n      \"size\": 1474559,\n      \"image_uuid\": \"9c198544-7194-3de6-b67e-4cc27eed2eab\",\n      \"arch\": \"x86_64\",\n      \"version\": \"0.0.0 - 0.0.0\",\n      \"name\": \"libPhysX3CommonPROFILE.dylib\",\n      \"path\": \"/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3CommonPROFILE.dylib\"\n    },\n    {\n      \"addr\": \"0x1131fa000\",\n      \"size\": 28671,\n      \"image_uuid\": \"890f0997-f904-3544-9af7-cf011f09a06e\",\n      \"arch\": \"x86_64\",\n      \"version\": \"400.9.0 - 1.0.0\",\n      \"name\": \"libPxFoundationPROFILE.dylib\",\n      \"path\": \"/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPxFoundationPROFILE.dylib\"\n    }\n  ]\n}");
}
