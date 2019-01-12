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
            (.*?)
            (?:\ (?:\+\ [0-9]+|\((.*?):([0-9]+)\)))?
            \s*
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
    pub incident_identifier: Uuid,
    pub timestamp: Option<DateTime<Utc>>,
    pub code_type: Option<String>,
    pub path: Option<String>,
    pub application_specific_information: Option<String>,
    pub report_version: u32,
    pub metadata: BTreeMap<String, String>,
    pub threads: Vec<Thread>,
    pub binary_images: Vec<BinaryImage>,
}

#[derive(Debug, Serialize)]
pub struct BinaryImage {
    pub addr: Addr,
    pub size: u64,
    pub image_uuid: Uuid,
    pub arch: String,
    pub version: Option<String>,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct Frame {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineno: Option<u32>,
    instruction_addr: Addr,
}

#[derive(Debug, Serialize)]
pub struct Thread {
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub frames: Vec<Frame>,
    pub crashed: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub registers: BTreeMap<String, Addr>,
}

enum ParsingState {
    Header,
    Thread,
    BinaryImages,
    ThreadState,
    ApplicationSpecificInformation,
}

#[derive(Fail, Debug)]
pub enum ParseError {
    #[fail(display = "io error during parsing")]
    Io(#[cause] io::Error),
    #[fail(display = "invalid incident identifer")]
    InvalidIncidentIdentifier(#[cause] uuid::parser::ParseError),
    #[fail(display = "invalid report version")]
    InvalidReportVersion(#[cause] std::num::ParseIntError),
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
            let line = line.trim_end();

            state = match state {
                ParsingState::Header => {
                    if let Some(thread) = thread.take() {
                        rv.threads.push(thread);
                    }
                    if line.is_empty() {
                        continue;
                    } else if line.starts_with("Binary Images:") {
                        ParsingState::BinaryImages
                    } else if line.starts_with("Application Specific Information:") {
                        ParsingState::ApplicationSpecificInformation
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
                            "Report Version" => {
                                rv.report_version =
                                    caps[2].parse().map_err(ParseError::InvalidReportVersion)?;
                            }
                            "Path" => {
                                rv.path = Some(caps[2].to_string());
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
                            "Crashed Thread" => {}
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
                            package: if &caps[1] == "???" {
                                None
                            } else {
                                Some(caps[1].to_string())
                            },
                            symbol: caps.get(3).and_then(|x| {
                                if x.as_str().starts_with("0x")
                                    && u64::from_str_radix(&x.as_str()[2..], 16).is_ok()
                                {
                                    None
                                } else {
                                    Some(x.as_str().to_string())
                                }
                            }),
                            filename: caps.get(4).map(|x| x.as_str().to_string()),
                            lineno: caps.get(5).map(|x| x.as_str().parse().unwrap()),
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
                ParsingState::ApplicationSpecificInformation => {
                    if line.is_empty() {
                        ParsingState::Header
                    } else {
                        let mut info = rv.application_specific_information.unwrap_or_default();
                        if !info.is_empty() {
                            info.push('\n');
                        }
                        info.push_str(line);
                        rv.application_specific_information = Some(info);
                        ParsingState::ApplicationSpecificInformation
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

Application Specific Information:
objc_msgSend() selector name: respondsToSelector:
  more information here

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
11  YetAnotherMac                       0x0000000108b702a6 a_function_here + 64
12  libdyld.dylib                       0x00007fff61a8e085 start + 0
13  YetanotherMac                       0x00000000000ea004 main (main.m:16)

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
    assert_eq!(json, r#"{
  "incident_identifier": "5c32df84-31a0-43e7-87d0-239f7f594940",
  "timestamp": "2019-01-09T17:42:22Z",
  "code_type": "X86-64",
  "path": "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/MacOS/YetAnotherMac",
  "application_specific_information": "objc_msgSend() selector name: respondsToSelector:\n  more information here",
  "report_version": 104,
  "metadata": {
    "CrashReporter Key": "TODO",
    "Exception Codes": "SEGV_MAPERR at 0x88",
    "Exception Type": "SIGSEGV",
    "Hardware Model": "MacBookPro14,3",
    "Identifier": "com.YourCompany.YetAnotherMac",
    "OS Version": "Mac OS X 10.14.0 (18A391)",
    "Parent Process": "launchd [1]",
    "Process": "YetAnotherMac [49028]",
    "Version": "4.21.1"
  },
  "threads": [
    {
      "id": 0,
      "frames": [
        {
          "package": "libsystem_kernel.dylib",
          "instruction_addr": "0x7fff61bc6c2a"
        },
        {
          "package": "CoreFoundation",
          "instruction_addr": "0x7fff349f505e"
        },
        {
          "package": "CoreFoundation",
          "instruction_addr": "0x7fff349f45ad"
        },
        {
          "package": "CoreFoundation",
          "instruction_addr": "0x7fff349f3ce4"
        },
        {
          "package": "HIToolbox",
          "instruction_addr": "0x7fff33c8d895"
        },
        {
          "package": "HIToolbox",
          "instruction_addr": "0x7fff33c8d5cb"
        },
        {
          "package": "HIToolbox",
          "instruction_addr": "0x7fff33c8d348"
        },
        {
          "package": "AppKit",
          "instruction_addr": "0x7fff31f4a95b"
        },
        {
          "package": "AppKit",
          "instruction_addr": "0x7fff31f496fa"
        },
        {
          "package": "AppKit",
          "instruction_addr": "0x7fff31f4375d"
        },
        {
          "package": "YetAnotherMac",
          "instruction_addr": "0x108b7092b"
        },
        {
          "package": "YetAnotherMac",
          "symbol": "a_function_here",
          "instruction_addr": "0x108b702a6"
        },
        {
          "package": "libdyld.dylib",
          "symbol": "start",
          "instruction_addr": "0x7fff61a8e085"
        },
        {
          "package": "YetanotherMac",
          "symbol": "main",
          "filename": "main.m",
          "lineno": 16,
          "instruction_addr": "0xea004"
        }
      ],
      "crashed": false
    },
    {
      "id": 1,
      "name": "Test Thread Name",
      "frames": [
        {
          "package": "libsystem_kernel.dylib",
          "instruction_addr": "0x7fff61bc85be"
        },
        {
          "package": "libsystem_pthread.dylib",
          "instruction_addr": "0x7fff61c7f415"
        },
        {
          "instruction_addr": "0x54485244"
        }
      ],
      "crashed": true,
      "registers": {
        "cs": "0x2b",
        "fs": "0x0",
        "gs": "0x0",
        "r10": "0x0",
        "r11": "0xffffffff",
        "r12": "0x8",
        "r13": "0x11e800b00",
        "r14": "0x1",
        "r15": "0x0",
        "r8": "0x3",
        "r9": "0x10",
        "rax": "0x20261bb4775b008f",
        "rbp": "0x700015a616d0",
        "rbx": "0x0",
        "rcx": "0x1288266c0",
        "rdi": "0x0",
        "rdx": "0x1",
        "rflags": "0x10206",
        "rip": "0x1090a0132",
        "rsi": "0x0",
        "rsp": "0x700015a613f0"
      }
    }
  ],
  "binary_images": [
    {
      "addr": "0x10864e000",
      "size": 108797951,
      "image_uuid": "2d903291-397d-3d14-bfca-52c7fb8c5e00",
      "arch": "x86_64",
      "version": "400.9.4 - 1.0.0",
      "name": "YetAnotherMac",
      "path": "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/MacOS/YetAnotherMac"
    },
    {
      "addr": "0x112bb2000",
      "size": 2170879,
      "image_uuid": "6deccee4-a052-3ea4-bb67-957b06f53ad1",
      "arch": "x86_64",
      "version": "0.0.0 - 0.0.0",
      "name": "libPhysX3PROFILE.dylib",
      "path": "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3PROFILE.dylib"
    },
    {
      "addr": "0x112fc0000",
      "size": 221183,
      "image_uuid": "5e012a64-6cc5-36f1-9b4d-a0564049169b",
      "arch": "x86_64",
      "version": "0.0.0 - 0.0.0",
      "name": "libPhysX3CookingPROFILE.dylib",
      "path": "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3CookingPROFILE.dylib"
    },
    {
      "addr": "0x113013000",
      "size": 1474559,
      "image_uuid": "9c198544-7194-3de6-b67e-4cc27eed2eab",
      "arch": "x86_64",
      "version": "0.0.0 - 0.0.0",
      "name": "libPhysX3CommonPROFILE.dylib",
      "path": "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3CommonPROFILE.dylib"
    },
    {
      "addr": "0x1131fa000",
      "size": 28671,
      "image_uuid": "890f0997-f904-3544-9af7-cf011f09a06e",
      "arch": "x86_64",
      "version": "400.9.0 - 1.0.0",
      "name": "libPxFoundationPROFILE.dylib",
      "path": "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPxFoundationPROFILE.dylib"
    }
  ]
}"#);
}
