use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read};

use chrono::{DateTime, FixedOffset, Utc};
use lazy_static::lazy_static;
use regex::Regex;
#[cfg(feature = "with_serde")]
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

/// A newtype for addresses.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Addr(u64);

#[cfg(feature = "with_serde")]
impl Serialize for Addr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        format!("0x{:x}", self.0).serialize(serializer)
    }
}

/// Holds a parsed apple crash report.
#[derive(Debug, Default)]
#[cfg_attr(feature = "with_serde", derive(Serialize))]
pub struct AppleCrashReport {
    /// The unique crash ID.
    pub incident_identifier: Uuid,
    /// The timestamp of the crash.
    pub timestamp: Option<DateTime<Utc>>,
    /// The architecture of the crash (might require further parsing)
    pub code_type: Option<String>,
    /// The path to the application.
    pub path: Option<String>,
    /// Optional application specific crash information as string.
    pub application_specific_information: Option<String>,
    /// The internal report version.
    pub report_version: u32,
    /// Extra metdata.
    pub metadata: BTreeMap<String, String>,
    /// A list of threads.
    pub threads: Vec<Thread>,
    /// A list of referenced binary images.
    pub binary_images: Vec<BinaryImage>,
}

/// A single binary image in the crash.
#[derive(Debug)]
#[cfg_attr(feature = "with_serde", derive(Serialize))]
pub struct BinaryImage {
    /// The address of the image,
    pub addr: Addr,
    /// The size of the image,
    pub size: u64,
    /// The unique ID of the image,
    pub uuid: Uuid,
    /// The architecture of the image,
    pub arch: String,
    /// The version of the image if available. This might require further parsing.
    pub version: Option<String>,
    /// The short name of the image.
    pub name: String,
    /// The full path of the image.
    pub path: String,
}

/// Represents a single frame.
#[derive(Debug)]
#[cfg_attr(feature = "with_serde", derive(Serialize))]
pub struct Frame {
    /// The module of the frame.
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_none"))]
    pub module: Option<String>,
    /// The symbol of the frame if available.
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_none"))]
    pub symbol: Option<String>,
    /// The filename of the frame if available.
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_none"))]
    pub filename: Option<String>,
    /// The line number of the frame if available.
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_none"))]
    pub lineno: Option<u32>,
    //// The instruction address of the frame.
    pub instruction_addr: Addr,
}

/// A single thread in the crash.
#[derive(Debug)]
#[cfg_attr(feature = "with_serde", derive(Serialize))]
pub struct Thread {
    /// The ID (index) of the thread.
    pub id: u64,
    /// The name of the thread if available.
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_none"))]
    pub name: Option<String>,
    /// `true` if this thread crashed.
    pub crashed: bool,
    /// The list of frames
    pub frames: Vec<Frame>,
    /// A dump of all the registers of the thread if available.
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_some"))]
    pub registers: Option<BTreeMap<String, Addr>>,
}

enum ParsingState {
    Header,
    Thread,
    BinaryImages,
    ThreadState,
    ApplicationSpecificInformation,
}

/// Represents a parsing error.
#[derive(Debug)]
pub enum ParseError {
    Io(io::Error),
    InvalidIncidentIdentifier(uuid::parser::ParseError),
    InvalidReportVersion(std::num::ParseIntError),
    InvalidTimestamp(chrono::ParseError),
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            ParseError::Io(ref err) => Some(err),
            ParseError::InvalidIncidentIdentifier(ref err) => Some(err),
            ParseError::InvalidReportVersion(ref err) => Some(err),
            ParseError::InvalidTimestamp(ref err) => Some(err),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseError::Io(..) => write!(f, "io error during parsing"),
            ParseError::InvalidIncidentIdentifier(..) => write!(f, "invalid incident identifier"),
            ParseError::InvalidReportVersion(..) => write!(f, "invalid report version"),
            ParseError::InvalidTimestamp(..) => write!(f, "invalid timestamp"),
        }
    }
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
                            registers: None,
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
                            module: if &caps[1] == "???" {
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
                            uuid: caps[6]
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
                    thread.registers = Some(registers);
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

    assert_eq!(format!("{:#?}", &report), r#"AppleCrashReport {
    incident_identifier: Uuid(
        [
            92,
            50,
            223,
            132,
            49,
            160,
            67,
            231,
            135,
            208,
            35,
            159,
            127,
            89,
            73,
            64
        ]
    ),
    timestamp: Some(
        2019-01-09T17:42:22Z
    ),
    code_type: Some(
        "X86-64"
    ),
    path: Some(
        "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/MacOS/YetAnotherMac"
    ),
    application_specific_information: Some(
        "objc_msgSend() selector name: respondsToSelector:\n  more information here"
    ),
    report_version: 104,
    metadata: {
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
    threads: [
        Thread {
            id: 0,
            name: None,
            crashed: false,
            frames: [
                Frame {
                    module: Some(
                        "libsystem_kernel.dylib"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734833126442
                    )
                },
                Frame {
                    module: Some(
                        "CoreFoundation"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734076244062
                    )
                },
                Frame {
                    module: Some(
                        "CoreFoundation"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734076241325
                    )
                },
                Frame {
                    module: Some(
                        "CoreFoundation"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734076239076
                    )
                },
                Frame {
                    module: Some(
                        "HIToolbox"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734062188693
                    )
                },
                Frame {
                    module: Some(
                        "HIToolbox"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734062187979
                    )
                },
                Frame {
                    module: Some(
                        "HIToolbox"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734062187336
                    )
                },
                Frame {
                    module: Some(
                        "AppKit"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734031505755
                    )
                },
                Frame {
                    module: Some(
                        "AppKit"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734031501050
                    )
                },
                Frame {
                    module: Some(
                        "AppKit"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734031476573
                    )
                },
                Frame {
                    module: Some(
                        "YetAnotherMac"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        4441180459
                    )
                },
                Frame {
                    module: Some(
                        "YetAnotherMac"
                    ),
                    symbol: Some(
                        "a_function_here"
                    ),
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        4441178790
                    )
                },
                Frame {
                    module: Some(
                        "libdyld.dylib"
                    ),
                    symbol: Some(
                        "start"
                    ),
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734831845509
                    )
                },
                Frame {
                    module: Some(
                        "YetanotherMac"
                    ),
                    symbol: Some(
                        "main"
                    ),
                    filename: Some(
                        "main.m"
                    ),
                    lineno: Some(
                        16
                    ),
                    instruction_addr: Addr(
                        958468
                    )
                }
            ],
            registers: None
        },
        Thread {
            id: 1,
            name: Some(
                "Test Thread Name"
            ),
            crashed: true,
            frames: [
                Frame {
                    module: Some(
                        "libsystem_kernel.dylib"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734833132990
                    )
                },
                Frame {
                    module: Some(
                        "libsystem_pthread.dylib"
                    ),
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        140734833882133
                    )
                },
                Frame {
                    module: None,
                    symbol: None,
                    filename: None,
                    lineno: None,
                    instruction_addr: Addr(
                        1414025796
                    )
                }
            ],
            registers: Some(
                {
                    "cs": Addr(
                        43
                    ),
                    "fs": Addr(
                        0
                    ),
                    "gs": Addr(
                        0
                    ),
                    "r10": Addr(
                        0
                    ),
                    "r11": Addr(
                        4294967295
                    ),
                    "r12": Addr(
                        8
                    ),
                    "r13": Addr(
                        4806675200
                    ),
                    "r14": Addr(
                        1
                    ),
                    "r15": Addr(
                        0
                    ),
                    "r8": Addr(
                        3
                    ),
                    "r9": Addr(
                        16
                    ),
                    "rax": Addr(
                        2316569520239214735
                    ),
                    "rbp": Addr(
                        123145665517264
                    ),
                    "rbx": Addr(
                        0
                    ),
                    "rcx": Addr(
                        4974601920
                    ),
                    "rdi": Addr(
                        0
                    ),
                    "rdx": Addr(
                        1
                    ),
                    "rflags": Addr(
                        66054
                    ),
                    "rip": Addr(
                        4446617906
                    ),
                    "rsi": Addr(
                        0
                    ),
                    "rsp": Addr(
                        123145665516528
                    )
                }
            )
        }
    ],
    binary_images: [
        BinaryImage {
            addr: Addr(
                4435795968
            ),
            size: 108797951,
            uuid: Uuid(
                [
                    45,
                    144,
                    50,
                    145,
                    57,
                    125,
                    61,
                    20,
                    191,
                    202,
                    82,
                    199,
                    251,
                    140,
                    94,
                    0
                ]
            ),
            arch: "x86_64",
            version: Some(
                "400.9.4 - 1.0.0"
            ),
            name: "YetAnotherMac",
            path: "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/MacOS/YetAnotherMac"
        },
        BinaryImage {
            addr: Addr(
                4609220608
            ),
            size: 2170879,
            uuid: Uuid(
                [
                    109,
                    236,
                    206,
                    228,
                    160,
                    82,
                    62,
                    164,
                    187,
                    103,
                    149,
                    123,
                    6,
                    245,
                    58,
                    209
                ]
            ),
            arch: "x86_64",
            version: Some(
                "0.0.0 - 0.0.0"
            ),
            name: "libPhysX3PROFILE.dylib",
            path: "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3PROFILE.dylib"
        },
        BinaryImage {
            addr: Addr(
                4613472256
            ),
            size: 221183,
            uuid: Uuid(
                [
                    94,
                    1,
                    42,
                    100,
                    108,
                    197,
                    54,
                    241,
                    155,
                    77,
                    160,
                    86,
                    64,
                    73,
                    22,
                    155
                ]
            ),
            arch: "x86_64",
            version: Some(
                "0.0.0 - 0.0.0"
            ),
            name: "libPhysX3CookingPROFILE.dylib",
            path: "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3CookingPROFILE.dylib"
        },
        BinaryImage {
            addr: Addr(
                4613812224
            ),
            size: 1474559,
            uuid: Uuid(
                [
                    156,
                    25,
                    133,
                    68,
                    113,
                    148,
                    61,
                    230,
                    182,
                    126,
                    76,
                    194,
                    126,
                    237,
                    46,
                    171
                ]
            ),
            arch: "x86_64",
            version: Some(
                "0.0.0 - 0.0.0"
            ),
            name: "libPhysX3CommonPROFILE.dylib",
            path: "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3CommonPROFILE.dylib"
        },
        BinaryImage {
            addr: Addr(
                4615806976
            ),
            size: 28671,
            uuid: Uuid(
                [
                    137,
                    15,
                    9,
                    151,
                    249,
                    4,
                    53,
                    68,
                    154,
                    247,
                    207,
                    1,
                    31,
                    9,
                    160,
                    110
                ]
            ),
            arch: "x86_64",
            version: Some(
                "400.9.0 - 1.0.0"
            ),
            name: "libPxFoundationPROFILE.dylib",
            path: "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPxFoundationPROFILE.dylib"
        }
    ]
}"#);

    #[cfg(feature = "with_serde")]
    {
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
      "crashed": false,
      "frames": [
        {
          "module": "libsystem_kernel.dylib",
          "instruction_addr": "0x7fff61bc6c2a"
        },
        {
          "module": "CoreFoundation",
          "instruction_addr": "0x7fff349f505e"
        },
        {
          "module": "CoreFoundation",
          "instruction_addr": "0x7fff349f45ad"
        },
        {
          "module": "CoreFoundation",
          "instruction_addr": "0x7fff349f3ce4"
        },
        {
          "module": "HIToolbox",
          "instruction_addr": "0x7fff33c8d895"
        },
        {
          "module": "HIToolbox",
          "instruction_addr": "0x7fff33c8d5cb"
        },
        {
          "module": "HIToolbox",
          "instruction_addr": "0x7fff33c8d348"
        },
        {
          "module": "AppKit",
          "instruction_addr": "0x7fff31f4a95b"
        },
        {
          "module": "AppKit",
          "instruction_addr": "0x7fff31f496fa"
        },
        {
          "module": "AppKit",
          "instruction_addr": "0x7fff31f4375d"
        },
        {
          "module": "YetAnotherMac",
          "instruction_addr": "0x108b7092b"
        },
        {
          "module": "YetAnotherMac",
          "symbol": "a_function_here",
          "instruction_addr": "0x108b702a6"
        },
        {
          "module": "libdyld.dylib",
          "symbol": "start",
          "instruction_addr": "0x7fff61a8e085"
        },
        {
          "module": "YetanotherMac",
          "symbol": "main",
          "filename": "main.m",
          "lineno": 16,
          "instruction_addr": "0xea004"
        }
      ],
      "registers": null
    },
    {
      "id": 1,
      "name": "Test Thread Name",
      "crashed": true,
      "frames": [
        {
          "module": "libsystem_kernel.dylib",
          "instruction_addr": "0x7fff61bc85be"
        },
        {
          "module": "libsystem_pthread.dylib",
          "instruction_addr": "0x7fff61c7f415"
        },
        {
          "instruction_addr": "0x54485244"
        }
      ]
    }
  ],
  "binary_images": [
    {
      "addr": "0x10864e000",
      "size": 108797951,
      "uuid": "2d903291-397d-3d14-bfca-52c7fb8c5e00",
      "arch": "x86_64",
      "version": "400.9.4 - 1.0.0",
      "name": "YetAnotherMac",
      "path": "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/MacOS/YetAnotherMac"
    },
    {
      "addr": "0x112bb2000",
      "size": 2170879,
      "uuid": "6deccee4-a052-3ea4-bb67-957b06f53ad1",
      "arch": "x86_64",
      "version": "0.0.0 - 0.0.0",
      "name": "libPhysX3PROFILE.dylib",
      "path": "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3PROFILE.dylib"
    },
    {
      "addr": "0x112fc0000",
      "size": 221183,
      "uuid": "5e012a64-6cc5-36f1-9b4d-a0564049169b",
      "arch": "x86_64",
      "version": "0.0.0 - 0.0.0",
      "name": "libPhysX3CookingPROFILE.dylib",
      "path": "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3CookingPROFILE.dylib"
    },
    {
      "addr": "0x113013000",
      "size": 1474559,
      "uuid": "9c198544-7194-3de6-b67e-4cc27eed2eab",
      "arch": "x86_64",
      "version": "0.0.0 - 0.0.0",
      "name": "libPhysX3CommonPROFILE.dylib",
      "path": "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPhysX3CommonPROFILE.dylib"
    },
    {
      "addr": "0x1131fa000",
      "size": 28671,
      "uuid": "890f0997-f904-3544-9af7-cf011f09a06e",
      "arch": "x86_64",
      "version": "400.9.0 - 1.0.0",
      "name": "libPxFoundationPROFILE.dylib",
      "path": "/Users/bruno/Documents/Unreal Projects/YetAnotherMac/MacNoEditor/YetAnotherMac.app/Contents/UE4/Engine/Binaries/ThirdParty/PhysX3/Mac/libPxFoundationPROFILE.dylib"
    }
  ]
}"#);
    }
}
