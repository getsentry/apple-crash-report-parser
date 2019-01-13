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
    static ref THREAD_NAME_RE: Regex = Regex::new(
        r#"(?x)
        ^Thread\ ([0-9]+)\ name:\s*(.+?)
        (?:\s+Dispatch\ queue:\s*(.*?))?\s*$
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
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_none"))]
    pub timestamp: Option<DateTime<Utc>>,
    /// The architecture of the crash (might require further parsing)
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_none"))]
    pub code_type: Option<String>,
    /// The path to the application.
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_none"))]
    pub path: Option<String>,
    /// Optional application specific crash information as string.
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_none"))]
    pub application_specific_information: Option<String>,
    /// Optional syslog info
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_none"))]
    pub filtered_syslog: Option<String>,
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
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_none"))]
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
    /// The name of the dispatch queue
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_none"))]
    pub dispatch_queue: Option<String>,
    /// `true` if this thread crashed.
    pub crashed: bool,
    /// The list of frames
    pub frames: Vec<Frame>,
    /// A dump of all the registers of the thread if available.
    #[cfg_attr(feature = "with_serde", serde(skip_serializing_if = "Option::is_some"))]
    pub registers: Option<BTreeMap<String, Addr>>,
}

enum ParsingState {
    Root,
    Thread,
    BinaryImages,
    ThreadState,
    FilteredSyslog,
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

    #[allow(clippy::cyclomatic_complexity)]
    fn from_line_iter<'a, I: Iterator<Item = Result<Cow<'a, str>, io::Error>>>(
        iter: I,
    ) -> Result<AppleCrashReport, ParseError> {
        let mut state = ParsingState::Root;
        let mut thread = None;
        let mut thread_names = BTreeMap::new();
        let mut registers = BTreeMap::new();
        let mut application_specific_information = String::new();
        let mut filtered_syslog = String::new();

        let mut rv = AppleCrashReport::default();

        for line in iter {
            let line = line.map_err(ParseError::Io)?;
            let line = line.trim_end();

            if line.starts_with("Binary Images:") {
                state = ParsingState::BinaryImages;
                continue;
            } else if line.starts_with("Application Specific Information:") {
                state = ParsingState::ApplicationSpecificInformation;
                continue;
            } else if line.starts_with("Filtered syslog:") {
                state = ParsingState::FilteredSyslog;
                continue;
            } else if THREAD_STATE_RE.is_match(&line) {
                state = ParsingState::ThreadState;
                continue;
            } else if let Some(caps) = THREAD_RE.captures(&line) {
                if let Some(thread) = thread.take() {
                    rv.threads.push(thread);
                }
                thread = Some(Thread {
                    id: caps[1].parse().unwrap(),
                    name: caps.get(3).map(|m| m.as_str().to_string()),
                    dispatch_queue: None,
                    frames: vec![],
                    crashed: caps.get(2).is_some(),
                    registers: None,
                });
                state = ParsingState::Thread;
                continue;
            } else if let Some(caps) = THREAD_NAME_RE.captures(&line) {
                thread_names.insert(caps[1].parse::<u64>().unwrap(), (
                    caps[2].to_string(),
                    caps.get(3).map(|x| x.as_str().to_string())
                ));
                state = ParsingState::Root;
                continue;
            }

            state = match state {
                ParsingState::Root => {
                    if let Some(caps) = KEY_VALUE_RE.captures(&line) {
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
                    }
                    ParsingState::Root
                }
                ParsingState::ThreadState => {
                    if line.is_empty() {
                        ParsingState::Root
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
                        ParsingState::Root
                    }
                }
                ParsingState::BinaryImages => {
                    if line.is_empty() {
                        ParsingState::BinaryImages
                    } else if let Some(caps) = BINARY_IMAGE_RE.captures(&line) {
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
                        ParsingState::Root
                    }
                }
                ParsingState::ApplicationSpecificInformation => {
                    if !application_specific_information.is_empty() {
                        application_specific_information.push('\n');
                    }
                    application_specific_information.push_str(line);
                    ParsingState::ApplicationSpecificInformation
                }
                ParsingState::FilteredSyslog => {
                    if !filtered_syslog.is_empty() {
                        filtered_syslog.push('\n');
                    }
                    filtered_syslog.push_str(line);
                    ParsingState::FilteredSyslog
                }
            }
        }

        if let Some(thread) = thread.take() {
            rv.threads.push(thread);
        }

        for thread in rv.threads.iter_mut() {
            if let Some((name, dispatch_queue)) = thread_names.remove(&thread.id) {
                thread.name = Some(name);
                thread.dispatch_queue = dispatch_queue;
            }
        }

        if !registers.is_empty() {
            for thread in rv.threads.iter_mut() {
                if thread.crashed {
                    thread.registers = Some(registers);
                    break;
                }
            }
        }

        if !application_specific_information.is_empty() {
            if application_specific_information.ends_with('\n') {
                application_specific_information.truncate(application_specific_information.len() - 1);
            }
            rv.application_specific_information = Some(application_specific_information);
        }
        if !filtered_syslog.is_empty() {
            if filtered_syslog.ends_with('\n') {
                filtered_syslog.truncate(filtered_syslog.len() - 1);
            }
            rv.filtered_syslog = Some(filtered_syslog);
        }

        Ok(rv)
    }
}