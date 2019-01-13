//! This library implements a simple parser for the apple crash report
//! text format.
//! 
//! This library also defines a `with_serde` feature to enable serde
//! serialization (not not deserialization).
mod parser;

pub use crate::parser::*;
