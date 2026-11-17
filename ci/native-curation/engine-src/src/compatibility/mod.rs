//! Immutable compatibility environments and bounded, non-executing binary inspection.
mod acquire;
mod binary;
mod container;
mod environment;
pub use acquire::*;
pub use binary::*;
pub use container::*;
pub use environment::*;

pub mod perl;

pub mod windows_crt;
