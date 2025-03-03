//! Finite state machine for Grease payment channels
//!
//! ```mermaid
//! stateDiagram-v2
//!     [*] --> Still
//!     Still --> [*]
//!
//!     Still --> Moving
//!     Moving --> Still
//!     Moving --> Crash
//!     Crash --> [*]
//! ```
//!
//! # See how it looks
