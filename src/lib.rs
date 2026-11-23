//! The `honeypot` library: everything the honeypot knows how to do.
//!
//! `src/main.rs` is the program you run, and it uses this library. Each module
//! below is one stage of the course. New stages add a new `pub mod` line here.

// This makes the compiler refuse any `unsafe` code in this library.
#![forbid(unsafe_code)]

pub mod deploy;
pub mod fake_shell;
pub mod fake_web;
pub mod log_files;
pub mod login;
pub mod report;
pub mod server;
pub mod services;
pub mod visit;
