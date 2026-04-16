/// Top-level re-export so `main.rs` can declare `mod window;` and engine/mod.rs
/// can use `crate::window::TimeWindow`.
///
/// The actual implementation lives in `engine/window.rs`.
pub use crate::engine::window::TimeWindow;
