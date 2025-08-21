pub mod client;
pub(crate) mod mdns; // New module
pub(crate) mod mdns_sidecar; // Renamed from original purpose
pub mod models;
pub mod server;
pub use models::*;