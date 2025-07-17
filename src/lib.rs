#![deny(warnings)]
#![warn(clippy::all, clippy::cargo, clippy::nursery, clippy::pedantic)]
#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::missing_const_for_fn,
    clippy::module_name_repetitions
)]

pub mod allocator;
pub mod crypto;
pub mod types;

pub use crypto::error::CryptoError;
pub use crypto::noise::NoiseState;
pub use crypto::tfhe_context::{ContextConfig, SecurityLevel, TfheContext, TfheContextError};
