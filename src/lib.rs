#![doc = include_str!("../docs/lib.md")]

// Macro for getters
macro_rules! getters {
    (deref: $($(#[$doc:meta])* $name:ident -> $ret:ty),* $(,)?) => {
        $($(#[$doc])* #[must_use] pub fn $name(&self) -> $ret { self.$name.as_deref() })*
    };
    (copy: $($(#[$doc:meta])* $name:ident -> $ret:ty),* $(,)?) => {
        $($(#[$doc])* #[must_use] pub fn $name(&self) -> $ret { self.$name })*
    };
    (by_ref: $($(#[$doc:meta])* $name:ident -> $ret:ty),* $(,)?) => {
        $($(#[$doc])* #[must_use] pub fn $name(&self) -> $ret { &self.$name })*
    };
}

pub mod headers;
pub mod keys;

pub mod agent;
pub mod algs;
pub mod message;

pub mod errors;

pub(crate) mod common;
pub(crate) mod cose_struct;
