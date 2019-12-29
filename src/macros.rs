//! Here we implement a dumb FIDO2 device that just outputs
//! diagnostic messages using semihosting
//!
//! Maybe a better place is in a separate crate.
//!
//! Maybe also want to pull in dependencies like littlefs2, nisty, salty, ...
//!
//! Similar to littlefs2, the idea is to run test using this MVP implementation

#[macro_export]
macro_rules! semihosting_device {
    () => {{}}
}
