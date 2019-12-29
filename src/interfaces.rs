//! The idea here is to model the mandatory
//! and optional parts of the Authenticator API
//! as traits.
//!
//! The `usbd-ctaphid` layer is then supposed to handle
//! all kinds of low-level protocol details, leaving it
//! to the fido2 device to implement the actual functionality,
//! using nicer objects instead of transport-level bytes.
//!
//! TODO: Confirm that dependency injection of device logic
//! into CTAPHID driver is the right approach.

use crate::pipe::AuthenticatorInfo;

trait Mandatory {
    fn ping(&self);
    fn init(&self);
    fn msg(&self, message: &[u8]);
}

trait Ctap1Mandatory {
    fn ping(&self);
    fn msg(&self, message: &[u8]);
}

trait Ctap2Device {
    fn get_info(&self) -> AuthenticatorInfo;

    fn wink(&self);
}
