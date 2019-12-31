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

use crate::types::{
    AuthenticatorInfo,
    MakeCredentialParameters,
};

pub struct Credential {}

/// an authenticator implements this `authenticator::Api`.
/// TODO: modify interface so authenticator can process requests asynchronously.
/// Maybe with core::future::Future?
pub trait Api
{
    /// describe authenticator capabilities
    fn get_info(&self) -> AuthenticatorInfo;

    /// eventually generate a credential with specified options
    fn make_credential(&mut self, params: &MakeCredentialParameters)
        // TODO: use core::future::Future or something similar
        // -> Future<Credential>;
        -> Credential;

    // fn get_assertions(&self) -> Future<Credential>;
}

trait Wink {
    fn wink(&self);
}
