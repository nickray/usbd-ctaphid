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

use crate::types::AuthenticatorInfo;

// trait Mandatory {
//     fn ping(&self);
//     fn init(&self);
//     fn msg(&self, message: &[u8]);
// }

// trait Ctap1Mandatory {
//     fn ping(&self);
//     fn msg(&self, message: &[u8]);
// }

pub struct Credential {}

/// an authenticator implements this `authenticator::Api`.
// trait Api<FutureCredential>
// where
//     FutureCredential: core::future::Future,
pub trait Api
{
    /// describe authenticator capabilities
    fn get_info(&self) -> AuthenticatorInfo;

    /// eventually generate a credential with specified options
    fn make_credential(
        &self,
        client_data_hash: &[u8; 32],
        rp: &RelyingParty,
        user: &User,
        algorithms: &[Algorithm],
    )
        // TODO: use core::future::Future or something similar
        // -> Future<Credential>;
        -> Credential;

    /////
    //fn get_assertions(&self) -> Future<Credential>;
}

const MAX_RP_ID_SIZE: usize = 128;
pub struct RelyingPartyId([u8; MAX_RP_ID_SIZE]);

pub struct RelyingParty {
    id: RelyingPartyId,
}

const MAX_USER_ID_SIZE: usize = 128;
pub struct UserId([u8; MAX_USER_ID_SIZE]);

pub struct User {
    id: UserId,
}

pub enum Algorithm {
    ES256,
    EdDSA,
}

trait Wink {
    fn wink(&self);
}
