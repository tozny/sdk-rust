use protocol::{KeyId, SessionId, SignatureType, Timestamp, UserId};

/// Upon success authentication, the `user.check_session_status` API call will
/// return a `Login` value.
#[derive(Debug, RustcDecodable, RustcEncodable)]
pub struct Login {
    pub user_id:        UserId,
    pub session_id:     SessionId,
    pub realm_key_id:   KeyId,
    pub user_display:   String,
    pub expires_at:     Timestamp,
    pub signature_type: SignatureType,
}
