//! High level methods for making realm-level API calls to the Tozny API.
//!
//! API calls defined in this module do not require authentication.

use hyper::client::{Client};
use rustc_serialize::json::{Json};
use url;
use url::Url;

use protocol;
use protocol::{Challenge, KeyId, Presence, Newtype, SessionId, Timestamp, UserId};
use question;
use question::{Question, QuestionError, from_json};

/// Information associated with a Tozny user.  This struct should be expanded in
/// the future.
#[derive(Debug, RustcDecodable, RustcEncodable)]
pub struct User {
    pub id:     UserId,
    pub logins: isize,
}

/// Result of `login_challenge` call.  Contains a number of values that are
/// necessary for an authentication flow.  A brief rundown:
///
/// - `qr_url` is the URL of a QR code that can be displayed to the user.  The
/// user authenticates by scanning the code with the Tozny mobile app.
/// - `mobile_url` is the URL encoded in that QR code.  It uses a custom scheme.
///  If opened on a device with the Tozny app installed, the app will open
///  automatically.
/// - `presence` this value may be stored for future logins. If a stored
/// presence value from a previous login is available, it may be used with the
/// `push` method to send a push notification to the user's mobile device
/// instead of (or in addition to) displaying a QR code.
/// - `session_id` is used with `check_session_status` determine whether the
/// user has completed authentication.
#[derive(Debug, RustcDecodable, RustcEncodable)]
pub struct LoginChallenge {
    pub challenge:    Challenge,
    pub realm_key_id: KeyId,
    pub session_id:   SessionId,
    pub qr_url:       Url,
    pub mobile_url:   Url,
    pub created_at:   Timestamp,
    pub presence:     Presence,
}

/// Interface for sending user-level API calls to Tozny.
pub struct UserApi {
    key_id:  KeyId,
    api_url: url::Url,
}

impl UserApi {
    /// It is necessary to provide a realm key id to identify a realm.  However
    /// the corresponding secret is not required.  So this method can be called
    /// in an untrusted environment.
    ///
    /// The URL's for the public Tozny API is: https://api.tozny.com
    pub fn new(key_id: KeyId, url: Url) -> UserApi {
        UserApi {
            key_id: key_id,
            api_url: url,
        }
    }

    /// Low-level method for sending arbitrary user-level API calls.
    pub fn raw_call<'a>(&self, params: Vec<(&'a str, &'a str)>) -> Result<Json, QuestionError> {
        let mut url = question::translate_url(&self.api_url);
        let mut client = Client::new();
        url.set_query_from_pairs(params.into_iter());
        client.get(url).send().map_err(QuestionError::HttpError)
        .and_then(|mut res| {
            Json::from_reader(&mut res)
                .map_err(QuestionError::ParserError)
        })
        .and_then(|json| {
            match protocol::error_response(&json.clone()) {
                Some(errs) => Err(QuestionError::ErrorResponse(errs.clone())),
                None       => Ok(json),
            }
        })
    }

    /// Use this method to initiate a login.  See the documentation on
    /// `LoginChallenge` for some information on how to use the response.
    pub fn login_challenge(&self) -> Result<LoginChallenge, QuestionError> {
        self.raw_call(vec![
            ("method",       "user.login_challenge"),
            ("realm_key_id", self.key_id.as_slice()),
            ("user_add",     "0"),
            ("format",       "json"),
        ])
        .and_then(|json| {
            from_json(&json).map_err(QuestionError::DecoderError)
        })
    }

    /// Sends a push notification to a user's mobile device asking the user to
    /// sign in to something.
    pub fn push(&self, session_id: &SessionId, presence: &Presence
                ) -> Result<(), QuestionError> {
        self.raw_call(vec![
            ("method",       "user.push"),
            ("realm_key_id", self.key_id.as_slice()),
            ("session_id",   session_id.as_slice()),
            ("presence",     presence.as_slice()),
        ])
        .map(|_| ())
    }

    /// Returns a signed question that may be checked via the `Realm`
    /// `verify_login` method to verify an authenticated session (if the result
    /// is `Ok(Some(question))`.  If the result is `Ok(None)` that indicates
    /// that the session is "pending" - the user has not yet confirmed the
    /// session via the Tozny app.
    pub fn check_session_status(&self, session_id: &SessionId
                               ) -> Result<Option<Question>, QuestionError> {
        self.raw_call(vec![
            ("method",       "user.check_session_status"),
            ("session_id",   session_id.as_slice()),
            ("realm_key_id", self.key_id.as_slice()),
            ("format",       "json"),
        ])
        .and_then(|json| {
            if json.find("signed_data").is_some() && json.find("signature").is_some() {
                from_json::<Question>(&json)
                    .map_err(QuestionError::DecoderError)
                    .map(Some)
            }
            else {
                Ok(None)
            }
        })
    }
}
