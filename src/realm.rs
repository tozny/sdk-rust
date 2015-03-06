//! High level methods for making realm-level API calls to the Tozny API.
//!
//! API calls defined in this module require a realm key id and a corresponding
//! realm secret.

use collections::BTreeMap;
use rustc_serialize::{Decodable, json};
use rustc_serialize::json::{Json, ToJson};
use url::{Url};

use login::Login;
use protocol::{
    KeyId, Method, Secret, SessionId, Timestamp, UserId
};
use user::User;
use question;
use question::{QuestionError, from_json};

/// Type representing a particular Tozny realm.
#[derive(PartialEq, Eq, Debug, RustcDecodable, RustcEncodable)]
pub struct Realm {
    key_id:  KeyId,
    secret:  Secret,
    api_url: Url
}

impl Realm {
    /// Creates a new realm interface.
    ///
    /// This does not create a Tozny realm - it just creates an object to
    /// interact with an existing real.
    pub fn new(key_id: KeyId, secret: Secret, url: Url) -> Realm {
        Realm {
            key_id: key_id,
            secret: secret,
            api_url: url,
        }
    }

    /// Low-level method to make arbitrary realm-level API calls.
    pub fn raw_call(&self, method: &Method, params: &json::Object
                    ) -> Result<Json, QuestionError> {
        let &Realm{ ref key_id, ref secret, ref api_url } = self;
        question::send_request(api_url, key_id, secret, method, params)
    }

    /// Given a response from the `check_session_status` call in UserApi,
    /// verifies that the response is signed by Tozny, and decodes a `Login`
    /// value.
    ///
    /// This function runs locally - it does not make any network requests.
    pub fn verify_login(&self, signed_data: &str, signature: &str
                        ) -> Result<Login, QuestionError> {
        if question::check_signature(&self.secret, signature, signed_data) {
            question::unpack::<Login>(signed_data)
        }
        else {
            Err(QuestionError::InvalidSignature)
        }
    }

    /// Checks whether a given session is valid for a given user.  This is an
    /// alternative to using `check_session_status` and `verify_login`.
    pub fn check_valid_login(&self, uid: &UserId, sid: &SessionId, expires_at: &Timestamp
                             ) -> Result<bool, question::QuestionError> {
        let mut q: json::Object = BTreeMap::new();
        q.insert("user_id"   .to_string(), uid       .to_json());
        q.insert("session_id".to_string(), sid       .to_json());
        q.insert("expires_at".to_string(), expires_at.to_json());
        self.raw_call(&Method::from_slice("realm.check_valid_login"), &q)
        .and_then(|resp| {
            match resp {
                Json::Object(obj) => Ok(obj),
                _                 => Err(QuestionError::BadlyFormedResponse),
            }
        })
        .and_then(|obj| {
            match obj.get("return") {
                Some(&Json::String(ref s)) => Ok(s.as_slice() == "true"),
                _                          => Err(QuestionError::BadlyFormedResponse),
            }
        })
    }

    pub fn question_challenge<A, B>(&self, question: &A, user_id: &Option<UserId>
                                   ) -> Result<B, QuestionError>
        where A: ToJson, B: Decodable {
        let mut q: json::Object = BTreeMap::new();
        q.insert("question".to_string(), question.to_json());

        match user_id {
            &Some(ref uid) => q.insert("user_id".to_string(), uid.to_json()),
            _              => None,
        };

        self.raw_call(&Method::from_slice("realm.question_challenge"), &q)
        .and_then(|resp| {
            match resp {  // TODO: extract response-unpacking boilerplate into helper
                Json::Object(obj) => Ok(obj),
                _                 => Err(QuestionError::BadlyFormedResponse),
            }
        })
        .and_then(|obj| {
            match obj.get("results") {
                Some(js) => from_json(js).map_err(QuestionError::DecoderError),
                None     => Err(QuestionError::BadlyFormedResponse),
            }
        })
    }

    /// Given a Tozny user id, retrieves additional information associated with
    /// that user.
    pub fn user_get(&self, user_id: &UserId) -> Result<User, QuestionError> {
        let mut q: json::Object = BTreeMap::new();
        q.insert("user_id".to_string(), user_id.to_json());
        self.raw_call(&Method::from_slice("realm.user_get"), &q)
        .and_then(|resp| {
            match resp {
                Json::Object(obj) => Ok(obj),
                _                 => Err(QuestionError::BadlyFormedResponse),
            }
        })
        .and_then(|obj| {
            match obj.get("results") {
                Some(js) => from_json(js).map_err(QuestionError::DecoderError),
                None     => Err(QuestionError::BadlyFormedResponse),
            }
        })
    }
}
