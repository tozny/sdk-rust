/// Provides types and function for signing messages, and for verifying
/// signatures.
///
/// This is a low-level interface.  It is recommended that application authors
/// use higher-level methods on `Realm` or `UserApi`.

use chrono::{Duration, UTC};
use core::ops::Add;
use crypto::hmac::{Hmac};
use crypto::mac::{Mac, MacResult};
use crypto::sha2::{Sha256};
use hyper;
use hyper::client::{Client};
use rustc_serialize::base64::{FromBase64, ToBase64, URL_SAFE};
use rustc_serialize::{base64, json, Decodable, Encodable};
use rustc_serialize::json::{Json, ToJson};
use rand::{Rng, OsRng};
use std::{fmt, old_io, str};

use protocol;
use protocol::{KeyId, Secret, Method, Newtype, Timestamp};
use url;

/// Type representing a signed message.  The data in a `Question` is signed
/// using HMAC-SHA256.
#[derive(Debug)]
#[derive(RustcDecodable)]
#[derive(RustcEncodable)]
pub struct Question {
    pub signed_data: String,
    pub signature:   String
}

impl Question {
    /// Constructs a message to send to the Tozny API.  The format value for
    /// `params` will vary depending on the choice of `method`.
    pub fn new(key_id: &KeyId, secret: &Secret, method: &Method, params: &json::Object
               ) -> Result<Question, json::EncoderError> {
        let nonce      = get_nonce();
        let expires_at = get_expires();

        let mut req = params.clone();
        req.insert("nonce"       .to_string(), nonce     .to_json());
        req.insert("expires_at"  .to_string(), expires_at.to_json());
        req.insert("realm_key_id".to_string(), key_id    .to_json());
        req.insert("method"      .to_string(), method    .to_json());

        json::encode(&req).map(|js| {
            let encoded = js.as_bytes().to_base64(URL_SAFE);
            let mac = sign(secret, &encoded);
            let signature = mac.code().to_base64(URL_SAFE);
            Question {
                signed_data: encoded,
                signature: signature
            }
        })
    }
}

/// Enumerates the possible errors that may occur while signing a message,
/// verifying the signature of a message, or transmitting a signed message to
/// the Tozny API.
#[derive(Debug)]
pub enum QuestionError {
    DecoderError(json::DecoderError),
    EncoderError(json::EncoderError),
    ParserError(json::ParserError),
    Base64Error(base64::FromBase64Error),
    HttpError(hyper::HttpError),
    IoError(old_io::IoError),
    Utf8Error(str::Utf8Error),
    InvalidSignature,
    BadlyFormedResponse,
    ErrorResponse(Json),
}

impl fmt::Display for QuestionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &QuestionError::DecoderError(ref err) => {
                f.write_fmt(format_args!(
                        "Error decoding message from API server: {}", err))
            },
            &QuestionError::EncoderError(ref err) => {
                f.write_fmt(format_args!(
                        "Error encoding question parameters: {}", err))
            },
            &QuestionError::ParserError(ref err) => {
                f.write_fmt(format_args!(
                        "Error decoding message from API server: {}", err))
            },
            &QuestionError::Base64Error(ref err) => {
                f.write_fmt(format_args!(
                        "Error decoding message from API server: {}", err))
            },
            &QuestionError::HttpError(ref err) => {
                f.write_fmt(format_args!(
                        "Error connecting to API server: {}", err))
            },
            &QuestionError::IoError(ref err) => {
                f.write_fmt(format_args!(
                        "An error occurred: {}", err))
            },
            &QuestionError::Utf8Error(ref err) => {
                f.write_fmt(format_args!(
                        "Error decoding message from API server: {}", err))
            },
            &QuestionError::InvalidSignature => {
                f.write_str("Invalid signature.")
            },
            &QuestionError::BadlyFormedResponse => {
                f.write_str("Message from API server is missing expected field(s).")
            },
            &QuestionError::ErrorResponse(ref errs) => {
                f.write_fmt(format_args!(
                        "Received error response from API server: {}", errs))
            },
        }
    }
}

/// Unpacks a base64-encoded JSON value.
pub fn unpack<T: Decodable>(payload: &str) -> Result<T, QuestionError> {
    payload.from_base64()
        .map_err(QuestionError::Base64Error)
    .and_then(|b64| {
        str::from_utf8(&b64)
            .map_err(QuestionError::Utf8Error)
        .and_then(|decoded| {
            json::decode(&decoded)
                .map_err(QuestionError::DecoderError)
        })
    })
}

/// Low-level function to dispatch a `Question` to the Tozny API.
pub fn send_request(api_url: &url::Url,
                    key_id:  &KeyId,
                    secret:  &Secret,
                    method:  &Method,
                    params:  &json::Object) -> Result<Json, QuestionError> {
    Question::new(key_id, secret, method, params)
        .map_err(QuestionError::EncoderError)
    .and_then(|req| {
        let mut client = Client::new();
        let js = json::encode(&req).unwrap();
        client.post(translate_url(api_url))
            .body(js.as_slice())
            .send()
            .map_err(QuestionError::HttpError)
    })
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

/// Produces a signature using HMAC-SHA256.
pub fn sign(secret: &Secret, message: &str) -> MacResult {
    let key  = secret.as_slice().as_bytes();
    let data = message.as_bytes();
    let mut hmac = Hmac::new(Sha256::new(), key);
    hmac.input(data);
    hmac.result()
}

/// Verifies a signature using a constant-time comparison.
pub fn check_signature(secret: &Secret, signature: &str, message: &str) -> bool {
    let mac = sign(secret, message);
    signature.from_base64().map(|sig| {
        let expected = MacResult::new_from_owned(sig);
        expected.eq(&mac)
    })
    .unwrap_or(false)
}

fn get_nonce() -> [u8; 32] {
    let mut rng = OsRng::new().ok().expect("Error reading from /dev/urandom");
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn get_expires() -> Timestamp {
    Timestamp::new(UTC::now().add(Duration::minutes(5)))
}

/// Translates a `url::Url` value to a `hyper::Url` value.
pub fn translate_url(url: &url::Url) -> hyper::Url {
    let url::Url { scheme, scheme_data, query, fragment } = url.clone();
    hyper::Url {
        scheme:      scheme,
        scheme_data: scheme_data,
        query:       query,
        fragment:    fragment,
    }
}

/// Gets a value of a `Decodable` type out of a `Json` value.
pub fn from_json<T: Decodable>(js: &Json) -> Result<T, json::DecoderError> {
    // TODO: What a hack!  Where is the `FromJson` trait?
    let s = json::encode(js).unwrap();
    json::decode(&s)
}

#[cfg(test)]
mod tests {
    use collections::BTreeMap;
    use rustc_serialize::base64::{FromBase64, ToBase64, URL_SAFE};
    use rustc_serialize::json::{Json, ToJson};
    use std::str;

    use super::*;
    use protocol::{KeyId, Method, Secret};

    #[test]
    fn it_encodes_base64() {
        let encoded = DATA.as_bytes().to_base64(URL_SAFE);
        assert_eq!(encoded, ENCODED);
    }

    #[test]
    fn it_decodes_base64() {
        let decoded = ENCODED.from_base64();
        assert!(decoded.is_ok());
        let bytes = decoded.unwrap();
        let s = str::from_utf8(&bytes).unwrap();
        assert_eq!(s, DATA);
    }

    #[test]
    fn base64_to_text_to_base64_is_stable() {
        let decoded = SIGNATURE.from_base64().unwrap();
        let reencoded = decoded.to_base64(URL_SAFE);
        assert_eq!(reencoded, SIGNATURE);
    }

    #[test]
    fn text_to_base64_to_text_is_stable() {
        let encoded = DATA.as_bytes().to_base64(URL_SAFE);
        let bytes = encoded.from_base64().unwrap();
        let redecoded = str::from_utf8(&bytes).unwrap();
        assert_eq!(redecoded, DATA);
    }

    #[test]
    fn it_signs_messages() {
        let encoded = DATA.as_bytes().to_base64(URL_SAFE);
        let secret = Secret::from_slice(SECRET);
        let sig = sign(&secret, &encoded);
        assert_eq!(sig.code().to_base64(URL_SAFE), SIGNATURE);
    }

    #[test]
    fn it_verifies_signatures() {
        let secret = Secret::from_slice(SECRET);
        let legit = check_signature(&secret, SIGNATURE, ENCODED);
        assert!(legit)
    }

    #[test]
    fn it_rejects_invalid_signatures() {
        let mut bytes = SECRET.as_bytes().to_vec();
        bytes.reverse();
        let secret = String::from_utf8(bytes).unwrap();
        let legit = check_signature(&Secret::new(secret), SIGNATURE, ENCODED);
        assert!(!legit)
    }

    #[test]
    fn it_formats_expiration_time_as_a_number() {
        let key_id = KeyId::from_slice(REALM_KEY_ID);
        let secret = Secret::from_slice(SECRET);
        let method = Method::from_slice("realm.user_get");
        let mut params = BTreeMap::new();
        params.insert("user_id".to_string(), "sid_1234".to_json());
        let question = Question::new(&key_id, &secret, &method, &params).unwrap();
        let bytes = question.signed_data.from_base64().unwrap();
        let decoded = str::from_utf8(bytes.as_slice()).unwrap();
        let req = Json::from_str(decoded).unwrap();
        let expires_at = req.find("expires_at").unwrap();
        assert!(expires_at.is_number());
        assert!(expires_at.as_i64().unwrap() > 1000000000);
        assert!(expires_at.as_i64().unwrap() < 9999999999);
    }

    const REALM_KEY_ID: &'static str = "sid_d915e7226947b";
    const SECRET: &'static str = "8f8c9b8df39f8c8be4a39378bece4ac01cba948f9b4ef7b90acad3f49d5358f2";
    #[allow(dead_code)]
    const NONCE: &'static str = "6b49eac58dd5e8d9aab6a5eab919fc47863cb233cc560c9b60772685e321ff50";
    #[allow(dead_code)]
    const EXPIRE: &'static str = "1414541972";
    const DATA: &'static str = "{\"nonce\":\"6b49eac58dd5e8d9aab6a5eab919fc47863cb233cc560c9b60772685e321ff50\", \"expires_at\":\"1414541972\", \"realm_key_id\":\"sid_d915e7226947b\", \"user_id\":\"sid_1234\", \"method\":\"realm.user_get\"}";
    const ENCODED: &'static str = "eyJub25jZSI6IjZiNDllYWM1OGRkNWU4ZDlhYWI2YTVlYWI5MTlmYzQ3ODYzY2IyMzNjYzU2MGM5YjYwNzcyNjg1ZTMyMWZmNTAiLCAiZXhwaXJlc19hdCI6IjE0MTQ1NDE5NzIiLCAicmVhbG1fa2V5X2lkIjoic2lkX2Q5MTVlNzIyNjk0N2IiLCAidXNlcl9pZCI6InNpZF8xMjM0IiwgIm1ldGhvZCI6InJlYWxtLnVzZXJfZ2V0In0";
    const SIGNATURE: &'static str = "HB8PQnwlqsB6JlU9NFoDAS_NwUzEtY7EYcgVyZfjsH4";
}
