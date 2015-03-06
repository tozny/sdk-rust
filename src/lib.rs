#![feature(collections)]
#![feature(core)]
#![feature(old_io)]
#![feature(std_misc)]

//! Library interface to the [Tozny authentication service][tozny].  The purpose
//! of this SDK is to make it easy to add Tozny support to Rust apps.
//!
//! For a working example that uses this library, see [tozny-pam][].
//!
//! [tozny]: http://tozny.com/
//! [tozny-pam]: https://github.com/tozny/tozny-pam

extern crate chrono;
extern crate collections;
extern crate core;
extern crate crypto;
extern crate hyper;
extern crate rand;
extern crate "rustc-serialize" as rustc_serialize;
extern crate url;

pub use self::login::{Login};
pub use self::realm::{Realm};
pub use self::user::{User, UserApi};

pub mod login;
pub mod protocol;
pub mod question;
pub mod realm;
pub mod user;
