extern crate thrussh;
extern crate thrussh_keys;
extern crate futures;
extern crate tokio;
extern crate env_logger;

use std::sync::Arc;

use thrussh::*;
use thrussh::server::{Auth, Session};
use thrussh_keys::*;

use futures::Future;

#[derive(Clone)]
struct Server {
    client_pubkey: Arc<thrussh_keys::key::PublicKey>
}

impl server::Server for Server {
    type Handler = Self;
    fn new(&self) -> Self {
        self.clone()
    }
}

impl server::Handler for Server {
    type Error = std::io::Error;
    type FutureAuth = futures::Finished<(Self, server::Auth), Self::Error>;
    type FutureUnit = futures::Finished<(Self, server::Session), Self::Error>;
    type FutureBool = futures::Finished<(Self, server::Session, bool), Self::Error>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        println!("finished auth");
        futures::finished((self, auth))
    }

    fn finished_bool(self, session: Session, b: bool) -> Self::FutureBool {
        println!("finished bool");
        futures::finished((self, session, b))
    }

    fn finished(self, session: Session) -> Self::FutureUnit {
        println!("finished");
        futures::finished((self, session))
    }

    fn auth_publickey(self, _: &str, _: &key::PublicKey) -> Self::FutureAuth {
        println!("auth pubkey");
        futures::finished((self, server::Auth::Accept))
    }

    fn data(self, channel: ChannelId, data: &[u8], mut session: server::Session) -> Self::FutureUnit {
        println!("data on channel {:?}: {:?}", channel, std::str::from_utf8(data));
        session.data(channel, None, data);
        futures::finished((self, session))
    }
}

fn main() {
    env_logger::init();

    let client_key = thrussh_keys::key::KeyPair::generate(thrussh_keys::key::ED25519).unwrap();
    let client_pubkey = Arc::new(client_key.clone_public_key());

    let mut config = thrussh::server::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(600));
    config.auth_rejection_time = std::time::Duration::from_secs(10);
    config.keys.push(thrussh_keys::key::KeyPair::generate(thrussh_keys::key::ED25519).unwrap());

    let config = Arc::new(config);

    let sh = Server { client_pubkey };
    thrussh::server::run(config, "0.0.0.0:8080", sh);
}
