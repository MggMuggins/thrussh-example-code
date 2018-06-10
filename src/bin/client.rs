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

struct Client {
    key: Arc<thrussh_keys::key::KeyPair>
}

impl client::Handler for Client {
    type Error = ();
    type FutureBool = futures::Finished<(Self, bool), Self::Error>;
    type FutureUnit = futures::Finished<Self, Self::Error>;
    type FutureSign = futures::Finished<(Self, thrussh::CryptoVec), Self::Error>;
    type SessionUnit = futures::Finished<(Self, client::Session), Self::Error>;

    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
        println!("check_server_key: {:?}", server_public_key);
        futures::finished((self, true))
    }

    fn channel_open_confirmation(self, channel: ChannelId, session: client::Session) -> Self::SessionUnit {
        println!("channel_open_confirmation: {:?}", channel);
        futures::finished((self, session))
    }

    fn data(self, channel: ChannelId, ext: Option<u32>, data: &[u8], session: client::Session) -> Self::SessionUnit {
        println!("data on channel {:?} {:?}: {:?}", ext, channel, std::str::from_utf8(data));
        futures::finished((self, session))
    }
}

impl Client {
    fn run(self, config: Arc<client::Config>, ip: &str) {
        let key = self.key.clone();
        tokio::run(
            client::connect_future(
                ip, config, None, self,
                |connection| {
                    println!("auth");
                    connection.authenticate_key("pe", key)
                        .and_then(|session| {
                            println!("open");
                            session.channel_open_session().and_then(|(session, channelid)| {
                                println!("send");
                                session.data(channelid, None, "Hello, world!").and_then(|(mut session, _)| {
                                    session.disconnect(Disconnect::ByApplication, "Ciao", "");
                                    session
                                })
                            })
                        })
                    }).unwrap().map_err(|err| println!("auth error: {:?}", err))
                )
    }
}

fn main() {
    env_logger::init();

    // Starting the server thread.
    let client_key = thrussh_keys::key::KeyPair::generate(thrussh_keys::key::ED25519).unwrap();

    let mut config = thrussh::client::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(600));
    let config = Arc::new(config);

    let sh = Client { key: Arc::new(client_key) };
    //sh.run(config, "127.0.0.1:8080");
    sh.run(config, "10.0.2.2:8080");
}
