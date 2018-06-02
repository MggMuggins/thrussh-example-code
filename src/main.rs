/* Original Code
extern crate thrussh;
extern crate thrussh_keys;
extern crate futures;
extern crate env_logger;

use std::io::Read;
use std::sync::Arc;
use std::process::exit;

use futures::Future;

use thrussh::{ChannelId, CryptoVec, Disconnect};
use thrussh::client;
use thrussh::server;
use thrussh_keys::load_secret_key;
use thrussh_keys::key::{ED25519, KeyPair, PublicKey};

#[derive(Clone)]
struct TestServer {}

impl server::Server for TestServer {
    type Handler = Self;
    fn new(&self) -> Self {
        TestServer {}
    }
}

impl server::Handler for TestServer {
    type Error = std::io::Error;
    type FutureAuth = futures::Finished<(Self, server::Auth), Self::Error>;
    type FutureUnit = futures::Finished<(Self, server::Session), Self::Error>;
    type FutureBool = futures::Finished<(Self, server::Session, bool), Self::Error>;
    
    fn finished_auth(self, auth: server::Auth) -> Self::FutureAuth {
        futures::finished((self, auth))
    }
    
    fn finished_bool(self, session: server::Session, b: bool) -> Self::FutureBool {
        futures::finished((self, session, b))
    }
    
    fn finished(self, session: server::Session) -> Self::FutureUnit {
        futures::finished((self, session))
    }
   
    fn auth_publickey(self, _: &str, _: &PublicKey) -> Self::FutureAuth {
        futures::finished((self, server::Auth::Accept))
    }
    
    fn data(self, channel: ChannelId, data: &[u8], mut session: server::Session) -> Self::FutureUnit {
        println!("data on channel {:?}: {:?}", channel, std::str::from_utf8(data));
        session.data(channel, None, data);
        futures::finished((self, session))
    }
}

struct Client { }

impl client::Handler for Client {
    type Error = ();
    type FutureBool = futures::Finished<(Self, bool), Self::Error>;
    type FutureUnit = futures::Finished<Self, Self::Error>;
    type FutureSign = futures::Finished<(Self, CryptoVec), Self::Error>;
    type SessionUnit = futures::Finished<(Self, client::Session), Self::Error>;
    
    fn check_server_key(self, server_public_key: &PublicKey) -> Self::FutureBool {
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

    fn run(self, config: Arc<client::Config>, _: &str) {
        
        client::connect_future(
            "127.0.0.1:2222", config, None, self,
            |connection| {
                
                let mut key_file = std::fs::File::open("/home/user/.ssh/id_ed25519_pkcs8").unwrap();
                let mut key = String::new();
                key_file.read_to_string(&mut key).unwrap();
                let key = load_secret_key(&key, None).unwrap();
                
                connection.authenticate_key("wesley", Arc::new(key))
                    .and_then(|session| {
                        
                        session.channel_open_session().and_then(|(session, channelid)| {
                            
                            session.data(channelid, None, "Hello, world!").and_then(|(mut session, _)| {
                                session.disconnect(Disconnect::ByApplication, "Ciao", "");
                                session
                            })
                        })
                    })
                }).unwrap_or_else(|err| {
                    println!("{:?}", err);
                    exit(1);
                });
        }
}

fn main() {
    env_logger::init();
    println!("Logger Init");
    
    // Starting the server thread.
    let t = std::thread::spawn(|| {
        let mut config = thrussh::server::Config::default();
        config.connection_timeout = Some(std::time::Duration::from_secs(600));
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config.keys.push(KeyPair::generate(ED25519).unwrap());
        
        let config = Arc::new(config);
        
        let sh = TestServer {};
        thrussh::server::run(config, "127.0.0.1:2222", sh);
    });
    println!("Server Started");
    
    let mut config = thrussh::client::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(600));
    let config = Arc::new(config);
    let sh = Client {};
    sh.run(config, "127.0.0.1:2222");
    
    println!("Client has run");
    
    std::mem::forget(t);
}*/

//Code that matches source (I hope)
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
        futures::finished((self, auth))
    }
    
    fn finished_bool(self, session: Session, b: bool) -> Self::FutureBool {
        futures::finished((self, session, b))
    }
    
    fn finished(self, session: Session) -> Self::FutureUnit {
        futures::finished((self, session))
    }

    fn auth_publickey(self, _: &str, _: &key::PublicKey) -> Self::FutureAuth {
        futures::finished((self, server::Auth::Accept))
    }
    
    fn data(self, channel: ChannelId, data: &[u8], mut session: server::Session) -> Self::FutureUnit {
        println!("data on channel {:?}: {:?}", channel, std::str::from_utf8(data));
        session.data(channel, None, data);
        futures::finished((self, session))
    }
}

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
    fn run(self, config: Arc<client::Config>, _: &str) {
        let key = self.key.clone();
        tokio::run(
            client::connect_future(
                "127.0.0.1:2222", config, None, self,
                |connection| {
                    connection.authenticate_key("pe", key)
                        .and_then(|session| {
                            session.channel_open_session().and_then(|(session, channelid)| {
                                session.data(channelid, None, "Hello, world!").and_then(|(mut session, _)| {
                                    session.disconnect(Disconnect::ByApplication, "Ciao", "");
                                    session
                                })
                            })
                        })
                    }).unwrap().map_err(|err| println!("{:?}", err))
                )
    }
}

fn main() {
    env_logger::init();
    
    // Starting the server thread.
    let client_key = thrussh_keys::key::KeyPair::generate(thrussh_keys::key::ED25519).unwrap();
    let client_pubkey = Arc::new(client_key.clone_public_key());
    
    println!("Client key: {:?}\n", client_key);
    println!("Client public key: {:?}\n", client_pubkey);
    
    let server_thread = std::thread::spawn(|| {
        let mut config = thrussh::server::Config::default();
        config.connection_timeout = Some(std::time::Duration::from_secs(600));
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config.keys.push(thrussh_keys::key::KeyPair::generate(thrussh_keys::key::ED25519).unwrap());
        
        let config = Arc::new(config);
        
        let sh = Server { client_pubkey };
        thrussh::server::run(config, "0.0.0.0:2222", sh);
    });
    
    std::thread::sleep(std::time::Duration::from_secs(3));
    let mut config = thrussh::client::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(600));
    let config = Arc::new(config);
    
    let sh = Client { key: Arc::new(client_key) };
    sh.run(config, "127.0.0.1:2222");
    
    // Kill the server thread after the client has ended.
    std::mem::forget(server_thread)
}
