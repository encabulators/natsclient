use crate::ClientOptions;
use crate::{AuthenticationStyle, Result};
use crossbeam_channel as channel;
use nats_types::DeliveredMessage;
use nkeys::KeyPair;
use rand::{self, seq::SliceRandom, thread_rng};
use url::Url;

pub use nats_types::{ConnectionInformation, ProtocolMessage};

#[derive(Debug, Clone)]
pub(crate) struct ServerInfo {
    pub host: String,
    pub port: u16,
}

const URI_SCHEME: &str = "nats";
const DEFAULT_NAME: &str = "#natsclientrust";
const DEFAULT_PORT: u16 = 4222;

pub(crate) fn parse_nats_uri(uri: &str) -> Result<Url> {
    let url_str = if uri.to_owned().contains("://") {
        uri.to_owned()
    } else {
        let mut url_str = "nats://".to_owned();
        url_str.push_str(uri);
        url_str
    };
    let url = Url::parse(&url_str)?;
    if url.scheme() != URI_SCHEME {
        Err(err!(UriParseFailure, "Failed to parse NATS URI"))
    } else {
        Ok(url)
    }
}

pub(crate) fn parse_server_uris(uris: &[String]) -> Result<Vec<ServerInfo>> {
    let mut servers = Vec::new();

    for uri in uris {
        let parsed = parse_nats_uri(uri)?;
        let host = parsed
            .host_str()
            .ok_or((
                crate::error::ErrorKind::InvalidClientConfig,
                "Missing host name",
            ))?
            .to_owned();
        let port = parsed.port().unwrap_or(DEFAULT_PORT);
        servers.push(ServerInfo { host, port });
    }

    let mut rng = thread_rng();
    servers.shuffle(&mut rng);

    Ok(servers)
}

pub(crate) fn is_multiline_message(line: &str) -> bool {
    line.starts_with("MSG") || line.starts_with("PUB")
}

pub(crate) fn generate_connect_command(
    info: &ProtocolMessage,
    auth: &AuthenticationStyle,
) -> ProtocolMessage {
    let mut user: Option<String> = None;
    let mut pass: Option<String> = None;
    let mut auth_token: Option<String> = None;
    let mut jwt: Option<String> = None;
    let mut sig: Option<String> = None;

    if let AuthenticationStyle::UserCredentials(injwt, seed) = auth {
        if let ProtocolMessage::Info(ref server_info) = info {
            let kp = KeyPair::from_seed(seed.as_ref()).unwrap();
            let nonce = server_info.nonce.clone().unwrap();
            let sigbytes = kp.sign(nonce.as_bytes()).unwrap();
            sig = Some(data_encoding::BASE64URL_NOPAD.encode(&sigbytes));
            jwt = Some(injwt.to_string());
        } else {
            panic!("No server information!");
        }
    }

    if let AuthenticationStyle::Basic {
        username: uname,
        password: pwd,
    } = auth
    {
        user = Some(uname.to_string());
        pass = Some(pwd.to_string());
    }

    if let AuthenticationStyle::Token(tok) = auth {
        auth_token = Some(tok.to_string());
    }

    let ci = crate::protocol::ConnectionInformation::new(
        false,
        false,
        false,
        auth_token,
        user,
        pass,
        "en-us".to_string(),
        "natsclient-rust".to_string(),
        "0.0.1".to_string(),
        Some(1),
        sig,
        jwt,
    );
    ProtocolMessage::Connect(ci)
}

#[derive(Debug, Clone)]
pub(crate) struct ProtocolHandler {
    opts: ClientOptions,
    delivery_sender: channel::Sender<DeliveredMessage>,
}

impl ProtocolHandler {
    pub fn new(
        opts: ClientOptions,
        delivery_sender: channel::Sender<DeliveredMessage>,
    ) -> ProtocolHandler {
        ProtocolHandler {
            opts,
            delivery_sender,
        }
    }

    pub fn handle_protocol_message(
        &self,
        pm: &ProtocolMessage,
        sender: &channel::Sender<Vec<u8>>,
    ) -> Result<()> {
        match pm {
            ProtocolMessage::Info(server_info) => {
                if let Some(urls) = &server_info.connect_urls {
                    let _server_urls = parse_server_uris(&urls)?;
                    //TODO: dispatch these new URLs to the client for mutation
                }

                let conn = generate_connect_command(pm, &self.opts.authentication); // TODO: once accepting URL updates, only send connect once
                sender.send(conn.to_string().into_bytes())?;
            }
            ProtocolMessage::Ping => {
                sender.send(ProtocolMessage::Pong.to_string().into_bytes())?;
            }
            ProtocolMessage::Message(msg) => {
                self.delivery_sender.send(msg.clone())?;
            }
            _ => {}
        };

        Ok(())
    }
}
