use http::{Version, Response, StatusCode, HeaderMap, HeaderValue};
use std::io::{Write, Read};
use sha1::{Digest, Sha1};
use http::header::HeaderName;

// from tungstenite
/// Generate key for the upgrade request
pub fn generate_key() -> String {
    // see RFC 4648 and RFC 6455
    let r: [u8; 16] = rand::random();
    base64::encode(&r)
}

// from tungstenite
/// Get accept key used to validate the upgrade response
pub fn get_accept_key(input_key: &[u8]) -> String {
    // generate accept key by concatenating input_key with "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::default();
    hasher.update(input_key);
    hasher.update(WS_GUID);
    base64::encode(&hasher.finalize())
}

/// Generate web socket upgrade request
pub fn generate_request(host: &str, path: &str, key: &str) -> Vec<u8> {
    let version = Version::HTTP_11;

    let mut raw_request: Vec<u8> = Vec::new();
    write!(
        raw_request,
        "\
         GET {path} {version:?}\r\n\
         Host: {host}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {key}\r\n\r\n",
        version = version,
        host = host,
        path = path,
        key = key
    ).unwrap();

    return raw_request
}

/// An error in parsing the http response
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    ParseHttpResponseError,
    HttpVersion,
    HttpStatusCode
}

/// parse raw buffer of bytes into an http response
pub fn parse_response(buffer: &[u8]) -> Result<Option<http::Response<()>>, Error> {
    // use the httparse::Response object as an intermediate object to parse the slice of bytes
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut res = httparse::Response::new(&mut headers);

    match res.parse(buffer) {
        Ok(status) => {
            match status {
                httparse::Status::Partial => Ok(None),
                httparse::Status::Complete(_n) => {
                    // successfully parsed a complete response

                    // allocate http response struct
                    let mut response = http::Response::new(());

                    // version
                    if let Some(1) = res.version {
                        *response.version_mut() = http::Version::HTTP_11;
                    } else {
                        return Err(Error::HttpVersion)
                    }

                    // status
                    let code = res.code.expect("Missing http status code");
                    match StatusCode::from_u16(code) {
                        Ok(status_code) => {
                            *response.status_mut() = status_code
                        },
                        Err(_e) => {
                            return Err(Error::HttpStatusCode)
                        }
                    }

                    // headers
                    let mut header_map = HeaderMap::new();
                    for h in res.headers.iter() {
                        let h_name = HeaderName::from_bytes(h.name.as_bytes());
                        let h_value = HeaderValue::from_bytes(h.value);

                        match (h_name, h_value) {
                            (Ok(name), Ok(value)) => {
                                header_map.append(name, value);
                            }
                            _ => {}
                        }
                    }
                    *response.headers_mut() = header_map;

                    Ok(Some(response))
                }
            }
        }
        _ => {
            Err(Error::ParseHttpResponseError)
        }
    }
}

pub fn validate_response(response: &Response<()>, accept_key: &str) {
    // status code 101
    // Upgrade: websocket
    // Connection: upgrade
    // Sec-WebSocket-Accept: key
}

/// Represents an error during the handshake
pub struct HandshakeError;

/// Do the handshake over the given stream
pub fn do_handshake<Stream>(host: &str, path: &str, mut stream: Stream) -> Result<Stream, HandshakeError> where
    Stream: Read + Write {
    // generate the key
    let key = generate_key();
    let upgrade_request = generate_request(host, path, key.as_str());

    match stream.write(upgrade_request.as_slice()) {
        Ok(n) => {
            if n < upgrade_request.len() {
                return Err(HandshakeError);
            }
        }
        Err(_e) => {
            return Err(HandshakeError);
        }
    }

    let mut buffer = [0 as u8; 8192];
    // read message off of socket, expecting an http response to complete handshake
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {}
            Ok(n) => {
                let response = parse_response(&buffer[0..n]);
                match response {
                    Ok(res) => {
                        if let Some(r) = res {
                            // FIXME: verify response
                            break;
                        }
                    },
                    Err(_e) => {
                        return Err(HandshakeError);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {},
            Err(_e) => {
                return Err(HandshakeError)
            },
        }
    }

    Ok(stream)
}

// TODO: tests
