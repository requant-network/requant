//! Where the wallet asks: a node's JSON-RPC (`--rpc HOST:PORT`, the default), or a node's public API
//! (`--api http://HOST:PORT`, the explorer's port) for a wallet without its own node. The API serves what
//! the wallet needs (coins, history, transactions, fee estimate, sending); keys never leave the wallet.
//! It answers what that node sees, so balances and history are as trustworthy as the node, and the node
//! learns which addresses the wallet asks about.

use serde_json::{json, Value};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

pub enum Backend {
    Rpc(SocketAddr),
    Api {
        host: String,
        addr: SocketAddr,
    },
    /// The same API over TLS (`https://host[:port][/prefix]`): an answer on the way cannot be changed.
    ApiTls {
        base: String,
    },
}

impl Backend {
    /// `http://host:port`, `http://host` (port 80), `host:port`, or `https://host[:port][/prefix]`.
    pub fn api(url: &str) -> Result<Backend, String> {
        if let Some(rest) = url.strip_prefix("https://") {
            if rest.is_empty() || rest.chars().any(|c| c.is_whitespace() || c == '?' || c == '#') {
                return Err(format!("{url}: not an https address"));
            }
            return Ok(Backend::ApiTls { base: url.trim_end_matches('/').to_string() });
        }
        let rest = url.strip_prefix("http://").unwrap_or(url).trim_end_matches('/');
        let hostport = if rest.contains(':') { rest.to_string() } else { format!("{rest}:80") };
        let host = hostport.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_default();
        let addr = hostport
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .ok_or_else(|| format!("cannot resolve {hostport}"))?;
        Ok(Backend::Api { host, addr })
    }

    /// Owners per list request: a hundred through RPC; through the API, as many as fit the 2048-byte
    /// request line of nodes up to 0.15.1 (a key hash takes 65 bytes of it).
    pub fn list_max(&self) -> usize {
        match self {
            Backend::Rpc(_) => 100,
            Backend::Api { .. } | Backend::ApiTls { .. } => 25,
        }
    }

    /// Whether a failed list request may be retried one owner at a time: only through RPC, for a node
    /// older than lists (every node with the API has them, and a refusal there is not a reason to send
    /// more requests).
    pub fn per_owner_fallback(&self) -> bool {
        matches!(self, Backend::Rpc(_))
    }

    /// A node RPC call; with an API backend, the calls the wallet makes are mapped to API paths.
    pub fn call(&self, method: &str, params: Value) -> io::Result<Value> {
        if let Backend::Rpc(a) = self {
            return requant_node::rpc::request(*a, method, params);
        }
        let p = |k: usize| -> io::Result<String> {
            match &params[k] {
                Value::String(s) if s.chars().all(|c| c.is_ascii_alphanumeric()) => Ok(s.clone()),
                Value::Number(n) => Ok(n.to_string()),
                _ => Err(io::Error::other(format!("{method}: parameter {k} missing or not plain"))),
            }
        };
        // a list of key hashes (a whole wallet in one request)
        let list = params[0].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(","));
        let (verb, path, body) = match (method, list) {
            ("sendpackage", _) => ("POST", "/api/package".to_string(), Some(json!({"hex": params[0]}).to_string())),
            ("utxos", Some(l)) => ("GET", format!("/api/utxos?owners={l}"), None),
            ("history", Some(l)) => {
                ("GET", format!("/api/history?owners={l}&limit={}", p(1).unwrap_or("100".into())), None)
            }
            _ => self.path_of(method, &p)?,
        };
        let (status, v) = match self {
            Backend::Api { host, addr } => http(*addr, host, verb, &path, body.as_deref())?,
            Backend::ApiTls { base } => https(base, verb, &path, body.as_deref())?,
            Backend::Rpc(_) => unreachable!("answered above"),
        };
        if status != 200 {
            return Err(io::Error::other(v["error"].as_str().unwrap_or("API error").to_string()));
        }
        // sendtx and sendpackage answer the txids themselves, as RPC does
        Ok(match method {
            "sendtx" => v["txid"].clone(),
            "sendpackage" => v["txids"].clone(),
            _ => v,
        })
    }

    /// The API request for a call with plain parameters.
    fn path_of(
        &self,
        method: &str,
        p: &dyn Fn(usize) -> io::Result<String>,
    ) -> io::Result<(&'static str, String, Option<String>)> {
        Ok(match method {
            "utxos" => ("GET", format!("/api/address/{}/utxos", p(0)?), None),
            "history" => {
                ("GET", format!("/api/address/{}/history?limit={}", p(0)?, p(1).unwrap_or("100".into())), None)
            }
            "gettx" => ("GET", format!("/api/tx/{}", p(0)?), None),
            "getinfo" => ("GET", "/api/info".to_string(), None),
            "estimatefee" => ("GET", format!("/api/fee?blocks={}", p(0).unwrap_or("3".into())), None),
            "sendtx" => ("POST", "/api/tx".to_string(), Some(json!({"hex": p(0)?}).to_string())),
            _ => {
                return Err(io::Error::other(format!("{method} is not available through --api; use --rpc with a node")))
            }
        })
    }
}

/// One HTTP/1.1 request; (status, JSON body).
/// One request over TLS (the system's roots through rustls): status and JSON body.
fn https(base: &str, verb: &str, path: &str, body: Option<&str>) -> io::Result<(u16, Value)> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(60)).redirects(0).build();
    let request = agent.request(verb, &format!("{base}{path}")).set("Content-Type", "application/json");
    let answer = match body {
        Some(b) => request.send_string(b),
        None => request.call(),
    };
    let response = match answer {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(io::Error::other(e.to_string())),
    };
    let status = response.status();
    let text = response.into_string().map_err(|e| io::Error::other(e.to_string()))?;
    Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
}

fn http(addr: SocketAddr, host: &str, verb: &str, path: &str, body: Option<&str>) -> io::Result<(u16, Value)> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(15))?;
    s.set_read_timeout(Some(Duration::from_secs(60)))?;
    let body = body.unwrap_or("");
    write!(
        s,
        "{verb} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut resp = String::new();
    s.read_to_string(&mut resp)?;
    let status =
        resp.split(' ').nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| io::Error::other("bad HTTP answer"))?;
    let json = resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    Ok((status, serde_json::from_str(json).unwrap_or(Value::Null)))
}

#[cfg(test)]
mod tls_tests {
    use super::*;

    #[test]
    fn an_https_api_address_goes_over_tls() {
        assert!(
            matches!(Backend::api("https://api.example.org/requant/"), Ok(Backend::ApiTls { base }) if base == "https://api.example.org/requant")
        );
        assert!(Backend::api("https://").is_err());
        assert!(Backend::api("https://a.example.org/x?y=1").is_err());
        assert!(matches!(Backend::api("http://127.0.0.1:19380"), Ok(Backend::Api { .. })));
    }
}
