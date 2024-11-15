use clap::{Parser, Subcommand};
use hex::ToHex;
use serde::{Deserialize, Serialize};
use serde_json;
use sha1::{Digest, Sha1};
use std::borrow::Cow;
use std::error::Error;
use std::fs;
use std::net::Ipv4Addr;
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
// Available if you need it!
use serde_bencode;
use serde_bencode::value::Value;

const PEER_ID: &str = "12345678901234567890";

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[clap(rename_all = "snake_case")]
enum Command {
    Decode { encoded_value: String },
    Info { torrent_file: String },
    Peers { torrent_file: String },
    Handshake { torrent_file: String, peer: Peer },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TorrentInfo {
    length: usize,
    pub name: String,
    #[serde(rename = "piece length")]
    pub piece_length: usize,
    pub pieces: Value,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TrackerResponse {
    #[serde(rename = "min interval")]
    min_interval: usize,
    peers: Value,
    complete: usize,
    incomplete: usize,
    interval: usize,
}

impl TorrentInfo {
    fn compute_hexsha1_binary(&self) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(&serde_bencode::to_bytes(self).expect("problems with re-serialization"));
        hasher.finalize().as_slice().to_vec()
    }

    fn compute_hexsha1(&self) -> String {
        let mut hasher = Sha1::new();
        hasher.update(&serde_bencode::to_bytes(self).expect("problems with re-serialization"));
        let hash_value = hasher.finalize();
        hash_value.encode_hex::<String>()
    }

    fn get_pieces(&self) -> Vec<[u8; 20]> {
        match self.pieces {
            Value::Bytes(ref bytes) => bytes.chunks(20).map(|x| x.try_into().unwrap()).collect(),
            _ => vec![],
        }
    }
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub host: Ipv4Addr,
    pub port: u16,
}

impl Peer {
    fn as_tuple(&self) -> (Ipv4Addr, u16) {
        (self.host, self.port)
    }
}

impl FromStr for Peer {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, port) = s
            .split_once(':')
            .ok_or("Invalid peer address format".to_string())?;
        Ok(Peer {
            host: Ipv4Addr::from_str(host).map_err(|_| "Invalid peer host".to_string())?,
            port: port.parse().map_err(|_| "Invalid peer port".to_string())?,
        })
    }
}

impl TrackerResponse {
    fn get_peers(&self) -> Vec<Peer> {
        match self.peers {
            Value::Bytes(ref bytes) => bytes
                .chunks(6)
                .map(|x| Peer {
                    host: Ipv4Addr::new(x[0], x[1], x[2], x[3]),
                    port: (x[4] as u16 * 256u16) + x[5] as u16,
                })
                .collect(),
            _ => vec![],
        }
    }
}

#[derive(Debug, Deserialize)]
struct Metainfo {
    announce: String,
    info: TorrentInfo,
}

fn map_bencode_to_json(value: Value) -> serde_json::Value {
    match value {
        Value::Bytes(v) => serde_json::Value::String(String::from_utf8_lossy(&v).to_string()),
        Value::Int(v) => {
            v.into()
            // serde_json::Value::Number(serde_json::value::Number::from_f64(v as f64).unwrap())
        }
        Value::List(v) => {
            serde_json::Value::Array(v.into_iter().map(map_bencode_to_json).collect())
        }
        Value::Dict(v) => {
            let map: serde_json::Map<String, serde_json::Value> = v
                .into_iter()
                .map(|(k, v)| {
                    let string_k: String = String::from_utf8_lossy(&k).to_string();
                    let val = map_bencode_to_json(v);
                    (string_k, val)
                })
                .collect();
            serde_json::Value::Object(map)
        }
    }
}

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    let val: Value = serde_bencode::from_str(encoded_value).unwrap();
    map_bencode_to_json(val)
}

fn decode_bencoded_metainfo(encoded_value: &[u8]) -> Metainfo {
    serde_bencode::from_bytes(encoded_value).unwrap()
}

fn compute_info_hash(torrent_file: String) -> Vec<u8> {
    let content = fs::read(torrent_file).expect("Cannot read the file.");
    let decoded_info = decode_bencoded_metainfo(&content);
    decoded_info.info.compute_hexsha1_binary()
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    match args.command {
        Command::Decode { encoded_value } => {
            let decoded_value = decode_bencoded_value(encoded_value.as_str());
            println!("{}", decoded_value.to_string());
            Ok(())
        }
        Command::Info { torrent_file } => {
            let content = fs::read(torrent_file).expect("Cannot read the file.");
            let decoded_info = decode_bencoded_metainfo(&content);
            // dbg!(&decoded_info);
            let url = decoded_info.announce;
            let length = decoded_info.info.length;
            let hash_value = decoded_info.info.compute_hexsha1();
            let piece_length = decoded_info.info.piece_length;

            println!(
                "Tracker URL: {}\nLength: {}\nInfo Hash: {}\nPiece Length: {}\nPiece Hashes:",
                url, length, hash_value, piece_length
            );

            println!(
                "{}",
                decoded_info
                    .info
                    .get_pieces()
                    .iter()
                    .map(|piece| piece.encode_hex())
                    .collect::<Vec<String>>()
                    .join("\n")
            );
            Ok(())
        }
        Command::Peers { torrent_file } => {
            let content = fs::read(torrent_file).expect("Cannot read the file.");
            let decoded_info = decode_bencoded_metainfo(&content);

            let url = decoded_info.announce;
            let mut reqwest_url = reqwest::Url::parse(&url).unwrap();
            let info_hash = decoded_info.info.compute_hexsha1_binary();

            reqwest_url
                .query_pairs_mut()
                .encoding_override(Some(&|x| {
                    if x == "INFOHASH" {
                        Cow::Owned(info_hash.clone())
                    } else {
                        Cow::Borrowed(x.as_bytes())
                    }
                }))
                .append_pair("info_hash", "INFOHASH")
                .append_pair("peer_id", PEER_ID)
                .append_pair("port", "6881")
                .append_pair("uploaded", "0")
                .append_pair("downloaded", "0")
                .append_pair("left", decoded_info.info.length.to_string().as_str())
                .append_pair("compact", "1")
                .finish();

            let resp = reqwest::get(reqwest_url).await;
            let body = resp.unwrap().bytes().await.unwrap();

            let traker_response: TrackerResponse = serde_bencode::from_bytes(&body).unwrap();

            // dbg!(&traker_response);
            let peers = traker_response.get_peers();

            println!(
                "{}",
                peers
                    .iter()
                    .map(|peer| format!("{}:{}", peer.host, peer.port))
                    .collect::<Vec<String>>()
                    .join("\n")
            );
            Ok(())
        }
        Command::Handshake { torrent_file, peer } => {
            let info_hash = compute_info_hash(torrent_file);

            let mut stream = TcpStream::connect(peer.as_tuple()).await?;

            let mut buffer: Vec<u8> = Vec::with_capacity(68);
            let mut response_buffer: Vec<u8> = Vec::with_capacity(68);

            buffer.push(19);
            buffer.extend_from_slice(b"BitTorrent protocol");
            buffer.extend_from_slice(&[0; 8]);
            buffer.extend_from_slice(info_hash.as_slice());
            buffer.extend_from_slice(PEER_ID.as_bytes());

            stream.write_all(&buffer).await?;

            stream.read_buf(&mut response_buffer).await?;

            println!(
                "Peer ID: {}",
                (&response_buffer[48..68]).encode_hex::<String>()
            );
            Ok(())
        }
    }
}
