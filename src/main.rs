use serde_json;
use std::env;
use std::fs;

// Available if you need it!
use serde_bencode;
use serde_bencode::value::Value;

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

fn decode_bencoded_value_u8(encoded_value: &[u8]) -> serde_json::Value {
    let val: Value = serde_bencode::from_bytes(encoded_value).unwrap();
    map_bencode_to_json(val)
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else if command == "info" {
        let filename = &args[2];
        let content = fs::read(filename).expect("Cannot read the file.");
        let decoded_info = decode_bencoded_value_u8(&content);
        let url = decoded_info
            .as_object()
            .unwrap()
            .get("announce")
            .unwrap()
            .as_str()
            .unwrap();
        let length = decoded_info
            .as_object()
            .unwrap()
            .get("info")
            .unwrap()
            .as_object()
            .unwrap()
            .get("length")
            .unwrap()
            .to_string();

        println!("Tracker URL: {}\nLength: {}", url, length);
    } else {
        println!("unknown command: {}", args[1])
    }
}
