use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
// use actix_web::Error::{BadRequest};
use super::models::CreateKeyRequest;
use crate::{AppState, KMEStorageData, Key, KeyContainer};
use base64::{engine::general_purpose, Engine as _};
use num::{BigUint, Num};
use serde::{Deserialize, Serialize};
use std::str;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Status {
    source_KME_ID: String,
    target_KME_ID: String,
    master_SAE_ID: String,
    slave_SAE_ID: String,
    key_size: u32,
    max_key_count: u32,
    max_key_per_request: u32,
    min_key_size: u32,
    max_key_size: u32,
    stored_key_count: usize,
    max_SAE_ID_count: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct KeyContainerRes {
    key_container_extension: Vec<Extension>,
    keys: Vec<KeyRes>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct KeyRes {
    key_ID: String,
    key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Extension {
    message: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct GeneralError {
    message: String,
}
struct GeneralWarning {
    message: String,
}

#[get("/api/v1/keys/{slave_SAE_ID}/status")]
async fn get_status(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let storage_data: KMEStorageData = data.kme_storage_data.lock().unwrap().clone();
    let key_data: KeyContainer = data.kme_key_data.lock().unwrap().clone();
    let slave_SAE_ID: String = path.into_inner();
    if slave_SAE_ID == storage_data.SAE_ID {
        let error: GeneralError = GeneralError {
            message: "Invalid slave SAE_ID".to_string(),
        };
        return HttpResponse::BadRequest().json(error);
    };
    let mut matched_keys: Vec<Key> = Vec::new();
    for key in key_data.keys.iter() {
        if key.KME_ID[3..] == slave_SAE_ID[3..] {
            matched_keys.push(key.clone())
        }
    }
    let stored_key_count: usize = if matched_keys.is_empty() {
        0
    } else {
        matched_keys.len()
    };
    let status: Status = Status {
        source_KME_ID: storage_data.KME_ID,
        target_KME_ID: "???".to_string(),
        master_SAE_ID: storage_data.SAE_ID,
        slave_SAE_ID,
        key_size: storage_data.key_size,
        max_key_count: storage_data.max_key_count,
        max_key_per_request: storage_data.max_key_per_request,
        min_key_size: storage_data.min_key_size,
        max_key_size: storage_data.max_key_size,
        stored_key_count,
        max_SAE_ID_count: storage_data.max_SAE_ID_count,
    };

    HttpResponse::Ok().json(status)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Params {
    number: Option<u64>,
    size: Option<u64>,
}

#[get("/api/v1/keys/{slave_SAE_ID}/enc_keys")]
async fn get_keys_get(
    data: web::Data<AppState>,
    path: web::Path<String>,
    info: web::Query<Params>,
) -> impl Responder {
    let storage_data: KMEStorageData = data.kme_storage_data.lock().unwrap().clone();
    let key_data: KeyContainer = data.kme_key_data.lock().unwrap().clone();
    let slave_SAE_ID: String = path.into_inner();
    let (number, size) = (info.number, info.size);

    if slave_SAE_ID == storage_data.SAE_ID {
        let error: GeneralError = GeneralError {
            message: "Invalid slave SAE_ID".to_string(),
        };
        return HttpResponse::BadRequest().json(error);
    };
    let mut matched_keys: Vec<Key> = Vec::new();
    for key in key_data.keys.iter() {
        if key.KME_ID[3..] == slave_SAE_ID[3..] {
            matched_keys.push(key.clone())
        }
    }
    let mut matched_keys = match number {
        Some(x) => matched_keys.splice(0..x as usize, []).collect(),
        _ => matched_keys,
    };
    let mut matched_keys = match size {
        // general_purpose::STANDARD_NO_PAD.decode(key).unwrap()
        //  decoded_key_vec.iter_mut().map(|x| (*x - 48)).collect()
        Some(x) => {
            for key in &mut matched_keys {
                let key_str = &key.key;
                let decoded_bytes_res = general_purpose::STANDARD.decode(key_str);
                let decoded_bytes = match decoded_bytes_res {
                    Ok(res) => res,
                    Err(e) => {
                        println!("Failed Decoding Key: {}", e);
                        break;
                    }
                };
                let decoded_bytes_scaled: Vec<_> = decoded_bytes.iter().map(|x| *x - 48).collect();
                let decoded_str: String = decoded_bytes_scaled
                    .iter()
                    .map(|&num| num.to_string())
                    .collect();
                let decoded_key: BigUint = decoded_str.parse().unwrap();
                let decoded_key_str = format!("{:b}", decoded_key);
                if decoded_key.bits() < x {
                    // let warning: GeneralWarning = GeneralWarning {
                    //     message: "Key"
                    // }
                    continue;
                }
                let truc_key_bin = &decoded_key_str[0..x as usize];
                // Encode the key back
                let truc_key_bytes = BigUint::from_str_radix(truc_key_bin, 2).unwrap();
                let truc_encode_key = encode(truc_key_bytes.to_string());
                key.key = truc_encode_key;
            }

            matched_keys
        }
        _ => matched_keys,
    };

    // Clear the other variables not needed
    let mut keys_vec = Vec::new();
    for key in matched_keys {
        keys_vec.push(KeyRes {
            key_ID: key.key_ID,
            key: key.key,
        })
    }
    let extension = Extension { message: None };
    let key_container_res = KeyContainerRes {
        key_container_extension: vec![extension],
        keys: keys_vec,
    };

    HttpResponse::Ok().json(key_container_res)
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(get_status).service(get_keys_get);
}

fn encode(s: String) -> String {
    general_purpose::STANDARD_NO_PAD.encode(s.as_bytes())
}

fn decode(s: String) -> String {
    let bytes = general_purpose::STANDARD_NO_PAD
        .decode(s.as_bytes())
        .unwrap();
    let s = match str::from_utf8(&bytes) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };
    s.to_string()
}
