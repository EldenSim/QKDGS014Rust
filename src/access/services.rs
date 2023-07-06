use actix_web::{get, post, web, App, HttpRequest, HttpResponse, Responder};
// use actix_web::Error::{BadRequest};
use super::models::CreateKeyRequest;
use crate::{AppState, KMEStorageData, Key, KeyContainer};
use base64::{engine::general_purpose, Engine as _};
use num::{BigUint, Num};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::{f32::consts::E, str};

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
    details: Option<HashMap<String, Vec<String>>>,
}
struct GeneralWarning {
    message: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Params {
    number: Option<u64>,
    size: Option<u64>,
}

#[get("/api/v1/keys/{slave_SAE_ID}/status")]
async fn get_status(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let storage_data: KMEStorageData = data.kme_storage_data.lock().unwrap().clone();
    let key_data: KeyContainer = data.kme_key_data.lock().unwrap().clone();
    let slave_SAE_ID: String = path.into_inner();
    if slave_SAE_ID == storage_data.SAE_ID {
        let error: GeneralError = GeneralError {
            message: "Invalid slave SAE_ID".to_string(),
            details: None,
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

#[get("/api/v1/keys/{slave_SAE_ID}/enc_keys")]
async fn get_keys_get(
    data: web::Data<AppState>,
    path: web::Path<String>,
    info: web::Query<Params>,
) -> impl Responder {
    // Obtaining state data from the Appstate
    let storage_data: KMEStorageData = data.kme_storage_data.lock().unwrap().clone();
    let key_data: KeyContainer = data.kme_key_data.lock().unwrap().clone();
    let slave_SAE_ID: String = path.into_inner();

    // Checking if SAE_ID does not match server's SAE_ID
    if slave_SAE_ID == storage_data.SAE_ID {
        let error: GeneralError = GeneralError {
            message: "Invalid slave SAE_ID".to_string(),
            details: None,
        };
        return HttpResponse::BadRequest().json(error);
    };

    // Obtaining the params from the URL
    let (number, size) = (info.number, info.size);

    // Obtain the keys that matches the SAE_ID in server's storage
    let mut matched_keys: Vec<Key> = Vec::new();
    let extension_warning: Vec<Extension> = Vec::new();
    for key in key_data.clone().keys.iter() {
        if key.KME_ID[3..] == slave_SAE_ID[3..] {
            matched_keys.push(key.clone())
        }
    }
    // If no keys match, return error message
    if matched_keys.len() == 0 {
        let error: GeneralError = GeneralError {
            message: "No keys found in storage".to_string(),
            details: None,
        };
        return HttpResponse::NotFound().json(error);
    }

    // Unwrap number,
    // if num = 0, return error
    // else return Vec of respective num of keys
    // If no number provided, default to 1
    let mut matched_keys: Vec<Key> = match number {
        Some(x) => {
            if x == 0 {
                let error: GeneralError = GeneralError {
                    message: "Invalid number param provided.".to_string(),
                    details: None,
                };
                return HttpResponse::BadRequest().json(error);
            }

            if matched_keys.len() < x as usize {
                matched_keys
            } else {
                matched_keys.splice(0..x as usize, []).collect()
            }
        }
        _ => matched_keys.splice(0..1 as usize, []).collect(),
    };

    // Unwarp size,
    // if size = 0, return error
    // else return Vec of respective keys truncated
    // If no size provided, default to whatever key size is stored
    let matched_keys: Vec<Key> = match size {
        Some(x) => {
            // Check if size param is valid
            if x == 0 {
                let error: GeneralError = GeneralError {
                    message: "Invalid size param provided.".to_string(),
                    details: None,
                };
                return HttpResponse::BadRequest().json(error);
            }
            // loop through the remaining keys to mutate the key string
            let matched_keys = match trunc_by_size(x, matched_keys) {
                Ok(keys) => keys,
                Err(e) => return HttpResponse::NotFound().json(e),
            };
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

#[post("/api/v1/keys/{slave_SAE_ID}/enc_keys")]
async fn get_keys_post(
    data: web::Data<AppState>,
    path: web::Path<String>,
    req_obj: web::Json<CreateKeyRequest>,
) -> impl Responder {
    let slave_SAE_ID: String = path.into_inner();
    let storage_data: KMEStorageData = data.kme_storage_data.lock().unwrap().clone();
    let key_data: KeyContainer = data.kme_key_data.lock().unwrap().clone();
    if slave_SAE_ID == storage_data.SAE_ID {
        let error: GeneralError = GeneralError {
            message: "Invalid slave SAE_ID".to_string(),
            details: None,
        };
        return HttpResponse::BadRequest().json(error);
    };
    // Obtain the keys that matches the SAE_ID in server's storage
    let mut matched_keys: Vec<Key> = Vec::new();
    let extension_warning: Vec<Extension> = Vec::new();
    for key in key_data.clone().keys.iter() {
        if key.KME_ID[3..] == slave_SAE_ID[3..] {
            matched_keys.push(key.clone())
        }
    }
    // match every variable
    // If no keys match, return error message
    if matched_keys.len() == 0 {
        let error: GeneralError = GeneralError {
            message: "No keys found in storage".to_string(),
            details: None,
        };
        return HttpResponse::NotFound().json(error);
    }

    let (number, size, extension_mandatory, extension_optional) = (
        req_obj.number,
        req_obj.size,
        req_obj.extension_mandatory.clone(),
        req_obj.extension_optional.clone(),
    );
    // Unwrap number,
    // if num = 0, return error
    // else return Vec of respective num of keys
    // If no number provided, default to 1
    let matched_keys: Vec<Key> = match number {
        Some(x) => {
            if x == 0 {
                let error: GeneralError = GeneralError {
                    message: "Invalid number param provided.".to_string(),
                    details: None,
                };
                return HttpResponse::BadRequest().json(error);
            }
            matched_keys.splice(0..x as usize, []).collect()
        }
        _ => matched_keys.splice(0..1 as usize, []).collect(),
    };
    // Unwarp size,
    // if size = 0, return error
    // else return Vec of respective keys truncated
    // If no size provided, default to whatever key size is stored
    let mut matched_keys: Vec<Key> = match size {
        Some(x) => {
            // Check if size param is valid
            if x == 0 {
                let error: GeneralError = GeneralError {
                    message: "Invalid size param provided.".to_string(),
                    details: None,
                };
                return HttpResponse::BadRequest().json(error);
            }
            // loop through the remaining keys to mutate the key string
            let matched_keys = match trunc_by_size(x, matched_keys) {
                Ok(keys) => keys,
                Err(e) => return HttpResponse::NotFound().json(e),
            };
            matched_keys
        }
        _ => matched_keys,
    };

    // Unwrap extensions requested
    // First check if vendor extension requested matches matched_keys vendor
    // Next, check if extension value matches requested
    let matched_keys = match extension_mandatory {
        Some(mut extensions) => {
            // Loop through the vec
            // Get the vendor
            // Get the extension name and value
            let mut exts_vendor: Vec<_> = Vec::new();
            let mut exts_requested: Vec<_> = Vec::new();
            let mut exts_values: Vec<_> = Vec::new();
            for extension in &mut extensions {
                for (k, v) in extension {
                    match k.split_once("_") {
                        Some((vendor, ext)) => {
                            exts_vendor.push(vendor);
                            exts_requested.push(ext)
                        }
                        None => {
                            let error: GeneralError = GeneralError {
                                message: "Invalid extension provided".to_string(),
                                details: None,
                            };
                            return HttpResponse::BadRequest().json(error);
                        }
                    }
                    exts_values.push(v);
                }
                println!("{:?}", exts_vendor);
                println!("{:?}", exts_requested);
            }
            let supported_extensions: Vec<String> =
                vec!["route_type".to_string(), "transfer_method".to_string()];
            let mut unsupported_extension = Vec::new();
            for ext_requested in &exts_requested {
                if !supported_extensions.contains(&ext_requested.to_string()) {
                    unsupported_extension.push(ext_requested.to_string());
                }
            }
            println!("{:?}", unsupported_extension);
            if unsupported_extension.len() > 0 {
                let details = HashMap::from([(
                    "extension_mandatory_unsupported".to_string(),
                    unsupported_extension,
                )]);
                let error: GeneralError = GeneralError {
                    message: "not all extension_mandatory parameters are supported".to_string(),
                    details: Some(details),
                };
                return HttpResponse::BadRequest().json(error);
            }
            // Check if keys meet requested extension
            let mut ext_not_met: Vec<String> = Vec::new();
            let mut requested_keys: Vec<Key> = Vec::new();
            for key in &mut matched_keys {
                // Some and None for key.extension NOT handled yet ERROR indirect routetype still showing
                for (k, v) in &key.extensions {
                    for (i, (k, v)) in key_extensions.iter().enumerate() {
                        if exts_requested.contains(&k.as_str()) && exts_values[i] == v {
                            requested_keys.push(key.clone());
                        }
                    }
                }
            }
            requested_keys
        }
        _ => matched_keys,
    };
    println!("{:?}", matched_keys);
    // let matched_keys: Vec<Key> = match extension_mandatory {
    //     Some(data) => {
    //         // Obtain extension vendor
    //         let mut ext_vendors = Vec::new();
    //         for extension in &data {
    //             for (k, v) in extension {
    //                 let ext_parts: Vec<&str> = k.split("_").collect();
    //                 ext_vendors.push(ext_parts[0]);
    //             }
    //         }
    //         // Check extension vendor matches key vendor
    //         // let mut matched_keys = matched_keys.iter().map(|key| {for vendor in ext_vendors{
    //         //     if key.vendor != vendor
    //         // }})
    //         // for key in &matched_keys {
    //         //     if key.vendor != ext_vendors[0] {
    //         //         continue;
    //         //     }
    //         //     for extension in &key.extensions {
    //         //         match extension {
    //         //             Some(key_extension) => {
    //         //                 let matched =
    //         //             }
    //         //             _ => {}
    //         //         }
    //         //     }
    //         // }
    //         matched_keys
    //     }
    //     _ => matched_keys,
    // };

    // println!(
    //     "{}, {}, {:?}, {:?}",
    //     number.unwrap(),
    //     size.unwrap(),
    //     extension_mandatory.unwrap(),
    //     extension_optional.unwrap()
    // );

    // let mut matched_keys: Vec<Key> = Vec::new();
    // let extension_warning: Vec<Extension> = Vec::new();
    // let extension = Extension { message: None };
    // let key_container_res = KeyContainerRes {
    //     key_container_extension: vec![extension],
    //     keys: keys_vec,
    // };
    HttpResponse::Ok().json(matched_keys)
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(get_status)
        .service(get_keys_get)
        .service(get_keys_post);
}

fn trunc_by_size(size: u64, mut keys: Vec<Key>) -> Result<Vec<Key>, GeneralError> {
    for key in &mut keys {
        let key_str = &key.key;
        // Decode the keys string into bytes from base64
        let decoded_bytes_res = general_purpose::STANDARD.decode(key_str);
        let decoded_bytes = match decoded_bytes_res {
            Ok(res) => res,
            Err(e) => {
                println!("Failed Decoding Key: {}", e);
                break;
            }
        };
        // Scale the bytes to number range
        let decoded_bytes_scaled: Vec<_> = decoded_bytes.iter().map(|x| *x - 48).collect();
        // Join the number into a decimal string
        let decoded_str: String = decoded_bytes_scaled
            .iter()
            .map(|&num| num.to_string())
            .collect();
        // Parse the decimal string into a BigUint
        let decoded_key: BigUint = decoded_str.parse().unwrap();
        // Format the decimal string into binary for truncation
        let decoded_key_str = format!("{:b}", decoded_key);
        // Check if requested size exceeds the key size
        if decoded_key.bits() < size {
            let error: GeneralError = GeneralError {
                message: "Requested key size exceeds available key size.".to_string(),
                details: None,
            };
            return Err(error);
        }
        // Slice the binary string into requested size
        let truc_key_bin = &decoded_key_str[0..size as usize];
        // Change the key back into a BigUint
        let truc_key_bytes = BigUint::from_str_radix(truc_key_bin, 2).unwrap();
        // Encode the key back into base64
        let truc_encode_key =
            general_purpose::STANDARD.encode(truc_key_bytes.to_string().as_bytes());
        // Update the truncated key string into key struct
        key.key = truc_encode_key;
    }
    Ok(keys)
}
