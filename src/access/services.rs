use actix_web::{get, post, web, App, HttpRequest, HttpResponse, Responder};
// use actix_web::Error::{BadRequest};
use super::models::{
    CreateKeyIDRequest, CreateKeyRequest, Extension, GeneralError, KeyContainerRes, KeyIDParams,
    KeyRes, NumSizeParams, ServerError, Status,
};
use crate::{AppState, KMEStorageData, Key, KeyContainer};
use base64::{engine::general_purpose, Engine as _};
use num::{BigUint, Num};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::str;
use uuid::Uuid;

// Common function
// - Check if SAE_ID != slave SAE_ID
// - Obtain keys that matches slave SAE_ID

#[get("/api/v1/keys/{slave_SAE_ID}/status")]
async fn get_status(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    // Obtaining slave SAE from path
    let slave_SAE_ID: String = path.into_inner();

    // Obtaining state data from the Appstate
    let (storage_data, key_data) = match validate_inp(data, &slave_SAE_ID) {
        Err(error) => return HttpResponse::BadRequest().json(error),
        Ok((storage_data, key_data)) => (storage_data, key_data),
    };

    // Checking number of keys stored that matches SAE_ID
    let stored_key_count: usize = match get_matched_keys(key_data.keys, &slave_SAE_ID) {
        Some(matched_keys) => matched_keys.len(),
        _ => 0,
    };

    // KME and SAE IDs to be changed in the future when uuids are known
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

// Clones KME storage and key data from the AppState and returns the 2 struct
fn get_storage_key_data(data: web::Data<AppState>) -> (KMEStorageData, KeyContainer) {
    (
        data.kme_storage_data.lock().unwrap().clone(),
        data.kme_key_data.lock().unwrap().clone(),
    )
}

// Checks if SAE_ID is not equal to self SAE_ID (To be change in the future when IDs are known)
fn check_SAE_ID(other_SAE_ID: &String, self_SAE_ID: &String) -> Result<(), GeneralError> {
    if other_SAE_ID == self_SAE_ID {
        let error: GeneralError = GeneralError {
            message: "Invalid SAE_ID in url".to_string(),
            details: None,
        };
        return Err(error);
    }
    Ok(())
}

// Checks if any key in own storage matches the requested SAE and returns the vec of keys or None
fn get_matched_keys(keys: Vec<Key>, slave_SAE_ID: &String) -> Option<Vec<Key>> {
    let mut matched_keys: Vec<Key> = Vec::new();
    for key in keys.iter() {
        if key.KME_ID[3..] == slave_SAE_ID[3..] {
            matched_keys.push(key.clone())
        }
    }
    if matched_keys.is_empty() {
        None
    } else {
        Some(matched_keys)
    }
}

// Get AppState data and checks if the slave SAE_ID input is not equal to self
fn validate_inp(
    data: web::Data<AppState>,
    SAE_ID: &String,
) -> Result<(KMEStorageData, KeyContainer), GeneralError> {
    // Obtaining state data from the Appstate
    let (storage_data, key_data) = get_storage_key_data(data);

    // Checking if SAE_ID does not match server's SAE_ID
    match check_SAE_ID(SAE_ID, &storage_data.SAE_ID) {
        Err(error) => Err(error),
        _ => Ok((storage_data, key_data)),
    }
}

#[get("/api/v1/keys/{slave_SAE_ID}/enc_keys")]
async fn get_keys_get(
    data: web::Data<AppState>,
    path: web::Path<String>,
    params: web::Query<NumSizeParams>,
) -> impl Responder {
    // Obtaining slave SAE from path
    let slave_SAE_ID: String = path.into_inner();

    // Obtaining state data from the Appstate
    let (storage_data, key_data) = match validate_inp(data, &slave_SAE_ID) {
        Err(error) => return HttpResponse::BadRequest().json(error),
        Ok((storage_data, key_data)) => (storage_data, key_data),
    };

    // Obtaining the params from the URL
    let (number, size) = (params.number, params.size);

    // For key container extensions
    let mut extension_msgs: Vec<Extension> = Vec::new();

    // Getting the keys stored that matches the slave_SAE_ID
    let mut matched_keys: Vec<Key> = match get_matched_keys(key_data.keys, &slave_SAE_ID) {
        Some(matched_keys) => matched_keys,
        _ => {
            let error: GeneralError = GeneralError {
                message: "No keys found in storage".to_string(),
                details: None,
            };
            return HttpResponse::NotFound().json(error);
        }
    };

    // Unwrap number,
    // if num = 0, return error
    // else return Vec of respective num of keys
    // If no number provided, default to 1
    let matched_keys: Vec<Key> = match number {
        Some(x) => {
            // Check if number param > 0
            if x == 0 {
                let error: GeneralError = GeneralError {
                    message: "Invalid number param provided.".to_string(),
                    details: None,
                };
                return HttpResponse::BadRequest().json(error);
            } else if x > storage_data.max_key_per_request as u64 {
                let error: GeneralError = GeneralError {
                    message: "Number of keys requested exceeds max_key_per_request of KMS."
                        .to_string(),
                    details: None,
                };
                return HttpResponse::BadRequest().json(error);
            }
            // Check if keys available is less than requested,
            // Returns warning if so
            if matched_keys.len() < x as usize {
                let msg = format!("Number of keys requested exceeds number of keys stored, defaulting to {} keys that meet requirement", matched_keys.len());
                let key_container_ext_msg = Extension {
                    message: Some(msg),
                    details: None,
                };
                extension_msgs.push(key_container_ext_msg);
                matched_keys
            } else {
                matched_keys.splice(0..x as usize, []).collect()
            }
        }
        None => {
            let msg = "Number of keys not specified, defaulting to 1 key returned".to_string();
            let key_container_ext_msg = Extension {
                message: Some(msg),
                details: None,
            };
            extension_msgs.push(key_container_ext_msg);
            matched_keys.splice(0..1, []).collect()
        }
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
            // Check if size param is multiple of 8 (Depending on KME status)
            } else if x % 8 != 0 {
                let error: GeneralError = GeneralError {
                    message: "Size parameter shall be a multiple of 8".to_string(),
                    details: None,
                };
                return HttpResponse::BadRequest().json(error);
            // Check if size param exceeds stored key size
            // Can prob change to message only
            } else if x > storage_data.key_size as u64 {
                let details_key: String =
                    format!("Key size stored in KME: {}", storage_data.key_size);
                let details_val: Vec<_> = vec![format!("Key size requested: {}", x)];
                let details: HashMap<String, Vec<String>> =
                    HashMap::from([(details_key, details_val)]);
                let error: GeneralError = GeneralError {
                    message: "Size paramter exceeded stored key size".to_string(),
                    details: Some(details),
                };
                return HttpResponse::BadRequest().json(error);
            }
            // loop through the remaining keys to mutate the key string
            match trunc_by_size(x, matched_keys) {
                Ok(keys) => keys,
                Err(e) => return HttpResponse::NotFound().json(e),
            }
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
    // let extension = Extension { message: None };
    let key_container_res = KeyContainerRes {
        key_container_extension: extension_msgs,
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
    // Obtaining slave SAE from path
    let slave_SAE_ID: String = path.into_inner();

    // Obtaining state data from the Appstate
    let (storage_data, key_data) = match validate_inp(data, &slave_SAE_ID) {
        Err(error) => return HttpResponse::BadRequest().json(error),
        Ok((storage_data, key_data)) => (storage_data, key_data),
    };
    // For key container extensions
    let mut extension_msgs: Vec<Extension> = Vec::new();
    // Obtain the keys that matches the SAE_ID in server's storage
    let mut matched_keys: Vec<Key> = Vec::new();
    for key in key_data.keys.iter() {
        if key.KME_ID[3..] == slave_SAE_ID[3..] {
            matched_keys.push(key.clone())
        }
    }
    // match every variable
    // If no keys match, return error message
    if matched_keys.is_empty() {
        let error: GeneralError = GeneralError {
            message: "No keys found in storage".to_string(),
            details: None,
        };
        return HttpResponse::NotFound().json(error);
    }
    // Obtain params from request body
    let (number, size, extension_mandatory, extension_optional) = (
        req_obj.number,
        req_obj.size,
        req_obj.extension_mandatory.clone(),
        req_obj.extension_optional.clone(),
    );

    // Unwrap extensions requested
    // First, data validate extension request format
    // Next, check if vendor extension requested matches KME supported extensions
    // Next, check if key vendor matches extension vendor
    // Next, check if extension value matches requested extension value
    let mut matched_keys = match extension_mandatory {
        Some(mut extensions) => {
            if extensions.is_empty() {
                matched_keys
            } else {
                // Loop through the extensions vec
                // Get the vendor
                // Get the extension name and value
                let mut exts_vendor: Vec<_> = Vec::new();
                let mut req_exts_hashmap = HashMap::new();

                // Loop through the HashMaps
                for extension in &mut extensions {
                    // Loop through the key value pairs
                    for (k, v) in extension {
                        // Split the key_string once to get the vendor name and extension
                        match k.split_once('_') {
                            Some((vendor, ext)) => {
                                exts_vendor.push(vendor);
                                req_exts_hashmap.insert(ext, v);
                            }
                            // Handles if extensions not provided in request body
                            None => {
                                let error: GeneralError = GeneralError {
                                    message: "Invalid extension provided".to_string(),
                                    details: None,
                                };
                                return HttpResponse::BadRequest().json(error);
                            }
                        }
                    }
                }

                // Currently supported extension by KME (Can change later to a read file function)
                let supported_extensions: Vec<String> = vec![
                    "route_type".to_string(),
                    "transfer_method".to_string(),
                    "max_age".to_string(),
                ];

                // Checking if extension requested is in supported extensions
                let mut unsupported_extension = Vec::new();
                for ext_requested in req_exts_hashmap.keys() {
                    if !supported_extensions.contains(&ext_requested.to_string()) {
                        unsupported_extension.push(ext_requested.to_string());
                    }
                }

                // If unsupported extension flagged
                //      returns Error and details of which extension is not supported
                if !unsupported_extension.is_empty() {
                    let details = HashMap::from([(
                        "extension_mandatory_unsupported".to_string(),
                        unsupported_extension,
                    )]);
                    let error: GeneralError = GeneralError {
                        message: "Not all extension_mandatory parameters are supported".to_string(),
                        details: Some(details),
                    };
                    return HttpResponse::BadRequest().json(error);
                }

                // Check if keys meet requested extension
                let mut requested_keys: Vec<Key> = Vec::new();
                for key in &mut matched_keys {
                    // Check key vendor (Assuming ext vendor is same for all ext requested)
                    if key.vendor != exts_vendor[0] {
                        continue;
                    }
                    let mut ext_met: Vec<bool> = Vec::new();
                    // Some and None for key.extension NOT handled yet ERROR indirect routetype still showing
                    for key_extensions in &key.extensions {
                        for (k, v) in key_extensions {
                            if req_exts_hashmap.contains_key(&k.as_str())
                                && req_exts_hashmap[&k.as_str()] == v
                            {
                                ext_met.push(true);
                            }
                        }
                        let pass_count = ext_met.iter().filter(|&n| *n).count();
                        if pass_count == req_exts_hashmap.len() {
                            requested_keys.push(key.clone());
                        }
                    }
                }
                requested_keys
            }
        }
        _ => matched_keys,
    };

    // Check if no keys match extension and return error
    if matched_keys.is_empty() {
        let error: GeneralError = GeneralError {
            message: "No keys found meeting requested extensions".to_string(),
            details: None,
        };
        return HttpResponse::NotFound().json(error);
    }

    // Unwrap number,
    // if num = 0, return error
    // else return Vec of respective num of keys
    // If no number provided, default to 1
    let matched_keys: Vec<Key> = match number {
        Some(x) => {
            // Check if number param > 0
            if x == 0 {
                let error: GeneralError = GeneralError {
                    message: "Invalid number param provided.".to_string(),
                    details: None,
                };
                return HttpResponse::BadRequest().json(error);
            } else if x > storage_data.max_key_per_request as u64 {
                let error: GeneralError = GeneralError {
                    message: "Number of keys requested exceeds max_key_per_request of KMS."
                        .to_string(),
                    details: None,
                };
                return HttpResponse::BadRequest().json(error);
            }
            // Check if keys available is less than requested,
            // Returns warning if so
            if matched_keys.len() < x as usize {
                let msg = format!("Number of keys request exceeds number of keys that met requirements, defaulting to {} keys that meet requirement", matched_keys.len());
                let key_container_ext_msg = Extension {
                    message: Some(msg),
                    details: None,
                };
                extension_msgs.push(key_container_ext_msg);
                matched_keys
            } else {
                matched_keys.splice(0..x as usize, []).collect()
            }
        }
        _ => {
            let msg = "Number of keys not specified, defaulting to 1 key returned".to_string();
            let key_container_ext_msg = Extension {
                message: Some(msg),
                details: None,
            };
            extension_msgs.push(key_container_ext_msg);
            matched_keys.splice(0..1, []).collect()
        }
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
            // Check if size param is multiple of 8 (Depending on KME status)
            } else if x % 8 != 0 {
                let error: GeneralError = GeneralError {
                    message: "Size parameter shall be a multiple of 8".to_string(),
                    details: None,
                };
                return HttpResponse::BadRequest().json(error);
            // Check if size param exceeds stored key size
            // Can prob change to message only
            } else if x > storage_data.key_size as u64 {
                let details_key: String =
                    format!("Key size stored in KME: {}", storage_data.key_size);
                let details_val: Vec<_> = vec![format!("Key size requested: {}", x)];
                let details: HashMap<String, Vec<String>> =
                    HashMap::from([(details_key, details_val)]);
                let error: GeneralError = GeneralError {
                    message: "Size paramter exceeded stored key size".to_string(),
                    details: Some(details),
                };
                return HttpResponse::BadRequest().json(error);
            }
            // loop through the remaining keys to mutate the key string
            match trunc_by_size(x, matched_keys) {
                Ok(keys) => keys,
                Err(e) => return HttpResponse::NotFound().json(e),
            }
        }
        _ => matched_keys,
    };

    // Repackage key into KeyRes struct for KeyContainerRes
    let mut keys_vec = Vec::new();
    for key in matched_keys {
        keys_vec.push(KeyRes {
            key_ID: key.key_ID,
            key: key.key,
        })
    }
    let key_container_res = KeyContainerRes {
        key_container_extension: extension_msgs,
        keys: keys_vec,
    };
    HttpResponse::Ok().json(key_container_res)
}

#[get("/api/v1/keys/{master_SAE_ID}/dec_keys")]
async fn get_keys_with_keyID_get(
    data: web::Data<AppState>,
    path: web::Path<String>,
    info: web::Query<KeyIDParams>,
) -> impl Responder {
    // Obtaining slave SAE from path
    let master_SAE_ID: String = path.into_inner();

    // Obtaining state data from the Appstate
    let (storage_data, key_data) = match validate_inp(data, &master_SAE_ID) {
        Err(error) => return HttpResponse::BadRequest().json(error),
        Ok((storage_data, key_data)) => (storage_data, key_data),
    };
    // Obtain the keys that matches the SAE_ID in server's storage
    let mut matched_keys: Vec<Key> = Vec::new();
    for key in key_data.keys.iter() {
        // To be changed to ID lookup table
        if key.KME_ID[3..] == master_SAE_ID[3..] {
            matched_keys.push(key.clone())
        }
    }
    // Check if key_ID param provided
    let key_ID = match &info.key_ID {
        Some(id) => {
            // Use uuid crate to parse string to check if param is uuid format
            if Uuid::parse_str(id).is_err() {
                let error: GeneralError = GeneralError {
                    message: "Invalid key_ID provided".to_string(),
                    details: None,
                };
                return HttpResponse::BadRequest().json(error);
            }
            id
        }
        _ => {
            let error: GeneralError = GeneralError {
                message: "No key_ID provided".to_string(),
                details: None,
            };
            return HttpResponse::BadRequest().json(error);
        }
    };
    // Obtain key that matches the key_ID requested
    let mut requested_keys: Vec<Key> = Vec::new();
    for key in matched_keys {
        if &key.key_ID == key_ID {
            requested_keys.push(key);
        }
    }
    // Check if key is found
    if requested_keys.is_empty() {
        let error: GeneralError = GeneralError {
            message: "Requested key not found".to_string(),
            details: None,
        };
        return HttpResponse::NotFound().json(error);
    // If more than one key obtain, throw server error as this is not suppose to happen
    } else if requested_keys.len() > 1 {
        let error: ServerError = ServerError {
            message: "Multiple key with same key_ID obtain".to_string(),
        };
        return HttpResponse::InternalServerError().json(error);
    }

    // Repackage key into KeyRes struct for KeyContainerRes
    let mut keys_vec = Vec::new();
    for key in requested_keys {
        keys_vec.push(KeyRes {
            key_ID: key.key_ID,
            key: key.key,
        })
    }
    let extension = Extension {
        message: None,
        details: None,
    };
    let key_container_res = KeyContainerRes {
        key_container_extension: vec![extension],
        keys: keys_vec,
    };

    HttpResponse::Ok().json(key_container_res)
}

#[post("/api/v1/keys/{master_SAE_ID}/dec_keys")]
async fn get_keys_with_keyID_post(
    data: web::Data<AppState>,
    path: web::Path<String>,
    req_obj: web::Json<CreateKeyIDRequest>,
) -> impl Responder {
    // Obtaining slave SAE from path
    let master_SAE_ID: String = path.into_inner();

    // Obtaining state data from the Appstate
    let (storage_data, key_data) = match validate_inp(data, &master_SAE_ID) {
        Err(error) => return HttpResponse::BadRequest().json(error),
        Ok((storage_data, key_data)) => (storage_data, key_data),
    };
    // Obtain the keys that matches the SAE_ID in server's storage
    let mut matched_keys: Vec<Key> = Vec::new();
    let mut key_IDs: Vec<String> = Vec::new();
    for key in key_data.keys.iter() {
        // To be changed to ID lookup table
        if key.KME_ID[3..] == master_SAE_ID[3..] {
            matched_keys.push(key.clone());
            key_IDs.push(key.key_ID.clone());
        }
    }
    let mut extension_msgs: Vec<Extension> = Vec::new();
    // Data validation of key_IDs
    let mut invalid_IDs = Vec::new();
    let mut valid_IDs = Vec::new();
    let req_key_IDs = match &req_obj.key_IDs {
        Some(req_key_IDs) => {
            for key_ID in req_key_IDs {
                for (_k, v) in key_ID {
                    if Uuid::parse_str(v).is_err() {
                        invalid_IDs.push(v.to_string());
                    } else {
                        valid_IDs.push(v.to_string());
                    }
                }
            }
            // Check if all the requested key_IDs are invalid and return Error
            if invalid_IDs.len() == req_key_IDs.len() {
                let error: GeneralError = GeneralError {
                    message: "Invalid key_IDs provided".to_string(),
                    details: None,
                };
                return HttpResponse::BadRequest().json(error);
            }
            valid_IDs
        }
        _ => {
            let error: GeneralError = GeneralError {
                message: "No key_IDs provided".to_string(),
                details: None,
            };
            return HttpResponse::BadRequest().json(error);
        }
    };
    // Check if key_IDs is found in KME storage
    let mut requested_keys: Vec<Key> = Vec::new();
    let mut not_found_IDs: Vec<String> = Vec::new();
    let mut found_IDs: Vec<String> = Vec::new();
    let KME_key_IDs: Vec<String> = matched_keys.iter().map(|key| key.key_ID.clone()).collect();
    for req_key_ID in req_key_IDs {
        if KME_key_IDs.contains(&req_key_ID) {
            found_IDs.push(req_key_ID);
        } else {
            not_found_IDs.push(req_key_ID);
        }
    }
    // If key_ID is not found is throw warning in the key container extension
    if !not_found_IDs.is_empty() {
        let msg: String = format!("{} key_ID provided not found in KME", not_found_IDs.len());
        let details = HashMap::from([("key_IDs not found".to_string(), not_found_IDs)]);
        let key_container_ext_msg = Extension {
            message: Some(msg),
            details: Some(details),
        };
        extension_msgs.push(key_container_ext_msg);
    }
    // Push keys found into requested_key vec
    for key in matched_keys {
        if found_IDs.contains(&key.key_ID) {
            requested_keys.push(key);
        }
    }
    // Final check if there are keys found (Should not be needed)
    if requested_keys.is_empty() {
        let error: GeneralError = GeneralError {
            message: "Requested keys not found".to_string(),
            details: None,
        };
        return HttpResponse::NotFound().json(error);
    }
    // Repackage key into KeyRes struct for KeyContainerRes
    let mut keys_vec = Vec::new();
    for key in requested_keys {
        keys_vec.push(KeyRes {
            key_ID: key.key_ID,
            key: key.key,
        })
    }
    let key_container_res = KeyContainerRes {
        key_container_extension: extension_msgs,
        keys: keys_vec,
    };
    HttpResponse::Ok().json(key_container_res)
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(get_status)
        .service(get_keys_get)
        .service(get_keys_post)
        .service(get_keys_with_keyID_get)
        .service(get_keys_with_keyID_post);
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
