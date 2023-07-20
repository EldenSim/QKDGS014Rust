use super::utils::functions::validate_inp;
use crate::access::models::{CreateKeyIDRequest, Extension, GeneralError, KeyContainerRes, KeyRes};
use crate::{AppState, Key};
use actix_web::{post, web, HttpResponse, Responder};
use std::collections::HashMap;
use uuid::Uuid;

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
