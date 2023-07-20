use super::utils::functions::{get_matched_keys, trunc_by_size, validate_inp};
use crate::access::models::{Extension, GeneralError, KeyContainerRes, KeyRes, NumSizeParams};
use crate::{AppState, Key};
use actix_web::{get, web, HttpResponse, Responder};
use std::collections::HashMap;

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
        Ok((storage_data, key_data)) => (storage_data, key_data),
        Err(error) => return HttpResponse::BadRequest().json(error),
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
            // Check if request number exceeds max_key_per_request of KME
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
                let msg: String = format!("Number of keys requested exceeds number of keys stored, defaulting to {} keys that meet requirement", matched_keys.len());
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
            // Check if size param is multiple of 8 (Depending on how KME is set up)
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
    let mut keys_vec: Vec<KeyRes> = Vec::new();
    for key in matched_keys {
        keys_vec.push(KeyRes {
            key_ID: key.key_ID,
            key: key.key,
        })
    }
    // let extension = Extension { message: None };
    let key_container_res: KeyContainerRes = KeyContainerRes {
        key_container_extension: extension_msgs,
        keys: keys_vec,
    };

    HttpResponse::Ok().json(key_container_res)
}
