use super::utils::functions::{delete_keys, trunc_by_size, validate_inp};
use crate::access::models::{CreateKeyRequest, Extension, GeneralError, KeyContainerRes, KeyRes};
use crate::{AppState, Key};
use actix_web::{post, web, HttpResponse, Responder};
use std::collections::HashMap;
#[post("/api/v1/keys/{slave_SAE_ID}/enc_keys")]
async fn get_keys_post(
    data: web::Data<AppState>,
    path: web::Path<String>,
    req_obj: web::Json<CreateKeyRequest>,
) -> impl Responder {
    // Obtaining slave SAE from path
    let slave_SAE_ID: String = path.into_inner();

    // Obtaining state data from the Appstate
    let (storage_data, key_data) = match validate_inp(data.clone(), &slave_SAE_ID) {
        Ok((storage_data, key_data)) => (storage_data, key_data),
        Err(error) => return HttpResponse::BadRequest().json(error),
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
                let mut req_exts_hashmap: HashMap<&str, &mut String> = HashMap::new();

                // Loop through the HashMaps
                for extension in &mut extensions {
                    // Loop through the key value pairs
                    for (k, v) in extension {
                        // Split the key_string once to get the vendor name and extension
                        match k.split_once('_') {
                            Some((vendor, ext)) => {
                                // Might need to clean the string further, rm extra "_" or spaces
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
                let mut unsupported_extension: Vec<String> = Vec::new();
                for ext_requested in req_exts_hashmap.keys() {
                    if !supported_extensions.contains(&ext_requested.to_string()) {
                        unsupported_extension.push(ext_requested.to_string());
                    }
                }

                // If unsupported extension flagged
                //      returns Error and details of which extension is not supported
                if !unsupported_extension.is_empty() {
                    let details: HashMap<String, Vec<String>> = HashMap::from([(
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
        keys: keys_vec.clone(),
    };

    // Delete keys returned as specified in documentation post-condition
    delete_keys(data, keys_vec);

    HttpResponse::Ok().json(key_container_res)
}
