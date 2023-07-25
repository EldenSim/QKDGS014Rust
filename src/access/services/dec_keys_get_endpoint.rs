use super::utils::functions::{delete_keys, validate_inp};
use crate::access::models::{
    Extension, GeneralError, KeyContainerRes, KeyIDParams, KeyRes, ServerError,
};
use crate::{AppState, Key};
use actix_web::{get, web, HttpResponse, Responder};
use uuid::Uuid;

#[get("/api/v1/keys/{master_SAE_ID}/dec_keys")]
async fn get_keys_with_keyID_get(
    data: web::Data<AppState>,
    path: web::Path<String>,
    info: web::Query<KeyIDParams>,
) -> impl Responder {
    // Obtaining slave SAE from path
    let master_SAE_ID: String = path.into_inner();

    // Obtaining state data from the Appstate
    let (storage_data, key_data) = match validate_inp(data.clone(), &master_SAE_ID) {
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

    // Clear the other variables not needed
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
        keys: keys_vec.clone(),
    };

    // Delete keys returned as specified in documentation post-condition
    delete_keys(data, keys_vec);

    HttpResponse::Ok().json(key_container_res)
}
