use actix_web::{get, post, web, Responder, HttpResponse, HttpRequest};
// use actix_web::Error::{BadRequest};
use serde::{Deserialize, Serialize};
use crate::{AppState, KMEStorageData, KeyContainer, Key};
use super::models::{CreateKeyRequest};

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
struct GeneralError {
    message: String,
}

#[get("/api/v1/keys/{slave_SAE_ID}/status")]
async fn get_status(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let storage_data: KMEStorageData = data.kme_storage_data.lock().unwrap().clone();
    let key_data: KeyContainer = data.kme_key_data.lock().unwrap().clone();
    let slave_SAE_ID: String = path.into_inner();
    if slave_SAE_ID == storage_data.SAE_ID {
        let error: GeneralError = GeneralError { message: "Invalid slave SAE_ID".to_string() };
        return HttpResponse::BadRequest().json(error)
    };
    let mut matched_keys: Vec<Key> = Vec::new();
    let key_data_iter: std::slice::Iter<'_, Key> = key_data.keys.iter();
    for key in key_data_iter {
        if &key.KME_ID[3..] == &slave_SAE_ID[3..] {
            matched_keys.insert(0, key.clone())
        }
    }
    let stored_key_count: usize = if matched_keys.len() == 0 {0} else {matched_keys.len()};
    let status: Status = Status {
        source_KME_ID: storage_data.KME_ID,
        target_KME_ID: "???".to_string(),
        master_SAE_ID: storage_data.SAE_ID,
        slave_SAE_ID: slave_SAE_ID,
        key_size: storage_data.key_size,
        max_key_count: storage_data.max_key_count,
        max_key_per_request: storage_data.max_key_per_request,
        min_key_size: storage_data.min_key_size,
        max_key_size: storage_data.max_key_size,
        stored_key_count: stored_key_count,
        max_SAE_ID_count: storage_data.max_SAE_ID_count,
    };
    return HttpResponse::Ok().json(status)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Params {
    number: Option<u64>,
    size: Option<u64>,
}

#[get("/api/v1/keys/{slave_SAE_ID}/enc_keys")]
async fn get_keys_get(data: web::Data<AppState>, path: web::Path<String>, info: web::Query<Params>) -> impl Responder {
    let storage_data: KMEStorageData = data.kme_storage_data.lock().unwrap().clone();
    let key_data: KeyContainer = data.kme_key_data.lock().unwrap().clone();
    let slave_SAE_ID: String = path.into_inner();
    let (number, size) = (info.number, info.size);
    // let num_of_key = match number {
    //     Some(x) => {
    //         if x < 1 {
    //             let error: GeneralError = GeneralError { message: "Invalid number parameter".to_string() };
    //             return HttpResponse::BadRequest().json(error)
    //         } else {
    //             return x
    //         }
    //     },
    //     _ => {
    //         // Put up warning in the key container extension
    //         return 1
    //     }
    // };
    // let size = match size {
    //     Some(x) => {
    //         if x < 1 {
    //             let error: GeneralError = GeneralError { message: "Invalid size parameter".to_string() };
    //             return HttpResponse::BadRequest().json(error)
    //         } else {
    //             return storage_data.
    //         }
    //     },
    //     _ => {
    //         // Put up warning in the key container extension
    //     }
    // };
    if slave_SAE_ID == storage_data.SAE_ID {
        let error: GeneralError = GeneralError { message: "Invalid slave SAE_ID".to_string() };
        return HttpResponse::BadRequest().json(error)
    };
    let mut matched_keys: Vec<Key> = Vec::new();
    let key_data_iter: std::slice::Iter<'_, Key> = key_data.keys.iter();
    for key in key_data_iter {
        if &key.KME_ID[3..] == &slave_SAE_ID[3..] {
            matched_keys.insert(0, key.clone())
        }
    }


    return HttpResponse::Ok().json(matched_keys)
}



pub fn config(cfg: &mut web::ServiceConfig) {
    cfg
        .service(get_status)
        .service(get_keys_get);
}