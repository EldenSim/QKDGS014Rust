use actix_web::{get, post, web, Responder, HttpResponse};
use serde::{Deserialize, Serialize};
use crate::{AppState, KMEStorageData};
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
    stored_key_count: u32,
    max_SAE_ID_count: u32,
}

#[get("/api/v1/keys/{slave_SAE_ID}/status")]
async fn get_status(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let storage_data = data.kme_storage_data.lock().unwrap().clone();
    let key_data = data.kme_key_data.lock().unwrap().clone();
    let slave_SAE_ID = path.into_inner();
    // for KME_ID in key_data.keys {
    //     if slave_SAE_ID != KME_ID {
    //         HttpResponse::
    //     }
    // }
    let status = Status {
        source_KME_ID: storage_data.KME_ID,
        target_KME_ID: "???".to_string(),
        master_SAE_ID: storage_data.SAE_ID,
        slave_SAE_ID: slave_SAE_ID,
        key_size: storage_data.key_size,
        max_key_count: storage_data.max_key_count,
        max_key_per_request: storage_data.max_key_per_request,
        min_key_size: storage_data.min_key_size,
        max_key_size: storage_data.max_key_size,
        stored_key_count: storage_data.stored_key_count,
        max_SAE_ID_count: storage_data.max_SAE_ID_count,
    };
    HttpResponse::Ok().json(status)

}


pub fn config(cfg: &mut web::ServiceConfig) {
    cfg
        .service(get_status);
}