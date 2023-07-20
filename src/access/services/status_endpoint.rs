use super::utils::functions::{get_matched_keys, validate_inp};
use crate::access::models::Status;
use crate::AppState;
use actix_web::{get, web, HttpResponse, Responder};

#[get("/api/v1/keys/{slave_SAE_ID}/status")]
pub async fn get_status(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    // Obtaining slave SAE from path
    let slave_SAE_ID: String = path.into_inner();

    // Obtaining state data from the Appstate
    let (storage_data, key_data) = match validate_inp(data, &slave_SAE_ID) {
        Err(error) => return HttpResponse::BadRequest().json(error),
        Ok((storage_data, key_data)) => (storage_data, key_data),
    };

    // Checking number of keys stored that matches SAE_ID
    let stored_key_count: usize = get_matched_keys(key_data.keys, &slave_SAE_ID)
        .unwrap_or(vec![])
        .len();

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
