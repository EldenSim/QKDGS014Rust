use actix_web::{get, post, web, Responder, HttpResponse};
use crate::{AppState, KMEStorageData};
use super::models::{CreateKeyRequest};

#[get("/api/v1/keys/{slave_SAE_ID}/status")]
async fn get_status(data::web::Data<AppState>) -> imple Responder {
    let storage_data = data::KMEStorageData.lock().clone()

    println!(storage_data)
}