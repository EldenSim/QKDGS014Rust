use actix_web::{get, web, App, HttpServer};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

struct AppState {
    data: Mutex<Vec<KMEStorageData>>
}

#[derive(Serialize, Deserialize, Clone)]
struct KMEStorageData {
    KME_ID: String,
    SAE_ID: String,
    key_size: i32,
    max_key_count: i32,
    max_key_per_request: i32,
    min_key_size: i32,
    max_key_size: i32,
    max_SAE_ID_count: i32,
    QKD_ID: String,
    stored_key_count: i32,
    keys: Vec<KeyContainer>,
}

#[derive(Serialize, Deserialize, Clone)]
struct KeyContainer {
    key_ID: String,
    key: String,
    vendor: String,
    KME_ID: String,
    extensions: Vec<KeyExtensions>,
}

#[derive(Serialize, Deserialize, Clone)]
struct KeyExtensions;

#[get("/")]
async fn index() -> String {
    "This is a test".to_string()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_data = web::Data::new(AppState {
        data: Mutex::new(vec![])
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
            .service(index)
            // .configure(service::config)
    })
    .bind(("127.0.0.1", 5000))?
    .run()
    .await
}