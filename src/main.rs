use std::env;
use dotenv::dotenv;
use std::error::Error;

use actix_web::{get, web, App, HttpServer};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

struct AppState {
    key_data: Mutex<Vec<KMEStorageData>>
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
struct KMEStatus {
    source_KME_ID: String,
    target_KME_ID: String,
    master_SAE_ID: String,
    slave_SAE_ID: String,
    key_size: i32,
    stored_key_count: i32,
    max_key_count: i32,
    max_key_per_request: i32,
    max_key_size: i32,
    max_SAE_ID_count: i32,
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

// struct Config {
//     KME_ID: String,
//     STORAGE_PATH: String,
// }

// impl Config {
//     fn build() -> Result<Config, &'static str> {
//         let KME_ID = env::var("KME_ID").expect("KME_ID var not set");
//         let STORAGE_PATH = env::var("STORAGE_PATH").expect("STORAGE_PATH var not set");
//         // let KME_ID: String = env::var("KME_ID").expect("env var not set");
//         // let STORAGE_PATH: String = env::var("STORAGE_PATH").expect("env var not set");
//         Ok(Config {
//             KME_ID,
//             STORAGE_PATH
//         })
//     }
// }

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let KME_ID = env::var("KME_ID").expect("KME_ID var not set");
    let STORAGE_PATH = env::var("STORAGE_PATH").expect("STORAGE_PATH var not set");
    println!("{KME_ID}"); //, {KME_ID}, {STORAGE_PATH}
    let app_data = web::Data::new(AppState {
        key_data: Mutex::new(vec![])
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