use std::env;
use dotenv::dotenv;
use serde_json::Value;
use std::fs;
// use std::error::Error;

use actix_web::{get, web, App, HttpServer};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::fmt::Display;


struct AppState {
    // KME_storage_data: KMEStorageData,
    // KME_key_data: Vec<KeyContainer>,
    // KME_status_data: KMEStatus
    Temp: String
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct KMEStorageData {
    KME_ID: String,
    SAE_ID: String,
    key_size: i64,
    max_key_count: i64,
    max_key_per_request: i64,
    min_key_size: i32,
    max_key_size: i32,
    max_SAE_ID_count: i32,
    QKD_ID: String,
    stored_key_count: i32,
    // keys: Vec<KeyContainer>,
}


#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Serialize, Deserialize, Clone, Debug)]
struct KeyContainer {
    key_ID: String,
    key: String,
    vendor: String,
    KME_ID: String,
    extensions: Vec<KeyExtensions>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct KeyExtensions;

#[get("/")]
async fn index() -> String {
    "This is a test".to_string()
}

#[derive(Debug, Clone)]
struct Config {
    KME_ID: String,
    STORAGE_PATH: String,
}

impl Config {
    fn build() -> Result<Config, &'static str> {
        let KME_ID = env::var("KME_ID").expect("KME_ID var not set");
        let STORAGE_PATH = env::var("STORAGE_PATH").expect("STORAGE_PATH var not set");
        Ok(Config {
            KME_ID,
            STORAGE_PATH
        })
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let config = Config::build();
    println!("{:?}", config.clone().unwrap());
    // let storage_data = KMEStorageData::build(config.unwrap().STORAGE_PATH);
    // let key_data = Vec<KeyContainer> {};
    // let status_data = KMEStatus {};
    let app_data = web::Data::new(AppState {
        Temp: "Not functional".to_string(),
        // KME_storage_data: storage_data.unwrap(),
        // KME_key_data: key_data,
        // KME_status_data: status_data
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