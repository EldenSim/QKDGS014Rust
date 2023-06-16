use std::env;
use dotenv::dotenv;
use serde_json::Value;
use std::fs;
use std::collections::HashMap;
// use std::error::Error;

use actix_web::{get, web, App, HttpServer};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::fmt::Display;

use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;



mod access;
use access::services;

struct AppState {
    kme_storage_data: Mutex<KMEStorageData>,
    kme_key_data: Mutex<KeyContainer>,
    // Temp: String
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct KMEStorageData {
    KME_ID: String,
    SAE_ID: String,
    QKD_ID: String,
    key_size: u32,
    max_key_count: u32,
    max_key_per_request: u32,
    min_key_size: u32,
    max_key_size: u32,
    max_SAE_ID_count: u32,
    stored_key_count: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct KeyContainer {
    keys: Vec<Key>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Key {
    KME_ID: String,
    key_ID: String,
    key: String,
    vendor: String,
    extensions: Vec<KeyExtensions>
    // extensions: HashMap<String, KeyExtensions>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct KeyExtensions {
    route_type: Option<String>,
    max_age: Option<String>,
    transfer_method: Option<String>,
}



// #[derive(Serialize, Deserialize, Clone, Debug)]
// struct KMEStatus {
//     source_KME_ID: String,
//     target_KME_ID: String,
//     master_SAE_ID: String,
//     slave_SAE_ID: String,
//     key_size: i32,
//     stored_key_count: i32,
//     max_key_count: i32,
//     max_key_per_request: i32,
//     max_key_size: i32,
//     max_SAE_ID_count: i32,
// }

#[derive(Debug, Clone)]
struct Config {
    kme_id: String,
    storage_path: String,
    key_data_path: String,
}

impl Config {
    fn build() -> Result<Config, &'static str> {
        let kme_id = env::var("KME_ID").expect("KME_ID env var not set");
        let storage_path = env::var("STORAGE_PATH").expect("STORAGE_PATH env var not set");
        let key_data_path = env::var("KEY_DATA_PATH").expect("KEY_DATA_PATH env var not set");
        Ok(Config {
            kme_id,
            storage_path,
            key_data_path
        })
    }
}

fn get_KME_storage_data(storage_path: String) -> Result<KMEStorageData, Box<dyn Error>> {
    // Open file in read-only mode.
    let file = File::open(storage_path)?;
    let reader = BufReader::new(file);
    let result = serde_json::from_reader(reader)?;
    Ok(result)
}

fn get_key_data(storage_path: String) -> Result<KeyContainer, Box<dyn Error>> {
    let file = File::open(storage_path)?;
    let reader = BufReader::new(file);
    let key_data = serde_json::from_reader(reader)?;
    Ok(key_data)
}


#[get("/")]
async fn index() -> String {
    "This is a test".to_string()
}



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let config = Config::build();
    let (kme_id, storage_path, key_data_path) = (config.clone().unwrap().kme_id, config.clone().unwrap().storage_path, config.clone().unwrap().key_data_path);

    // println!("{}", kme_id);
    // println!("{}", storage_path);
    let data = get_KME_storage_data(storage_path);
    // println!("{:?}", data);
    let key_data = get_key_data(key_data_path);
    // println!("{:?}", key_data);


    let app_data = web::Data::new(AppState {
        kme_storage_data: data.unwrap().clone().into(),
        kme_key_data: key_data.unwrap().clone().into(),
    });

    HttpServer::new(move || {
        // Need to remove for production server
        let cors = Cors::default();
        App::new()
            .app_data(app_data.clone())
            .wrap(cors)
            .service(index)
            .configure(services::config)
    })
    .bind(("127.0.0.1", 5001))?
    .run()
    .await
}