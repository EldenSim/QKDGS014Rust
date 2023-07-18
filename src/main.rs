use actix_cors::Cors;
use actix_web::{get, web, App, HttpServer};
use dotenv::dotenv;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

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
    stored_key_count: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct KeyContainer {
    keys: Vec<Key>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Key {
    KME_ID: String,
    key_ID: String,
    key: String,
    vendor: String,
    extensions: Option<HashMap<String, String>>, // extensions: HashMap<String, KeyExtensions>,
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
            key_data_path,
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

// fn get_extensions(storage_path: String) -> Result<Vec<Extensions>>

#[get("/")]
async fn index() -> String {
    "This is a test".to_string()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let config = Config::build();
    let (_kme_id, storage_path, key_data_path) = (
        config.clone().unwrap().kme_id,
        config.clone().unwrap().storage_path,
        config.clone().unwrap().key_data_path,
    );

    let data = get_KME_storage_data(storage_path);
    let key_data = get_key_data(key_data_path);
    let app_data = web::Data::new(AppState {
        kme_storage_data: data.unwrap().into(),
        kme_key_data: key_data.unwrap().into(),
    });

    // Https certs
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("localhost-key.pem", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("localhost.pem").unwrap();

    // bind to local LAN ip address
    let localhost = true;
    use local_ip_address::local_ip;
    let my_local_ip = if localhost {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    } else {
        local_ip().unwrap()
    };
    println!("Server is hosted on: https://{my_local_ip}:8080");

    HttpServer::new(move || {
        // Need to remove for production server
        let cors = Cors::default()
            .allow_any_header()
            .allow_any_method()
            .allow_any_origin();
        App::new()
            .app_data(app_data.clone())
            .wrap(cors)
            .service(index)
            .configure(services::config)
    })
    .bind_openssl(format!("{my_local_ip}:8080"), builder)?
    // .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
