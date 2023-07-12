use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Clone)]
pub struct CreateKeyRequest {
    pub number: Option<u64>,
    pub size: Option<u64>,
    pub extension_mandatory: Option<Vec<HashMap<String, String>>>,
    pub extension_optional: Option<Vec<HashMap<String, String>>>,
}

#[derive(Deserialize, Clone)]
pub struct CreateKeyIDRequest {
    pub key_IDs: Option<Vec<HashMap<String, String>>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Status {
    pub source_KME_ID: String,
    pub target_KME_ID: String,
    pub master_SAE_ID: String,
    pub slave_SAE_ID: String,
    pub key_size: u32,
    pub max_key_count: u32,
    pub max_key_per_request: u32,
    pub min_key_size: u32,
    pub max_key_size: u32,
    pub stored_key_count: usize,
    pub max_SAE_ID_count: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyContainerRes {
    pub key_container_extension: Vec<Extension>,
    pub keys: Vec<KeyRes>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyRes {
    pub key_ID: String,
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Extension {
    pub message: Option<String>,
    pub details: Option<HashMap<String, Vec<String>>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GeneralError {
    pub message: String,
    pub details: Option<HashMap<String, Vec<String>>>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerError {
    pub message: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct NumSizeParams {
    pub number: Option<u64>,
    pub size: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyIDParams {
    pub key_ID: Option<String>,
}
