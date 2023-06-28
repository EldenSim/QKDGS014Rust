use std::collections::HashMap;

use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct CreateKeyRequest {
    pub number: Option<u64>,
    pub size: Option<u64>,
    pub extension_mandatory: Option<Vec<HashMap<String, String>>>,
    pub extension_optional: Option<Vec<HashMap<String, String>>>,
}
