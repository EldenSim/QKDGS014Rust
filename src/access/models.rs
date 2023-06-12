use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct ExtensionRequest;

#[derive(Deserialize, Clone)]
pub struct CreateKeyRequest {
    number:i32,
    size:i32,
    extensions: Vec<ExtensionRequest>
}
