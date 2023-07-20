use actix_web::web;

pub mod utils;

// TODO:
// When checking if key KME == SAE, change to a look up table with respective KME_ID and SAE_ID
pub mod status_endpoint;
use status_endpoint::get_status;

pub mod enc_keys_get_endpoint;
use enc_keys_get_endpoint::get_keys_get;

pub mod enc_keys_post_endpoint;
use enc_keys_post_endpoint::get_keys_post;

pub mod dec_keys_get_endpoint;
use dec_keys_get_endpoint::get_keys_with_keyID_get;

pub mod dec_keys_post_endpoint;
use dec_keys_post_endpoint::get_keys_with_keyID_post;

// CONFIG
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(get_status)
        .service(get_keys_get)
        .service(get_keys_post)
        .service(get_keys_with_keyID_get)
        .service(get_keys_with_keyID_post);
}
