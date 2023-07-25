use crate::access::models::{GeneralError, KeyRes};
use crate::{AppState, KMEStorageData, Key, KeyContainer};
use actix_web::web;
use base64::{engine::general_purpose, Engine as _};
use num::{BigUint, Num};

// Clones KME storage and key data from the AppState and returns the 2 struct
pub fn get_storage_key_data(data: web::Data<AppState>) -> (KMEStorageData, KeyContainer) {
    (
        data.kme_storage_data.lock().unwrap().clone(),
        data.kme_key_data.lock().unwrap().clone(),
    )
}

// Checks if SAE_ID is not equal to self SAE_ID (To be change in the future when IDs are known)
pub fn check_SAE_ID(other_SAE_ID: &String, self_SAE_ID: &String) -> Result<(), GeneralError> {
    if other_SAE_ID == self_SAE_ID {
        let error: GeneralError = GeneralError {
            message: "Invalid SAE_ID in url".to_string(),
            details: None,
        };
        return Err(error);
    }
    Ok(())
}

// Checks if any key in own storage matches the requested SAE and returns the vec of keys or None
pub fn get_matched_keys(keys: Vec<Key>, other_SAE_ID: &String) -> Option<Vec<Key>> {
    let mut matched_keys: Vec<Key> = Vec::new();
    for key in keys {
        if key.KME_ID[3..] == other_SAE_ID[3..] {
            matched_keys.push(key.clone())
        }
    }
    if matched_keys.is_empty() {
        None
    } else {
        Some(matched_keys)
    }
}

// Get AppState data and checks if the master/slave SAE_ID input is not equal to self
pub fn validate_inp(
    data: web::Data<AppState>,
    other_SAE_ID: &String,
) -> Result<(KMEStorageData, KeyContainer), GeneralError> {
    // Obtaining state data from the Appstate
    let (storage_data, key_data) = get_storage_key_data(data);

    // Checking if SAE_ID does not match server's SAE_ID
    match check_SAE_ID(other_SAE_ID, &storage_data.SAE_ID) {
        Err(error) => Err(error),
        _ => Ok((storage_data, key_data)),
    }
}

pub fn trunc_by_size(size: u64, mut keys: Vec<Key>) -> Result<Vec<Key>, GeneralError> {
    for key in &mut keys {
        let key_str = &key.key;
        // Decode the keys string into bytes from base64
        let decoded_bytes_res = general_purpose::STANDARD.decode(key_str);
        let decoded_bytes = match decoded_bytes_res {
            Ok(res) => res,
            Err(e) => {
                println!("Failed Decoding Key: {}", e);
                break;
            }
        };
        // Scale the bytes to number range
        let decoded_bytes_scaled: Vec<_> = decoded_bytes.iter().map(|x| *x - 48).collect();
        // Join the number into a decimal string
        let decoded_str: String = decoded_bytes_scaled
            .iter()
            .map(|&num| num.to_string())
            .collect();
        // Parse the decimal string into a BigUint
        let decoded_key: BigUint = decoded_str.parse().unwrap();
        // Format the decimal string into binary for truncation
        let decoded_key_str = format!("{:b}", decoded_key);
        // Check if requested size exceeds the key size
        if decoded_key.bits() < size {
            let error: GeneralError = GeneralError {
                message: "Requested key size exceeds available key size.".to_string(),
                details: None,
            };
            return Err(error);
        }
        // Slice the binary string into requested size
        let truc_key_bin = &decoded_key_str[0..size as usize];
        // Change the key back into a BigUint
        let truc_key_bytes = BigUint::from_str_radix(truc_key_bin, 2).unwrap();
        // Encode the key back into base64
        let truc_encode_key =
            general_purpose::STANDARD.encode(truc_key_bytes.to_string().as_bytes());
        // Update the truncated key string into key struct
        key.key = truc_encode_key;
    }
    Ok(keys)
}

// Get current keys in state from AppSatae and delete the keys given in keys_to_delete vec
pub fn delete_keys(data: web::Data<AppState>, keys_to_delete: Vec<KeyRes>) {
    // Unlocks the data from the Arc and Mutex type - https://snorre.io/blog/2018-08-23-shared-mutable-cache-in-actix-web/
    // Arc is a thread safe reference count pointer and that invoking clone on such a pointer creates a new reference to the same value in the heap.
    let mut current_keys_in_storage = data.kme_key_data.lock().unwrap();

    // Edit the keys in the storage by mutating the data inside the mutex
    *current_keys_in_storage = current_keys_in_storage
        .keys
        .to_vec()
        .into_iter()
        // May have a faster way to filter the key
        .filter(|x| !keys_to_delete.contains(&KeyRes::from(x)))
        .collect::<KeyContainer>();
}

// Implementing the FromIterator trait for KeyContainer for delete_keys function
impl FromIterator<Key> for KeyContainer {
    fn from_iter<T: IntoIterator<Item = Key>>(iter: T) -> Self {
        let mut key_vec = Vec::new();
        for key in iter {
            key_vec.push(key)
        }
        KeyContainer { keys: key_vec }
    }
}

// Implementing the From trait for KeyRes, used in delete_keys function
// For comparing the Key and KeyRes types from the matched keys to be deleted
impl From<&Key> for KeyRes {
    fn from(value: &Key) -> Self {
        KeyRes {
            key_ID: value.key_ID.clone(),
            key: value.key.clone(),
        }
    }
}
// Implementing the PartialEq trait for KeyRes (Not needed for now)
impl PartialEq for KeyRes {
    fn eq(&self, other: &Self) -> bool {
        self.key_ID == other.key_ID
    }
    fn ne(&self, other: &Self) -> bool {
        self.key_ID != other.key_ID
    }
}
