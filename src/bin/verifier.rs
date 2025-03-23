mod types {
    include!("../types.rs");
}

use rocket::http::Status;
use rocket::response::status;
use types::Payload;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

use ring::signature;

#[macro_use]
extern crate rocket;

struct NonceEntry {
    created_at: Instant,
    used: bool,
}

struct NonceStore {
    nonces: HashMap<String, NonceEntry>, // nonce -> NonceEntry
    expiration_time: Duration,
}

impl NonceStore {
    fn new(expiration_seconds: u64) -> Self {
        Self {
            nonces: HashMap::new(),
            expiration_time: Duration::from_secs(expiration_seconds),
        }
    }

    fn generate_nonce(&mut self) -> String {
        let nonce = Uuid::new_v4().to_string();
        self.nonces.insert(
            nonce.clone(),
            NonceEntry {
                created_at: Instant::now(),
                used: false,
            },
        );
        nonce
    }

    fn verify_and_use_nonce(&mut self, nonce: &str) -> bool {
        // Check if the nonce exists
        if let Some(nonce_entry) = self.nonces.get_mut(nonce) {
            // Check if the nonce has already been used
            if nonce_entry.used {
                return false;
            }

            // Check if the nonce has expired
            if nonce_entry.created_at.elapsed() > self.expiration_time {
                self.nonces.remove(nonce);
                return false;
            }

            // Mark the nonce as used
            nonce_entry.used = true;
            return true;
        }
        false
    }
}

type NonceStoreRef = rocket::State<Arc<Mutex<NonceStore>>>;

// Generate nonce
#[get("/nonce")]
fn nonce(store: &NonceStoreRef) -> String {
    let mut store = store.lock().unwrap();

    store.generate_nonce()
}

#[post("/verify", format = "json", data = "<payload>")]
fn verify_signature(payload: String, store: &NonceStoreRef) -> status::Custom<String> {
    let mut store = store.lock().unwrap();

    let payload: Payload = serde_json::from_str(&payload)
        .map_err(|e| {
            status::Custom(
                Status::BadRequest,
                format!("Failed to parse payload: {}", e),
            )
        })
        .unwrap();

    // Extract the payload parts
    let message_bytes = payload.message.as_slice();
    let public_key_bytes = payload.public_key.as_slice();
    let signature_bytes = payload.signature.as_slice();
    let nonce = payload.nonce.as_str();

    if !store.verify_and_use_nonce(nonce) {
        return status::Custom(Status::Unauthorized, "Invalid or expired nonce".to_string());
    }

    let holder_public_key =
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);

    // Verify the signature
    if holder_public_key
        .verify(message_bytes, signature_bytes)
        .is_ok()
    {
        return status::Custom(Status::Ok, "Signature verified successfully".to_string());
    }

    status::Custom(Status::Unauthorized, "Invalid Signature".to_string())
}

#[launch]
fn rocket() -> _ {
    // 5 seconds expiration time - just to make it easier to test
    let nonce_store = NonceStore::new(5);

    rocket::build()
        .configure(rocket::Config {
            port: 1843,
            ..Default::default()
        })
        .manage(Arc::new(Mutex::new(nonce_store)))
        .mount("/", routes![nonce, verify_signature])
}
