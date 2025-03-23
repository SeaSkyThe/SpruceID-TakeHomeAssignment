mod types {
    include!("../types.rs");
}

use core::time;
use std::thread;

use reqwest::blocking::Client;
use ring::rand;
use ring::signature::{Ed25519KeyPair, KeyPair, Signature};
use types::Payload;
use uuid::Uuid;

const FETCH_NONCE_URL: &str = "http://localhost:1843/nonce";
const VERIFY_SIGNATURE_URL: &str = "http://localhost:1843/verify";

fn generate_keypair() -> Result<Ed25519KeyPair, String> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| "Failed to generate Ed25519 Key Pair".to_string())?;

    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|_| "Failed to parse Ed25519 Key Pair".to_string());

    key_pair
}

fn build_payload(
    key_pair: Ed25519KeyPair,
    message: &[u8],
    sig: Signature,
    nonce: String,
) -> Payload {
    let public_key_bytes = key_pair.public_key().as_ref();

    Payload {
        nonce: nonce.to_string(),
        message: message.as_ref().to_vec(),
        signature: sig.as_ref().to_vec(),
        public_key: public_key_bytes.to_vec(),
    }
}

// HTTP Related Functions
// Fetch a nonce value from the server
fn fetch_nonce() -> Result<String, String> {
    println!("  1. Fetching Nonce...");
    let client = Client::new();
    let response = client
        .get(FETCH_NONCE_URL)
        .send()
        .map_err(|_| "Failed to fetch nonce".to_string())?;
    let nonce = response
        .text()
        .map_err(|_| "Failed to fetch nonce".to_string())?;

    // Check if is a valid uuid
    Uuid::parse_str(&nonce).map_err(|_| "Invalid nonce".to_string())?;

    //Ok("bdf3b304-0e37-4639-9eed-039e16f1c171".to_string())

    Ok(nonce)
}

// Assks for the Verifier to verify the signature of the payload
fn verify_signature(payload: Payload) -> Result<(), String> {
    let client = Client::new();

    let payload_json =
        serde_json::to_string(&payload).map_err(|_| "Failed to serialize payload".to_string())?;

    let response = client
        .post(VERIFY_SIGNATURE_URL)
        .header("Content-Type", "application/json")
        .body(payload_json)
        .send()
        .map_err(|_| "Failed to fetch nonce".to_string())?;

    if response.status().is_success() {
        Ok(())
    } else if response.status() == 401 {
        let text_response = response.text().unwrap();
        Err(text_response)
    } else {
        Err("Failed to verify signature".to_string())
    }
}

fn main() {
    const MESSAGE: &[u8] = b"Hello, world!";

    // Here we gonna set up 4 cases:
    //   1. Valid Signature
    //   2. Invalid Signature
    //   3. Expired Nonce
    //   4. Invalid Nonce

    println!();
    test_1(MESSAGE);
    println!();
    test_2(MESSAGE);
    println!();
    test_3(MESSAGE);
    println!();
    test_4(MESSAGE);
    println!();
}

// TEST FUNCTIONS
fn test_1(message: &[u8]) {
    // Generate Key Pair
    let key_pair = match generate_keypair() {
        Ok(key_pair) => key_pair,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    // Case 1: Valid Check
    println!("---- Case 1: Valid Check ----");
    let nonce = match fetch_nonce() {
        Ok(nonce) => nonce,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    run_valid_check(key_pair, message, nonce, None);
}

fn test_2(message: &[u8]) {
    // Generate Key Pair
    let key_pair = match generate_keypair() {
        Ok(key_pair) => key_pair,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    println!("\n---- Case 2: Valid Check followed by Check with same nonce (Should Fail) ----");
    let nonce = match fetch_nonce() {
        Ok(nonce) => nonce,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    run_valid_check(key_pair, message, nonce.clone(), None);

    let key_pair2 = match generate_keypair() {
        Ok(key_pair) => key_pair,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    run_valid_check(key_pair2, message, nonce.clone(), None);
}

fn test_3(message: &[u8]) {
    // Generate Key Pair
    let key_pair = match generate_keypair() {
        Ok(key_pair) => key_pair,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    println!("---- Case 3: Valid Nonce but Invalid Signature (Should Fail) ----");
    let nonce = match fetch_nonce() {
        Ok(nonce) => nonce,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    run_valid_check(key_pair, message, nonce, Some(b"RANDOM MESSAGE"));
}

fn test_4(message: &[u8]) {
    // Generate Key Pair
    let key_pair = match generate_keypair() {
        Ok(key_pair) => key_pair,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    println!("\n---- Case 4: Valid Check After Nonce Expiration (Should Fail) ----");
    let nonce = match fetch_nonce() {
        Ok(nonce) => nonce,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    thread::sleep(time::Duration::from_secs(6));
    run_valid_check(key_pair, message, nonce, None);
}

fn run_valid_check(
    key_pair: Ed25519KeyPair,
    message: &[u8],
    nonce: String,
    wrong_message: Option<&[u8]>,
) {
    let message_to_sign = wrong_message.unwrap_or(message);

    println!("  2. Signing Message Correctly...");
    let sig = key_pair.sign(message_to_sign);
    println!("  3. Building Payload...");
    let payload = build_payload(key_pair, message, sig, nonce);

    println!("  4. Verifying Signature...");
    match verify_signature(payload) {
        Ok(_) => println!("Signature verified successfully!"),
        Err(e) => eprintln!("Error: {}", e),
    };
}
