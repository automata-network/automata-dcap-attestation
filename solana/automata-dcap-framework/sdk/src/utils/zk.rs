use anyhow::Result;
use ecdsa_secp256r1_host::verify_non_blocking;
use der::{Encode, Decode};
use der_parser::{ber::BerObjectContent, der::parse_der};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

/// We use the ecdsa guest program here instead becasue
/// we are not verifying the entire chain
/// the ecdsa guest program can also be used to verify JSON collaterals

pub async fn get_x509_ecdsa_verify_proof(
    subject_der: &[u8],
    issuer_der: &[u8]
) -> Result<(
    [u8; 32], // image_id
    Vec<u8>,  // journal_bytes
    Vec<u8>,  // Groth16 Seal
)> {
    let subject = Certificate::from_der(subject_der).unwrap();
    let tbs = subject.tbs_certificate;
    let digest: [u8; 32] = Sha256::digest(tbs.to_der().unwrap().as_slice()).into();

    let subject_signature_encoded = subject.signature.as_bytes().unwrap();
    let subject_signature = process_sig(subject_signature_encoded);

    let (image_id, journal, seal) = verify_non_blocking(
        digest, 
        subject_signature, 
        issuer_der.to_vec()
    ).await?;

    Ok((
        image_id,
        journal,
        seal
    ))
}

fn process_sig(der_sig: &[u8]) -> [u8; 64] {
    let decoded = parse_der(der_sig).unwrap().1.content;
    
    let mut ret = [0u8; 64];

    match decoded {
        BerObjectContent::Sequence(sig_sequence) => {
            // ECDSA
            for (i, v) in sig_sequence.iter().enumerate() {
                let extracted = v.as_slice().unwrap();
                let processed = pad_or_trim_to_length(extracted, 32);
                ret[i * 32..(i + 1) * 32].copy_from_slice(&processed);
            }
        },
        _ => {
            panic!("Must be a sequence");
        }
    }

    ret
}

fn pad_or_trim_to_length(input: &[u8], expected_length: usize) -> Vec<u8> {
    let n = input.len();
    let mut ret: Vec<u8> = vec![];
    if n < expected_length {
        ret.extend_from_slice(input);
        ret.resize(expected_length, 0);
        ret
    } else if n > expected_length {
        let offset = n - expected_length;
        let trimmed = &input[offset..];
        trimmed.to_vec()
    } else {
        input.to_vec()
    }
}