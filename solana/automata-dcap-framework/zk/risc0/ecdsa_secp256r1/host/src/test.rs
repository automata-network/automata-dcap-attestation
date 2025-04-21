use der::{Encode, Decode};
use der_parser::{ber::BerObjectContent, der::parse_der};
use x509_cert::Certificate;
use sha2::{Sha256, Digest};

#[test]
pub fn test_verify_sample() {
    use super::*;

    let root_der_bytes = include_bytes!("../sample/root.der");
    let root_cert = Certificate::from_der(root_der_bytes).unwrap();

    let root_tbs = root_cert.tbs_certificate.to_der().unwrap();
    let root_tbs_digest: [u8; 32] = Sha256::digest(root_tbs.as_slice()).into();
    let root_sig_der = root_cert.signature.as_bytes().unwrap();

    // decode signature into (r, s)
    let root_sig = process_sig(root_sig_der);

    // println!("root tbs: {:x?}", root_tbs);
    // println!("sig: {:x?}", root_sig);

    // get proof
    let (image_id, _output, seal) = verify(
        root_tbs_digest,
        root_sig,
        root_der_bytes.to_vec()
    ).unwrap();

    // image_id: [194, 21, 109, 235, 1, 169, 108, 160, 120, 19, 109, 161, 132, 3, 137, 247, 33, 214, 159, 202, 194, 231, 231, 232, 220, 92, 169, 60, 231, 241, 64, 82]
    println!("image_id: {:?}", image_id);
    println!("seal: {:?}", seal);
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