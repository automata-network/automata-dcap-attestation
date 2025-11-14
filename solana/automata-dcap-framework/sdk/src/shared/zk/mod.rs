pub mod sp1;
use dcap_p256_zk_lib::InputType;

pub trait RequestProof {
    fn request_p256_proof(
        &self,
    ) -> impl std::future::Future<
        Output = std::result::Result<([u8; 32], Vec<u8>, Vec<u8>), anyhow::Error>,
    >;
}
