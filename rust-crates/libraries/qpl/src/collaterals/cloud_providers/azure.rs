use crate::types::*;
use libloading::{Library, Symbol};
use std::ffi::c_char;

const AZURE_DCAP_CLIENT_SO: &str = "libdcap_az_client.so";

pub fn az_dcap_sgx_ql_get_quote_config(
    p_pck_cert_id: *const SgxQlPckCertId,
    pp_quote_config: *mut *mut SgxQlConfig,
) -> Quote3Error {
    unsafe {
        let lib = Library::new(AZURE_DCAP_CLIENT_SO).unwrap();
        let func: Symbol<
            unsafe extern "C" fn(*const SgxQlPckCertId, *mut *mut SgxQlConfig) -> Quote3Error,
        > = lib.get(b"sgx_ql_get_quote_config").unwrap();
        func(p_pck_cert_id, pp_quote_config)
    }
}

pub fn az_dcap_sgx_ql_free_quote_config(p_quote_config: *mut SgxQlConfig) -> Quote3Error {
    unsafe {
        let lib = Library::new(AZURE_DCAP_CLIENT_SO).unwrap();
        let func: Symbol<unsafe extern "C" fn(*mut SgxQlConfig) -> Quote3Error> =
            lib.get(b"sgx_ql_free_quote_config").unwrap();
        func(p_quote_config)
    }
}

pub fn az_dcap_sgx_ql_get_quote_verification_collateral(
    fmspc: *const u8,
    fmspc_size: u16,
    pck_ca: *const c_char,
    pp_quote_collateral: *mut *mut SgxQlQveCollateral,
) -> Quote3Error {
    unsafe {
        let lib = Library::new(AZURE_DCAP_CLIENT_SO).unwrap();
        let func: Symbol<
            unsafe extern "C" fn(
                *const u8,
                u16,
                *const c_char,
                *mut *mut SgxQlQveCollateral,
            ) -> Quote3Error,
        > = lib
            .get(b"sgx_ql_get_quote_verification_collateral")
            .unwrap();
        func(fmspc, fmspc_size, pck_ca, pp_quote_collateral)
    }
}

pub fn az_dcap_sgx_ql_free_quote_verification_collateral(
    p_quote_collateral: *mut SgxQlQveCollateral,
) -> Quote3Error {
    unsafe {
        let lib = Library::new(AZURE_DCAP_CLIENT_SO).unwrap();
        let func: Symbol<unsafe extern "C" fn(*mut SgxQlQveCollateral) -> Quote3Error> = lib
            .get(b"sgx_ql_free_quote_verification_collateral")
            .unwrap();
        func(p_quote_collateral)
    }
}

pub fn az_dcap_tdx_ql_get_quote_verification_collateral(
    fmspc: *const u8,
    fmspc_size: u16,
    pck_ca: *const c_char,
    pp_quote_collateral: *mut *mut SgxQlQveCollateral,
) -> Quote3Error {
    unsafe {
        let lib = Library::new(AZURE_DCAP_CLIENT_SO).unwrap();
        let func: Symbol<
            unsafe extern "C" fn(
                *const u8,
                u16,
                *const c_char,
                *mut *mut SgxQlQveCollateral,
            ) -> Quote3Error,
        > = lib
            .get(b"tdx_ql_get_quote_verification_collateral")
            .unwrap();
        func(fmspc, fmspc_size, pck_ca, pp_quote_collateral)
    }
}

pub fn az_dcap_tdx_ql_free_quote_verification_collateral(
    p_quote_collateral: *mut SgxQlQveCollateral,
) -> Quote3Error {
    unsafe {
        let lib = Library::new(AZURE_DCAP_CLIENT_SO).unwrap();
        let func: Symbol<unsafe extern "C" fn(*mut SgxQlQveCollateral) -> Quote3Error> = lib
            .get(b"tdx_ql_free_quote_verification_collateral")
            .unwrap();
        func(p_quote_collateral)
    }
}

pub fn az_dcap_sgx_ql_get_qve_identity(
    pp_qve_identity: *mut *mut c_char,
    p_qve_identity_size: *mut u32,
    pp_qve_identity_issuer_chain: *mut *mut c_char,
    p_qve_identity_issuer_chain_size: *mut u32,
) -> Quote3Error {
    unsafe {
        let lib = Library::new(AZURE_DCAP_CLIENT_SO).unwrap();
        let func: Symbol<
            unsafe extern "C" fn(
                *mut *mut c_char,
                *mut u32,
                *mut *mut c_char,
                *mut u32,
            ) -> Quote3Error,
        > = lib.get(b"sgx_ql_get_qve_identity").unwrap();
        func(
            pp_qve_identity,
            p_qve_identity_size,
            pp_qve_identity_issuer_chain,
            p_qve_identity_issuer_chain_size,
        )
    }
}

pub fn az_dcap_sgx_ql_free_qve_identity(
    p_qve_identity: *mut c_char,
    p_qve_identity_issuer_chain: *mut c_char,
) -> Quote3Error {
    unsafe {
        let lib = Library::new(AZURE_DCAP_CLIENT_SO).unwrap();
        let func: Symbol<unsafe extern "C" fn(*mut c_char, *mut c_char) -> Quote3Error> =
            lib.get(b"sgx_ql_free_qve_identity").unwrap();
        func(p_qve_identity, p_qve_identity_issuer_chain)
    }
}

pub fn az_dcap_sgx_ql_get_root_ca_crl(
    pp_root_ca_crl: *mut *mut c_char,
    p_root_ca_crl_size: *mut u16,
) -> Quote3Error {
    unsafe {
        let lib = Library::new(AZURE_DCAP_CLIENT_SO).unwrap();
        let func: Symbol<unsafe extern "C" fn(*mut *mut c_char, *mut u16) -> Quote3Error> =
            lib.get(b"sgx_ql_get_root_ca_crl").unwrap();
        func(pp_root_ca_crl, p_root_ca_crl_size)
    }
}

pub fn az_dcap_sgx_ql_free_root_ca_crl(p_root_ca_crl: *mut c_char) -> Quote3Error {
    unsafe {
        let lib = Library::new(AZURE_DCAP_CLIENT_SO).unwrap();
        let func: Symbol<unsafe extern "C" fn(*mut c_char) -> Quote3Error> =
            lib.get(b"sgx_ql_free_root_ca_crl").unwrap();
        func(p_root_ca_crl)
    }
}
