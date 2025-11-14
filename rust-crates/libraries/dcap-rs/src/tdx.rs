use crate::types::enclave_identity::QeTcbStatus;
use crate::types::report::{Td10ReportBody, Td15ReportBody};
use crate::types::tcb_info::{TcbInfo, TcbStatus, TdxModuleIdentity};

pub fn verify_tdx_module(
    tcb_info: &TcbInfo,
    td_report: &Td10ReportBody,
) -> anyhow::Result<TcbStatus> {
    if tcb_info.tdx_module.is_none() {
        return Err(anyhow::anyhow!("no tdx module found in tcb info"));
    }

    if tcb_info.tdx_module_identities.is_none() {
        return Err(anyhow::anyhow!(
            "no tdx module identities found in tcb info"
        ));
    }

    let (tdx_module_isv_svn, tdx_module_version) =
        (td_report.tee_tcb_svn[0], td_report.tee_tcb_svn[1]);

    let tdx_module_identity =
        find_tdx_module_identity(tdx_module_version, tcb_info).ok_or(anyhow::anyhow!(
            "no tdx module identity found for version {}",
            tdx_module_version
        ))?;

    // Get the TDX module reference based on version
    let (mrsigner, attributes) = if tdx_module_version > 0 {
        (
            &tdx_module_identity.mrsigner,
            &tdx_module_identity.attributes,
        )
    } else {
        let tdx_module = tcb_info.tdx_module.as_ref().unwrap();
        (&tdx_module.mrsigner, &tdx_module.attributes)
    };

    // Convert mrsigner and attributes to the appropriate type
    let mrsigner_bytes: [u8; 48] = hex::decode(mrsigner).unwrap().try_into().unwrap();
    let attributes_bytes: [u8; 8] = hex::decode(attributes).unwrap().try_into().unwrap();

    // Check for mismatches with a single validation
    if mrsigner_bytes != td_report.mr_signer_seam {
        return Err(anyhow::anyhow!(
            "mrsigner mismatch between tdx module identity and tdx quote body"
        ));
    }

    if attributes_bytes != td_report.seam_attributes {
        return Err(anyhow::anyhow!(
            "attributes mismatch between tdx module identity and tdx quote body"
        ));
    }

    let tcb_level = tdx_module_identity
        .tcb_levels
        .iter()
        .find(|level| level.in_tcb_level(tdx_module_isv_svn))
        .ok_or(anyhow::anyhow!(
            "no tcb level found for tdx module identity within tdx module levels"
        ))?;

    Ok(tcb_level.tcb_status)
}

/// <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/stable/Src/AttestationLibrary/src/Verifiers/Checks/TDRelaunchCheck.cpp>
/// Returns a tuple of (tdx_relaunch_needed, tdx_relaunch_and_configuration_needed)
pub fn check_for_relaunch(
    tcb_info: &TcbInfo,
    td_report: &Td15ReportBody,
    qe_tcb_status: QeTcbStatus,
    sgx_tcb_status: TcbStatus,
    tdx_tcb_status: TcbStatus,
    tdx_module_tcb_status: TcbStatus,
) -> (bool, bool) {
    let mut relaunch_needed = false;
    let mut configuration_needed = false;

    if (qe_tcb_status != QeTcbStatus::OutOfDate
        || qe_tcb_status != QeTcbStatus::OutOfDateConfigurationNeeded)
        && !is_out_of_date(sgx_tcb_status)
        && is_out_of_date(tdx_tcb_status)
        && is_out_of_date(tdx_module_tcb_status)
    {
        configuration_needed =
            is_configuration_needed(sgx_tcb_status) || is_configuration_needed(tdx_tcb_status);

        let latest_tcb_level_tdx_svns = tcb_info
            .tcb_levels
            .first()
            .unwrap()
            .tcb
            .tdx_tcb_components()
            .unwrap();
        let tdx_module_version = td_report.tee_tcb_svn2[1];
        let tdx_module_svns = td_report.tee_tcb_svn2;

        if tdx_module_version == 0 {
            if tdx_module_svns[0] >= latest_tcb_level_tdx_svns[0]
                && tdx_module_svns[2] >= latest_tcb_level_tdx_svns[2]
            {
                relaunch_needed = true;
            }
        } else {
            let tdx_module_identity =
                find_tdx_module_identity(tdx_module_version, tcb_info).unwrap();
            if tdx_module_svns[0] >= tdx_module_identity.tcb_levels[0].tcb.isvsvn
                && tdx_module_svns[2] >= latest_tcb_level_tdx_svns[2]
            {
                relaunch_needed = true;
            }
        }
    }

    (relaunch_needed, configuration_needed)
}

fn find_tdx_module_identity(
    tdx_module_version: u8,
    tcb_info: &TcbInfo,
) -> Option<&TdxModuleIdentity> {
    let tdx_module_identity_id = format!("TDX_{:02x}", tdx_module_version);

    let tdx_module_identity = tcb_info
        .tdx_module_identities
        .as_ref()
        .unwrap()
        .iter()
        .find(|identity| identity.id == tdx_module_identity_id);

    tdx_module_identity
}

fn is_configuration_needed(tcb_status: TcbStatus) -> bool {
    tcb_status == TcbStatus::ConfigurationAndSWHardeningNeeded
        || tcb_status == TcbStatus::ConfigurationNeeded
        || tcb_status == TcbStatus::OutOfDateConfigurationNeeded
}

fn is_out_of_date(tcb_status: TcbStatus) -> bool {
    tcb_status == TcbStatus::OutOfDate || tcb_status == TcbStatus::OutOfDateConfigurationNeeded
}
