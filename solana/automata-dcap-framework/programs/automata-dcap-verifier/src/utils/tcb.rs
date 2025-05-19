pub fn tcb_status_to_string(status: u8) -> String {
    match status {
        0 => "UpToDate".to_string(),
        1 => "OutOfDate".to_string(),
        2 => "ConfigurationNeeded".to_string(),
        3 => "SWHardeningNeeded".to_string(),
        4 => "ConfigurationAndSWHardeningNeeded".to_string(),
        5 => "OutOfDateConfigurationNeeded".to_string(),
        6 => "Revoked".to_string(),
        _ => "".to_string(),
    }
}

pub fn qe_tcb_status_to_string(status: u8) -> String {
    match status {
        0 => "UpToDate".to_string(),
        1 => "SWHardeningNeeded".to_string(),
        2 => "OutOfDate".to_string(),
        3 => "OutOfDateConfigurationNeeded".to_string(),
        4 => "ConfigurationNeeded".to_string(),
        5 => "ConfigurationAndSWHardeningNeeded".to_string(),
        6 => "Revoked".to_string(),
        _ => "".to_string(),
    }
}