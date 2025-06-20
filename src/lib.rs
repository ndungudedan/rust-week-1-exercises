// Implement extract_tx_version function below
pub fn extract_tx_version(raw_tx_hex: &str) -> Result<u32, String> {
    let bytes = hex::decode(raw_tx_hex).map_err(|e| format!("Hex decode error: {}", e))?;
    if bytes.len() < 4 {
        return Err("Transaction data too short".to_string());
    }
    let version_bytes = bytes[..4]
        .try_into()
        .map_err(|_| "Failed to extract version bytes".to_string())?;
    let version = u32::from_le_bytes(version_bytes);
    println!("Version: {}", version);

    let input_count = decode_variable_int(&bytes[4..])
        .map_err(|e| format!("Failed to decode input count: {}", e))?;
    println!("Input count: {}", input_count);

    Ok(version)
}

pub fn decode_variable_int(bytes: &[u8]) -> Result<u64, String> {
    println!("Decoding variable int from bytes: {:?}", bytes);
    if bytes.is_empty() {
        return Err("No bytes to decode".to_string());
    }

    if bytes.starts_with(b"fd") {
        if bytes.len() < 4 {
            return Err("Not enough bytes for fd".to_string());
        }
        let mut val = [0u8; 8];
        val[0..2].copy_from_slice(&bytes[2..4]);
        Ok(u64::from_le_bytes(val))
    } else if bytes.starts_with(b"fe") {
        if bytes.len() < 6 {
            return Err("Not enough bytes for fe".to_string());
        }
        let mut val = [0u8; 8];
        val[0..4].copy_from_slice(&bytes[2..6]);
        Ok(u64::from_le_bytes(val))
    } else if bytes.starts_with(b"ff") {
        if bytes.len() < 10 {
            return Err("Not enough bytes for ff".to_string());
        }
        let mut val = [0u8; 8];
        val[0..8].copy_from_slice(&bytes[2..10]);
        Ok(u64::from_le_bytes(val))
    } else {
        let val = bytes.first().ok_or("Failed to decode variable int".to_string())?;
        println!("Decoding variable int: {:?}", val);
        Ok(*val as u64)
    }
}
