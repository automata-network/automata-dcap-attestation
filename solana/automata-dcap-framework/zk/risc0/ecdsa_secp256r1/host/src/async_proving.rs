use anyhow::Result;
use bonsai_sdk::non_blocking::{Client, SessionId};
use risc0_zkvm::{compute_image_id, sha::Digest, Receipt, VERSION as RISCZERO_VERSION};

pub async fn bonsai_prove_non_blocking(
    elf: &[u8],
    input: &[u8],
    prove_with_snark: bool,
) -> Result<Receipt> {
    let client = Client::from_env(RISCZERO_VERSION)?;

    // Compute the image ID, then upload the ELF if it hasn't been uploaded yet
    let image_id = compute_image_id(elf)?;
    let image_id_string = image_id.to_string();
    client.upload_img(&image_id_string, elf.to_vec()).await?;

    // Prepare the input data and upload it
    let input_data = input.to_vec();
    let input_id = client.upload_input(input_data).await?;

    // Zero assumptions
    let assumptions: Vec<String> = vec![];

    let (stark_session, receipt) =
        get_succinct_receipt(&client, image_id, input_id, assumptions).await?;

    if prove_with_snark {
        // Convert the succinct receipt to a snark receipt
        let snark_receipt = stark_to_snark(&client, stark_session).await?;

        // Verify the snark receipt
        snark_receipt.verify(image_id)?;

        // Return the snark receipt
        Ok(snark_receipt)
    } else {
        Ok(receipt)
    }
}

async fn get_succinct_receipt(
    client: &Client,
    image_id: Digest,
    input_id: String,
    assumptions: Vec<String>,
) -> Result<(SessionId, Receipt)> {
    // Start a session running the prover
    let session = client
        .create_session(image_id.to_string(), input_id, assumptions, false)
        .await
        .expect("Failed to create session");

    let receipt: Receipt;

    loop {
        let res = session.status(&client).await?;
        if res.status == "RUNNING" {
            eprintln!(
                "Current status: {} - state: {} - continue polling...",
                res.status,
                res.state.unwrap_or_default()
            );
            std::thread::sleep(std::time::Duration::from_secs(15));
            continue;
        }
        if res.status == "SUCCEEDED" {
            // Download the receipt, containing the output
            let receipt_url = res
                .receipt_url
                .expect("API error, missing receipt on completed session");

            let receipt_buf = client
                .download(&receipt_url)
                .await
                .expect("Failed to download receipt");
            receipt = bincode::deserialize(&receipt_buf).expect("Failed to deserialize receipt");
            receipt
                .verify(image_id)
                .expect("Failed to verify succinct receipt");
        } else {
            panic!(
                "Workflow exited: {} - | err: {}",
                res.status,
                res.error_msg.unwrap_or_default()
            );
        }
        break;
    }

    Ok((session, receipt))
}

async fn stark_to_snark(client: &Client, stark_session: SessionId) -> Result<Receipt> {
    let snark_session = client.create_snark(stark_session.uuid).await?;

    let snark_receipt: Receipt;
    loop {
        let res = snark_session.status(&client).await?;
        match res.status.as_str() {
            "RUNNING" => {
                eprintln!("Current status: {} - continue polling...", res.status,);
                std::thread::sleep(std::time::Duration::from_secs(15));
                continue;
            }
            "SUCCEEDED" => {
                let receipt_buf = client.download(&res.output.unwrap()).await?;
                snark_receipt = bincode::deserialize(&receipt_buf)?;
                break;
            }
            _ => {
                panic!(
                    "Workflow exited: {} err: {}",
                    res.status,
                    res.error_msg.unwrap_or_default()
                );
            }
        }
    }

    Ok(snark_receipt)
}