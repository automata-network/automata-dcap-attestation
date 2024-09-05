const ethers = require('ethers');
const fs = require('fs');
const { abi: IAttestationABI } = require('./abi/AutomataDcapAttestation.json');

const RPC_URL = "https://1rpc.io/ata/testnet";
const ATTESTATION_ADDR = "0xefE368b17D137E86298eec8EbC5502fb56d27832";

// two ways you may submit a quote:
// Option 1: node index.js -p <insert-path>
// Option 2: node index.js -h <insert-hex>
async function main() {
    // Instantiate the provider and the contract
    const provider = new ethers.JsonRpcProvider(RPC_URL);
    const attestation = new ethers.Contract(ATTESTATION_ADDR, IAttestationABI, provider);

    const flag = process.argv[2];
    if (flag === '-p' || flag === '--path') {
        // enter path relative to pwd
        // i suggest cd to the /js dir, so you can simply provide the following path:
        // ./data/quote.hex, which is the default path if the argument is not provided
        const path = process.argv[3] ? process.argv[3] : './data/quote.hex';
        const quote = _checkPrefix(fs.readFileSync(path, 'utf8'));
        _sendQuote(attestation, quote);
    } else if (flag === '-h' || flag === '--hex') {
        const quote = _checkPrefix(process.argv[3]);
        _sendQuote(attestation, quote);
    } else {
        throw new Error("Unknown option");
    }
}

async function _sendQuote(attestationContract, quote) {
    const output = await attestationContract.verifyAndAttestOnChain.staticCall(quote);
    const deserialized = _deserializeOutput(output);
    console.log(deserialized);
}

function _checkPrefix(hex) {
    let prefixed = '';
    if (hex.substring(0, 2) !== '0x') {
        prefixed = '0x' + hex;
    } else {
        prefixed = hex;
    }
    return prefixed.toLowerCase();
}

function _deserializeOutput(output) {
    const status = output[0];
    const serialized = output[1];

    if (status) {
        const serializedBytes = Buffer.from(serialized.substring(2), 'hex');
        const version = serializedBytes.subarray(0, 2);
        const tee = serializedBytes.subarray(2, 6);
        const tcbStatus = serializedBytes.subarray(6, 7);
        const fmspc = serializedBytes.subarray(7, 13);
        const quoteBody = serializedBytes.subarray(13, serializedBytes.length);

        let teeTypeString = "";
        let tcbStatusString = "";

        const teeHex = tee.toString('hex');
        if (teeHex === "00000000") {
            teeTypeString = "SGX";
        } else if (teeHex === "00000081") {
            teeTypeString = "TDX";
        }

        const tcbStatusEnumIsh = parseInt(tcbStatus.toString('hex'));
        switch (tcbStatusEnumIsh) {
            case 0:
                tcbStatusString = "OK";
                break;
            case 1:
                tcbStatusString = "TCB_SW_HARDENING_NEEDED";
                break;
            case 2:
                tcbStatusString = "TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED";
                break;
            case 3:
                tcbStatusString = "TCB_CONFIGURATION_NEEDED";
                break;
            case 4:
                tcbStatusString = "TCB_OUT_OF_DATE";
                break;
            case 5:
                tcbStatusString = "TCB_OUT_OF_DATE_CONFIGURATION_NEEDED";
                break;
            case 6:
                tcbStatusString = "TCB_REVOKED";
                break;
            default:
                tcbStatusString = "TCB_UNRECOGNIZED";
        }

        return {
            status: status,
            version: parseInt(version.toString('hex')),
            tee: teeTypeString,
            tcbStatus: tcbStatusString,
            fmspc: fmspc.toString('hex'),
            quoteBody: quoteBody.toString('hex')
        }
    } else {
        return {
            status: status,
            reason: ethers.toUtf8String(serialized)
        }
    }
}

main();