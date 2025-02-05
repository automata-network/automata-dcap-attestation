const fs = require('fs');
const { AbiCoder } = require('ethers'); 

const X509_FOOTER = '-----END CERTIFICATE-----';
const X509_CRL_FOOTER = '-----END X509 CRL-----';

function convertPemToDerHex(pemStr) {
    const pemLines = pemStr.split('\n');
    const contentArr = pemLines.slice(1, pemLines.length - 1);
    const contentPem = contentArr.join();
    return Buffer.from(contentPem, 'base64').toString('hex');
}

function convertDerHexToPem(derHex) {
    const derBuffer = Buffer.from(derHex, 'hex');
    return Buffer.from(derBuffer).toString('base64');
}

function splitPemCertchain(pem) {
    let pemArr = [];
    const pemLines = pem.split('\n');
    let singleton = [];
    for (line of pemLines) {
        singleton.push(line);
        if (line === X509_FOOTER || line === X509_CRL_FOOTER) {
            let joint = singleton.join('\n');
            pemArr.push(joint);
            singleton = [];
        }
    }
    return {
        pemArr: pemArr,
        count: pemArr.length
    };
}

/// The following command converts a PEM (can be an individual certificate or a certificate chain) to DER
/// node x509base64.js --decode <pem-path>
/// The following command converts the returned DER-encoded tuple to an array of Base64 encoded string
/// node x509base64.js --encode <solidity-returned-data>
/// each hexstrings are separated by a space
function main() {
    const flag = process.argv[2];
    if (flag === '--decode' || flag === '-d') {
        const path = process.argv[3];
        if (!path) {
            console.error("Missing PEM path");
            process.exit(1);
        }
        const pemString = fs.readFileSync(path, 'utf8');
        const res = splitPemCertchain(pemString);
        for (let i = 0; i < res.count; i++) {
            console.log(`=== Printing DER ${i + 1} of ${res.count} ===`);
            console.log(convertPemToDerHex(res.pemArr[i]));
            console.log('\n');
        }
    } else if (flag === '--encode' || flag === '-e') {
        const data = process.argv[3];
        const derArr = AbiCoder.defaultAbiCoder().decode([
            'bytes', 'bytes'
        ], data);
        for (let i = 0; i < 2; i++) {
            console.log(`=== Printing Base64 ${i + 1} of 2 ===`);
            console.log(convertDerHexToPem(derArr[i].substring(2))); // remove prefix
            console.log('\n');
        }
    } else {
        console.error("Unknown or missing instruction");
        process.exit(1);
    }
}

main();

module.exports = {
    convertDerHexToPem: convertDerHexToPem,
    convertPemToDerHex: convertPemToDerHex,
    splitPemCertchain: splitPemCertchain
};