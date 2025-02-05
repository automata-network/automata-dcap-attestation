const ethers = require('ethers');
const fs = require('fs');
const { abi: EnclaveIdentityABI } = require('./abi/EnclaveIdentityDao.json');

const enclaveIdentityDaoInterface = new ethers.Interface(EnclaveIdentityABI);

function checkPrefix(challenge) {
    let prefixed = '';
    if (challenge.substring(0, 2) !== '0x') {
        prefixed = '0x' + challenge;
    } else {
        prefixed = challenge;
    }
    return prefixed.toLowerCase();
}

function upsertEnclaveIdentity(id, version, enclaveIdentity, signature) {
    const enclaveIdentityObj = {
        identityStr: JSON.stringify(enclaveIdentity),
        signature: checkPrefix(signature)
    };
    return [
        "upsertEnclaveIdentity()", id, version, enclaveIdentityObj
    ]
}

function parseEnclaveIdentity(data) {
    const getEnclaveIdentityFragment = enclaveIdentityDaoInterface.fragments.find((f) => {
        return f.name === "getEnclaveIdentity";
    });
    return enclaveIdentityDaoInterface.decodeFunctionResult(getEnclaveIdentityFragment, data);
}

/// To upsert, run the command: node identity.js -u <id> <version> <path>
/// The upsert commmand generates the individual function arguments to be passed to the contract.
/// To parse the returned identity, node identity.js -p <solidity-returned-data>
/// The get command retrieves the Identity from the contract and returns the output as a JSON
/// To save a local copy of the JSON file, append the -s flag at the end.
function main() {
    const flag = process.argv[2];
    if (flag === '-u' || flag === '--upsert') {
        const id = process.argv[3];
        if (!id || isNaN(id)) {
            console.error("Missing or invalid ID");
            process.exit(1);
        }
        const version = process.argv[4];
        if (!version || isNaN(version)) {
            console.error("Missing or invalid version");
            process.exit(1);
        }
        const path = process.argv[5];
        const { enclaveIdentity, signature } = require(path);
        if (!path) {
            console.error("Missing Identity Path");
            process.exit(1);
        } 
        console.log(upsertEnclaveIdentity(id, version, enclaveIdentity, signature));
    } else if (flag === '-p' || flag === '--parse') {
        const data = process.argv[3];
        if (!data) {
            console.error("Missing data");
            process.exit(1);
        }
        const res = parseEnclaveIdentity(data);
        const identity = {
            enclaveIdentity: JSON.parse(res[0][0]),
            signature: res[0][1].substring(2) // remove the prefix
        }
        const identityJsonStr = JSON.stringify(identity);
        console.log(identityJsonStr);
        
        // save local copy
        const save = process.argv[4];
        if (save === '-s' || save === '--save') {
            fs.writeFileSync(`./${new Date(Date.now()).toISOString()}-identity.json`, identityJsonStr);
        }
    } else {
        console.error("Unknown or missing instruction");
        process.exit(1);
    }
}

main();