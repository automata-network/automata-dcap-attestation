const ethers = require('ethers');
const fs = require('fs');
const { abi: FmspcTcbABI } = require('./abi/FmspcTcbDao.json');

const fmspcTcbDaoInterface = new ethers.Interface(FmspcTcbABI);

function checkPrefix(challenge) {
    let prefixed = '';
    if (challenge.substring(0, 2) !== '0x') {
        prefixed = '0x' + challenge;
    } else {
        prefixed = challenge;
    }
    return prefixed.toLowerCase();
}

function upsertFmspcTcb(tcbInfo, signature) {
    const tcbInfoObj = {
        tcbInfoStr: JSON.stringify(tcbInfo),
        signature: checkPrefix(signature)
    };
    return [
        "upsertFmspcTcb()", tcbInfoObj
    ]
}

function parseTcbInfo(data) {
    const getTcbInfoFragment = fmspcTcbDaoInterface.fragments.find((f) => {
        return f.name === "getTcbInfo";
    });
    return fmspcTcbDaoInterface.decodeFunctionResult(getTcbInfoFragment, data);
}

/// To upsert, run the command: node tcbinfo.js -u <path>
/// The upsert commmand generates the individual function arguments to be passed to the contract.
/// To parse the returned TCBInfo, node tcbinfo.js -p <solidity-returned-data>
/// The get command retrieves the TCBInfo from the contract and returns the output as a JSON
/// To save a local copy of the JSON file, append the -s flag at the end.
function main() {
    const flag = process.argv[2];
    if (flag === '-u' || flag === '--upsert') {
        const path = process.argv[3];
        const { tcbInfo, signature } = require(path);
        if (!path) {
            console.error("Missing TCBInfo Path");
            process.exit(1);
        } 
        console.log(upsertFmspcTcb(tcbInfo, signature));
    } else if (flag === '-p' || flag === '--parse') {
        const data = process.argv[3];
        if (!data) {
            console.error("Missing data");
            process.exit(1);
        }
        const res = parseTcbInfo(data);
        const tcbInfo = {
            tcbInfo: JSON.parse(res[0][0]),
            signature: res[0][1].substring(2) // remove the prefix
        }
        const tcbInfoJsonStr = JSON.stringify(tcbInfo);
        console.log(tcbInfoJsonStr);
        
        // save local copy
        const save = process.argv[4];
        if (save === '-s' || save === '--save') {
            fs.writeFileSync(`./${new Date(Date.now()).toISOString()}-tcb.json`, tcbInfoJsonStr);
        }
    } else {
        console.error("Unknown or missing instruction");
        process.exit(1);
    }
}

main();