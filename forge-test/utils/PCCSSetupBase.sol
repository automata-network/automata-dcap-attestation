// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/StdJson.sol";
import "solady/utils/JSONParserLib.sol";
import "solady/utils/LibString.sol";

import {CA} from "@automata-network/on-chain-pccs/Common.sol";

import {
    EnclaveIdentityJsonObj,
    EnclaveIdentityHelper,
    IdentityObj
} from "@automata-network/on-chain-pccs/helpers/EnclaveIdentityHelper.sol";
import {TcbInfoJsonObj, FmspcTcbHelper} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";
import {PCKHelper} from "@automata-network/on-chain-pccs/helpers/PCKHelper.sol";
import {X509CRLHelper} from "@automata-network/on-chain-pccs/helpers/X509CRLHelper.sol";

import {AutomataFmspcTcbDao} from "@automata-network/on-chain-pccs/automata_pccs/AutomataFmspcTcbDao.sol";
import {AutomataEnclaveIdentityDao} from "@automata-network/on-chain-pccs/automata_pccs/AutomataEnclaveIdentityDao.sol";
import {AutomataPcsDao} from "@automata-network/on-chain-pccs/automata_pccs/AutomataPcsDao.sol";
import {AutomataPckDao} from "@automata-network/on-chain-pccs/automata_pccs/AutomataPckDao.sol";
import {AutomataDaoStorage} from "@automata-network/on-chain-pccs/automata_pccs/shared/AutomataDaoStorage.sol";

import "../../contracts/PCCSRouter.sol";

abstract contract PCCSSetupBase is Test {
    using JSONParserLib for JSONParserLib.Item;
    using LibString for string;

    EnclaveIdentityHelper public enclaveIdHelper;
    FmspcTcbHelper public tcbHelper;
    PCKHelper public x509;
    X509CRLHelper public x509Crl;

    AutomataPcsDao pcsDao;
    AutomataPckDao pckDao;
    AutomataFmspcTcbDao fmspcTcbDao;
    AutomataEnclaveIdentityDao enclaveIdDao;
    AutomataDaoStorage pccsStorage;
    address P256_VERIFIER;

    address internal constant admin = address(1);

    bytes constant tcbDer =
        hex"3082028b30820232a00302010202147e3882d5fb55294a40498e458403e91491bdf455300a06082a8648ce3d0403023068311a301806035504030c11496e74656c2053475820526f6f74204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553301e170d3138303532313130353031305a170d3235303532313130353031305a306c311e301c06035504030c15496e74656c2053475820544342205369676e696e67311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d0301070342000443451bcc73c9d5917caf766e61af3fe98087dd4f13257b261e851897799dd13d6811fb47713803bb9bae587fccddc2e31be9a28b86962acc6daf96da58eeca96a381b53081b2301f0603551d2304183016801422650cd65a9d3489f383b49552bf501b392706ac30520603551d1f044b30493047a045a043864168747470733a2f2f6365727469666963617465732e7472757374656473657276696365732e696e74656c2e636f6d2f496e74656c534758526f6f7443412e646572301d0603551d0e041604147e3882d5fb55294a40498e458403e91491bdf455300e0603551d0f0101ff0404030206c0300c0603551d130101ff04023000300a06082a8648ce3d040302034700304402201f42f3038037f226c43b46002576e3a29caa36a064e47493272dc81aec1862550220237ed6eb346b0653c607db5d5d46260da0f3eed7d669ff37bc26686e8c1d2807";
    bytes constant rootCaDer =
        hex"3082028f30820234a003020102021422650cd65a9d3489f383b49552bf501b392706ac300a06082a8648ce3d0403023068311a301806035504030c11496e74656c2053475820526f6f74204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553301e170d3138303532313130343531305a170d3439313233313233353935395a3068311a301806035504030c11496e74656c2053475820526f6f74204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d030107034200040ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394a381bb3081b8301f0603551d2304183016801422650cd65a9d3489f383b49552bf501b392706ac30520603551d1f044b30493047a045a043864168747470733a2f2f6365727469666963617465732e7472757374656473657276696365732e696e74656c2e636f6d2f496e74656c534758526f6f7443412e646572301d0603551d0e0416041422650cd65a9d3489f383b49552bf501b392706ac300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff020101300a06082a8648ce3d0403020349003046022100e5bfe50911f92f428920dc368a302ee3d12ec5867ff622ec6497f78060c13c20022100e09d25ac7a0cb3e5e8e68fec5fa3bd416c47440bd950639d450edcbea4576aa2";
    bytes constant platformDer =
        hex"308202963082023da003020102021500956f5dcdbd1be1e94049c9d4f433ce01570bde54300a06082a8648ce3d0403023068311a301806035504030c11496e74656c2053475820526f6f74204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553301e170d3138303532313130353031305a170d3333303532313130353031305a30703122302006035504030c19496e74656c205347582050434b20506c6174666f726d204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d0301070342000435207feeddb595748ed82bb3a71c3be1e241ef61320c6816e6b5c2b71dad5532eaea12a4eb3f948916429ea47ba6c3af82a15e4b19664e52657939a2d96633dea381bb3081b8301f0603551d2304183016801422650cd65a9d3489f383b49552bf501b392706ac30520603551d1f044b30493047a045a043864168747470733a2f2f6365727469666963617465732e7472757374656473657276696365732e696e74656c2e636f6d2f496e74656c534758526f6f7443412e646572301d0603551d0e04160414956f5dcdbd1be1e94049c9d4f433ce01570bde54300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff020100300a06082a8648ce3d040302034700304402205ec5648b4c3e8ba558196dd417fdb6b9a5ded182438f551e9c0f938c3d5a8b970220261bd520260f9c647d3569be8e14a32892631ac358b994478088f4d2b27cf37e";

    bytes constant rootCrlDer =
        hex"308201223081c8020101300a06082a8648ce3d0403023068311a301806035504030c11496e74656c2053475820526f6f74204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553170d3234303332303139313933305a170d3235303430333139313933305aa02f302d300a0603551d140403020101301f0603551d2304183016801422650cd65a9d3489f383b49552bf501b392706ac300a06082a8648ce3d0403020349003046022100e7606fef2da68785a0c39bc34ac344c9e2d6ed4b0223e79a6c6297d421b73784022100fc1587aece4296d5e9370fd6a444a72d03c598cb21dc8104c55b127b766ea82b";

    function setUp() public virtual {
        // pinned June 27th,2024 2pm UTC
        // comment this line out if you are replacing sampleQuote with your own
        // this line is needed to bypass expiry reverts for stale quotes
        vm.warp(1719496800);

        vm.deal(admin, 100 ether);

        vm.startPrank(admin);

        _deployP256();

        enclaveIdHelper = new EnclaveIdentityHelper();
        tcbHelper = new FmspcTcbHelper();
        x509 = new PCKHelper();
        x509Crl = new X509CRLHelper();

        pccsStorage = new AutomataDaoStorage(admin);
        pcsDao = new AutomataPcsDao(address(pccsStorage), P256_VERIFIER, address(x509), address(x509Crl));
        pckDao =
            new AutomataPckDao(address(pccsStorage), P256_VERIFIER, address(pcsDao), address(x509), address(x509Crl));
        enclaveIdDao = new AutomataEnclaveIdentityDao(
            address(pccsStorage), P256_VERIFIER, address(pcsDao), address(enclaveIdHelper), address(x509), address(x509Crl)
        );
        fmspcTcbDao = new AutomataFmspcTcbDao(
            address(pccsStorage), P256_VERIFIER, address(pcsDao), address(tcbHelper), address(x509), address(x509Crl)
        );

        pccsStorage.grantDao(address(pcsDao));
        pccsStorage.grantDao(address(pckDao));
        pccsStorage.grantDao(address(fmspcTcbDao));
        pccsStorage.grantDao(address(enclaveIdDao));

        vm.stopPrank();
    }

    function setupPccsRouter(address owner) internal returns (PCCSRouter pccsRouter) {
        pccsRouter = new PCCSRouter(
            owner,
            address(enclaveIdDao),
            address(fmspcTcbDao),
            address(pcsDao),
            address(pckDao),
            address(x509),
            address(x509Crl),
            address(tcbHelper)
        );

        // allow PCCS Router to read collaterals from the storage
        pccsStorage.setCallerAuthorization(address(pccsRouter), true);
    }

    function pcsDaoUpserts() internal {
        // upsert rootca
        pcsDao.upsertPcsCertificates(CA.ROOT, rootCaDer);

        // upsert tcb signing ca
        pcsDao.upsertPcsCertificates(CA.SIGNING, tcbDer);

        // upsert Platform intermediate CA
        pcsDao.upsertPcsCertificates(CA.PLATFORM, platformDer);

        // upsert rootca crl
        pcsDao.upsertRootCACrl(rootCrlDer);
    }

    function qeIdDaoUpsert(uint256 quoteVersion, string memory path) internal {
        EnclaveIdentityJsonObj memory identityJson = _readIdentityJson(path);
        (IdentityObj memory identity,) = enclaveIdHelper.parseIdentityString(identityJson.identityStr);
        enclaveIdDao.upsertEnclaveIdentity(uint256(identity.id), quoteVersion, identityJson);
    }

    function fmspcTcbDaoUpsert(string memory path) internal {
        TcbInfoJsonObj memory tcbInfoJson = _readTcbInfoJson(path);
        fmspcTcbDao.upsertFmspcTcb(tcbInfoJson);
    }

    function _readTcbInfoJson(string memory tcbInfoPath) private view returns (TcbInfoJsonObj memory tcbInfoJson) {
        string memory inputFile = string.concat(vm.projectRoot(), tcbInfoPath);
        string memory tcbInfoData = vm.readFile(inputFile);

        // use Solady JSONParserLib to get the stringified JSON object
        // since stdJson.readString() method does not accept JSON-objects as a valid string
        JSONParserLib.Item memory root = JSONParserLib.parse(tcbInfoData);
        JSONParserLib.Item[] memory tcbInfoObj = root.children();
        for (uint256 i = 0; i < root.size(); i++) {
            JSONParserLib.Item memory current = tcbInfoObj[i];
            string memory decodedKey = JSONParserLib.decodeString(current.key());
            if (decodedKey.eq("tcbInfo")) {
                tcbInfoJson.tcbInfoStr = current.value();
            }
        }

        // Solady JSONParserLib does not provide a method where I can convert a hexstring to bytes
        // i am sad
        tcbInfoJson.signature = stdJson.readBytes(tcbInfoData, ".signature");
    }

    function _readIdentityJson(string memory idPath)
        private
        view
        returns (EnclaveIdentityJsonObj memory identityJson)
    {
        string memory inputFile = string.concat(vm.projectRoot(), idPath);
        string memory idData = vm.readFile(inputFile);

        // use Solady JSONParserLib to get the stringified JSON object
        // since stdJson.readString() method does not accept JSON-objects as a valid string
        JSONParserLib.Item memory root = JSONParserLib.parse(idData);
        JSONParserLib.Item[] memory idObj = root.children();
        for (uint256 i = 0; i < root.size(); i++) {
            JSONParserLib.Item memory current = idObj[i];
            string memory decodedKey = JSONParserLib.decodeString(current.key());
            if (decodedKey.eq("enclaveIdentity")) {
                identityJson.identityStr = current.value();
            }
        }

        // Solady JSONParserLib does not provide a method where I can convert a hexstring to bytes
        // i am sad
        identityJson.signature = stdJson.readBytes(idData, ".signature");
    }

    function _deployP256() private {
        bytes memory txdata =
            hex"00000000000000000000000000000000000000000000000000000000000000006080806040523461001657610dd1908161001c8239f35b600080fdfe60e06040523461001a57610012366100c7565b602081519101f35b600080fd5b6040810190811067ffffffffffffffff82111761003b57604052565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60e0810190811067ffffffffffffffff82111761003b57604052565b90601f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0910116810190811067ffffffffffffffff82111761003b57604052565b60a08103610193578060201161001a57600060409180831161018f578060601161018f578060801161018f5760a01161018c57815182810181811067ffffffffffffffff82111761015f579061013291845260603581526080356020820152833560203584356101ab565b15610156575060ff6001915b5191166020820152602081526101538161001f565b90565b60ff909161013e565b6024837f4e487b710000000000000000000000000000000000000000000000000000000081526041600452fd5b80fd5b5080fd5b5060405160006020820152602081526101538161001f565b909283158015610393575b801561038b575b8015610361575b6103585780519060206101dc818301938451906103bd565b1561034d57604051948186019082825282604088015282606088015260808701527fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f60a08701527fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551958660c082015260c081526102588161006a565b600080928192519060055afa903d15610345573d9167ffffffffffffffff831161031857604051926102b1857fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f8401160185610086565b83523d828585013e5b156102eb57828280518101031261018c5750015190516102e693929185908181890994099151906104eb565b061490565b807f4e487b7100000000000000000000000000000000000000000000000000000000602492526001600452fd5b6024827f4e487b710000000000000000000000000000000000000000000000000000000081526041600452fd5b6060916102ba565b505050505050600090565b50505050600090565b507fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325518310156101c4565b5082156101bd565b507fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325518410156101b6565b7fffffffff00000001000000000000000000000000ffffffffffffffffffffffff90818110801590610466575b8015610455575b61044d577f5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b8282818080957fffffffff00000001000000000000000000000000fffffffffffffffffffffffc0991818180090908089180091490565b505050600090565b50801580156103f1575082156103f1565b50818310156103ea565b7f800000000000000000000000000000000000000000000000000000000000000081146104bc577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0190565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b909192608052600091600160a05260a05193600092811580610718575b61034d57610516838261073d565b95909460ff60c05260005b600060c05112156106ef575b60a05181036106a1575050507f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5957f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2969594939291965b600060c05112156105c7575050505050507fffffffff00000001000000000000000000000000ffffffffffffffffffffffff91506105c260a051610ca2565b900990565b956105d9929394959660a05191610a98565b9097929181928960a0528192819a6105f66080518960c051610722565b61060160c051610470565b60c0528061061b5750505050505b96959493929196610583565b969b5061067b96939550919350916001810361068857507f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5937f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29693610952565b979297919060a05261060f565b6002036106985786938a93610952565b88938893610952565b600281036106ba57505050829581959493929196610583565b9197917ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd0161060f575095508495849661060f565b506106ff6080518560c051610722565b8061070b60c051610470565b60c052156105215761052d565b5060805115610508565b91906002600192841c831b16921c1681018091116104bc5790565b8015806107ab575b6107635761075f91610756916107b3565b92919091610c42565b9091565b50507f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296907f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f590565b508115610745565b919082158061094a575b1561080f57507f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29691507f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5906001908190565b7fb01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a917fffffffff00000001000000000000000000000000ffffffffffffffffffffffff808481600186090894817f94e82e0c1ed3bdb90743191a9c5bbf0d88fc827fd214cc5f0b5ec6ba27673d6981600184090893841561091b575050808084800993840994818460010994828088600109957f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29609918784038481116104bc5784908180867fffffffff00000001000000000000000000000000fffffffffffffffffffffffd0991818580090808978885038581116104bc578580949281930994080908935b93929190565b9350935050921560001461093b5761093291610b6d565b91939092610915565b50506000806000926000610915565b5080156107bd565b91949592939095811580610a90575b15610991575050831580610989575b61097a5793929190565b50600093508392508291508190565b508215610970565b85919294951580610a88575b610a78577fffffffff00000001000000000000000000000000ffffffffffffffffffffffff968703918783116104bc5787838189850908938689038981116104bc5789908184840908928315610a5d575050818880959493928180848196099b8c9485099b8c920999099609918784038481116104bc5784908180867fffffffff00000001000000000000000000000000fffffffffffffffffffffffd0991818580090808978885038581116104bc578580949281930994080908929190565b965096505050509093501560001461093b5761093291610b6d565b9550509150915091906001908190565b50851561099d565b508015610961565b939092821580610b65575b61097a577fffffffff00000001000000000000000000000000ffffffffffffffffffffffff908185600209948280878009809709948380888a0998818080808680097fffffffff00000001000000000000000000000000fffffffffffffffffffffffc099280096003090884808a7fffffffff00000001000000000000000000000000fffffffffffffffffffffffd09818380090898898603918683116104bc57888703908782116104bc578780969481809681950994089009089609930990565b508015610aa3565b919091801580610c3a575b610c2d577fffffffff00000001000000000000000000000000ffffffffffffffffffffffff90818460020991808084800980940991817fffffffff00000001000000000000000000000000fffffffffffffffffffffffc81808088860994800960030908958280837fffffffff00000001000000000000000000000000fffffffffffffffffffffffd09818980090896878403918483116104bc57858503928584116104bc5785809492819309940890090892565b5060009150819081908190565b508215610b78565b909392821580610c9a575b610c8d57610c5a90610ca2565b9182917fffffffff00000001000000000000000000000000ffffffffffffffffffffffff80809581940980099009930990565b5050509050600090600090565b508015610c4d565b604051906020918281019183835283604083015283606083015260808201527fffffffff00000001000000000000000000000000fffffffffffffffffffffffd60a08201527fffffffff00000001000000000000000000000000ffffffffffffffffffffffff60c082015260c08152610d1a8161006a565b600080928192519060055afa903d15610d93573d9167ffffffffffffffff83116103185760405192610d73857fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f8401160185610086565b83523d828585013e5b156102eb57828280518101031261018c5750015190565b606091610d7c56fea2646970667358221220fa55558b04ced380e93d0a46be01bb895ff30f015c50c516e898c341cd0a230264736f6c63430008150033";
        (bool succ,) = address(0x4e59b44847b379578588920cA78FbF26c0B4956C).call(txdata);
        require(succ, "Failed to deploy P256");

        // check code
        P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
        uint256 codesize = P256_VERIFIER.code.length;
        require(codesize > 0, "P256 deployed to the wrong address");
    }
}
