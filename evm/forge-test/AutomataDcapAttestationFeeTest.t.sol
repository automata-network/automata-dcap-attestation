// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./utils/PCCSSetupBase.sol";
import "./utils/RiscZeroSetup.sol";

import {AutomataDcapAttestationFee} from "../contracts/AutomataDcapAttestationFee.sol";
import {V3QuoteVerifier} from "../contracts/verifiers/V3QuoteVerifier.sol";
import {V4QuoteVerifier} from "../contracts/verifiers/V4QuoteVerifier.sol";

import {BytesUtils} from "../contracts/utils/BytesUtils.sol";

contract AutomataDcapAttestationFeeTest is PCCSSetupBase, RiscZeroSetup {
    using BytesUtils for bytes;

    uint256 constant EXPECTED_GAS = 5_000_000;
    uint256 constant GAS_PRICE_WEI = 1_000_000_000; // 1 Gwei
    uint16 constant CONFIGURED_BP = 1_000; // 10 %
    uint16 constant MAX_BP = 10_000;

    AutomataDcapAttestationFee attestation;
    PCCSRouter pccsRouter;

    address user = address(69);

    function setUp() public override {
        super.setUp();

        vm.deal(user, 1 ether);
        vm.txGasPrice(GAS_PRICE_WEI);

        vm.startPrank(admin);

        // PCCS Setup
        pccsRouter = setupPccsRouter(admin);
        pcsDaoUpserts();

        // DCAP Contract Deployment
        attestation = new AutomataDcapAttestationFee(admin);

        // Setup Fee Management

        // 10% Fee
        attestation.setBp(CONFIGURED_BP);

        vm.stopPrank();
    }

    function testGetBp() public {
        uint16 bp = attestation.getBp();
        assertEq(bp, CONFIGURED_BP);
    }

    bytes constant platformCrlDer =
        hex"30820a6230820a08020101300a06082a8648ce3d04030230703122302006035504030c19496e74656c205347582050434b20506c6174666f726d204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553170d3234303632373133313733385a170d3234303732373133313733385a30820934303302146fc34e5023e728923435d61aa4b83c618166ad35170d3234303632373133313733385a300c300a0603551d1504030a01013034021500efae6e9715fca13b87e333e8261ed6d990a926ad170d3234303632373133313733385a300c300a0603551d1504030a01013034021500fd608648629cba73078b4d492f4b3ea741ad08cd170d3234303632373133313733385a300c300a0603551d1504030a010130340215008af924184e1d5afddd73c3d63a12f5e8b5737e56170d3234303632373133313733385a300c300a0603551d1504030a01013034021500b1257978cfa9ccdd0759abf8c5ca72fae3a78a9b170d3234303632373133313733385a300c300a0603551d1504030a01013033021474fea614a972be0e2843f2059835811ed872f9b3170d3234303632373133313733385a300c300a0603551d1504030a01013034021500f9c4ef56b3ab48d577e108baedf4bf88014214b9170d3234303632373133313733385a300c300a0603551d1504030a010130330214071de0778f9e5fc4f2878f30d6b07c9a30e6b30b170d3234303632373133313733385a300c300a0603551d1504030a01013034021500cde2424f972cea94ff239937f4d80c25029dd60b170d3234303632373133313733385a300c300a0603551d1504030a0101303302146c3319e5109b64507d3cf1132ce00349ef527319170d3234303632373133313733385a300c300a0603551d1504030a01013034021500df08d756b66a7497f43b5bb58ada04d3f4f7a937170d3234303632373133313733385a300c300a0603551d1504030a01013033021428af485b6cf67e409a39d5cb5aee4598f7a8fa7b170d3234303632373133313733385a300c300a0603551d1504030a01013034021500fb8b2daec092cada8aa9bc4ff2f1c20d0346668c170d3234303632373133313733385a300c300a0603551d1504030a01013034021500cd4850ac52bdcc69a6a6f058c8bc57bbd0b5f864170d3234303632373133313733385a300c300a0603551d1504030a01013034021500994dd3666f5275fb805f95dd02bd50cb2679d8ad170d3234303632373133313733385a300c300a0603551d1504030a0101303302140702136900252274d9035eedf5457462fad0ef4c170d3234303632373133313733385a300c300a0603551d1504030a01013033021461f2bf73e39b4e04aa27d801bd73d24319b5bf80170d3234303632373133313733385a300c300a0603551d1504030a0101303302143992be851b96902eff38959e6c2eff1b0651a4b5170d3234303632373133313733385a300c300a0603551d1504030a010130330214639f139a5040fdcff191e8a4fb1bf086ed603971170d3234303632373133313733385a300c300a0603551d1504030a01013034021500959d533f9249dc1e513544cdc830bf19b7f1f301170d3234303632373133313733385a300c300a0603551d1504030a0101303302140fda43a00b68ea79b7c2deaeac0b498bdfb2af90170d3234303632373133313733385a300c300a0603551d1504030a010130340215009d67753b81e47090aea763fbec4c4549bcdb9933170d3234303632373133313733385a300c300a0603551d1504030a01013033021434bfbb7a1d9c568147e118b614f7b76ed3ef68df170d3234303632373133313733385a300c300a0603551d1504030a0101303402150085d3c9381b77a7e04d119c9e5ad6749ff3ffab87170d3234303632373133313733385a300c300a0603551d1504030a0101303402150093887ca4411e7a923bd1fed2819b2949f201b5b4170d3234303632373133313733385a300c300a0603551d1504030a0101303302142498dc6283930996fd8bf23a37acbe26a3bed457170d3234303632373133313733385a300c300a0603551d1504030a010130340215008a66f1a749488667689cc3903ac54c662b712e73170d3234303632373133313733385a300c300a0603551d1504030a01013034021500afc13610bdd36cb7985d106481a880d3a01fda07170d3234303632373133313733385a300c300a0603551d1504030a01013034021500efe04b2c33d036aac96ca673bf1e9a47b64d5cbb170d3234303632373133313733385a300c300a0603551d1504030a0101303402150083d9ac8d8bb509d1c6c809ad712e8430559ed7f3170d3234303632373133313733385a300c300a0603551d1504030a0101303302147931fd50b5071c1bbfc5b7b6ded8b45b9d8b8529170d3234303632373133313733385a300c300a0603551d1504030a0101303302141fa20e2970bde5d57f7b8ddf8339484e1f1d0823170d3234303632373133313733385a300c300a0603551d1504030a0101303302141e87b2c3b32d8d23e411cef34197b95af0c8adf5170d3234303632373133313733385a300c300a0603551d1504030a010130340215009afd2ee90a473550a167d996911437c7502d1f09170d3234303632373133313733385a300c300a0603551d1504030a0101303302144481b0f11728a13b696d3ea9c770a0b15ec58dda170d3234303632373133313733385a300c300a0603551d1504030a01013034021500a7859f57982ef0e67d37bc8ef2ef5ac835ff1aa9170d3234303632373133313733385a300c300a0603551d1504030a0101303302147ae37748a9f912f4c63ba7ab07c593ce1d1d1181170d3234303632373133313733385a300c300a0603551d1504030a01013033021413884b33269938c195aa170fca75da177538df0b170d3234303632373133313733385a300c300a0603551d1504030a0101303302142c3cc6fe9279db1516d5ce39f2a898cda5a175e1170d3234303632373133313733385a300c300a0603551d1504030a010130330214717948687509234be979e4b7dce6f31bef64b68c170d3234303632373133313733385a300c300a0603551d1504030a010130340215009d76ef2c39c136e8658b6e7396b1d7445a27631f170d3234303632373133313733385a300c300a0603551d1504030a01013034021500c3e025fca995f36f59b48467939e3e34e6361a6f170d3234303632373133313733385a300c300a0603551d1504030a010130340215008c5f6b3257da05b17429e2e61ba965d67330606a170d3234303632373133313733385a300c300a0603551d1504030a01013034021500a17c51722ec1e0c3278fe8bdf052059cbec4e648170d3234303632373133313733385a300c300a0603551d1504030a0101a02f302d300a0603551d140403020101301f0603551d23041830168014956f5dcdbd1be1e94049c9d4f433ce01570bde54300a06082a8648ce3d04030203480030450220020322ffb92ae4bddb43c36c845e51e0f68368b94c82d2ca31345fa774068864022100c3251194239d58d449fec2c5abbbc9a81934f9d205150e0a726e06c29c75cdf9";

    function testTDXQuoteV4OnChainAttestationWithFee() public {
        pcsDao.upsertPckCrl(CA.PLATFORM, platformCrlDer);

        // pinned June 15th,2024 Midnight UTC
        // bypassing expiry errors
        vm.warp(1718409600);

        V4QuoteVerifier quoteVerifier;

        bytes memory sampleQuote =
            hex"040002008100000000000000939a7233f79c4ca9940a0db3957f0607000000000000000000000000000000000000000004010700000000000000000000000000ffc97a88587660fb04e1f7c851300c96ae0b5a463ac46d035d16c2d9f36d0ed1d23775bcbd27deb219e3a3cc2802389500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000e700060000000000935be7742dd89c6a4df6dba8353d89041ae0f052beef993b1e7f4524d3bc57650df20e5582158352e1240b3f1fed55d800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cb10000038e48e64abf8f5611911d4a4336e23e5f7391b93ceb84626e924b21924f46acea0ac936f32dfab2dbebcebc74505eb1029f6d4de0c3de764fa3bfb2e7e49405b3a7bfd5161496559f3a1beefa1c2834085bcf5848957721450ef5453137aebc5803205af25adc33a3264a25bfd194e938f6788fb41d29fce7b488c07cad0e8aa0600451000000707ff1a03ff0005000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000e700000000000000e5a3a7b5d830c2953b98534c6c59a3a34fdc34e933f7f5898f0a85cf08846bca0000000000000000000000000000000000000000000000000000000000000000dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ed3968c320e160628a093e3db8b40896ba0be928222ff1b4650aec7732002e4f00000000000000000000000000000000000000000000000000000000000000000a6fc270854cea3f3e4d3e85d5a27ab2fb59ab670c4c85b9e1afb6010d721eb311de49eaf1f22294fd8250de07b45398358d62202a5802d1fc6ca0c83331d28d2000000000000000000000000000000000000000000000000000000000000000000005005d0e00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494538444343424a65674177494241674956414c626f5474584633754564704934375445303177713556717946544d416f4743437147534d343942414d430a4d484178496a416742674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d0a45556c756447567349454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155450a4341774351304578437a414a42674e5642415954416c56544d423458445449304d4449784e4445794d4455784f466f5844544d784d4449784e4445794d4455780a4f466f77634445694d434147413155454177775a535735305a5777675530645949464244537942445a584a3061575a70593246305a5445614d426747413155450a43677752535735305a577767513239796347397959585270623234784644415342674e564241634d43314e68626e526849454e7359584a684d517377435159440a5651514944414a445154454c4d416b474131554542684d4356564d775754415442676371686b6a4f5051494242676771686b6a4f50514d4242774e434141514a0a7546357974335071307430545278546d53705832354d674b68445332565857723179317277714b7244564d4c416b4d3168726d4559453974476b642b614e696b0a6c6d534d6c7532626365663873426644424872326f3449444444434341776777487759445652306a42426777466f41556c5739647a62306234656c4153636e550a3944504f4156634c336c5177617759445652306642475177596a42676f46366758495a616148523063484d364c79396863476b7564484a316333526c5a484e6c0a636e5a705932567a4c6d6c75644756734c6d4e766253397a5a3367765932567964476c6d61574e6864476c76626939324e4339775932746a636d772f593245390a6347786864475a76636d306d5a57356a62325270626d63395a4756794d4230474131556444675157424252753734554273776439726d4b7757522f6f493867720a5273675a6844414f42674e56485138424166384542414d434273417744415944565230544151482f4241497741444343416a6b4743537147534962345451454e0a4151534341696f776767496d4d42344743697147534962345451454e415145454549585643764b7459586d65764f6c3074374358693059776767466a42676f710a686b69472b453042445145434d494942557a415142677371686b69472b4530424451454341514942426a415142677371686b69472b45304244514543416749420a426a415142677371686b69472b4530424451454341774942416a415142677371686b69472b4530424451454342414942416a415142677371686b69472b4530420a4451454342514942417a415142677371686b69472b45304244514543426749424154415142677371686b69472b453042445145434277494241444151426773710a686b69472b4530424451454343414942417a415142677371686b69472b45304244514543435149424144415142677371686b69472b45304244514543436749420a4144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69472b4530420a44514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b453042445145434477494241444151426773710a686b69472b45304244514543454149424144415142677371686b69472b4530424451454345514942437a416642677371686b69472b45304244514543456751510a4267594341674d4241414d4141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b453042445145450a4241594167473846414141774477594b4b6f5a496876684e4151304242516f424154416542676f71686b69472b453042445145474242426a59435862523276320a757064486b387a73626b35314d45514743697147534962345451454e415163774e6a415142677371686b69472b45304244514548415145422f7a4151426773710a686b69472b45304244514548416745424144415142677371686b69472b45304244514548417745422f7a414b42676771686b6a4f5051514441674e48414442450a416941665651763145433233344a58526b5478427235344b572b6469616a75706a49536570485a69515430694667496745787a5055375668784754364b79327a0a4466544b4752693456302b4a7531754678644b41313454754d48593d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436c6a4343416a32674177494241674956414a567658633239472b487051456e4a3150517a7a674658433935554d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484178496a41670a42674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d45556c75644756730a49454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b474131554543417743513045780a437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454e53422f377432316c58534f0a3243757a7078773734654a423732457944476757357258437478327456544c7136684b6b367a2b5569525a436e71523770734f766771466553786c6d546c4a6c0a65546d693257597a33714f42757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f536347724442530a42674e5648523845537a424a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e5648513445466751556c5739640a7a62306234656c4153636e553944504f4156634c336c517744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159420a4166384341514177436759494b6f5a497a6a30454177494452774177524149675873566b6930772b6936565947573355462f32327561586530594a446a3155650a6e412b546a44316169356343494359623153416d4435786b66545670766f34556f79695359787244574c6d5552344349394e4b7966504e2b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        vm.startPrank(admin);

        // collateral upserts
        string memory tcbInfoPath = "/forge-test/assets/0624/tcbinfov3_00806f050000.json";
        string memory qeIdPath = "/forge-test/assets/0624/qeidentityv2_apiv4.json";
        qeIdDaoUpsert(4, qeIdPath);
        fmspcTcbDaoUpsert(tcbInfoPath);

        // deploy and configure QuoteV3Verifier on the Attestation contract
        quoteVerifier = new V4QuoteVerifier(P256_VERIFIER, address(pccsRouter));
        attestation.setQuoteVerifier(address(quoteVerifier));
        pccsRouter.setAuthorized(address(quoteVerifier), true);
        assertEq(address(attestation.quoteVerifiers(4)), address(quoteVerifier));

        vm.stopPrank();

        // verify the quote
        uint256 balanceBefore = user.balance;
        uint256 expectedFee = GAS_PRICE_WEI * EXPECTED_GAS;
        // console.log("expected fee: ", expectedFee);

        vm.prank(user);
        uint256 a = gasleft();
        (bool success, bytes memory output) = attestation.verifyAndAttestOnChain{value: expectedFee}(sampleQuote);
        uint256 b = gasleft();

        if (!success) {
            console.log(string(output));
        } else {
            uint256 gas = a - b;
            // console.log("gas: ", gas);

            uint256 balanceAfter = user.balance;
            uint256 paidFee = balanceBefore - balanceAfter;
            // console.log("paid fee: ", paidFee);
        }

        assertTrue(success);
    }
}
