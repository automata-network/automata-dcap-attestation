// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import "../../src/helpers/FmspcTcbHelper.sol";
import "./TCBConstants.t.sol";
import "./TDXConstants.t.sol";

contract TCBHelperTest is TCBConstants, TDXConstants, Test {
    FmspcTcbHelper fmspcTcbLib;

    function setUp() public {
        fmspcTcbLib = new FmspcTcbHelper();
    }

    function testTcbLevelsSerialization() public {

        string memory str = "{\"id\":\"SGX\",\"version\":3,\"issueDate\":\"2024-11-22T15:44:38Z\",\"nextUpdate\":\"2024-12-22T15:44:38Z\",\"fmspc\":\"00606A000000\",\"pceId\":\"0000\",\"tcbType\":0,\"tcbEvaluationDataNumber\":17,\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":14,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":14,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":255},{\"svn\":255},{\"svn\":1},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"SWHardeningNeeded\",\"advisoryIDs\":[\"INTEL-SA-00615\"]},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":14,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":14,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":255},{\"svn\":255},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"ConfigurationAndSWHardeningNeeded\",\"advisoryIDs\":[\"INTEL-SA-00657\",\"INTEL-SA-00767\",\"INTEL-SA-00615\"]},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":12,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":12,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":255},{\"svn\":255},{\"svn\":1},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13},\"tcbDate\":\"2023-08-09T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00960\",\"INTEL-SA-00657\",\"INTEL-SA-00767\",\"INTEL-SA-00615\"]},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":12,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":12,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":255},{\"svn\":255},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13},\"tcbDate\":\"2023-08-09T00:00:00Z\",\"tcbStatus\":\"OutOfDateConfigurationNeeded\",\"advisoryIDs\":[\"INTEL-SA-00657\",\"INTEL-SA-00767\",\"INTEL-SA-00960\",\"INTEL-SA-00615\"]},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":11,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":11,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":255},{\"svn\":255},{\"svn\":1},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13},\"tcbDate\":\"2023-02-15T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00828\",\"INTEL-SA-00837\",\"INTEL-SA-00657\",\"INTEL-SA-00767\",\"INTEL-SA-00960\",\"INTEL-SA-00615\"]},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":11,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":11,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":255},{\"svn\":255},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13},\"tcbDate\":\"2023-02-15T00:00:00Z\",\"tcbStatus\":\"OutOfDateConfigurationNeeded\",\"advisoryIDs\":[\"INTEL-SA-00828\",\"INTEL-SA-00837\",\"INTEL-SA-00657\",\"INTEL-SA-00767\",\"INTEL-SA-00960\",\"INTEL-SA-00615\"]},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":7,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":9,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":255},{\"svn\":255},{\"svn\":1},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13},\"tcbDate\":\"2022-08-10T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00657\",\"INTEL-SA-00730\",\"INTEL-SA-00738\",\"INTEL-SA-00767\",\"INTEL-SA-00828\",\"INTEL-SA-00837\",\"INTEL-SA-00960\",\"INTEL-SA-00615\"]},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":7,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":9,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":255},{\"svn\":255},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13},\"tcbDate\":\"2022-08-10T00:00:00Z\",\"tcbStatus\":\"OutOfDateConfigurationNeeded\",\"advisoryIDs\":[\"INTEL-SA-00657\",\"INTEL-SA-00730\",\"INTEL-SA-00738\",\"INTEL-SA-00767\",\"INTEL-SA-00828\",\"INTEL-SA-00837\",\"INTEL-SA-00960\",\"INTEL-SA-00615\"]},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":4,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":4,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":255},{\"svn\":255},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":11},\"tcbDate\":\"2021-11-10T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00586\",\"INTEL-SA-00614\",\"INTEL-SA-00615\",\"INTEL-SA-00657\",\"INTEL-SA-00730\",\"INTEL-SA-00738\",\"INTEL-SA-00767\",\"INTEL-SA-00828\",\"INTEL-SA-00837\",\"INTEL-SA-00960\"]},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":4,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":4,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":255},{\"svn\":255},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":10},\"tcbDate\":\"2020-11-11T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00477\",\"INTEL-SA-00586\",\"INTEL-SA-00614\",\"INTEL-SA-00615\",\"INTEL-SA-00657\",\"INTEL-SA-00730\",\"INTEL-SA-00738\",\"INTEL-SA-00767\",\"INTEL-SA-00828\",\"INTEL-SA-00837\",\"INTEL-SA-00960\"]},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":4,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":4,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":255},{\"svn\":255},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":5},\"tcbDate\":\"2018-01-04T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00106\",\"INTEL-SA-00115\",\"INTEL-SA-00135\",\"INTEL-SA-00203\",\"INTEL-SA-00220\",\"INTEL-SA-00233\",\"INTEL-SA-00270\",\"INTEL-SA-00293\",\"INTEL-SA-00320\",\"INTEL-SA-00329\",\"INTEL-SA-00381\",\"INTEL-SA-00389\",\"INTEL-SA-00477\",\"INTEL-SA-00586\",\"INTEL-SA-00614\",\"INTEL-SA-00615\",\"INTEL-SA-00657\",\"INTEL-SA-00730\",\"INTEL-SA-00738\",\"INTEL-SA-00767\",\"INTEL-SA-00828\",\"INTEL-SA-00837\",\"INTEL-SA-00960\"]}]}";

        (
            TcbInfoBasic memory tcbInfo,
            string memory tcbLevelsString,
            ,
            
        ) = fmspcTcbLib.parseTcbString(str);

        TCBLevelsObj[] memory tcbLevels = fmspcTcbLib.parseTcbLevels(tcbInfo.version, tcbLevelsString);

        TCBLevelsObj memory tcb = tcbLevels[1];

        bytes memory serialized = fmspcTcbLib.tcbLevelsObjToBytes(tcb);

        TCBLevelsObj memory ret = fmspcTcbLib.tcbLevelsObjFromBytes(serialized);

        assertEq(tcb.pcesvn, ret.pcesvn);
        assertEq(tcb.tcbDateTimestamp, ret.tcbDateTimestamp);
        assertEq(uint8(tcb.status), uint8(ret.status));
        
        for (uint256 i = 0; i < 16; i++) {
            assertEq(tcb.sgxComponentCpuSvns[i], ret.sgxComponentCpuSvns[i]);
            assertEq(tcb.tdxComponentCpuSvns[i], ret.tdxComponentCpuSvns[i]);
        }

        for (uint256 j = 0; j < tcb.advisoryIDs.length; j++) {
            assertEq(
                keccak256(bytes(tcb.advisoryIDs[j])), 
                keccak256(bytes(ret.advisoryIDs[j]))
            );
        }
    }

    function testTdxModulesTcbLevelsSerialization() public {
        string memory str = string(hex"7b226964223a22544458222c2276657273696f6e223a332c22697373756544617465223a22323032342d31322d30395430333a31383a30375a222c226e657874557064617465223a22323032352d30312d30385430333a31383a30375a222c22666d737063223a22393063303666303030303030222c227063654964223a2230303030222c2274636254797065223a302c227463624576616c756174696f6e446174614e756d626572223a31372c227464784d6f64756c65223a7b226d727369676e6572223a22303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c2261747472696275746573223a2230303030303030303030303030303030222c22617474726962757465734d61736b223a2246464646464646464646464646464646227d2c227464784d6f64756c654964656e746974696573223a5b7b226964223a225444585f3033222c226d727369676e6572223a22303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c2261747472696275746573223a2230303030303030303030303030303030222c22617474726962757465734d61736b223a2246464646464646464646464646464646222c227463624c6576656c73223a5b7b22746362223a7b2269737673766e223a337d2c2274636244617465223a22323032342d30332d31335430303a30303a30305a222c22746362537461747573223a225570546f44617465227d5d7d2c7b226964223a225444585f3031222c226d727369676e6572223a22303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c2261747472696275746573223a2230303030303030303030303030303030222c22617474726962757465734d61736b223a2246464646464646464646464646464646222c227463624c6576656c73223a5b7b22746362223a7b2269737673766e223a347d2c2274636244617465223a22323032342d30332d31335430303a30303a30305a222c22746362537461747573223a225570546f44617465227d2c7b22746362223a7b2269737673766e223a327d2c2274636244617465223a22323032332d30382d30395430303a30303a30305a222c22746362537461747573223a224f75744f6644617465227d5d7d5d2c227463624c6576656c73223a5b7b22746362223a7b22736778746362636f6d706f6e656e7473223a5b7b2273766e223a322c2263617465676f7279223a2242494f53222c2274797065223a224561726c79204d6963726f636f646520557064617465227d2c7b2273766e223a322c2263617465676f7279223a224f532f564d4d222c2274797065223a22534758204c617465204d6963726f636f646520557064617465227d2c7b2273766e223a322c2263617465676f7279223a224f532f564d4d222c2274797065223a225458542053494e4954227d2c7b2273766e223a322c2263617465676f7279223a2242494f53227d2c7b2273766e223a332c2263617465676f7279223a2242494f53227d2c7b2273766e223a312c2263617465676f7279223a2242494f53227d2c7b2273766e223a307d2c7b2273766e223a352c2263617465676f7279223a224f532f564d4d222c2274797065223a225345414d4c44522041434d227d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d5d2c2270636573766e223a31332c22746478746362636f6d706f6e656e7473223a5b7b2273766e223a352c2263617465676f7279223a224f532f564d4d222c2274797065223a22544458204d6f64756c65227d2c7b2273766e223a302c2263617465676f7279223a224f532f564d4d222c2274797065223a22544458204d6f64756c65227d2c7b2273766e223a322c2263617465676f7279223a224f532f564d4d222c2274797065223a22544458204c617465204d6963726f636f646520557064617465227d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d5d7d2c2274636244617465223a22323032342d30332d31335430303a30303a30305a222c22746362537461747573223a225570546f44617465227d2c7b22746362223a7b22736778746362636f6d706f6e656e7473223a5b7b2273766e223a322c2263617465676f7279223a2242494f53222c2274797065223a224561726c79204d6963726f636f646520557064617465227d2c7b2273766e223a322c2263617465676f7279223a224f532f564d4d222c2274797065223a22534758204c617465204d6963726f636f646520557064617465227d2c7b2273766e223a322c2263617465676f7279223a224f532f564d4d222c2274797065223a225458542053494e4954227d2c7b2273766e223a322c2263617465676f7279223a2242494f53227d2c7b2273766e223a332c2263617465676f7279223a2242494f53227d2c7b2273766e223a312c2263617465676f7279223a2242494f53227d2c7b2273766e223a307d2c7b2273766e223a352c2263617465676f7279223a224f532f564d4d222c2274797065223a225345414d4c44522041434d227d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d5d2c2270636573766e223a352c22746478746362636f6d706f6e656e7473223a5b7b2273766e223a352c2263617465676f7279223a224f532f564d4d222c2274797065223a22544458204d6f64756c65227d2c7b2273766e223a302c2263617465676f7279223a224f532f564d4d222c2274797065223a22544458204d6f64756c65227d2c7b2273766e223a322c2263617465676f7279223a224f532f564d4d222c2274797065223a22544458204c617465204d6963726f636f646520557064617465227d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d2c7b2273766e223a307d5d7d2c2274636244617465223a22323031382d30312d30345430303a30303a30305a222c22746362537461747573223a224f75744f6644617465222c2261647669736f7279494473223a5b22494e54454c2d53412d3030313036222c22494e54454c2d53412d3030313135222c22494e54454c2d53412d3030313335222c22494e54454c2d53412d3030323033222c22494e54454c2d53412d3030323230222c22494e54454c2d53412d3030323333222c22494e54454c2d53412d3030323730222c22494e54454c2d53412d3030323933222c22494e54454c2d53412d3030333230222c22494e54454c2d53412d3030333239222c22494e54454c2d53412d3030333831222c22494e54454c2d53412d3030333839222c22494e54454c2d53412d3030343737222c22494e54454c2d53412d3030383337225d7d5d7d");
        
        (
            ,
            ,
            string memory tdxModuleString,
            string memory tdxModuleIdentitiesString
        ) = fmspcTcbLib.parseTcbString(str);

        (, TDXModuleIdentity[] memory moduleIdentities) =
            fmspcTcbLib.parseTcbTdxModules(tdxModuleString, tdxModuleIdentitiesString);

        TDXModuleIdentity memory moduleIdentity = moduleIdentities[0];
        
        bytes memory serialized = fmspcTcbLib.tdxModuleIdentityToBytes(moduleIdentity);

        TDXModuleIdentity memory ret = fmspcTcbLib.tdxModuleIdentityFromBytes(serialized);

        assertEq(keccak256(bytes(moduleIdentity.id)), keccak256(bytes(ret.id)));
        assertEq(keccak256(moduleIdentity.mrsigner), keccak256(ret.mrsigner));
        assertEq(moduleIdentity.attributes, ret.attributes);
        assertEq(moduleIdentity.attributesMask, ret.attributesMask);
        assertEq(moduleIdentity.tcbLevels.length, ret.tcbLevels.length);

        for (uint256 i = 0; i < moduleIdentity.tcbLevels.length; i++) {
            assertEq(moduleIdentity.tcbLevels[i].isvsvn, ret.tcbLevels[i].isvsvn);
            assertEq(moduleIdentity.tcbLevels[i].tcbDateTimestamp, ret.tcbLevels[i].tcbDateTimestamp);
            assertEq(uint8(moduleIdentity.tcbLevels[i].status), uint8(ret.tcbLevels[i].status));
        }
    }

    function testTcbStringBasicParser() public {
        (
            TcbInfoBasic memory tcbInfo,
            ,
            ,
            
        ) = fmspcTcbLib.parseTcbString(string(tdx_tcbStr));
        assertEq(tcbInfo.tcbType, 0);
        assertEq(uint8(tcbInfo.id), uint8(TcbId.TDX));

        assertEq(keccak256(abi.encodePacked(tcbInfo.fmspc)), keccak256(hex"90C06f000000"));
        assertEq(tcbInfo.version, 3);
        assertEq(tcbInfo.issueDate, 1715843417);
        assertEq(tcbInfo.nextUpdate, 1718435417);
    }

    function testV3TcbLevelsParser() public {
       (
            TcbInfoBasic memory tcbInfo,
            string memory tcbLevelsString,
            ,
            
        ) = fmspcTcbLib.parseTcbString(string(tdx_tcbStr));
        assertEq(tcbInfo.version, 3);

        TCBLevelsObj[] memory tcbLevels = fmspcTcbLib.parseTcbLevels(tcbInfo.version, tcbLevelsString);

        // TODO: add test cases for the remaining tcblevels
        _assertTcbLevel(
            tcbLevels[0],
            [2, 2, 2, 2, 3, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0],
            [4, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            13,
            1710288000,
            TCBStatus.OK
        );
    }

    function testTdxModulesParser() public {
        (
            TcbInfoBasic memory tcbInfo,
            ,
            string memory tdxModuleString,
            string memory tdxModuleIdentitiesString
        ) = fmspcTcbLib.parseTcbString(string(tdx_tcbStr));
        assertEq(tcbInfo.version, 3);

        (
            TDXModule memory module, 
            TDXModuleIdentity[] memory moduleIdentities
        ) = fmspcTcbLib.parseTcbTdxModules(
            tdxModuleString,
            tdxModuleIdentitiesString
        );

        // module assertions
        assertEq(keccak256(module.mrsigner), keccak256(mrsigner));
        assertEq(module.attributes, attributes);
        assertEq(module.attributesMask, attributesMask);

        // module identity assertions
        TDXModuleIdentity memory moduleIdentity = moduleIdentities[0];
        assertEq(keccak256(bytes(moduleIdentity.id)), keccak256(bytes(moduleIdentitiesId)));
        assertEq(keccak256(moduleIdentity.mrsigner), keccak256(mrsigner));
        assertEq(moduleIdentity.attributes, attributes);
        assertEq(moduleIdentity.attributesMask, attributesMask);
        _assertTdxTcbLevels(
            moduleIdentity.tcbLevels,
            [4, 2],
            [uint256(1710288000), uint256(1691539200)],
            [TCBStatus.OK, TCBStatus.TCB_OUT_OF_DATE]
        );
    }

    function _assertTcbLevel(
        TCBLevelsObj memory tcbLevel,
        uint8[16] memory expectedSgxComponentCpuSvns,
        uint8[16] memory expectedTdxComponentCpuSvns,
        uint256 expectedPcesvn,
        uint256 expectedTimestamp,
        TCBStatus expectedStatus
    ) private {
        assertEq(tcbLevel.pcesvn, expectedPcesvn);
        assertEq(tcbLevel.tcbDateTimestamp, expectedTimestamp);
        assertEq(uint8(tcbLevel.status), uint8(expectedStatus));
        for (uint256 i = 0; i < 16; i++) {
            assertEq(tcbLevel.sgxComponentCpuSvns[i], expectedSgxComponentCpuSvns[i]);
            assertEq(tcbLevel.tdxComponentCpuSvns[i], expectedTdxComponentCpuSvns[i]);
        }
    }

    function _assertTdxTcbLevels(
        TDXModuleTCBLevelsObj[] memory tcbLevelsArr,
        uint8[2] memory isvsvnArr,
        uint256[2] memory timestampArr,
        TCBStatus[2] memory statusArr
    ) private {
        uint256 n = tcbLevelsArr.length;
        require(n == isvsvnArr.length, "isvsvn length incorrect");
        require(n == timestampArr.length, "timestamp length incorrect");
        require(n == statusArr.length, "status length incorrect");

        for (uint256 i = 0; i < n; i++) {
            assertEq(tcbLevelsArr[i].isvsvn, isvsvnArr[i]);
            assertEq(tcbLevelsArr[i].tcbDateTimestamp, timestampArr[i]);
            assertEq(uint8(tcbLevelsArr[i].status), uint8(statusArr[i]));
        }
    }
}
