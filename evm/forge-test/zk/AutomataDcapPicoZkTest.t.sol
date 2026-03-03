// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PicoVerifier} from "../../contracts/zk/pico/PicoVerifier.sol";
import {Test} from "forge-std/Test.sol";

contract AutomataDcapPicoZkTest is Test {
    PicoVerifier picoVerifier;

    function setUp() public {
        picoVerifier = new PicoVerifier();
    }

    function testPicoGroth16Verification() public view {
        bytes32 picoDcapRiscvVkey = 0x00a2d3636751871b1b97c0ada94d69daa8e0a31867b6f2c0e157e4cd198712d0;

        bytes32 hash = 0x087351bd6542ac375e4d59ca9f2943ce699caa3cdca845aede845ddd60f2f5ed;

        uint256[8] memory proofArray = [                                                                                                   
            3591825965511135046697555133016225065757641795524294370781434224913381488720,                   
            1364407140899100194271213745387537393082087945668350305832688826937815338314,                   
            17591463398178412952359195574847011000392328473726990443150970040970422970975,                
            21622718003562131013039784309498550693032980832269540525984664078202270988036,                
            8057387650915671174149115496748214136449899291193196764929390536057867854769,                   
            19115814143392039663886717084627804308208638619282260453513539088655508322871,                  
            4645753581076603851871376714359108232113686982028910190643364001848527422856,               
            13566255880842770844587500521817344470728065304775165892612254587470765380734               
        ];

        picoVerifier.verifyPicoProof(picoDcapRiscvVkey, hash, proofArray);
    }
}