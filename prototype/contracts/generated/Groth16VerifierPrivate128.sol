// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 16991866455667620745526137249248280850071440518438488664203698515978817163244;
    uint256 constant alphay  = 5735027138110284067072198581725424863966969918527979192553900360439604328500;
    uint256 constant betax1  = 14429774776384419947703069148567330409441026771612808843517990867311054742874;
    uint256 constant betax2  = 3965068202545630338316025817560468622586393248407630241461198906890459070264;
    uint256 constant betay1  = 17498377776192914136811987532203040174457982882512688280361807789039529437622;
    uint256 constant betay2  = 2715813373370094190923915195674753662486748457478240790070122635605639837796;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 8596405292036970041326194682614714135745062069510548494257133450066651719567;
    uint256 constant deltax2 = 1671767066646373413286979407012540570189401217395699980439612661134803903881;
    uint256 constant deltay1 = 13309977909739267608342114845781823757775403413689783600428564188042786441618;
    uint256 constant deltay2 = 2898778585082371579729750102331004987514938899489616571943284992356954907919;

    
    uint256 constant IC0x = 18578954320550370120921350235901498989539346995242683844512186267127072543073;
    uint256 constant IC0y = 21098788988346675399690338840801455031487969111189861207470774306624439701819;
    
    uint256 constant IC1x = 20183993336700044223220496712746667087919138895050948740525871304942357725556;
    uint256 constant IC1y = 18391501407080772614599442766357872066905182757520576063761065000372840353309;
    
    uint256 constant IC2x = 4217417378889389731834215153325438971910750542171519790864268098713516488312;
    uint256 constant IC2y = 11351436189539068348329456292161580628742263049234826630568420076240865901139;
    
    uint256 constant IC3x = 5363693269676350718749401578482351308938041985816517160939574166589074157666;
    uint256 constant IC3y = 1338216486780140165100858523165911111431814695871537834195140495845860603078;
    
    uint256 constant IC4x = 1398102682186028245117965161955906449449324318860590812932124088535341894408;
    uint256 constant IC4y = 2022960812718961504039432922452638387785226829299815670773325757817785310701;
    
    uint256 constant IC5x = 16852468237604106369608775318120073417052296873651547051788556807504809242858;
    uint256 constant IC5y = 10826528298190692723758536832183924290816227940796813779069105884612061891402;
    
    uint256 constant IC6x = 17772398643342420215252463252650390924686935203314726903336279350680192160021;
    uint256 constant IC6y = 1064160217298102315235510069971080648410428453093867695831542216319243810614;
    
    uint256 constant IC7x = 1812436251627867330031492096953737628913595730815313440447983871417933756628;
    uint256 constant IC7y = 21016131995227715650136889211344439492735412095115015791979679315897411048583;
    
    uint256 constant IC8x = 652117293473987813253566573430652923306084698673668711229094714293189247063;
    uint256 constant IC8y = 21564276163140907922240649462965230354617749637893921933553764431458651679984;
    
    uint256 constant IC9x = 16944237682674897435310269097071954855760048331852832455935504646943392709395;
    uint256 constant IC9y = 2103671948205061644429226357847170451431841199965104934098089668653106320541;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[9] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
