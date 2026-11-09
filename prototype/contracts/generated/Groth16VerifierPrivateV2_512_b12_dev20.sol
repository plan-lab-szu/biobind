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
    uint256 constant deltax1 = 2335077850599113610339285768585627865483179546232749006584168537871953569889;
    uint256 constant deltax2 = 8514747777703810880800691609343998495946492596366805896964564247721743869464;
    uint256 constant deltay1 = 11896763005305516579596731844268067696977082211049383338362092054531633111007;
    uint256 constant deltay2 = 1908125982827604530319832607309147796171756255818911264660757264282310549447;

    
    uint256 constant IC0x = 3175478665799707885126663443606255865686306921057364627677231061479964573215;
    uint256 constant IC0y = 1871505627019515264958892505758346431352411678366202132793079237266622767761;
    
    uint256 constant IC1x = 14548371801576561004783252025412278417011559167218887570497786605444025976907;
    uint256 constant IC1y = 1531442135211329148011355826550297326355618759075213946883973266341171328849;
    
    uint256 constant IC2x = 2838953095134634332663666958685303470983220591000912290713555187149426851430;
    uint256 constant IC2y = 9927823469069695548986586806714565181847758421039102014962489747534437699973;
    
    uint256 constant IC3x = 6480543330668194433062138661814085941528091830766918539859583664007412539679;
    uint256 constant IC3y = 16186273913610592305266105650793521069578055196458106523703259006165671002489;
    
    uint256 constant IC4x = 17890025575454019055746423312228790496596285986073020168405258717215964576560;
    uint256 constant IC4y = 7343705890992877334951466069021207028936564948168348317863558477011810240318;
    
    uint256 constant IC5x = 13719503264786795858950902795459254729265496165725583759835009693068996149182;
    uint256 constant IC5y = 15767774021041433935767565593927658234163351285023956232589685044868583531528;
    
    uint256 constant IC6x = 11364903736613439662730724952257513615359553571849343636251241181558778022431;
    uint256 constant IC6y = 13385070415030490788448939337383911863707541499271915084293703365815568595287;
    
    uint256 constant IC7x = 6094388198966216497368141580960896961724807518686239695921498053554189391390;
    uint256 constant IC7y = 18760251080796676077974552000685520327243140595273870100913175882209359712214;
    
    uint256 constant IC8x = 3074883903444051247356175025153913623358453907659724216869899339037040540701;
    uint256 constant IC8y = 6181611288391920479945169255354376930276556890694390542826233143563357513864;
    
    uint256 constant IC9x = 10324081201761139861679943694169656737871360933939444776455110610792284398242;
    uint256 constant IC9y = 19990609524139334986264483114345493758847266282922215098650067961300171038013;
    
 
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
