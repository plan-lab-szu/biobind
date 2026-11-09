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
    uint256 constant deltax1 = 11474584642099826172725376595338400607849052559704325122806646866218351593303;
    uint256 constant deltax2 = 20247371852431623673698236165073602792407409169096858772394287663641965859593;
    uint256 constant deltay1 = 16008111571333841365778683448358680937250344926865459787449814723799677341475;
    uint256 constant deltay2 = 11672247516858601115913481942937984145094036867380960237978655448785491951312;

    
    uint256 constant IC0x = 14167052949944717610408726574281827133017951985755065858196618540706803944482;
    uint256 constant IC0y = 10813423423910939332351003301437566979132508276474800664666032235681383401356;
    
    uint256 constant IC1x = 11100293574941839108766016433459959835720955576174315284890071381330210081934;
    uint256 constant IC1y = 4344122740199155046612888068186234112551912770467839890386542568125113452406;
    
    uint256 constant IC2x = 504221958294155599686218924921459963183842624707036989209110733997748946285;
    uint256 constant IC2y = 2978151791300400517399344926917933362321035369423350340183927983731386699684;
    
    uint256 constant IC3x = 1701323159365503876595889984207893800588644381645693273501574776841197469940;
    uint256 constant IC3y = 16798359748593243321951047030068847321951654249108164211558514753455874425184;
    
    uint256 constant IC4x = 15004591433352856809014217643539371658957732697827292692827560191456268573776;
    uint256 constant IC4y = 6596717872720575754834622529331464007788450457123810060075458121569661761404;
    
    uint256 constant IC5x = 13657405929787536139524291693006030351362204329556666109097746216797532026860;
    uint256 constant IC5y = 493289382938130760472627219410893486346718883270732129324126083959799176923;
    
    uint256 constant IC6x = 2423690866547856603176268125196598679581483069828046752013771107007342640058;
    uint256 constant IC6y = 6733214864626262675390606698751290647220931757841799007563123711106888461823;
    
    uint256 constant IC7x = 2212889148766871125572620866682797915342680325967587757292044804019219763256;
    uint256 constant IC7y = 20561964360117525818585451552882063323822148573099651156934656558988115769730;
    
    uint256 constant IC8x = 410768000310813617148517211662499935636981461229947368772581555445329900953;
    uint256 constant IC8y = 15564168048959879761806600702524122670208095021089429783897552844192314717759;
    
    uint256 constant IC9x = 17390822608106234690283982214758851968096789044184408052752149686015467933304;
    uint256 constant IC9y = 21374537749314926057944974146663846367257451763157428747960777042727667986607;
    
 
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
