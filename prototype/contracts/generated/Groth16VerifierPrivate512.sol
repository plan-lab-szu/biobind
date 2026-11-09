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
    uint256 constant alphax  = 3341896376395163784628127031749946045712688047634580721133642797717541491491;
    uint256 constant alphay  = 7984160242917083963199506992696618411904137458766880108895696437944962563383;
    uint256 constant betax1  = 10830154467438052145106518488506071255269535215850227433626131049314799470566;
    uint256 constant betax2  = 11367798705274467341049089627957479219832828229945006456013890370285556440087;
    uint256 constant betay1  = 9103396283614873642647625243630635094313750671952444975011045197236786017908;
    uint256 constant betay2  = 2067510065931960551344403745112288004567127344259670852688395988894990973104;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11552506990536887926349130310631845786946755109198313479099025599922226282978;
    uint256 constant deltax2 = 7233396913995441141415191489869077607141513514950710600541033481746049662804;
    uint256 constant deltay1 = 14614885206840653682239090216851519016774325135079273638350845419538320640926;
    uint256 constant deltay2 = 16105974553964969708898294540973876777097231352835190679281108822889137388433;

    
    uint256 constant IC0x = 11852714824213914707035191802037357223651963785513868013101958477702050453439;
    uint256 constant IC0y = 18061153798036268346613423553024451407416531041454667549224371517406915359996;
    
    uint256 constant IC1x = 4074401259466220975176570977983289938654590923253989851720325592504657093509;
    uint256 constant IC1y = 4513409262268480179273773895861073857732446450409248265571879777687155734974;
    
    uint256 constant IC2x = 6584194913547653887027668053349669107701495267122701334503690783688897214471;
    uint256 constant IC2y = 7043981190229042024354313131385271257132991229151423221431500648969973699306;
    
    uint256 constant IC3x = 17208079682536332162609655964699243081410754115081407596602720873656358500395;
    uint256 constant IC3y = 9183505633245191832778554149735030276450082295710522620337350355768817711525;
    
    uint256 constant IC4x = 16388808398700030331096572553910854522954765928571988087824469786558478927879;
    uint256 constant IC4y = 5161259791772432709629691160184213706765883592273837931900054760896814378334;
    
    uint256 constant IC5x = 17744134577262553424694102619368633624344537548783811709706281430237740474579;
    uint256 constant IC5y = 16671228657404252443434551832175852031381358712866585754978878476433396832054;
    
    uint256 constant IC6x = 18884966180393104889871006011591554318754537020481166118713843529961008827591;
    uint256 constant IC6y = 20678971646964011741573663206287616042358659578006774643919131707120058809994;
    
    uint256 constant IC7x = 6561965134032566236941110821378358395430385304631398844371329239119058905993;
    uint256 constant IC7y = 13986023851658320162355059811560897081599416907379690223240441815196271517130;
    
    uint256 constant IC8x = 4965674509326241437084852793806477954658296355200921515161261735006374720535;
    uint256 constant IC8y = 21129505414604578992111796575937926654844182378936303053958920300356085394479;
    
    uint256 constant IC9x = 3594780815030162280606263313578888363701296459392847340632787155632808781626;
    uint256 constant IC9y = 2453410392455020596679254651532600715351434755236110895794462177727555735710;
    
 
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
