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

pragma solidity 0.8.28;

contract Groth16VerifierK4 {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 2391818144344990469525131464582965385883830820422639372255237823615276732942;
    uint256 constant alphay  = 7592449206427109574524993956663455927334711177810607697479635281907338040305;
    uint256 constant betax1  = 11269130713831283520348246990360456118958792820426346832909606966425674788881;
    uint256 constant betax2  = 13152233683374987241203833481156333650160018695452540741505749949409610918319;
    uint256 constant betay1  = 1074971915483202685822496426040083040041304184766848483646705073597856128753;
    uint256 constant betay2  = 17534271079313699175792245423089042093559280016856045078822779891595665332439;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 18703224645741885151574248446818528945810267015303214975676635031866676461232;
    uint256 constant deltax2 = 5464530238999174547182589662210192251268348955110303375115883555581995462742;
    uint256 constant deltay1 = 15223847875491823414750985949764729120465328246213080927745791565654597071052;
    uint256 constant deltay2 = 1267477278676064641500401254184571986304455293099971605753566010317079456257;

    
    uint256 constant IC0x = 1782718938916190571426861868631243738843465917344770186470599388668962065048;
    uint256 constant IC0y = 3700766244460320954124989113964716141402199503652144273650692353195759218921;
    
    uint256 constant IC1x = 16262131806191210217191199379519287486971141255796871025360576765740517999585;
    uint256 constant IC1y = 13517150924090643482569294121964516526346022247067675399482020214213071659963;
    
    uint256 constant IC2x = 11668995207266670077107138199775630760110479338914048197527194251472915908855;
    uint256 constant IC2y = 9876852735016566697100367521413077355146363959917137388792894035506551343501;
    
    uint256 constant IC3x = 16224895244504338559918596875005887679027862239477056272759895317713082054975;
    uint256 constant IC3y = 18515609822457957445996919676655365702843671048010954403520236679680584798851;
    
    uint256 constant IC4x = 13578372129052615971614359291928764076465533983375157428365317235487082905783;
    uint256 constant IC4y = 1693255935147176108437649339797306505318804421328300684332229354607516257359;
    
    uint256 constant IC5x = 10854678922404766039222893169261968394085673050017745434313097901288750890720;
    uint256 constant IC5y = 20036325622917174067545037174436503222701199953878368788326975750499352585248;
    
    uint256 constant IC6x = 18857165450376585194637129480362412120616711655139133516933444151923466287961;
    uint256 constant IC6y = 12800635250783996583517771045995577502979599067213258594879912110400117069127;
    
    uint256 constant IC7x = 15704592258857299151082312196254666024391547100955332439122144551209833877232;
    uint256 constant IC7y = 15773080010426684074221167589063329495739390873909726393917684211869087992200;
    
    uint256 constant IC8x = 16219358996262331035733085068781079116760172426136637229803616510144823129327;
    uint256 constant IC8y = 10391214147348953529362802251400650248538012186227738967385527318795237014439;
    
    uint256 constant IC9x = 4146122125147191783620532594794986823277207118513649870676407897585510791790;
    uint256 constant IC9y = 2403753138589946093998425139525770066482336597367269855998906908721742985550;
    
    uint256 constant IC10x = 19460928950151990064926708642344084447991223169019725298232851890688947949011;
    uint256 constant IC10y = 14030780626877845079861520401796974299971097584331956125278550299466704903404;
    
    uint256 constant IC11x = 6112810117736976086955341252853429714273328694993992707554784218817803051297;
    uint256 constant IC11y = 18142742857099123935661574281786061391008747782857199854727244147469832745492;
    
    uint256 constant IC12x = 5426845234660353402048136529218321393731853970683229622915216595931241609329;
    uint256 constant IC12y = 7307587053316593501498035115248363014412348072858024187978789821102917896537;
    
    uint256 constant IC13x = 1270834737841766943106635353370110488716617871929832420973636503587421311106;
    uint256 constant IC13y = 2954644354054845657865108649720033604421714362617373870294117778460910759235;
    
    uint256 constant IC14x = 15063331348905375696502311834819840038056703768898070260940507249807116736306;
    uint256 constant IC14y = 12604689225112721989485709666756618372311556918341640359037646116653350866116;
    
    uint256 constant IC15x = 2013962272557485459464888364712395851745789687123430270481402510508204599955;
    uint256 constant IC15y = 6216559338021366958018032410605310489311523380248884158330393838036446904300;
    
    uint256 constant IC16x = 6284016954148993342741221578658466308056468473199393684713459355007241855211;
    uint256 constant IC16y = 14714248505864661426154938931869413495249720379284811159730203695655113785425;
    
    uint256 constant IC17x = 2438156678127791642508265910996316154463513377859152995074954748907562795433;
    uint256 constant IC17y = 8973514316149188464409456281558661160086086872010288728626328941092063845653;
    
    uint256 constant IC18x = 19798242312753450339073556862861252466764420510196583153564530044274919862022;
    uint256 constant IC18y = 16250350215616047084665762474145814968443837501398355386319202658367929396368;
    
    uint256 constant IC19x = 12345139238404197216776828095114992763161618200084759194619888262362605453569;
    uint256 constant IC19y = 673708195661584082234187165610233324767396602689108506584186015491087923161;
    
    uint256 constant IC20x = 21625577052956648829394561973128876898472768810861473770034380557837973765092;
    uint256 constant IC20y = 17211002064115451364710380167959660835341593848371138021546999034497615466102;
    
    uint256 constant IC21x = 16185449840928330678897053684873928616992481299487903157732644006546938347156;
    uint256 constant IC21y = 8041838932774756410390313999332887014733956929512578083424704155291331506661;
    
    uint256 constant IC22x = 7016310690953722646115119675195367805565300982642640202283736850372844067436;
    uint256 constant IC22y = 15407401351696321049113743486528339531301174441274889225654068233928542893652;
    
    uint256 constant IC23x = 14138834370652551255696815199332820937940897556064560780538198871718352344089;
    uint256 constant IC23y = 12524879842073449579529501893089429747690803781389037445192341334240221145182;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[23] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                

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
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
