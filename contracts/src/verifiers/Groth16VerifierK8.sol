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

contract Groth16VerifierK8 {
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
    uint256 constant deltax1 = 155733452490983340924546364945625275178638915311997773463775604673966711313;
    uint256 constant deltax2 = 2478701763039163914984844714307056392521047099243651702039687311197870148615;
    uint256 constant deltay1 = 8225925169448958868115032620782462668454908627615043070626227276077269638275;
    uint256 constant deltay2 = 4300314638931207964867930014762165511902367830055936416591854522297979067264;

    
    uint256 constant IC0x = 11798261925702397023192020103311396630721916094036377606027700248068490993706;
    uint256 constant IC0y = 6165949387225557925679658595617071528142284184447604170598761069581333138241;
    
    uint256 constant IC1x = 2859905681426379468043456179693883746125996408248952259240927533272313075048;
    uint256 constant IC1y = 16070213905687255398403814846624797028166550760023989887168532901119653360614;
    
    uint256 constant IC2x = 15128975452252845472472257843063374062624339580170966743590665664924218859905;
    uint256 constant IC2y = 6360722874999190821523851758393972736807977494881426414944172094439808032755;
    
    uint256 constant IC3x = 7462824821774045290457050755750843646652587359034550140832585677472097111499;
    uint256 constant IC3y = 2523346935484094560788659028537627580675248874270040845308754704335852637275;
    
    uint256 constant IC4x = 5249846393874074554407184832450780617910315854107130371734032547319551848651;
    uint256 constant IC4y = 21714806348306053385156925989071754191621215266137293380425729416951003267631;
    
    uint256 constant IC5x = 12128615862675071778369960785815620062461720165318376465554384076637139220062;
    uint256 constant IC5y = 9130127400227552305864313968799864223156602657550976605489099070537581485951;
    
    uint256 constant IC6x = 236502977090582051882773285511239504001194994735266872179178184456463462085;
    uint256 constant IC6y = 1472038112683067672944073040776742675202081983587569038370849991677424018461;
    
    uint256 constant IC7x = 15812942946043939304453578287436482877533172974425472835130585537094042169088;
    uint256 constant IC7y = 7533888098895973840234001560391094497662001135524434558347433489085081749327;
    
    uint256 constant IC8x = 21005868234034443508588124215359810530910566624238758062286240457970959488736;
    uint256 constant IC8y = 20477922793573355940831283376410346848794309028887472084946441201834923053305;
    
    uint256 constant IC9x = 4034655222576424128532057417716030297285947545150331008615886224150181370084;
    uint256 constant IC9y = 7907205281245062923643402479283167748672417675833744487726264995080836271279;
    
    uint256 constant IC10x = 4612423719764190578428259840646598849870761903001122743804819937169800859000;
    uint256 constant IC10y = 14296611561032645918665876585110307797245043036482067076244786618399186024411;
    
    uint256 constant IC11x = 21869625532089477119394356483132915227851265918422210561114607507603058324897;
    uint256 constant IC11y = 17973977920286928174075974250983996533939506795215655777958117058296520054924;
    
    uint256 constant IC12x = 7707320517853354889627851854588709552810055698720756805425716842169765160005;
    uint256 constant IC12y = 10112268035933857132636031642883416921882622592440947774503447041444794806146;
    
    uint256 constant IC13x = 1863392747019908405814517545012139668840099730508745069388013865785368785135;
    uint256 constant IC13y = 5097219950642369325152399066280989414523702635900022259788596837287584466854;
    
    uint256 constant IC14x = 11382584322117022973085159144356323165031268010117800846883537352525735390170;
    uint256 constant IC14y = 4107947112636200800284695321381775686044844833140901882295643355590081131026;
    
    uint256 constant IC15x = 1529320258001939596556467984976919730077984111716087473969362687075827406533;
    uint256 constant IC15y = 12437852525436103760623622002834023064731234878616464257509102509080806998758;
    
    uint256 constant IC16x = 17677580612399418990111071821719552406353809538193249625210524085723066875820;
    uint256 constant IC16y = 3308638446697809329078152787441032914302803436255510924663904965393242481629;
    
    uint256 constant IC17x = 13032074523308949128079656453374190636742300126250033186487419534833279646156;
    uint256 constant IC17y = 5864268872080191443184603131352603787391385729504735916435393594693567076613;
    
    uint256 constant IC18x = 21817349634378949154958602073947872602314408972662224299220084876015032694038;
    uint256 constant IC18y = 10889303717864139081182021386450016935473928314473211840737522040760433038817;
    
    uint256 constant IC19x = 9684297167674760283148178726148413563840195554251614301499518251603043802958;
    uint256 constant IC19y = 11881426198038409260315250126271137009851381067442825221834103969225336869420;
    
    uint256 constant IC20x = 3777617330223062644735112777074070569814912166321184888105769300321002804563;
    uint256 constant IC20y = 2506115347963471025900455155995271253370331682504443483798645162722050740342;
    
    uint256 constant IC21x = 11336778521822158824093933043315499868113321030761771732679229583177482118715;
    uint256 constant IC21y = 9678011954323046113344978240664328737638055556090631784989093633159004214328;
    
    uint256 constant IC22x = 10673782618662215069355200703575059214511001022285199856530385711640297091655;
    uint256 constant IC22y = 15027691854780669116214448980466293859272003921630633334474390093787216197236;
    
    uint256 constant IC23x = 7378365208321535389087980625951292526743375659654717165992581126349034938861;
    uint256 constant IC23y = 18774759262867358802887370047633249169543266626376404388752161534610943275275;
    
    uint256 constant IC24x = 17817126908759208653381934238701124414412441164022049333080196528415999857962;
    uint256 constant IC24y = 21425300948733763354118080470073117224972473678616917183690763873335834127694;
    
    uint256 constant IC25x = 13755850530294413155065619500313939238473437703901920691755045639186479729667;
    uint256 constant IC25y = 9031178676224435100256794272145619632363426548818419463608556056442015459993;
    
    uint256 constant IC26x = 6946002501058813367146188581118128107235721786069541342035148564075153992529;
    uint256 constant IC26y = 13138498271412222362979347184016411542812003204499954878786129814780338572869;
    
    uint256 constant IC27x = 712759243992581373438499331679921320853463568829961561704943296407095336360;
    uint256 constant IC27y = 5149511513213475710459887614751966495366602632424304428590368438620229920993;
    
    uint256 constant IC28x = 20846898151853625253148023424666682332121987404430712289230421156171037626;
    uint256 constant IC28y = 19393248709909943043631966667077107311239360294833244163621164907597153238902;
    
    uint256 constant IC29x = 5184805700432732104018772883623913483043602706509830712999647768963543212653;
    uint256 constant IC29y = 13612486982694224444878687471661508802167955513506282730488836984747633947001;
    
    uint256 constant IC30x = 12588987142590833480690811637213167346072748940296849146749587581037473294342;
    uint256 constant IC30y = 3425036664644125598448793537892160030319908585325514244649216267580385587007;
    
    uint256 constant IC31x = 1704331232142385054763541690309051779777553823790804510352415917452649217611;
    uint256 constant IC31y = 13993309913438461748562693777227704586589953680374610274854422027366659006350;
    
    uint256 constant IC32x = 14650881656003309340077891399861409737426993575511686025550788073414291875863;
    uint256 constant IC32y = 2862636217264172315661980523973459136926693534808810187100389048434174325966;
    
    uint256 constant IC33x = 11081547292905477372911689935079971491571989149563845217216927429735032334836;
    uint256 constant IC33y = 14616089454333860914531263448955836710624909289126407768569637953469462686293;
    
    uint256 constant IC34x = 625535990522972580202241468221605396737661957905069502935843291056775464486;
    uint256 constant IC34y = 13826271655180167801518360279683516519598667011327045440587369863814664678580;
    
    uint256 constant IC35x = 13314163859315289986197893455449802065141342766755247760461345237955643175940;
    uint256 constant IC35y = 2966183047428171712408988462759181289663199032376428649135417023399003270634;
    
    uint256 constant IC36x = 7388781991069481175783337655266112477473771456133033072254212717629838925779;
    uint256 constant IC36y = 14439419617613318149365341113247838135237039985225496554943852610201324560572;
    
    uint256 constant IC37x = 2467810157968627003376480569667745133578763685187898770250122856039809593372;
    uint256 constant IC37y = 11152272839639783011915907508593251994812037762531880947381510664320610231010;
    
    uint256 constant IC38x = 14467888055214733530753815756399974520674684522639440046793189239812870032257;
    uint256 constant IC38y = 4973505337123839195020565222924977924498930132932216414570676155960481518644;
    
    uint256 constant IC39x = 17056093363061589058065736349171279304740964520818937469309688911521312358563;
    uint256 constant IC39y = 15666249107222384422642702403595786164932206033422790484486572338469879726968;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[39] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                
                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))
                
                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))
                
                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))
                
                g1_mulAccC(_pVk, IC38x, IC38y, calldataload(add(pubSignals, 1184)))
                
                g1_mulAccC(_pVk, IC39x, IC39y, calldataload(add(pubSignals, 1216)))
                

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
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            
            checkField(calldataload(add(_pubSignals, 1088)))
            
            checkField(calldataload(add(_pubSignals, 1120)))
            
            checkField(calldataload(add(_pubSignals, 1152)))
            
            checkField(calldataload(add(_pubSignals, 1184)))
            
            checkField(calldataload(add(_pubSignals, 1216)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
