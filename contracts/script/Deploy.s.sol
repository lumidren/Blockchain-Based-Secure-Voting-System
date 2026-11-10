// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Election} from "../src/Election.sol";
import {VeriVoteFactory} from "../src/VeriVoteFactory.sol";
import {VoterRegistry} from "../src/VoterRegistry.sol";
import {TrusteeCoordinator} from "../src/TrusteeCoordinator.sol";
import {Tally} from "../src/Tally.sol";
import {Groth16VerifierK4} from "../src/verifiers/Groth16VerifierK4.sol";
import {Groth16VerifierK8} from "../src/verifiers/Groth16VerifierK8.sol";

/**
 * Deploys the VeriVote system and records it in deployments/<name>.json.
 *
 * Environment:
 *   DEPLOYMENT_NAME   manifest name (e.g. local, sepolia, base-sepolia)            [required]
 *   SAFE_ADDRESS      Safe multisig: timelock proposer/executor                     [required]
 *   PAUSER_ADDRESS    emergency pauser                                              [default: SAFE_ADDRESS]
 *   TIMELOCK_DELAY    seconds                                                       [default: 172800]
 *
 * Idempotent: if the manifest exists and its factory has code on this chain, nothing is deployed.
 *
 *   forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --verify   (key via --account / --ledger)
 */
contract Deploy is Script {
    struct Out {
        address factory;
        address registry;
        address coordinator;
        address tally;
        address timelock;
        address electionImplementation;
        address verifierK4;
        address verifierK8;
        uint256 startBlock;
    }

    function run() external returns (Out memory o) {
        string memory name = vm.envString("DEPLOYMENT_NAME");
        address safe = vm.envAddress("SAFE_ADDRESS");
        address pauser = vm.envOr("PAUSER_ADDRESS", safe);
        uint256 delay = vm.envOr("TIMELOCK_DELAY", uint256(2 days));
        string memory path = string.concat(vm.projectRoot(), "/deployments/", name, ".json");

        if (vm.isFile(path)) {
            address existing = vm.parseJsonAddress(vm.readFile(path), ".factory");
            if (existing.code.length > 0) {
                console2.log("already deployed, factory at", existing);
                return o;
            }
        }

        o.startBlock = block.number;
        vm.startBroadcast();
        address deployer = msg.sender;
        o.electionImplementation = address(new Election());
        VeriVoteFactory factory = VeriVoteFactory(
            address(
                new ERC1967Proxy(
                    address(new VeriVoteFactory()),
                    abi.encodeCall(VeriVoteFactory.initialize, (deployer, pauser, o.electionImplementation))
                )
            )
        );
        o.factory = address(factory);
        o.registry = address(
            new ERC1967Proxy(address(new VoterRegistry()), abi.encodeCall(VoterRegistry.initialize, (o.factory)))
        );
        o.coordinator = address(
            new ERC1967Proxy(address(new TrusteeCoordinator()), abi.encodeCall(TrusteeCoordinator.initialize, (o.factory)))
        );
        o.tally = address(new ERC1967Proxy(address(new Tally()), abi.encodeCall(Tally.initialize, (o.factory))));
        o.verifierK4 = address(new Groth16VerifierK4());
        o.verifierK8 = address(new Groth16VerifierK8());
        factory.setModules(o.registry, o.coordinator, o.tally);
        factory.setVerifier(4, o.verifierK4, 23);
        factory.setVerifier(8, o.verifierK8, 39);

        address[] memory roles = new address[](1);
        roles[0] = safe;
        o.timelock = address(new TimelockController(delay, roles, roles, address(0)));
        factory.grantRole(factory.DEFAULT_ADMIN_ROLE(), o.timelock);
        factory.renounceRole(factory.DEFAULT_ADMIN_ROLE(), deployer);
        vm.stopBroadcast();

        string memory k = "deployment";
        vm.serializeUint(k, "chainId", block.chainid);
        vm.serializeString(k, "name", name);
        vm.serializeAddress(k, "factory", o.factory);
        vm.serializeAddress(k, "registry", o.registry);
        vm.serializeAddress(k, "coordinator", o.coordinator);
        vm.serializeAddress(k, "tally", o.tally);
        vm.serializeAddress(k, "timelock", o.timelock);
        vm.serializeAddress(k, "safe", safe);
        vm.serializeAddress(k, "pauser", pauser);
        vm.serializeAddress(k, "electionImplementation", o.electionImplementation);
        string memory verifiers = "verifiers";
        vm.serializeAddress(verifiers, "4", o.verifierK4);
        string memory vjson = vm.serializeAddress(verifiers, "8", o.verifierK8);
        vm.serializeString(k, "verifiers", vjson);
        vm.serializeUint(k, "timelockDelay", delay);
        string memory json = vm.serializeUint(k, "startBlock", o.startBlock);
        vm.writeJson(json, path);
        console2.log("deployment written to", path);
    }
}
