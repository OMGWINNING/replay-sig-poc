# SCA/Permit2 sig replay problem

## Overview 

1. Most SCA's implement isValidSig as just a [wrapper over ECDSA.recover](https://github.com/OMGWINNING/replay-sig-poc/blob/master/test/GenericPoc.t.sol#L10-L21)

2. Permit2's 1271 signature implementation does not fully account for the SCA case:  
a. They use 1271 signatures if claimedSigner (the SCA) has code > 0: https://github.com/Uniswap/permit2/blob/main/src/libraries/SignatureVerification.sol#L26C13-L26C26  
b. In the 712 struct they use, they do not include the origin address for the tokens. [See example of how struct is built](https://github.com/OMGWINNING/replay-sig-poc/blob/master/test/GenericPoc.t.sol#L53-L73)  
c. They invalidate nonces based on `msg.sender` which are SCAs  
d. Result: If an owner owns multiple SCAs, the permit signature could be replayable across all his accounts  

## The attack:  
1. Owner has multiple SCAs. For example, lets use SCA_1 and SCA_2  
2. Owner signs permit from SCA_1 to transfer tokens to attacker  
3. Attacker calls permit2 with sig from step #2, then calls transferFrom to move tokens from SCA_1 to attacker  
4. Attacker calls permit2 replaying sig from step #2 and #3, then calls transferFrom to move tokens from SCA_2 to attacker  

If permit2 nonce of SCA_2 < permit2 nonce of SCA_1, max loss amount is min(erc20.allowance(SCA_2, permit2), erc20.balanceOf(SCA_2)) + time bounded by the time ranges specified in the original permit. (Note: If nonces in SCA_1 >> SCA_2, attacker can replay permits from SCA_1 to SCA_2 to increase nonce until nonce(SCA_1) = nonce(SCA_2) + 1. Permits will succeed, but token transfers would fail if SCA_2 did not approve that token to permit2 contract. )  

## Attack PoC 

A generic PoC in test/GenericPoc.t.sol. PoCs were also built for some wallets to demonstrate specific attack, for Alchemy's LightAccount, Biconomy, and Zerodev's Kernel. 

If you run into compile errors from building, it's because LightAccount uses solidity >0.8.21 and permit2 forces 0.8.17. Changing LightAccount in lib/ to 0.8.17 fixes the issue  

## SCAs that this replay attack would work on
1. [LightAccount](https://github.com/alchemyplatform/light-account) (PoC included)
2. Zerodev's [Kernel](https://github.com/zerodevapp/kernel/blob/main/src/Kernel.sol), including Kernel Lite v2.0/Kernel Lite v2.1 (PoC included for base kernel)
3. Patch wallet's [BaseAccount](https://github.com/PaymagicXYZ/patch-base-account-contracts/blob/main/contracts/BaseAccount.sol) as it's a fork of zerodev's kernel
4. Biconomy's [Smart Contract Wallet](https://github.com/bcnmy/scw-contracts) (PoC included)
5. Soul Wallet's [Smart Contract Account](https://github.com/SoulWallet/soul-wallet-contract)
6. eth-infinitism's [EIP4337Fallback used with Gnosis Safe](https://github.com/eth-infinitism/account-abstraction/blob/8215b88768d993fb6459c2723d173791a537a2e7/contracts/samples/gnosis/EIP4337Fallback.sol)
7. Ambire Wallet's [AmbireAccount](https://github.com/AmbireTech/wallet/blob/main/contracts/AmbireAccount.sol) 
8. zkSync's [default AA implementations](https://era.zksync.io/docs/dev/tutorials/custom-aa-tutorial.html#transaction-validation) (full scope unclear)
9. OKX's [SmartAccount](https://github.com/okx/AccountAbstraction/blob/main/contracts/wallet/SmartAccount.sol#L24) [isValidSignature](https://github.com/okx/AccountAbstraction/blob/6ee1c16d1184d40484918f9c581e92f55bb27ee2/contracts/wallet/base/SignatureManager.sol#L233)
10. Argent wallet's [BaseWallet](https://github.com/argentlabs/argent-contracts/blob/develop/contracts/wallet/BaseWallet.sol) if configured with [TransactionManager](https://github.com/argentlabs/argent-contracts/blob/develop/contracts/modules/TransactionManager.sol#L232) as a module for `isValidSignature`
11. [Fuse Wallet](https://github.com/fuseio/fuse-wallet-contracts) (fork of argent)

## Scope, Applications:
a. Permit2, token transfers are replayable. Bounded by token approvals + permit time ranges on initial permit from SCA. (PoC included)
b. Cowswap, trades are replayable if using the [1271 path](https://github.com/cowprotocol/contracts/blob/251bce00ef410602bd0ee2c1e3cd3402abd28c4e/src/contracts/mixins/GPv2Signing.sol#L281-L303). But the signature covers [token swap output address, and time validity](https://github.com/cowprotocol/contracts/blob/251bce00ef410602bd0ee2c1e3cd3402abd28c4e/src/contracts/libraries/GPv2Order.sol#L11-L24) so impact should be low.

## Protocols safe from this
1. Gnosis safe
2. ERC2612 permit - contains `address owner` in signed digest
3. Aave - uses [isValidSig](https://github.com/aave/Aave-Vault/blob/028d7696b323ae582dc7c43d3678789080a3ba92/src/libraries/MetaTxHelpers.sol#L29) for deposit flow, but passes in origin address into the msg digest