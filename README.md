# SCA/Permit2 sig replay problem

## Overview 

1. Most SCA's implement isValidSig as a wrapper over ECDSA.recover:  
a. LightAccount: https://github.com/alchemyplatform/light-account/blob/main/src/LightAccount.sol#L236  
b. Kernel: https://github.com/zerodevapp/kernel/blob/main/src/Kernel.sol#L247  
c. Biconomy: https://github.com/bcnmy/scw-contracts/blob/main/contracts/smart-account/SmartAccount.sol#L337  
d. Soul Wallet: https://github.com/SoulWallet/soul-wallet-contract/blob/20e2dde6af807498a6881452d6b4e9a38a0d6ac1/contracts/validator/BaseValidator.sol#L85  

2. Permit2's 1271 signature implementation does not fully account for the SCA case:  
a. They use 1271 signatures if claimedSigner (the SCA) has code > 0: https://github.com/Uniswap/permit2/blob/main/src/libraries/SignatureVerification.sol#L26C13-L26C26  
b. In the 712 struct they use, they do not include the origin address for the tokens. [See example of how struct is built](https://github.com/OMGWINNING/replay-sig-poc/blob/master/test/Counter.t.sol#L47-L68)  
c. They invalidate nonces based on `msg.sender` which are SCAs  
d. Result: If an owner owns multiple SCAs, the permit signature could be replayable across all his accounts  

## The attack:  
1. Owner has multiple SCAs. For example, lets use SCA_1 and SCA_2  
2. Owner signs permit from SCA_1 to transfer tokens to attacker  
3. Attacker calls permit2 with sig from step #2, then calls transferFrom to move tokens from SCA_1 to attacker  
4. Attacker calls permit2 replaying sig from step #2 and #3, then calls transferFrom to move tokens from SCA_2 to attacker  

If permit2 nonce of SCA_2 < permit2 nonce of SCA_1, max loss amount is min(erc20.allowance(SCA_2, permit2), erc20.balanceOf(SCA_2)) + time bounded by the time ranges specified in the original permit. (Note: If nonces in SCA_1 >> SCA_2, attacker can replay permits from SCA_1 to SCA_2 to increase nonce until nonce(SCA_1) = nonce(SCA_2) + 1. Permits will succeed, but token transfers would fail if SCA_2 did not approve that token to permit2 contract. )  

## Attack PoC 

Located is in test/Counter.t.sol.  

If you run into compile errors from building, it's because LightAccount uses solidity >0.8.21 and permit2 forces 0.8.17. Changing LightAccount in lib/ to 0.8.17 fixes the issue  

## Questions  

1. What are next steps for this? Our gut sense is that value at risk here is low, but don't have a good sense of what protocols are affected. We want to adhere to responsible disclosure rules. What applications + SCAs should be research to see if they are at risk here, and how do we proceed?  
2. Should SCA implementations change how 1271 signatures should be calculated, or should permit2 + other dapps do so? Gnosis safe is not affected by this because they rolled a [custom domain separator](https://github.com/safe-global/safe-contracts/blob/main/contracts/handler/CompatibilityFallbackHandler.sol#L59-L60) on top of the 1271 digest. Should this become an industry standard? For reference - when considering signatures for LightAccount, our internal discussion was adding the wrapper created bad UX with current signing SDKs - essentially, the user would only see the struct typed data of the outer struct (in the account), but the digest being passed in would be hashed instead of readable, and we didn't want to create a culture of users signing unreadable bytes32 hashes.  
3. Any chance this can/should qualify for a permit2 bug bounty? This vulnerability doesn't happen for permit1 as [EIP2612 implementations include "origin address" in the 712 struct](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/ERC20Permit.sol#L57)  