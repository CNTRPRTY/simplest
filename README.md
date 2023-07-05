# Simplest Bitcoin Wallet

THE FOLLOWING WALLET COMPROMISES SAFE BITCOIN HANDLING FOR (VERIFIABLE) SIMPLICITY! 

Use at your own risk, preferably with small amounts of bitcoin. Avoid using this wallet ONLINE with large amounts of assets.

**OFFLINE use is SMART.**

## Requirements / Usage:

### Generate your key and deposit bitcoin

0. basic knowledge of [NodeJS](https://www.w3schools.com/nodejs/), study / verify the [code](/wallet-address-sign.js), then: `npm install`

1. run wallet-address-sign.js as is to obtain your key (and store safely!)

2. edit wallet-address-sign.js to use the key generated in step 1 (and delete afterwards appropriately!)

3. send bitcoin to the generated address (check if received / confirmed: https://mempool.space/address/PutAddressHere)

4. you have bitcoin!

### Use with Counterparty

5. use address to generate your desired (unsigned) CNTRPRTY transaction hex (you can use: [xcp.dev/wallet](https://xcp.dev/wallet))

6. input the generated unsigned hex into wallet-address-sign.js

7. run wallet-address-sign.js to generate a signed transaction hex

8. finally broadcast your signed transaction (https://mempool.space/tx/push)

---

Script based on [counterwallet](https://github.com/CounterpartyXCP/counterwallet).
