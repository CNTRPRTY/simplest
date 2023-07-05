
const {
    getGeneratedMnemonic,
    getWalletFromMnemonic,
    getAddressForWallet,
    printSignedHex
} = require('./js/counterwallet-mini');



///////////////////////////////////////////////////
// section of the script that is user edited
///////////////////////////////////////////////////


// 1.generate / 2.write mnemonic //////////////////

// first generate your seed here
const my_mnemonic = getGeneratedMnemonic().join(' ');

// then to use the same seed, write your seed below (uncomment the below and comment the above)
// const my_mnemonic = `one two three four five six seven eight nine ten eleven twelve`;


// 3.choose address ///////////////////////////////

// choose from multiple addresses 0, 1, 2, ...
const my_address_index = 0;


// 4.write hex ////////////////////////////////////

// put counterpartylib unsigned tx hex here
const my_tx_hex = "000000000000000000000000000000";

///////////////////////////////////////////////////
///////////////////////////////////////////////////






// no need to edit after here

const my_wallet = getWalletFromMnemonic(my_mnemonic);
const my_address_for_index = getAddressForWallet(my_wallet, my_address_index);

console.log(`Mnemonic: ${my_mnemonic}`);
console.log(`Address ${my_address_index}: ${my_address_for_index}`);


// 6.broadcast 5.signed hex ///////////////////////

// broadcast the signed tx hex printed here
printSignedHex(my_wallet, my_address_index, my_tx_hex);
