// minimal bitcore-lib wallet (based on https://github.com/CounterpartyXCP/counterwallet)

const bitcore = require('bitcore-lib');
const assert = require('node:assert'); // using legacy instead of strict (https://nodejs.org/api/assert.html)
const async = require('async');

const { Mnemonic } = require('./external/mnemonic');

const USE_TESTNET = false;
const USE_REGTEST = false;
const NETWORK = (USE_TESTNET || USE_REGTEST) ? bitcore.Networks.testnet : bitcore.Networks.livenet;

// no old key support for now
class CWHierarchicalKey {

    // no password support for now
    constructor(passphrase) {
        // constructor(passphrase, password = null) {

        checkArgType(passphrase, "string");
        // if (password) {
        //     checkArgType(password, "string");
        //     passphrase = CWBitcore.decrypt(passphrase, password);
        // }
        // same as bitcoinjs-lib :
        // m : master key / 0' : first private derivation / 0 : external account / i : index
        this.basePath = 'm/0\'/0/';
        this.useOldHierarchicalKey = false;

        // init

        this.passphrase = passphrase;

        const words = passphrase.toLowerCase().trim().split(' ');
        // var words = $.trim(passphrase.toLowerCase()).split(' ');

        // // if first word == 'old' then use the  oldHierarchicalKey
        // if (words.length == 13) {
        //     var first = words.shift();
        //     if (first == 'old') {
        //         this.useOldHierarchicalKey = true;
        //     } else {
        //         throw new Error("mnemonic was 13 words but the first was not 'old'");
        //     }
        // }

        var seed = CWHierarchicalKey.wordsToSeed(words);

        this.HierarchicalKey = bitcore.HDPrivateKey.fromSeed(seed, NETWORK);
        // /*
        //  * for historical reasons we create an 'old' HDPrivateKey where the seed is used as a string and wrangled a bit
        //  * this is used for sweeping the old wallet into the new wallet
        //  */
        // this.oldHierarchicalKey = bitcore.HDPrivateKey.fromSeed(bitcore.deps.Buffer(wordArrayToBytes(bytesToWordArray(seed)), 'ascii'), NETWORK);
        // this.HierarchicalKey = this.useOldHierarchicalKey ? this.oldHierarchicalKey : bitcore.HDPrivateKey.fromSeed(seed, NETWORK);
    }

    static wordsToSeed(words) {
        var m = new Mnemonic(words);
        return m.toHex();
    }

    getAddressKey(index) {
        checkArgType(index, "number");
        var derivedKey = this.HierarchicalKey.derive(this.basePath + index);
        return new CWPrivateKey(derivedKey.privateKey);
    }

}

class CWPrivateKey {

    // priv: private key wif or hex
    constructor(priv) {

        this.priv = null;

        // init

        try {
            if (typeof priv === "string") {
                priv = bitcore.PrivateKey(priv, NETWORK);
            }
            this.priv = priv;
        } catch (err) {
            this.priv = null;
        }
    }

    getAddress() {
        return this.priv.toAddress(NETWORK).toString();
    }

    getWIF() {
        return this.priv.toWIF();
    }

}

class CWBitcore {

    static genKeyMap(cwPrivateKeys) {
        var wkMap = {};
        cwPrivateKeys.forEach(function (cwPrivateKey) {
            wkMap[cwPrivateKey.getAddress()] = cwPrivateKey.priv;
        });

        return wkMap;
    }

    /**
     *
     * @param {string} unsignedHex
     * @param {CWPrivateKey} cwPrivateKey
     * @param {boolean|function} [disableIsFullySigned]
     * @param {function} cb
     * @returns {*}
     */
    static signRawTransaction(unsignedHex, cwPrivateKey, disableIsFullySigned, cb) {
        // make disableIsFullySigned optional
        if (typeof disableIsFullySigned === "function") {
            cb = disableIsFullySigned;
            disableIsFullySigned = null;
        }
        checkArgType(unsignedHex, "string");
        checkArgType(cwPrivateKey, "object");
        checkArgType(cb, "function");

        try {
            var tx = bitcore.Transaction(unsignedHex);

            var keyMap = CWBitcore.genKeyMap([cwPrivateKey]);
            var keyChain = [];

            async.forEachOf(
                tx.inputs,
                function (input, idx, cb) {
                    (function (cb) {
                        var inputObj;

                        // dissect what was set as input script to use it as output script
                        var script = bitcore.Script(input._scriptBuffer.toString('hex'));
                        var multiSigInfo;
                        var addresses = [];

                        switch (script.classify()) {
                            case bitcore.Script.types.PUBKEY_OUT:
                                inputObj = input.toObject();
                                inputObj.output = bitcore.Transaction.Output({
                                    script: input._scriptBuffer.toString('hex'),
                                    satoshis: 0 // we don't know this value, setting 0 because otherwise it's going to cry about not being an INT
                                });
                                tx.inputs[idx] = new bitcore.Transaction.Input.PublicKey(inputObj);

                                addresses = [script.toAddress(NETWORK).toString()];

                                return cb(null, addresses);

                            case bitcore.Script.types.PUBKEYHASH_OUT:
                                inputObj = input.toObject();
                                inputObj.output = bitcore.Transaction.Output({
                                    script: input._scriptBuffer.toString('hex'),
                                    satoshis: 0 // we don't know this value, setting 0 because otherwise it's going to cry about not being an INT
                                });
                                tx.inputs[idx] = new bitcore.Transaction.Input.PublicKeyHash(inputObj);

                                addresses = [script.toAddress(NETWORK).toString()];

                                return cb(null, addresses);

                            case bitcore.Script.types.MULTISIG_IN:
                                inputObj = input.toObject();

                                return failoverAPI(
                                    'get_script_pub_key',
                                    { tx_hash: inputObj.prevTxId, vout_index: inputObj.outputIndex },
                                    function (data) {
                                        inputObj.output = bitcore.Transaction.Output({
                                            script: data['scriptPubKey']['hex'],
                                            satoshis: bitcore.Unit.fromBTC(data['value']).toSatoshis()
                                        });

                                        multiSigInfo = CWBitcore.extractMultiSigInfoFromScript(inputObj.output.script);

                                        inputObj.signatures = bitcore.Transaction.Input.MultiSig.normalizeSignatures(
                                            tx,
                                            new bitcore.Transaction.Input.MultiSig(inputObj, multiSigInfo.publicKeys, multiSigInfo.threshold),
                                            idx,
                                            script.chunks.slice(1, script.chunks.length).map(function (s) { return s.buf; }),
                                            multiSigInfo.publicKeys
                                        );

                                        tx.inputs[idx] = new bitcore.Transaction.Input.MultiSig(inputObj, multiSigInfo.publicKeys, multiSigInfo.threshold);

                                        addresses = CWBitcore.extractMultiSigAddressesFromScript(inputObj.output.script);

                                        return cb(null, addresses);
                                    }
                                );

                            case bitcore.Script.types.MULTISIG_OUT:
                                inputObj = input.toObject();
                                inputObj.output = bitcore.Transaction.Output({
                                    script: input._scriptBuffer.toString('hex'),
                                    satoshis: 0 // we don't know this value, setting 0 because otherwise it's going to cry about not being an INT
                                });

                                multiSigInfo = CWBitcore.extractMultiSigInfoFromScript(inputObj.output.script);
                                tx.inputs[idx] = new bitcore.Transaction.Input.MultiSig(inputObj, multiSigInfo.publicKeys, multiSigInfo.threshold);

                                addresses = CWBitcore.extractMultiSigAddressesFromScript(inputObj.output.script);

                                return cb(null, addresses);

                            case bitcore.Script.types.SCRIPTHASH_OUT:
                                // signing scripthash not supported, just skipping it, something external will have to deal with it
                                return cb();

                            case bitcore.Script.types.DATA_OUT:
                            case bitcore.Script.types.PUBKEY_IN:
                            case bitcore.Script.types.PUBKEYHASH_IN:
                            case bitcore.Script.types.SCRIPTHASH_IN:
                                // these are 'done', no reason to touch them!
                                return cb();

                            default:
                                return cb(new Error("Unknown scriptPubKey [" + script.classify() + "](" + script.toASM() + ")"));
                        }

                    })(function (err, addresses) {
                        if (err) {
                            return cb(err);
                        }

                        // NULL means it isn't neccesary to sign it
                        if (addresses === null) {
                            return cb();
                        }

                        // unique filter
                        addresses = addresses.filter(function (address, idx, self) {
                            return address && self.indexOf(address) === idx;
                        });

                        var _keyChain = addresses.map(function (address) {
                            return typeof keyMap[address] !== "undefined" ? keyMap[address] : null;
                        }).filter(function (key) {
                            return !!key
                        });

                        if (_keyChain.length === 0) {
                            throw new Error("Missing private key to sign input: " + idx);
                        }

                        keyChain = keyChain.concat(_keyChain);

                        cb();
                    });
                },
                function (err) {
                    if (err) {
                        // async.nextTick to avoid parent trycatch
                        return async.nextTick(function () {
                            cb(err);
                        });
                    }

                    // unique filter
                    keyChain = keyChain.filter(function (key, idx, self) {
                        return key && self.indexOf(key) === idx;
                    });

                    // sign with each key
                    keyChain.forEach(function (priv) {
                        tx.sign(priv);
                    });

                    // disable any checks that have anything to do with the values, because we don't know the values of the inputs
                    var opts = {
                        disableIsFullySigned: disableIsFullySigned,
                        disableSmallFees: true,
                        disableLargeFees: true,
                        disableDustOutputs: true,
                        disableMoreOutputThanInput: true
                    };

                    // async.nextTick to avoid parent trycatch
                    async.nextTick(function () {
                        cb(null, tx.serialize(opts));
                    });
                }
            );
        } catch (err) {
            // async.nextTick to avoid parent trycatch
            async.nextTick(function () {
                cb(err);
            });
        }
    }

    extractMultiSigAddressesFromScript(script) {
        checkArgType(script, "object");

        if (!script.isMultisigOut()) {
            return [];
        }

        var nKeysCount = bitcore.Opcode(script.chunks[script.chunks.length - 2].opcodenum).toNumber() - bitcore.Opcode.map.OP_1 + 1;
        var pubKeys = script.chunks.slice(script.chunks.length - 2 - nKeysCount, script.chunks.length - 2);

        return pubKeys.map(function (pubKey) {
            // using custom code to pubKey->address instead of PublicKey.fromDER because pubKey isn't valid DER
            return bitcore.Address(bitcore.crypto.Hash.sha256ripemd160(pubKey.buf), NETWORK, bitcore.Address.PayToPublicKeyHash).toString();
            // return bitcore.Address.fromPublicKey(bitcore.PublicKey.fromDER(pubKey.buf, /* strict= */false)).toString();
        });
    }

    extractMultiSigInfoFromScript(script) {
        checkArgType(script, "object");

        if (!script.isMultisigOut()) {
            return [];
        }

        var nKeysCount = bitcore.Opcode(script.chunks[script.chunks.length - 2].opcodenum).toNumber() - bitcore.Opcode.map.OP_1 + 1;
        var threshold = bitcore.Opcode(script.chunks[script.chunks.length - nKeysCount - 2 - 1].opcodenum).toNumber() - bitcore.Opcode.map.OP_1 + 1;
        return {
            publicKeys: script.chunks.slice(script.chunks.length - 2 - nKeysCount, script.chunks.length - 2).map(function (pubKey) {
                return bitcore.PublicKey(pubKey.buf);
            }),
            threshold: threshold
        };
    }

}

function checkArgType(arg, type) {
    assert((typeof arg).toLowerCase() == type.toLowerCase(), "Invalid argument type");
}

function getGeneratedMnemonic() {
    const m = new Mnemonic(128); // 128 bits of entropy (12 word passphrase)
    const words = m.toWords();
    return words;
}

function getWalletFromMnemonic(mnemonic) {
    const wallet = new CWHierarchicalKey(mnemonic);
    return wallet;
}

function getAddressForWallet(wallet, index) {
    const cwk = wallet.getAddressKey(index);
    const address = cwk.getAddress();
    return address;
}

function printSignedHex(wallet, index, tx_hex) {
    const cwk = wallet.getAddressKey(index);
    const cb = function (err, signedHex) {
        if (err) {
            console.log(`err!`)
            console.error(err);
        }
        else {
            console.log(`signedHex:`)
            console.error(signedHex);
        }
    }
    CWBitcore.signRawTransaction(tx_hex, cwk, true, cb);
}

module.exports = {
    getGeneratedMnemonic,
    getWalletFromMnemonic,
    getAddressForWallet,
    printSignedHex,
};
