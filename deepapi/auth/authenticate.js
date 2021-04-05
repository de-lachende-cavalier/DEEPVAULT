const crypto = require('crypto');

function getKeys(deepvault_public_key) {
    /*
     * Computes the shared secret from the public key sent by DEEPVAULT
     *
     * returns the secret key and deepapi's public key
     */

    let {publicKey, privateKey} = crypto.generateKeyPairSync('ec', {
                                                            namedCurve: 'secp521r1',
                                                            publicKeyEncoding: {
                                                                type: 'spki',
                                                                format: 'pem',
                                                            }
                                                        });

    deepvault_public_key = crypto.createPublicKey(deepvault_public_key);  // the DEEPVAULT key is also pem, spki
    return [crypto.diffieHellman({privateKey: privateKey, publicKey: deepvault_public_key}), publicKey];

}

module.exports.getKeys = getKeys;




