const crypto = require('crypto');
const bytebuffer = require('bytebuffer');

let global_key;

function operateOnNonce(key, iv, nonce, salt, iters) {
    /*
     * Encrypts/decrypts the nonce based on the encrypt boolean: if true -> encrypt, else -> decrypt
     *
     * returns the new nonce
     */
    salt = bytebuffer.fromHex(salt).buffer;
    iv = bytebuffer.fromHex(iv).buffer

    const kdf_key = crypto.pbkdf2Sync(key, salt, iters, 32, 'sha512');
    global_key = kdf_key;

    let decipher = crypto.createDecipheriv('aes-256-cbc', kdf_key, iv);
    decipher.setAutoPadding(false);

    let decryptedNonce = decipher.update(nonce, 'hex', 'utf8');
    decryptedNonce += decipher.final('utf8');

    // the operation on the nonce could be whatever, in this case it's a concat
    decryptedNonce += 'somerandomstuffhere'

    let cipher = crypto.createCipheriv('aes-256-cbc', kdf_key, iv);

    let newEncryptedNonce = cipher.update(decryptedNonce, 'utf8', 'hex');
    newEncryptedNonce += cipher.final('hex');

    return newEncryptedNonce;

};

function generateAESKey() {
    /*
     * Generates the AES key to send to DEEPVAULT
     *
     * returns the generated key
     */
    clear_key = crypto.randomBytes(32).toString('hex');
    iv = crypto.randomBytes(16);

    let cipher = crypto.createCipheriv('aes-256-cbc', global_key, iv);
    global_key = undefined;

    let encryptedAESKey = cipher.update(clear_key, 'utf8', 'hex');
    encryptedAESKey += cipher.final('hex');

    return [encryptedAESKey, iv.toString('hex')]; 
};

module.exports.generateAESKey = generateAESKey;
module.exports.operateOnNonce = operateOnNonce;
