/*
 * REQUEST FLOW:
 *
 * DEEPVAULT -> POST /auth :: to send the pub key to deepapi, and get deepapi's public key
 * DEEPVAULT -> POST /auth/challenge :: to engage challenge-response auth
 * DEEPVAULT -> GET /auth/challenge :: to get the AES key from deepapi
 *
 */

const { getKeys } = require('../auth/authenticate.js');
const { operateOnNonce, generateAESKey } = require('../auth/utils.js');
const { check_ecdh, check_nonce } = require('../auth/validate.js');

const express = require('express');
const router = express.Router();

let sharedSecret; 
let count = 0;

router.post('/auth', (req, res) => {
    /*
     * Receives the DEEPVAULT public key and sends its own public key
     */
    count += 1;

    if (check_ecdh) { 
        keys = getKeys(req.body.pub_key);
        res.status(200).json({pub_key: keys[1]});
        sharedSecret = keys[0]; 
    } else {
        res.status(400).end();
    }
});

let completedChallengeResponse = false;

router.post('/auth/challenge', (req, res) => {
    /*
     * Receives the encrypted nonce from DEEPVAULT and operates on it; sends it back at the end
     */
    count += 1;

    if (check_nonce) {
        completedChallengeResponse = true;
        updatedNonce = operateOnNonce(sharedSecret, req.body.iv, req.body.nonce, 
                                    req.body.salt, req.body.iterations);
        res.status(200).json({api_nonce: updatedNonce});
    } else {
        res.status(400).end();
    }
});


router.get('/aes', (req, res) => {
    /*
     * Exposes the AES key
     */
    count += 1;

    if (completedChallengeResponse) {
        aes_key_iv = generateAESKey(sharedSecret)
        res.status(200).json({key: aes_key_iv[0], iv: aes_key_iv[1]});
    } else {
        res.status(403).end();
    }
});

module.exports = router;

