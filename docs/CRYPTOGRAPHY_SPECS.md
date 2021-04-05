***BACKEND*** => pyca/cryptography

***PRIMITIVE*** => AES-GCM

VAULT
=====
**ENCRYPTION**: Encryption happens as soon as the user logs out. We use the new password token to derive a key and a nonce 
                later saved on the DB. The session data containing the user token is deleted as soon as the user logs out and
                the encryption is done for every single field, which is overwritten with the cipher-text.

**DECRYPTION**: Decryption is done as soon as the user has been authenticated. We rebuild the cipher used for 
                encryption with the token provided (by deriving the key with the same KDF as for encryption) and get 
                the nonce corresponding to the user from the DB. Once decryption is done, the nonce is set to its default 
                value and we wait for the user to log out to re-encrypt the vault with a new key-nonce pair.

**FEATURES**:
 1. The key is never stored on the server
 2. The nonce is only kept in the DB for as long as necessary and is reset with each use
 3. AES-GCM provides authenticated encryption, thus we get integrity guarantees on top of confidentiality
 4. Seeing as the encryption is done ona a per-field basis we can imagine a system where the strength of the encryption 
    is tunable individually, both for single fields and single vaults => extensibility
