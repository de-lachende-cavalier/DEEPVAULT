const Joi = require('joi');

const ecdh_schema = Joi.object({
    key: Joi.string()
            .hex()
            .length(266)
            .required(),

    counter: Joi.number()
                .integer()
                .min(1)
                .max(10)
});

function check_ecdh(data) {
    /*
     * Validate ECDH data sent from DEEPVAULT
     *
     * returns false if the data is invalid
     */
    const { error } = Joi.validate(data, ecdh_schema);

    if (error) {
        return false;
    } else {
        return true;
    }
};

const nonce_schema = Joi.object({
    nonce: Joi.string()
              .hex()
              .length(128)
              .required(),

    counter: Joi.number()
                .integer()
                .min(1)
                .max(10),

    iv: Joi.string()
            .hex()
            .length(32)
            .required(),

    salt: Joi.string()
             .hex()
             .length(64)
             .required(),

    iterations: Joi.number()
                   .integer()
                   .min(100000)
                   .required()
});

function check_nonce(data) {
    /*
     * Validate the nonce sent by DEEPVAULT
     *
     * returns false if the data is invalid
     */
    const { error } = Joi.validate(data, nonce_schema);

    if (error) {
        return false;
    } else {
        return true;
    }
};

module.exports.check_ecdh = check_ecdh;
module.exports.check_nonce = check_nonce;
