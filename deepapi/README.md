A simple NodeJS API running as a separate server from DEEPVAULT that's responsible for generating and holding the crypto key necessary for encryption at rest on the main app.

***Example Flow:***
    1. After startup DEEPVAULT sends a POST request with some data to authenticate it and some parameters to generate the new session key
    2. deepapi generates the correct key and sends it back to DEEPVAULT, together with some authentication data to check authenticity of the request
    3. DEEPVAULT stores the key in /tmp and uses it on a per request basis, leaving the data encrypted unless requested (AES is used precisely to speed up this process)
    4. At the end of its activity (or, in production, when we have less users using DEEPVAULT) we restart the whole process and rotate encryption keys for extra forward secrecy
