1. Generate EC private key with `$ openssl ecparam -name secp256k1 -genkey -noout -out server_signer_priv.pem`

2. Place correct name to private-key file in `server.conf`

3. Extract public key with `$ openssl ec -in server_signer_priv.pem -pubout -out server_signer_pub.pem` (for client and token)
