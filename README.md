# JWT Tool

This tool is meant to aid in development of JWT authentication by giving the ability to create valid JWTs
as long as you have the following:
- RSA Private Key (.pem)
- Well-Known endpoint OR JWK JSON that you can use locally

### Setup
```shell
./scripts/bootstrap.sh
```
This will create a `config.json`file. Be sure to fill in your tenant details in the `config.json` file before proceeding.

## config.json

This file contains your JWT details.
```json
{
  "use_rs": true, // used in determining whether to use the the resouece server or create a custom token
  "debug": false, // activate extra logging
  "custom": {
    "claims": {
      "iss": "https://domain.com",
      "aud": "https://domain.com/audience",
      "client_id": "<CLIENT_ID>",
      "sub": "<USER_ID>",
      "custom_claim": "<CUSTOM_CLAIM>",
      "scope": "myscope",
      "exp": 9413432160
    },
    "header": {
      "kid": "<YOU CAN GRAB THIS FROM YOUR JWK"
    },
    "well_known_endpoint": "https://domain.com/.well-known/jwks.json",
    "jwk_local": false, // activate if storing the jwk in a local file, combine with the a config value for `jwk_local_file`
    "private_key_file_path": "private-key.pem"
  },
  // NOTE: this config is not necessary and won't work until we are properly generating the access token in auth0-server for my-account
  "rs": {
    "setup_rs": false,
    "domain": "domain.com",
    "client_secret": "<CLIENT_SECRET>",
    "client_id": "<CLIENT_ID>",
    // TODO: Use M2M for this....
    "username": "<USER_IDENTIFIER>",
    "password": "<USER_PASSWORD>"
  }
}
```

If using `custom` it is **required** to fill in the following:
- `iss`
- `aud`
- `client_id`
- `sub`

## Usage

### Flags
- `-configFile`: Path to your `config.json` file

### Using a Well-Known Endpoint
Be sure to configure the `well_known_endpoint` property in the `config.json` file
```sh
  go run *.go -configFile config.json
```

### Using a Local JWK File
Be sure to configure the `well_known_endpoint` property in the `confi.json` file
```sh
  ggo run *.go -configFile config.json
```

### Debug Logs
You can get some extra log details, by using the `debug` setting in the config file
```sh
  go run *.go -configFile config.json
```

## Make script executable from terminal
If you don't want to `cd` into this repo each time to run the script, execute the following commands.
Note your'll need admin privs on your mac.
```shell
## Build executable
go build .

## OPTIONAL: Rename if you want
sudo mv jwt_tool jwttool

## Move to bin
sudo mv jwttool /usr/local/bin/
```
After these command you should be able to run the script from any location with
```shell
jwttool -configFile config.json
```
