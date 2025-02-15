# JWT Tool

This tool is meant to aid in development of JWT authentication by giving the ability to create valid JWTs
as long as you have the following:
- RSA Private Key (.pem)
- Well-Known endpoint OR JWK JSON that you can use locally

### Setup
```shell
./scripts/bootstrap.sh
```
This will create `private-key.pem`, `config.json` and `users.json` files. Be sure to fill in your tenant details in the `config.json` file before proceeding.

## config.json

This file contains your JWT details.
```json
{
  "claims": {
    "iss": "<ISS_CLAIM>",
    "aud": "<AUD_CLAIM>",
    "client_id": "<CLIENT_ID_CLAIM>",
    "sub": "<SUB_CLAIM>",
    "custom_claim_1": "<CUSTOM_CLAIM_1>",
    "custom_claim_2": "<CUSTOM_CLAIM_2>"
    ...
  },
  "header": {
    "kid": "<OPTIONAL_KID>"
  },
  "well_known_endpoint": "<PATH_TO_WELL_KNOWN_JSON"
}
```

It is **required** to fill in the following:
- `iss`
- `aud`
- `client_id`
- `sub`

## Usage

### Flags
- `-configFile`: Path to your `config.json` file
- `-privateKeyFile`: Path to your private key `.pem` file
- `-jwkFile`: Local JWK file. Will be used if defined, regardless of `well_known_endpoint` being defined in `config.json`
- `-debug`: Log extra details

### Using a Well-Known Endpoint
Be sure to configure the `well_known_endpoint` property in the `confi.json` file
```sh
  go run main.go -configFile config.json -privateKeyFile private_key.pem
```

### Using a Local JWK File
Be sure to configure the `well_known_endpoint` property in the `confi.json` file
```sh
  go run main.go -configFile config.json -privateKeyFile private_key.pem
```

### Debug Logs
You can get some extra log details, by using the `-debug` flag
```sh
  go run main.go -configFile config.json -privateKeyFile private_key.pem -debug true
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
jwttool -configFile ~/Docments/jwt/config.json -privateKeyFile ~/Docments/jwt/private_key.pem -debug true
```