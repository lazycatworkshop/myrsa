# myrsa Project

This project implements RSA public-key cryptography in C. It includes utilities for generating RSA keys, signing messages, and verifying message signatures. This implementation serves as an educational tool for understanding the basics of RSA cryptography and its application in secure communication.

## Features

- **Key Generation**: Generate RSA public and private keys.
- **Signing**: Sign messages using a private key.
- **Verification**: Verify the authenticity of messages using the corresponding public key.

## Getting Started

### Prerequisites

- GCC compiler
- Standard C library

## Getting the code
```bash
git clone https://github.com/lazycatworkshop/myrsa.git
```
```bash
git clone git@github.com:lazycatworkshop/myrsa.git
```

### Building the Project

To build the project, run the following command in the terminal:

```sh
make all
```
This will compile the source files and generate the executable files in the bin/ directory.

## Directories

- **`/src`**: The source code.

- **`/bin`**: The executable files that are created from the source code.

- **`/include`**: The header files.

- **`/doc`**: The documents.

## Usage

### Generate RSA keys
```bash
./bin/demo_rsa_keys
```
### Signing a Message
```bash
./bin/myrsa_sign --key <private_key> --modulus <modulus> --message-file <message_file>
```
### Verifing a Message
```bash
./bin/myrsa_verify --key <public_key> --modulus <modulus> --message-file <message_file> --signature <signature>
```
## Acknowledgments

This material is for educational purposes and not recommended for production use.

This material is provided "as is" without any warranty of any kind, express or implied. By using this material, you acknowledge and agree that you are solely responsible for any and all consequences arising from its use. The creators, contributors, and distributors of this material make no representations or warranties regarding its accuracy, completeness, or fitness for any particular purpose.

You assume all risk and responsibility for any loss or damage resulting from the use of this material. In no event shall the creators, contributors, or distributors be liable for any direct, indirect, incidental, special, or consequential damages, or any damages whatsoever, arising out of or in connection with the use or performance of this material.

Use this material at your own risk.

---