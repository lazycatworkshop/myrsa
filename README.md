# myrsa Project

This project implements RSA public-key cryptography in C. It includes utilities for generating RSA keys, signing messages, and verifying message signatures. This implementation serves as an educational tool for understanding the basics of RSA cryptography and its applications in secure communication.

## Getting Started

### Prerequisites

- GCC compiler
- Standard C library

## Getting the code
```bash
git clone https://github.com/lazycatworkshop/myrsa.git
```

### Building the Project

To build the project, run the following command in the terminal:

```sh
make all
```
This will compile the source files and generate the executable files.

To build the project with debug symbols:
```sh
make DEBUG=1
```

To remove the executables:
```console
$ make clean
rm -rf obj/* bin/* test/*
$ 
```

To remove the directories created by the build process:
```console
$ make clean_dir
rm -rf obj bin test
$ 
```

## Directories

- **`/src`**: The source code.

- **`/include`**: The header files.

- **`/doc`**: The documents.

Created directories by the build process:

- **`/obj`**: The object files.
- **`/bin`**: The executables except for unit tests.
- **`/test`**: The executables for unit tests.

## Documents

The `doc` directory contains the following documentation files in Markdown:

- **`pub_key_cryptography.md`**: A simple explanation about the two-key scheme.
- **`rsa_lab_signing.md`**: A hands-on exercise with the OpenSSL utility.
- **`how_rsa_works.md`**: A deeper exploration of the RSA algorithm.
- **`public_key_certificate.md`**: A look into X.509 certificates.
- **`code_signing_self_signed_cert.md`**: A demonstration of code signing using a self-signed certificate stored in a YubiKey token.
- **`PKCS#7.md`**: A tutorial of document signing with Cryptographic Message Syntax specification.

## Development environment
- Raspberry Pi 4B, 4GB memory
- OS:
```console
$ uname -a
Linux fortest 6.6.31+rpt-rpi-v8 #1 SMP PREEMPT Debian 1:6.6.31-1+rpt1 (2024-05-29) aarch64 GNU/Linux
$
```
- Compiler
```text
gcc version 12.2.0 (Debian 12.2.0-14) 
```
- make
```console
$ make -v
GNU Make 4.3
Built for aarch64-unknown-linux-gnu
```
- Microsoft Visual Studio Code


## Disclaimer

This material is provided "as is" without any warranty of any kind, express or implied. By using this material, you acknowledge and agree that you are solely responsible for any and all consequences arising from its use. The creators, contributors, and distributors of this material make no representations or warranties regarding its accuracy, completeness, or fitness for any particular purpose.

You assume all risk and responsibility for any loss or damage resulting from the use of this material. In no event shall the creators, contributors, or distributors be liable for any direct, indirect, incidental, special, or consequential damages, or any damages whatsoever, arising out of or in connection with the use or performance of this material.

Use this material at your own risk.

---