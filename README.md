# myrsa Project

This project implements RSA public-key cryptography in C. It includes utilities for generating RSA keys, signing messages, and verifying message signatures. This implementation serves as an educational tool for understanding the basics of RSA cryptography and its applications.

## Getting Started

### Environment
A reference Dockerfile:

```console
FROM ubuntu:26.04

# Install minimal tools to run the test
RUN apt-get update && apt-get install -y \
    build-essential \
    make \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /workspace

# Default command to open an interactive shell when the container starts
CMD ["/bin/sh"]
```


### Getting the code
```bash
git clone https://github.com/lazycatworkshop/myrsa.git
```

### Building the Project

To build the project, run the following command in the terminal:

```sh
make all
```

To remove created artifacts during the build process:

```sh
make clean
```

## doc
The doc directory contains Markdown documents.

**pub_key_cryptography.md**: Introduction to the two-key lock.

**how_rsa_works.md**: Introduction to the RSA system.

**rsa_lab_signing.md**: A practical exercise of RSA process using openssl.

**public_key_certificate.md**: An exercise of X.509 certifications.

**p7b.md**: An exercise of document signing using PKCS#7.

**code_signing.md**: An exercise of software signing with a hardware security module (HSM).

## Disclaimer

This material is provided "as is" without any warranty of any kind, express or implied. By using this material, you acknowledge and agree that you are solely responsible for any and all consequences arising from its use. The creators, contributors, and distributors of this material make no representations or warranties regarding its accuracy, completeness, or fitness for any particular purpose.

You assume all risk and responsibility for any loss or damage resulting from the use of this material. In no event shall the creators, contributors, or distributors be liable for any direct, indirect, incidental, special, or consequential damages, or any damages whatsoever, arising out of or in connection with the use or performance of this material.

Use this material at your own risk.
