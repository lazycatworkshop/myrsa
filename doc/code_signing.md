# Code Signing

Malicious software, commonly referred to as malware, dates back to the 1970s, with the term "virus" becoming even more widespread. In response, people have relied on antivirus software to detect and eliminate such threats, only to discover that these programs themselves are sometimes Trojan horses. If we could assign a unique ID to each piece of software, similar to how passports are used at immigration checkpoints, it could provide greater peace of mind.

Today, electronic documents are often protected by digital signatures, ensuring their authenticity and integrity. We can apply the same concept to software to enhance its identification and verification.

To achieve maximum security, it is generally preferred to obtain a certificate from a Certificate Authority (CA), trusted organizations or entities responsible for issuing digital certificates [X.509][RFC5280]. Requirements for publicly trusted code signing certificates are defined by the CA/Browser Forum [CSBR]. However, in certain limited access environments, it can be as simple as using a self-signed certificate. This approach is often used to verify that code comes from the same publisher throughout the development and testing stages or for internal deployments. In this tutorial, we will use a self-signed certificate for educational purposes to demonstrate the process.

## Preparation

### Private key
Like signing a document, signing software requires a private key. The RSA key pair and its signature scheme follow PKCS #1 [PKCS#1]:

```console 
sender$ openssl genrsa -out private_key.pem 2048
sender$ openssl rsa -text -in private_key.pem -noout
Private-Key: (2048 bit, 2 primes)
modulus:
    00:b6:4f:d8:1e:a7:51:9e:20:c4:05:7a:0a:0e:bb:
    3a:c9:04:0e:08:c2:65:6a:fe:f2:3a:ea:f8:17:48:
    39:03:ea:78:a7:41:e4:fa:43:cc:2b:8e:e4:c0:0b:
    13:27:a2:cb:d9:a8:dc:6b:2b:1f:90:e1:06:6a:78:
    29:7f:93:cc:16:94:09:d5:ee:b9:10:6d:ec:6e:b6:
    f6:55:fa:a1:63:9f:ab:7f:ce:8f:fd:86:56:3b:fc:
    1d:45:c8:a3:ea:cc:a8:c5:f5:e9:e3:3d:01:30:cd:
    42:33:18:c8:e2:d3:44:54:c8:4d:d3:77:e7:7d:a4:
    f9:52:99:1a:c8:15:4b:c8:b0:c5:49:09:6d:67:25:
    02:cd:7a:c5:78:1f:93:43:49:1b:61:b9:c2:f0:d7:
    60:67:df:18:ef:a9:77:15:93:56:49:e0:e0:f1:44:
    cc:f7:1a:7a:4a:c8:c8:45:5b:10:b3:e6:97:eb:bb:
    ad:95:ae:f2:cc:e2:24:0c:85:b6:e0:39:67:57:b0:
    f2:61:fc:c1:70:49:20:27:a0:39:8a:00:c1:a5:29:
    5a:7f:5e:6a:03:69:e1:b3:5b:3d:8d:55:90:dd:57:
    8f:3d:f0:d6:b0:77:9a:88:66:3b:e6:81:94:74:4b:
    04:eb:f8:68:2e:7e:6a:61:f7:4b:bc:1f:9d:80:bc:
    06:cb
publicExponent: 65537 (0x10001)
privateExponent:
    52:d3:67:6e:55:b9:a0:cb:66:02:ce:f4:ee:c8:64:
    e6:9a:2e:fe:0f:c3:1f:9e:ff:d1:80:9a:81:89:50:
    4d:d5:22:47:6a:8a:6a:a0:8e:8b:63:79:cd:3d:ba:
    d0:11:07:e7:b4:ed:9e:ca:92:a6:b1:74:c6:be:1c:
    ac:57:2b:2b:3e:ca:51:25:09:72:cb:5d:d4:d6:ce:
    87:35:3c:49:14:6b:47:bf:42:6f:7d:ae:83:c6:00:
    4e:89:de:de:77:68:5d:b7:61:30:d9:b0:46:c9:99:
    bf:b9:0c:da:ef:fc:65:40:33:0b:55:b8:17:be:f1:
    7e:73:0c:55:c6:47:0d:bf:6a:b8:1c:36:cc:30:d9:
    a4:2f:3d:15:a0:2d:94:22:bc:c9:dc:5b:53:df:fd:
    ce:c1:40:b1:40:dd:de:3c:cb:72:c5:9d:f1:bb:53:
    37:3e:26:05:f9:47:81:8d:92:18:ed:1f:1e:6d:77:
    11:ed:fb:11:6c:ae:18:e7:a1:09:4a:c7:9e:6c:87:
    cd:2d:d4:d6:e1:6e:7e:ca:ff:82:49:b3:5a:4d:1e:
    a9:35:3f:56:e3:28:24:54:8f:09:cf:e3:09:04:cf:
    7d:27:b5:3a:37:2b:0b:62:5e:bf:93:4c:0d:97:f8:
    8b:47:cd:db:7c:e1:e6:83:27:92:ca:00:a7:70:3c:
    b1
prime1:
:
:
```

### Certificate Signing Request (CSR)
We create a CSR [PKCS#10] to send to a Certificate Authority (CA) for signing. In this example, the CA is ourself: self-signing.

```console
sender$ openssl req -new -key private_key.pem -outform DER -out code_signing.csr -nodes -subj="/CN=localhost"
sender$ ../csr_text -f code_signing.csr 
Certificate Request:
  CertificationRequestInfo:
    Version: v1
    Subject: CN=localhost
    Subject Public Key Info:
      algorithm: rsaEncryption
Modulus:
B6 4F D8 1E A7 51 9E 20 C4 05 7A 0A 0E BB 3A C9
04 0E 08 C2 65 6A FE F2 3A EA F8 17 48 39 03 EA
78 A7 41 E4 FA 43 CC 2B 8E E4 C0 0B 13 27 A2 CB
D9 A8 DC 6B 2B 1F 90 E1 06 6A 78 29 7F 93 CC 16
94 09 D5 EE B9 10 6D EC 6E B6 F6 55 FA A1 63 9F
AB 7F CE 8F FD 86 56 3B FC 1D 45 C8 A3 EA CC A8
C5 F5 E9 E3 3D 01 30 CD 42 33 18 C8 E2 D3 44 54
C8 4D D3 77 E7 7D A4 F9 52 99 1A C8 15 4B C8 B0
C5 49 09 6D 67 25 02 CD 7A C5 78 1F 93 43 49 1B
61 B9 C2 F0 D7 60 67 DF 18 EF A9 77 15 93 56 49
E0 E0 F1 44 CC F7 1A 7A 4A C8 C8 45 5B 10 B3 E6
97 EB BB AD 95 AE F2 CC E2 24 0C 85 B6 E0 39 67
57 B0 F2 61 FC C1 70 49 20 27 A0 39 8A 00 C1 A5
29 5A 7F 5E 6A 03 69 E1 B3 5B 3D 8D 55 90 DD 57
8F 3D F0 D6 B0 77 9A 88 66 3B E6 81 94 74 4B 04
EB F8 68 2E 7E 6A 61 F7 4B BC 1F 9D 80 BC 06 CB

Exponent: 65537
    Attributes: Empty
  Signature Algorithm: sha256WithRSAEncryption
  Signature:
21 85 1A C4 5D AD 1E DE EF 63 5D E9 21 E7 DA 75
58 88 44 F9 E7 66 70 B9 1C EA AE DE AB D9 52 08
AB BA C9 29 67 9A 7D 2C 83 7B 19 E1 43 85 4A 41
87 AB 91 14 A4 3E E4 26 BF F1 CB 2B 58 9C 2D 91
91 8F 77 D2 1D CF 9C 26 46 DB 7B 8F C2 52 EC 78
4A 18 54 8F EB 04 5B 03 1F 5F DA 6B 65 14 E6 AE
23 0B BA 1B 73 26 36 EC BB 28 6C E7 DA 87 A1 F7
F8 2E FF AD 9D 45 E5 D3 9F 28 7F C7 13 38 7B F4
F3 94 D9 A1 F4 54 A9 E7 E7 89 AD BE 5A EB E4 68
46 03 6D 06 EA 26 2F F7 99 ED F3 23 8D DA B6 D3
1E AD 84 D3 0C C4 EC 9D 7A 2B 27 30 75 E2 FD 2D
4C AC 05 25 DC C1 72 CD AA D0 78 CE 43 42 1D 3F
01 51 A2 D3 CD 23 3F E9 C1 A4 CA D8 15 02 5A A8
DC DC 2B 90 71 7D 1F 44 89 6E 46 F1 02 7A 78 5A
83 0B 45 2B D7 B6 DE C0 E5 0E 46 71 C5 49 E4 E7
96 9E C0 7E E4 53 CA F5 5C 2C 2D 6F 1D 8D 55 B8
```

The top level of CSR structure is as follows [PKCS#10]:

```text
CertificationRequest ::= SEQUENCE {
        certificationRequestInfo CertificationRequestInfo,
        signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
        signature          BIT STRING
}
```

The certificationRequestInfo is the value to be signed, similar the toBeSigned component in a public key certificate:

```text
-- Certificate requests
   CertificationRequestInfo ::= SEQUENCE {
        version       INTEGER { v1(0) } (v1,...),
        subject       Name,
        subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
        attributes    [0] Attributes{{ CRIAttributes }}
}
```

We gave openssl reduced arguments to build the key components to our example: `subjectPKInfo` in `certificationRequestInfo` and `signature`.

###  Certificate
We submit the CSR to generate a certificate [X.509][RFC5280] associated with the software to be sent out. The certificate is DER-encoded [X.690].

```console
sender$ openssl x509 -req -days 365 -inform DER -in code_signing.csr -signkey private_key.pem  -outform DER -out code_signing_cert.der
Certificate request self-signature ok
subject=CN=localhost
sender$ ../asn1parser -f code_signing_cert.der | head
SEQUENCE  L = 727
-SEQUENCE  L = 447
--Context-specific 0  L = 3
---INTEGER  L = 1
--INTEGER  L = 20
--SEQUENCE  L = 13
---OBJECT IDENTIFIER  L = 9
---NULL  L = 0
--SEQUENCE  L = 20
---SET  L = 18
sender$ ../x509_text_public_key -f code_signing_cert.der 
X.509 Certificate:
  TBSCertificate:
    Version: v3
    Serial Number: 55CD4EDE55EB4C462EFD52D19BAFA8489A3D1220
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: CN=localhost
    Validity:
      Not Before: 261122113327Z
      Not After : 271122113327Z
    Subject: CN=localhost
    Subject Public Key Info:
      Algorithm: rsaEncryption
      Subject Public Key:
Modulus:
B6 4F D8 1E A7 51 9E 20 C4 05 7A 0A 0E BB 3A C9
04 0E 08 C2 65 6A FE F2 3A EA F8 17 48 39 03 EA
78 A7 41 E4 FA 43 CC 2B 8E E4 C0 0B 13 27 A2 CB
D9 A8 DC 6B 2B 1F 90 E1 06 6A 78 29 7F 93 CC 16
94 09 D5 EE B9 10 6D EC 6E B6 F6 55 FA A1 63 9F
AB 7F CE 8F FD 86 56 3B FC 1D 45 C8 A3 EA CC A8
C5 F5 E9 E3 3D 01 30 CD 42 33 18 C8 E2 D3 44 54
C8 4D D3 77 E7 7D A4 F9 52 99 1A C8 15 4B C8 B0
C5 49 09 6D 67 25 02 CD 7A C5 78 1F 93 43 49 1B
61 B9 C2 F0 D7 60 67 DF 18 EF A9 77 15 93 56 49
E0 E0 F1 44 CC F7 1A 7A 4A C8 C8 45 5B 10 B3 E6
97 EB BB AD 95 AE F2 CC E2 24 0C 85 B6 E0 39 67
57 B0 F2 61 FC C1 70 49 20 27 A0 39 8A 00 C1 A5
29 5A 7F 5E 6A 03 69 E1 B3 5B 3D 8D 55 90 DD 57
8F 3D F0 D6 B0 77 9A 88 66 3B E6 81 94 74 4B 04
EB F8 68 2E 7E 6A 61 F7 4B BC 1F 9D 80 BC 06 CB

Exponent: 65537
    Extensions:
id-ce-subjectKeyIdentifier
E1 9E 49 98 96 BD 36 99 D9 D1 F8 67 2F F9 00 3B
03 C9 C5 81 

  Signature:
    Algorithm: sha256WithRSAEncryption
    Signature:
9C 48 13 EB BD B1 7E C8 CA 67 2E 03 D3 59 60 78
61 BE CD 82 9E AA 4A 1E 3A FF EA 8B 66 DC A7 0C
9C B9 A5 9D 7F DE DE 59 03 99 D0 F9 A1 DC B6 5D
30 57 1C BA 83 09 13 B1 80 36 ED 73 85 AC FD 62
47 A6 B1 43 FC 96 9C 76 E3 68 47 E1 17 DD DF 2E
E0 D6 86 2A F5 70 39 4A BE 56 97 FD 80 5E 13 E6
61 88 64 ED 72 40 6D FC 60 E4 78 6B D3 99 13 9F
A4 55 6D 04 F7 73 89 C8 0B B2 99 FE D3 5F A4 90
D5 54 3F 61 AC 44 71 95 56 4A 13 49 83 FB 8C DC
FD 00 EF 70 50 27 E1 26 BF EB 02 2F A0 0B 5D 15
C1 03 B7 EE AE EC 15 DE AC 97 E8 27 04 48 33 DD
30 DC A6 54 2F B9 05 05 6D 86 D3 CB FD 53 4B D2
8F EB C3 D9 90 80 66 92 FB 2C D0 72 F7 F7 37 11
2B DA 86 EA 07 D1 A6 7F 90 AE 6E 2F FD DD D6 DA
50 55 B7 48 D8 17 5A FB BC 84 AA C1 F5 C8 BB E6
9B 01 0F 31 B6 4D 77 11 3F DE A4 DC C7 43 2E 31
```

## Hardware key storage

From ssl.com:

```text
Starting June 1, 2023, SSL.com’s Organization Validation (OV) and Individual Validation (IV) Code Signing Certificates will only be issued either on Federal Information Processing Standard 140-2 (FIPS 140-2) [FIPS 140-2] USB tokens or through our eSigner cloud code signing service.
```

This highlights the importance of securing private keys in a secure enclave, such as a hardware token.

In this example, we use an YubiKey NFC FIPS [YubiKey] as the secure token. Its PIV application [SP800-73] stores the private key and certificate. We start with installing Yubico’s YubiKey Manager CLI:

```console
sender$ sudo apt update
Hit:1 http://deb.debian.org/debian trixie InRelease
Hit:2 http://deb.debian.org/debian trixie-updates InRelease     
Hit:3 http://deb.debian.org/debian-security trixie-security InRelease          
Hit:4 http://archive.raspberrypi.com/debian trixie InRelease                   
62 packages can be upgraded. Run 'apt list --upgradable' to see them.
sender$ sudo apt install yubikey-manager
The following packages were automatically installed and are no longer required:
  libeac3  opensc-pkcs11
Use 'sudo apt autoremove' to remove them.

Installing:
  yubikey-manager

Summary:
  Upgrading: 0, Installing: 1, Removing: 0, Not Upgrading: 62
  Download size: 49.7 kB
  Space needed: 293 kB / 49.2 GB available

Get:1 http://deb.debian.org/debian trixie/main arm64 yubikey-manager all 5.6.1+repack1-1 [49.7 kB]
Fetched 49.7 kB in 0s (259 kB/s)           
Selecting previously unselected package yubikey-manager.
(Reading database ... 89786 files and directories currently installed.)
Preparing to unpack .../yubikey-manager_5.6.1+repack1-1_all.deb ...
Unpacking yubikey-manager (5.6.1+repack1-1) ...
Setting up yubikey-manager (5.6.1+repack1-1) ...
Processing triggers for man-db (2.13.1-1) ...
sender$ ykman info
WARNING: PC/SC not available. Smart card (CCID) protocols will not function.
ERROR: No YubiKey detected!
sender$ sudo ykman info
Device type: YubiKey 5 NFC FIPS
Serial number: 28989286
Firmware version: 5.4.3
Form factor: Keychain (USB-A)
Enabled USB interfaces: OTP, FIDO, CCID
NFC transport is enabled

Applications	USB    	NFC    
Yubico OTP  	Enabled	Enabled
FIDO U2F    	Enabled	Enabled
FIDO2       	Enabled	Enabled
OATH        	Enabled	Enabled
PIV         	Enabled	Enabled
OpenPGP     	Enabled	Enabled
YubiHSM Auth	Enabled	Enabled
```

With the tool is ready, we can transfer the private key and optionally the certificate to the YubiKey.

```console
sender$ sudo ykman piv keys import 9a private_key.pem 
Enter a management key [blank to use default key]: 
Private key imported into slot AUTHENTICATION.
sender$ sudo ykman piv certificates import 9a  code_signing_cert.der 
Enter a management key [blank to use default key]: 
Certificate imported into slot AUTHENTICATION
sender$ 
```

## The signing
Applications access the saved private key on the YubiKey through a cryptographic token interface, PKCS #11 [PKCS#11]. Install Opensc for PKCS #11 operations:

```console
sender$ sudo apt install opensc
Installing:                     
  opensc

Summary:
  Upgrading: 0, Installing: 1, Removing: 0, Not Upgrading: 62
  Download size: 394 kB
  Space needed: 2,618 kB / 49.2 GB available

Get:1 http://deb.debian.org/debian trixie/main arm64 opensc arm64 0.26.1-2 [394 kB]
Fetched 394 kB in 0s (1,185 kB/s)
Selecting previously unselected package opensc.
(Reading database ... 89804 files and directories currently installed.)
Preparing to unpack .../opensc_0.26.1-2_arm64.deb ...
Unpacking opensc (0.26.1-2) ...
Setting up opensc (0.26.1-2) ...
Processing triggers for man-db (2.13.1-1) ...
sender$ pkcs11-tool -T
Available slots:
No slots.
sender$ sudo pkcs-tool -T
sudo: pkcs-tool: command not found
sender$ sudo pkcs11-tool -T
Available slots:
Slot 0 (0x0): Yubico YubiKey OTP+FIDO+CCID 00 00
  token label        : localhost
  token manufacturer : piv_II
  token model        : PKCS#15 emulated
  token flags        : login required, rng, token initialized, PIN initialized
  hardware version   : 0.0
  firmware version   : 0.0
  serial num         : 97c1aed7dcce1aea
  pin min/max        : 4/8
  uri                : pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost
  ```

We can find the slot in which our private key and certificate preside.

```console
ender$ sudo pkcs11-tool -O
Using slot 0 with a present token (0x0)
Public Key Object; RSA 2048 bits
  label:      PIV AUTH pubkey
  ID:         01
  Usage:      encrypt, verify, verifyRecover, wrap
  Access:     none
  uri:        pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;id=%01;object=PIV%20AUTH%20pubkey;type=public
Certificate Object; type = X.509 cert
  label:      Certificate for PIV Authentication
  subject:    DN: CN=localhost
  serial:     55CD4EDE55EB4C462EFD52D19BAFA8489A3D1220
  ID:         01
  uri:        pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;id=%01;object=Certificate%20for%20PIV%20Authentication;type=cert
  :
  :
  ```
Yubico's slot numbers (e.g., 9a) map to PKCS #11 slots (starting from ID 1).

### A test software

Create a simple C program as the signing target:

```console
sender$ echo -e '#include <stdio.h>\n\nint main() {\n    printf("Hello, World!\\n");\n    return 0;\n}' > hello.c
sender$ cat hello.c
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
sender$ gcc hello.c -o hello
sender$ ./hello
Hello, World!
sender$ 
```

### Signing the code

The `SHA256-RSA-PKCS` mechanism hashes the file with SHA-256 [FIPS 180-4], wraps the digest in a DigestInfo structure, and applies RSASSA-PKCS1-v1_5 padding and the private-key operation [PKCS#1].

```console
sender$ sudo pkcs11-tool --sign --id 1 --mechanism SHA256-RSA-PKCS -i hello -o hello.sig
Using slot 0 with a present token (0x0)
Logging in to "localhost".
Please enter User PIN: 
Using signature algorithm SHA256-RSA-PKCS
sender$ 
```

### The code and collaterals

In addition to the software, we also need to attach some other information so that the recipient can verify its authenticity, such as the signature and the public key or certificate. The certificate can be put online when it is used to sign multiple products.

```console
sender$ cp hello ../receiver
sender$ sudo cp hello.sig ../receiver/
sender$ cp code_signing_cert.der ../receiver
```

## The authentication

### Validating the certificate

```console
sender$ cd ../receiver/
```

When a recipient received the software and its collaterals, the first step is to validate the certificate which contains the public key. 

```console
receiver$ ../x509_extract_sig -c code_signing_cert.der -s code_signing_cert.der.sig
receiver$ ../x509_extract_pubkey -c code_signing_cert.der -p code_signing_cert.der.pubkey
receiver$ ../myrsa_trapdoor -m code_signing_cert.der.sig -k code_signing_cert.der.pubkey 
00 01 ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff 00 30 31 30 
0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 
1e 33 cd c0 88 94 78 4f f6 48 84 de 8b 02 ce a8 
9e df ec 9d 0d 47 93 20 7b 82 21 04 71 0d a4 ea 

receiver$ ../x509_extract_tbs -c code_signing_cert.der -t code_signing_cert.der.tbs
receiver$ ../myrsa_sha256 -i code_signing_cert.der.tbs -o code_signing_cert.der.tbs.dgst
receiver$ hexdump -C code_signing_cert.der.tbs.dgst 
00000000  1e 33 cd c0 88 94 78 4f  f6 48 84 de 8b 02 ce a8  |.3....xO.H......|
00000010  9e df ec 9d 0d 47 93 20  7b 82 21 04 71 0d a4 ea  |.....G. {.!.q...|
00000020
receiver$ 
```

The TBSCertificate's digest matches the one extracted from the certificate's signature [RFC5280].

### Authenticating the software

```console
receiver$ sudo ../myrsa_trapdoor -m helo.sig -k code_signing_cert.der.pubkey 
fopen message file: No such file or directory
receiver$ sudo ../myrsa_trapdoor -m hello.sig -k code_signing_cert.der.pubkey 
00 01 ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff 00 30 31 30 
0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 
5b 1d f8 ea b3 c4 b4 50 49 95 3c 6c 62 9a 0a 22 
24 f2 ac b6 3a 2b 9e 6a d6 d6 68 74 37 2b 9d 0e 

receiver$ ../myrsa_sha256 -i hello -o hello.dgst
receiver$ hexdump -C hello.dgst
00000000  5b 1d f8 ea b3 c4 b4 50  49 95 3c 6c 62 9a 0a 22  |[......PI.<lb.."|
00000010  24 f2 ac b6 3a 2b 9e 6a  d6 d6 68 74 37 2b 9d 0e  |$...:+.j..ht7+..|
00000020
receiver$ 
```

The software's digest matches the one extracted from the signature [PKCS#1].


## References

1. [X.509] - ITU-T Recommendation X.509: Information Technology - Open Systems Interconnection - The Directory: Public-key and attribute certificate frameworks. Retrieved from https://www.itu.int/rec/t-rec-x.509/en
2. [X.690] - ITU-T Recommendation X.690: Information Technology - ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER). Retrieved from https://www.itu.int/rec/T-REC-X.690-202102-I
3. [PKCS#1] - Moriarty, K., Kaliski, B., Jonsson, J., & Rusch, A. (2016). RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2. Retrieved from https://www.rfc-editor.org/info/rfc8017/
4. [PKCS#10] - Nystrom, M., & Kaliski, B. (2000). RFC 2986: PKCS #10: Certification Request Syntax Specification Version 1.7. Retrieved from https://www.rfc-editor.org/info/rfc2986/
5. [RFC5280] - Cooper, D., et al. (2008). RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile. Retrieved from https://www.rfc-editor.org/info/rfc5280/
6. [PKCS#11] - OASIS. (2015). PKCS #11 Cryptographic Token Interface Base Specification Version 2.40. Retrieved from https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
7. [FIPS 180-4] - National Institute of Standards and Technology. (2015). Secure Hash Standard (SHS). Retrieved from https://csrc.nist.gov/pubs/fips/180-4/upd1/final
8. [FIPS 140-2] - National Institute of Standards and Technology. (2001). Security Requirements for Cryptographic Modules. Retrieved from https://csrc.nist.gov/pubs/fips/140-2/upd2/final
9. [SP800-73] - National Institute of Standards and Technology. (2015). SP 800-73-4: Interfaces for Personal Identity Verification. Retrieved from https://csrc.nist.gov/pubs/sp/800/73/4/upd1/final
10. [CSBR] - CA/Browser Forum. Baseline Requirements for the Issuance and Management of Publicly-Trusted Code Signing Certificates. Retrieved from https://cabforum.org/working-groups/code-signing/requirements/
11. [YubiKey] - Yubico. YubiKey 5 Series. Retrieved from https://www.yubico.com/products/yubikey-5-overview/



## Complete Listing

```console
sender$ openssl genrsa -out private_key.pem 2048
sender$ openssl rsa -text -in private_key.pem -noout
Private-Key: (2048 bit, 2 primes)
modulus:
    00:b6:4f:d8:1e:a7:51:9e:20:c4:05:7a:0a:0e:bb:
    3a:c9:04:0e:08:c2:65:6a:fe:f2:3a:ea:f8:17:48:
    39:03:ea:78:a7:41:e4:fa:43:cc:2b:8e:e4:c0:0b:
    13:27:a2:cb:d9:a8:dc:6b:2b:1f:90:e1:06:6a:78:
    29:7f:93:cc:16:94:09:d5:ee:b9:10:6d:ec:6e:b6:
    f6:55:fa:a1:63:9f:ab:7f:ce:8f:fd:86:56:3b:fc:
    1d:45:c8:a3:ea:cc:a8:c5:f5:e9:e3:3d:01:30:cd:
    42:33:18:c8:e2:d3:44:54:c8:4d:d3:77:e7:7d:a4:
    f9:52:99:1a:c8:15:4b:c8:b0:c5:49:09:6d:67:25:
    02:cd:7a:c5:78:1f:93:43:49:1b:61:b9:c2:f0:d7:
    60:67:df:18:ef:a9:77:15:93:56:49:e0:e0:f1:44:
    cc:f7:1a:7a:4a:c8:c8:45:5b:10:b3:e6:97:eb:bb:
    ad:95:ae:f2:cc:e2:24:0c:85:b6:e0:39:67:57:b0:
    f2:61:fc:c1:70:49:20:27:a0:39:8a:00:c1:a5:29:
    5a:7f:5e:6a:03:69:e1:b3:5b:3d:8d:55:90:dd:57:
    8f:3d:f0:d6:b0:77:9a:88:66:3b:e6:81:94:74:4b:
    04:eb:f8:68:2e:7e:6a:61:f7:4b:bc:1f:9d:80:bc:
    06:cb
publicExponent: 65537 (0x10001)
privateExponent:
    52:d3:67:6e:55:b9:a0:cb:66:02:ce:f4:ee:c8:64:
    e6:9a:2e:fe:0f:c3:1f:9e:ff:d1:80:9a:81:89:50:
    4d:d5:22:47:6a:8a:6a:a0:8e:8b:63:79:cd:3d:ba:
    d0:11:07:e7:b4:ed:9e:ca:92:a6:b1:74:c6:be:1c:
    ac:57:2b:2b:3e:ca:51:25:09:72:cb:5d:d4:d6:ce:
    87:35:3c:49:14:6b:47:bf:42:6f:7d:ae:83:c6:00:
    4e:89:de:de:77:68:5d:b7:61:30:d9:b0:46:c9:99:
    bf:b9:0c:da:ef:fc:65:40:33:0b:55:b8:17:be:f1:
    7e:73:0c:55:c6:47:0d:bf:6a:b8:1c:36:cc:30:d9:
    a4:2f:3d:15:a0:2d:94:22:bc:c9:dc:5b:53:df:fd:
    ce:c1:40:b1:40:dd:de:3c:cb:72:c5:9d:f1:bb:53:
    37:3e:26:05:f9:47:81:8d:92:18:ed:1f:1e:6d:77:
    11:ed:fb:11:6c:ae:18:e7:a1:09:4a:c7:9e:6c:87:
    cd:2d:d4:d6:e1:6e:7e:ca:ff:82:49:b3:5a:4d:1e:
    a9:35:3f:56:e3:28:24:54:8f:09:cf:e3:09:04:cf:
    7d:27:b5:3a:37:2b:0b:62:5e:bf:93:4c:0d:97:f8:
    8b:47:cd:db:7c:e1:e6:83:27:92:ca:00:a7:70:3c:
    b1
prime1:
    00:fd:4c:72:8f:d2:8d:9e:13:a7:a7:57:a9:28:ae:
    f1:0c:51:15:15:1b:fb:cf:68:e7:7f:92:87:68:5b:
    c8:4e:e0:f2:5d:ff:99:cf:d3:9f:c3:3d:e3:b7:cc:
    12:84:52:13:bf:2c:df:8f:5d:66:4f:cd:11:1c:f0:
    7b:8e:e3:df:98:07:d2:c0:fd:25:71:5a:dc:96:85:
    32:4e:31:29:6b:43:54:bd:ec:f2:e8:01:75:de:e3:
    cd:03:ce:6e:51:b2:07:dd:3a:0b:68:0d:88:eb:9f:
    bc:6b:b2:c4:44:d1:d3:6f:a9:d9:a0:4a:14:90:eb:
    38:f3:8b:47:6c:83:37:7b:27
prime2:
    00:b8:41:96:f5:fe:dd:f3:72:0e:ac:a8:a5:4c:cf:
    64:9f:0f:9a:06:3c:36:77:e2:11:84:bd:be:c1:c7:
    c8:fc:3c:6f:98:e8:bf:d6:f5:47:52:66:5f:67:15:
    7c:09:6d:bf:4f:b6:7a:f2:52:b8:f4:2b:a6:dd:e4:
    ce:cb:9d:f1:f8:a4:2d:ff:a5:d4:26:08:67:73:f2:
    b9:0c:06:a6:6a:d4:13:fd:13:03:96:20:44:0c:ed:
    32:20:ca:73:82:4b:9f:d3:4a:49:87:2d:15:54:59:
    4d:b5:90:ce:14:a0:74:78:26:ca:de:e8:27:e8:41:
    fe:61:e8:3a:81:c4:05:ed:bd
exponent1:
    2c:13:7d:6b:e1:6b:9b:32:38:5e:3a:36:c9:49:87:
    d0:68:db:8e:4c:cc:48:8f:2c:99:5a:5a:0d:a2:ca:
    fc:4e:d0:5d:e2:f8:54:dd:b2:53:3b:15:c1:09:d5:
    bf:08:b9:3e:ef:04:07:e2:6c:c7:3e:1b:d8:39:50:
    86:d0:c8:3b:a0:40:e0:2c:2c:b3:c8:e7:d1:99:63:
    e3:8f:52:71:c3:c9:9f:32:f8:21:be:ff:4f:c5:bc:
    0b:09:84:d0:da:75:db:dd:19:d7:05:63:e9:fc:65:
    c1:27:de:57:4b:5b:cb:76:76:d4:19:8f:f2:97:bb:
    d5:45:4b:2c:6a:b8:e0:c9
exponent2:
    70:06:c0:e8:13:eb:92:66:58:71:b5:9f:bb:11:a5:
    55:e8:40:77:66:08:9f:de:fd:53:bd:a1:cb:63:d2:
    d9:39:4d:88:a4:8a:6f:01:76:39:ad:30:78:16:61:
    f1:c1:9e:3d:b2:ef:11:82:26:1d:9e:a4:b7:e8:b3:
    aa:ac:ff:3f:73:62:dc:3a:50:c0:46:ff:cf:49:56:
    24:ef:ae:22:e9:8a:b5:a5:e7:da:51:07:ce:ec:30:
    3c:2b:9b:0b:2f:3b:9f:55:5d:5b:28:97:fd:4e:c6:
    a6:8b:c2:20:5c:66:33:df:32:1d:50:fd:62:83:2d:
    4d:0d:ca:f4:b6:df:fb:e9
coefficient:
    00:e3:91:13:d2:0e:01:16:87:64:1d:89:ec:b7:a6:
    14:4b:ce:01:02:e3:da:72:6c:5a:4e:0b:68:3a:fd:
    61:b2:b9:55:b9:80:7a:38:9c:bd:ee:54:e2:d2:9b:
    ee:de:09:f9:84:b8:10:de:f8:38:8f:11:83:cc:43:
    90:98:47:f0:15:57:95:dd:a1:19:7f:13:49:5c:ab:
    b0:15:8a:5c:b4:e3:0e:c9:6c:b0:53:e1:95:ca:b4:
    4f:86:d9:6e:66:7e:1f:9e:0c:2f:d2:11:1a:8c:1c:
    23:6c:13:ea:7d:71:22:58:db:c5:b1:28:ff:80:8e:
    3c:45:80:83:70:97:74:6a:a1
sender$ openssl req -new -key private_key.pem -outform DER -out code_signing.csr -nodes -subj="/CN=localhost"
sender$ ../csr_text -f code_signing.csr 
Certificate Request:
  CertificationRequestInfo:
    Version: v1
    Subject: CN=localhost
    Subject Public Key Info:
      algorithm: rsaEncryption
Modulus:
B6 4F D8 1E A7 51 9E 20 C4 05 7A 0A 0E BB 3A C9
04 0E 08 C2 65 6A FE F2 3A EA F8 17 48 39 03 EA
78 A7 41 E4 FA 43 CC 2B 8E E4 C0 0B 13 27 A2 CB
D9 A8 DC 6B 2B 1F 90 E1 06 6A 78 29 7F 93 CC 16
94 09 D5 EE B9 10 6D EC 6E B6 F6 55 FA A1 63 9F
AB 7F CE 8F FD 86 56 3B FC 1D 45 C8 A3 EA CC A8
C5 F5 E9 E3 3D 01 30 CD 42 33 18 C8 E2 D3 44 54
C8 4D D3 77 E7 7D A4 F9 52 99 1A C8 15 4B C8 B0
C5 49 09 6D 67 25 02 CD 7A C5 78 1F 93 43 49 1B
61 B9 C2 F0 D7 60 67 DF 18 EF A9 77 15 93 56 49
E0 E0 F1 44 CC F7 1A 7A 4A C8 C8 45 5B 10 B3 E6
97 EB BB AD 95 AE F2 CC E2 24 0C 85 B6 E0 39 67
57 B0 F2 61 FC C1 70 49 20 27 A0 39 8A 00 C1 A5
29 5A 7F 5E 6A 03 69 E1 B3 5B 3D 8D 55 90 DD 57
8F 3D F0 D6 B0 77 9A 88 66 3B E6 81 94 74 4B 04
EB F8 68 2E 7E 6A 61 F7 4B BC 1F 9D 80 BC 06 CB

Exponent: 65537
    Attributes: Empty
  Signature Algorithm: sha256WithRSAEncryption
  Signature:
21 85 1A C4 5D AD 1E DE EF 63 5D E9 21 E7 DA 75
58 88 44 F9 E7 66 70 B9 1C EA AE DE AB D9 52 08
AB BA C9 29 67 9A 7D 2C 83 7B 19 E1 43 85 4A 41
87 AB 91 14 A4 3E E4 26 BF F1 CB 2B 58 9C 2D 91
91 8F 77 D2 1D CF 9C 26 46 DB 7B 8F C2 52 EC 78
4A 18 54 8F EB 04 5B 03 1F 5F DA 6B 65 14 E6 AE
23 0B BA 1B 73 26 36 EC BB 28 6C E7 DA 87 A1 F7
F8 2E FF AD 9D 45 E5 D3 9F 28 7F C7 13 38 7B F4
F3 94 D9 A1 F4 54 A9 E7 E7 89 AD BE 5A EB E4 68
46 03 6D 06 EA 26 2F F7 99 ED F3 23 8D DA B6 D3
1E AD 84 D3 0C C4 EC 9D 7A 2B 27 30 75 E2 FD 2D
4C AC 05 25 DC C1 72 CD AA D0 78 CE 43 42 1D 3F
01 51 A2 D3 CD 23 3F E9 C1 A4 CA D8 15 02 5A A8
DC DC 2B 90 71 7D 1F 44 89 6E 46 F1 02 7A 78 5A
83 0B 45 2B D7 B6 DE C0 E5 0E 46 71 C5 49 E4 E7
96 9E C0 7E E4 53 CA F5 5C 2C 2D 6F 1D 8D 55 B8

sender$ openssl x509 -req -days 365 -inform DER -in code_signing.csr -signkey private_key.pem  -outform DER -out code_signing_cert.der
Certificate request self-signature ok
subject=CN=localhost
sender$ ../asn1parser -f code_signing_cert.der | head
SEQUENCE  L = 727
-SEQUENCE  L = 447
--Context-specific 0  L = 3
---INTEGER  L = 1
--INTEGER  L = 20
--SEQUENCE  L = 13
---OBJECT IDENTIFIER  L = 9
---NULL  L = 0
--SEQUENCE  L = 20
---SET  L = 18
sender$ ../x509_text_public_key -f code_signing_cert.der 
X.509 Certificate:
  TBSCertificate:
    Version: v3
    Serial Number: 55CD4EDE55EB4C462EFD52D19BAFA8489A3D1220
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: CN=localhost
    Validity:
      Not Before: 261122113327Z
      Not After : 271122113327Z
    Subject: CN=localhost
    Subject Public Key Info:
      Algorithm: rsaEncryption
      Subject Public Key:
Modulus:
B6 4F D8 1E A7 51 9E 20 C4 05 7A 0A 0E BB 3A C9
04 0E 08 C2 65 6A FE F2 3A EA F8 17 48 39 03 EA
78 A7 41 E4 FA 43 CC 2B 8E E4 C0 0B 13 27 A2 CB
D9 A8 DC 6B 2B 1F 90 E1 06 6A 78 29 7F 93 CC 16
94 09 D5 EE B9 10 6D EC 6E B6 F6 55 FA A1 63 9F
AB 7F CE 8F FD 86 56 3B FC 1D 45 C8 A3 EA CC A8
C5 F5 E9 E3 3D 01 30 CD 42 33 18 C8 E2 D3 44 54
C8 4D D3 77 E7 7D A4 F9 52 99 1A C8 15 4B C8 B0
C5 49 09 6D 67 25 02 CD 7A C5 78 1F 93 43 49 1B
61 B9 C2 F0 D7 60 67 DF 18 EF A9 77 15 93 56 49
E0 E0 F1 44 CC F7 1A 7A 4A C8 C8 45 5B 10 B3 E6
97 EB BB AD 95 AE F2 CC E2 24 0C 85 B6 E0 39 67
57 B0 F2 61 FC C1 70 49 20 27 A0 39 8A 00 C1 A5
29 5A 7F 5E 6A 03 69 E1 B3 5B 3D 8D 55 90 DD 57
8F 3D F0 D6 B0 77 9A 88 66 3B E6 81 94 74 4B 04
EB F8 68 2E 7E 6A 61 F7 4B BC 1F 9D 80 BC 06 CB

Exponent: 65537
    Extensions:
id-ce-subjectKeyIdentifier
E1 9E 49 98 96 BD 36 99 D9 D1 F8 67 2F F9 00 3B
03 C9 C5 81 

  Signature:
    Algorithm: sha256WithRSAEncryption
    Signature:
9C 48 13 EB BD B1 7E C8 CA 67 2E 03 D3 59 60 78
61 BE CD 82 9E AA 4A 1E 3A FF EA 8B 66 DC A7 0C
9C B9 A5 9D 7F DE DE 59 03 99 D0 F9 A1 DC B6 5D
30 57 1C BA 83 09 13 B1 80 36 ED 73 85 AC FD 62
47 A6 B1 43 FC 96 9C 76 E3 68 47 E1 17 DD DF 2E
E0 D6 86 2A F5 70 39 4A BE 56 97 FD 80 5E 13 E6
61 88 64 ED 72 40 6D FC 60 E4 78 6B D3 99 13 9F
A4 55 6D 04 F7 73 89 C8 0B B2 99 FE D3 5F A4 90
D5 54 3F 61 AC 44 71 95 56 4A 13 49 83 FB 8C DC
FD 00 EF 70 50 27 E1 26 BF EB 02 2F A0 0B 5D 15
C1 03 B7 EE AE EC 15 DE AC 97 E8 27 04 48 33 DD
30 DC A6 54 2F B9 05 05 6D 86 D3 CB FD 53 4B D2
8F EB C3 D9 90 80 66 92 FB 2C D0 72 F7 F7 37 11
2B DA 86 EA 07 D1 A6 7F 90 AE 6E 2F FD DD D6 DA
50 55 B7 48 D8 17 5A FB BC 84 AA C1 F5 C8 BB E6
9B 01 0F 31 B6 4D 77 11 3F DE A4 DC C7 43 2E 31

sender$ sudo apt update
Hit:1 http://deb.debian.org/debian trixie InRelease
Hit:2 http://deb.debian.org/debian trixie-updates InRelease     
Hit:3 http://deb.debian.org/debian-security trixie-security InRelease          
Hit:4 http://archive.raspberrypi.com/debian trixie InRelease                   
62 packages can be upgraded. Run 'apt list --upgradable' to see them.
sender$ sudo apt install yubikey-manager
The following packages were automatically installed and are no longer required:
  libeac3  opensc-pkcs11
Use 'sudo apt autoremove' to remove them.

Installing:
  yubikey-manager

Summary:
  Upgrading: 0, Installing: 1, Removing: 0, Not Upgrading: 62
  Download size: 49.7 kB
  Space needed: 293 kB / 49.2 GB available

Get:1 http://deb.debian.org/debian trixie/main arm64 yubikey-manager all 5.6.1+repack1-1 [49.7 kB]
Fetched 49.7 kB in 0s (259 kB/s)           
Selecting previously unselected package yubikey-manager.
(Reading database ... 89786 files and directories currently installed.)
Preparing to unpack .../yubikey-manager_5.6.1+repack1-1_all.deb ...
Unpacking yubikey-manager (5.6.1+repack1-1) ...
Setting up yubikey-manager (5.6.1+repack1-1) ...
Processing triggers for man-db (2.13.1-1) ...
sender$ ykman info
WARNING: PC/SC not available. Smart card (CCID) protocols will not function.
ERROR: No YubiKey detected!
sender$ sudo ykman info
Device type: YubiKey 5 NFC FIPS
Serial number: 28989286
Firmware version: 5.4.3
Form factor: Keychain (USB-A)
Enabled USB interfaces: OTP, FIDO, CCID
NFC transport is enabled

Applications	USB    	NFC    
Yubico OTP  	Enabled	Enabled
FIDO U2F    	Enabled	Enabled
FIDO2       	Enabled	Enabled
OATH        	Enabled	Enabled
PIV         	Enabled	Enabled
OpenPGP     	Enabled	Enabled
YubiHSM Auth	Enabled	Enabled
sender$ sudo ykman piv keys import 9a private_key.pem 
Enter a management key [blank to use default key]: 
Private key imported into slot AUTHENTICATION.
sender$ sudo ykman piv certificates import 9a  code_signing_cert.der 
Enter a management key [blank to use default key]: 
Certificate imported into slot AUTHENTICATION
sender$ 
sender$ sudo apt install opensc
Installing:                     
  opensc

Summary:
  Upgrading: 0, Installing: 1, Removing: 0, Not Upgrading: 62
  Download size: 394 kB
  Space needed: 2,618 kB / 49.2 GB available

Get:1 http://deb.debian.org/debian trixie/main arm64 opensc arm64 0.26.1-2 [394 kB]
Fetched 394 kB in 0s (1,185 kB/s)
Selecting previously unselected package opensc.
(Reading database ... 89804 files and directories currently installed.)
Preparing to unpack .../opensc_0.26.1-2_arm64.deb ...
Unpacking opensc (0.26.1-2) ...
Setting up opensc (0.26.1-2) ...
Processing triggers for man-db (2.13.1-1) ...
sender$ pkcs11-tool -T
Available slots:
No slots.
sender$ sudo pkcs-tool -T
sudo: pkcs-tool: command not found
sender$ sudo pkcs11-tool -T
Available slots:
Slot 0 (0x0): Yubico YubiKey OTP+FIDO+CCID 00 00
  token label        : localhost
  token manufacturer : piv_II
  token model        : PKCS#15 emulated
  token flags        : login required, rng, token initialized, PIN initialized
  hardware version   : 0.0
  firmware version   : 0.0
  serial num         : 97c1aed7dcce1aea
  pin min/max        : 4/8
  uri                : pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost
sender$ sudo pkcs11-tool -O
Using slot 0 with a present token (0x0)
Public Key Object; RSA 2048 bits
  label:      PIV AUTH pubkey
  ID:         01
  Usage:      encrypt, verify, verifyRecover, wrap
  Access:     none
  uri:        pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;id=%01;object=PIV%20AUTH%20pubkey;type=public
Certificate Object; type = X.509 cert
  label:      Certificate for PIV Authentication
  subject:    DN: CN=localhost
  serial:     55CD4EDE55EB4C462EFD52D19BAFA8489A3D1220
  ID:         01
  uri:        pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;id=%01;object=Certificate%20for%20PIV%20Authentication;type=cert
Profile object 2934600384
  profile_id:          CKP_PUBLIC_CERTIFICATES_TOKEN (4)
Data object 2934598512
  label:          'Card Capability Container'
  application:    'Card Capability Container'
  app_id:         2.16.840.1.101.3.7.1.219.0
  flags:          <empty>
  uri:            pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;object=Card%20Capability%20Container;type=data
Data object 2934598608
  label:          'Card Holder Unique Identifier'
  application:    'Card Holder Unique Identifier'
  app_id:         2.16.840.1.101.3.7.2.48.0
  flags:          <empty>
  uri:            pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;object=Card%20Holder%20Unique%20Identifier;type=data
Data object 2934598704
  label:          'Unsigned Card Holder Unique Identifier'
  application:    'Unsigned Card Holder Unique Identifier'
  app_id:         2.16.840.1.101.3.7.2.48.2
  flags:          <empty>
  uri:            pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;object=Unsigned%20Card%20Holder%20Unique%20Identifier;type=data
Data object 2934598800
  label:          'X.509 Certificate for PIV Authentication'
  application:    'X.509 Certificate for PIV Authentication'
  app_id:         2.16.840.1.101.3.7.2.1.1
  flags:          <empty>
  uri:            pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;object=X.509%20Certificate%20for%20PIV%20Authentication;type=data
Data object 2934599184
  label:          'X.509 Certificate for Digital Signature'
  application:    'X.509 Certificate for Digital Signature'
  app_id:         2.16.840.1.101.3.7.2.1.0
  flags:          <empty>
  uri:            pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;object=X.509%20Certificate%20for%20Digital%20Signature;type=data
Data object 2934599280
  label:          'X.509 Certificate for Key Management'
  application:    'X.509 Certificate for Key Management'
  app_id:         2.16.840.1.101.3.7.2.1.2
  flags:          <empty>
  uri:            pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;object=X.509%20Certificate%20for%20Key%20Management;type=data
Data object 2934599376
  label:          'X.509 Certificate for Card Authentication'
  application:    'X.509 Certificate for Card Authentication'
  app_id:         2.16.840.1.101.3.7.2.5.0
  flags:          <empty>
  uri:            pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;object=X.509%20Certificate%20for%20Card%20Authentication;type=data
Data object 2934599472
  label:          'Security Object'
  application:    'Security Object'
  app_id:         2.16.840.1.101.3.7.2.144.0
  flags:          <empty>
  uri:            pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;object=Security%20Object;type=data
Data object 2934599568
  label:          'Discovery Object'
  application:    'Discovery Object'
  app_id:         2.16.840.1.101.3.7.2.96.80
  flags:          <empty>
  uri:            pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;object=Discovery%20Object;type=data
Data object 2934599760
  label:          'Biometric Information Templates Group Template'
  application:    'Biometric Information Templates Group Template'
  app_id:         2.16.840.1.101.3.7.2.16.22
  flags:          <empty>
  uri:            pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;object=Biometric%20Information%20Templates%20Group%20Template;type=data
Data object 2934599856
  label:          'Secure Messaging Certificate Signer'
  application:    'Secure Messaging Certificate Signer'
  app_id:         2.16.840.1.101.3.7.2.16.23
  flags:          <empty>
  uri:            pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=97c1aed7dcce1aea;token=localhost;object=Secure%20Messaging%20Certificate%20Signer;type=data
sender$ 
sender$ echo -e '#include <stdio.h>\n\nint main() {\n    printf("Hello, World!\\n");\n    return 0;\n}' > hello.c
sender$ cat hello.c
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
sender$ gcc hello.c -o hello
sender$ ./hello
Hello, World!
sender$ 
sender$ sudo pkcs11-tool --sign --id 1 --mechanism SHA256-RSA-PKCS -i hello -o hello.sig
Using slot 0 with a present token (0x0)
Logging in to "localhost".
Please enter User PIN: 
Using signature algorithm SHA256-RSA-PKCS
sender$ 
sender$ cp hello ../receiver
sender$ sudo cp hello.sig ../receiver/
sender$ cp code_signing_cert.der ../receiver
sender$ cd ../receiver/
receiver$ 
receiver$ ../x509_extract_sig -c code_signing_cert.der -s code_signing_cert.der.sig
receiver$ ../x509_extract_pubkey -c code_signing_cert.der -p code_signing_cert.der.pubkey
receiver$ ../myrsa_trapdoor -m code_signing_cert.der.sig -k code_signing_cert.der.pubkey 
00 01 ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff 00 30 31 30 
0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 
1e 33 cd c0 88 94 78 4f f6 48 84 de 8b 02 ce a8 
9e df ec 9d 0d 47 93 20 7b 82 21 04 71 0d a4 ea 

receiver$ ../x509_extract_tbs -c code_signing_cert.der -t code_signing_cert.der.tbs
receiver$ ../myrsa_sha256 -i code_signing_cert.der.tbs -o code_signing_cert.der.tbs.dgst
receiver$ hexdump -C code_signing_cert.der.tbs.dgst 
00000000  1e 33 cd c0 88 94 78 4f  f6 48 84 de 8b 02 ce a8  |.3....xO.H......|
00000010  9e df ec 9d 0d 47 93 20  7b 82 21 04 71 0d a4 ea  |.....G. {.!.q...|
00000020
receiver$ 
receiver$ sudo ../myrsa_trapdoor -m helo.sig -k code_signing_cert.der.pubkey 
fopen message file: No such file or directory
receiver$ sudo ../myrsa_trapdoor -m hello.sig -k code_signing_cert.der.pubkey 
00 01 ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff 00 30 31 30 
0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 
5b 1d f8 ea b3 c4 b4 50 49 95 3c 6c 62 9a 0a 22 
24 f2 ac b6 3a 2b 9e 6a d6 d6 68 74 37 2b 9d 0e 

receiver$ ../myrsa_sha256 -i hello -o hello.dgst
receiver$ hexdump -C hello.dgst
00000000  5b 1d f8 ea b3 c4 b4 50  49 95 3c 6c 62 9a 0a 22  |[......PI.<lb.."|
00000010  24 f2 ac b6 3a 2b 9e 6a  d6 d6 68 74 37 2b 9d 0e  |$...:+.j..ht7+..|
00000020
receiver$ 
```
