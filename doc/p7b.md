# PKCS#7
In today's digital age, ensuring the authenticity and integrity of documents is paramount. Digital signatures offer a solution by encrypting the document's hash, thus creating a unique digital fingerprint. However, for the recipient to verify the signature, it's essential to provide detailed information about the hashing method, encryption algorithm, and the public key used.

Traditionally, sharing this information separately can be cumbersome and poses security risks. Enter Cryptographic Message Syntax (CMS) [RFC5652], an advanced protocol derived from PKCS#7 [PKCS#7]. CMS streamlines the process by consolidating all necessary data into a single, secure file, typically with a .p7b extension. This not only simplifies verification but also enhances security by minimizing the chances of data mismanagement.

In this tutorial, we will delve into the practical application of Cryptographic Message Syntax.

## Sign a document

### Generate a private key and associate certificate

```console
sender$ openssl req -newkey rsa:2048 -x509 -keyout private.key -outform DER -out certificate.crt -days 365 -nodes -subj="/CN=localhost"
...+....+......+............+..+...............+...+.......+........+.........+....+..+.......+++++++++++++++++++++++++++++++++++++++*..+++++++++++++++++++++++++++++++++++++++*.+..+.........++++++
...+........+.+..+............+.+.....+......+....+......+++++++++++++++++++++++++++++++++++++++*.....+...+++++++++++++++++++++++++++++++++++++++*....+........+..................+....+...++++++
-----
```

### The document
```console
sender$ echo "This is the document" > document.txt
```

### Sign the document
```console
sender$ openssl smime -sign -binary -in document.txt -out signature.p7b \
  -signer certificate.crt -inkey private.key -outform DER -nodetach
sender$ ls
certificate.crt  document.txt  private.key  signature.p7b
```

## Transfer the document and the associated signature information

```console
sender$ cp document.txt ../receiver/
sender$ cp signature.p7b ../receiver/
```

## Verify the document

```console
receiver$ ls
document.txt  signature.p7b
```

### What does a .p7b file contain?

```console
receiver$ ../p7b_text -f signature.p7b 
contentType: id_signedData
version: 1
digestAlgorithms: id_sha256
encapContentInfo:
  eContentType: id_data
  eContent:
54 68 69 73 20 69 73 20 74 68 65 20 64 6F 63 75
6D 65 6E 74 0A 
certificates: present (781 bytes)
crls: not present
signerInfos:
  version: 1
  sid-issuerAndSerialNumber:
    issuer: CN=localhost
    serialNumber: 2AEB1476FB1D5DDED27AB16D10B1B1EA36F1F349
  digestAlgorithm: id_sha256
  signedAttrs:
    id_contentType: id_data
    id_signingTime: 261120100514Z
    id_messageDigest
68 05 E9 82 8E C4 9C 53 17 3B 2A 7A E5 C9 4A 8A
B5 AE A5 AA 57 77 6C 1F 87 A5 9B 08 C7 22 C4 14

    smimeCapabilities
      id-aes256-CBC
      id-aes192-CBC
      id-aes128-CBC
      des-EDE3-CBC
      rc2CBC: 128
      rc2CBC: 64
      desCBC
      rc2CBC: 40

  signatureAlgorithm: rsaEncryption
  signature:
17 64 21 B1 E4 F0 16 41 25 F8 C7 8B 8D 46 E3 5D
33 CE 00 10 BD E3 E0 0D 19 37 4C 8F B5 F0 64 52
9A F1 B9 72 1E 11 6E 8B 29 70 0E 42 EB 3B F6 DB
A6 4D DA 76 35 8D 86 0F 51 82 AF E9 0C B5 24 12
96 26 EE 2D F0 9A 78 37 DB 74 58 C6 7B 62 EB 12
BE 3F 2E E0 E0 B6 CF 19 3D 6C 4C 28 03 BE CC 70
AD BA B9 56 A1 40 E4 6A 42 A9 B4 14 7E 2A 4A E1
0C BC 76 13 1D A6 BA 3F 04 EE B9 27 16 A0 8B 3A
E8 19 4A 07 10 CA A5 05 11 D4 58 59 47 20 15 65
1F 9F CC 4E D9 C0 A8 A9 85 35 C2 1F 2C 78 8D 03
BB 9D 28 93 86 5D 94 0E 37 B3 91 38 ED 41 1C 81
5B F2 9C 93 45 B7 6A 2D DD 89 E6 35 37 7D A8 06
3B 0E FD B8 0A 9B 3F 7D 14 5E 50 41 E8 7C 60 9A
A6 EC B9 05 35 72 17 CF 79 28 77 80 7C 15 85 B9
8D 0B D4 53 CC F3 36 8B 18 1D 82 61 26 FA B1 67
5D 37 15 95 6A 31 12 2E 1C AF 07 32 2E E7 9A 6D
```

The beginning of the DER-encoded [X.690] file specifies what the content is [RFC5652]:

```text
ContentInfo ::= SEQUENCE {
	contentType ContentType,
	content [0] EXPLICIT ANY DEFINED BY contentType }

ContentType ::= OBJECT IDENTIFIER
```

```console
receiver$ ../asn1parser -f signature.p7b -v | head 
SEQUENCE  L = 1440
-OBJECT IDENTIFIER  L = 9
OID: 1.2.840.113549.1.7.2

-Context-specific 0  L = 1425
--SEQUENCE  L = 1421
---INTEGER  L = 1
01 
---SET  L = 15
----SEQUENCE  L = 13
```

It is a **signedData** [RFC5652]:

```text
id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }

SignedData ::= SEQUENCE {
	version CMSVersion,
	digestAlgorithms 	DigestAlgorithmIdentifiers,
	encapContentInfo 	EncapsulatedContentInfo,
	certificates [0] 	IMPLICIT CertificateSet OPTIONAL,
	crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
	signerInfos SignerInfos }
```

It shows the algorithm for digest (fingerprint), SHA-256 [FIPS 180-4]:

```text
digestAlgorithms: id_sha256
```

### Decrypt the signature

**signerInfos** contains the information regarding **signature** [RFC5652]:

```text
SignerInfo ::= SEQUENCE {
	version 			CMSVersion,
	sid 				SignerIdentifier,
	digestAlgorithm 		DigestAlgorithmIdentifier,
	signedAttrs 		[0] 	IMPLICIT SignedAttributes OPTIONAL,
	signatureAlgorithm		SignatureAlgorithmIdentifier,
	signature 			SignatureValue,
	unsignedAttrs 	[1] 	IMPLICIT UnsignedAttributes OPTIONAL }
```

```console
digestAlgorithm: id_sha256

signatureAlgorithm: rsaEncryption
```

#### Retrieve the signature
**signature** contains the document's signature.

```console
receiver$ ../p7b_extract_sig
Usage: ../p7b_extract_sig -i <cms file> -o <signature file>
receiver$ ../p7b_extract_sig -i signature.p7b -o signature.p7b.sig
receiver$ hexdump -C signature.p7b.sig
00000000  17 64 21 b1 e4 f0 16 41  25 f8 c7 8b 8d 46 e3 5d  |.d!....A%....F.]|
00000010  33 ce 00 10 bd e3 e0 0d  19 37 4c 8f b5 f0 64 52  |3........7L...dR|
00000020  9a f1 b9 72 1e 11 6e 8b  29 70 0e 42 eb 3b f6 db  |...r..n.)p.B.;..|
00000030  a6 4d da 76 35 8d 86 0f  51 82 af e9 0c b5 24 12  |.M.v5...Q.....$.|
00000040  96 26 ee 2d f0 9a 78 37  db 74 58 c6 7b 62 eb 12  |.&.-..x7.tX.{b..|
00000050  be 3f 2e e0 e0 b6 cf 19  3d 6c 4c 28 03 be cc 70  |.?......=lL(...p|
00000060  ad ba b9 56 a1 40 e4 6a  42 a9 b4 14 7e 2a 4a e1  |...V.@.jB...~*J.|
00000070  0c bc 76 13 1d a6 ba 3f  04 ee b9 27 16 a0 8b 3a  |..v....?...'...:|
00000080  e8 19 4a 07 10 ca a5 05  11 d4 58 59 47 20 15 65  |..J.......XYG .e|
00000090  1f 9f cc 4e d9 c0 a8 a9  85 35 c2 1f 2c 78 8d 03  |...N.....5..,x..|
000000a0  bb 9d 28 93 86 5d 94 0e  37 b3 91 38 ed 41 1c 81  |..(..]..7..8.A..|
000000b0  5b f2 9c 93 45 b7 6a 2d  dd 89 e6 35 37 7d a8 06  |[...E.j-...57}..|
000000c0  3b 0e fd b8 0a 9b 3f 7d  14 5e 50 41 e8 7c 60 9a  |;.....?}.^PA.|`.|
000000d0  a6 ec b9 05 35 72 17 cf  79 28 77 80 7c 15 85 b9  |....5r..y(w.|...|
000000e0  8d 0b d4 53 cc f3 36 8b  18 1d 82 61 26 fa b1 67  |...S..6....a&..g|
000000f0  5d 37 15 95 6a 31 12 2e  1c af 07 32 2e e7 9a 6d  |]7..j1.....2...m|
00000100
```

#### Retrieve the public key
The signature is calculated with signer's public key which is included in the **certificates** as an X.509 certificate [X.509].

```console
receiver$ ../p7b_extract_cert -i signature.p7b -o signature.p7b.cer
receiver$ ../x509_extract_pubkey -c signature.p7b.cer -p signature.p7b.pubkey
receiver$ ../asn1parser -f signature.p7b.pubkey 
SEQUENCE  L = 266
-INTEGER  L = 257
-INTEGER  L = 3
receiver$ ../asn1parser -f signature.p7b.pubkey -v
SEQUENCE  L = 266
-INTEGER  L = 257
00 89 9d 4b f1 a0 62 79 48 6d d1 c8 f6 53 ec c0 
c7 b0 5b 71 f5 51 d1 a7 c0 58 21 77 fc d8 49 20 
4e bc f7 97 31 a9 64 04 4a f5 9b a3 e6 b2 9d 3f 
9a 6c 36 d3 6f 72 fe 39 1a 06 a1 7a 74 4b 5b f6 
0b 06 a8 de 0c 80 0e 84 26 74 fb a6 61 cb a8 57 
a4 f7 9b f6 1c e9 88 dd 30 5e 0a a1 72 08 5b c2 
da 08 41 06 16 31 d8 88 aa 35 f3 5a a8 13 fb 32 
47 74 3e 46 b4 44 bd 54 6f d7 22 39 31 17 5f 95 
f4 ef 4a 9a 20 bb 04 40 28 81 4f 4a b6 23 a7 f1 
85 65 de ee 94 94 3d 27 a9 5a 7b 0f 23 19 c7 00 
f9 b7 bd f3 c0 55 b5 44 f0 a3 be 7f fa 28 da e8 
14 ac 90 34 a7 5b 83 74 9b 7f 9f 2c 14 c8 f4 d7 
5a 82 3c c8 7d 6c f7 28 2c 21 02 49 1e 2f b7 93 
76 e0 43 4a 5e 24 a4 4c 65 d8 41 08 a0 3d 86 5a 
a0 f5 92 b1 3b ae b6 f1 99 32 7a 7e c4 8e de ae 
5f c9 7f e2 02 eb 3b f7 9c 05 86 27 d3 e3 c3 cc 
e5 
-INTEGER  L = 3
01 00 01 
```

#### Reverse the signature to the digest

The result is an encoded message padded by EMSA-PKCS1-v1_5 [PKCS#1] that ends with the digest.

```console
receiver$ ../myrsa_trapdoor -m signature.p7b.sig -k signature.p7b.pubkey 
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
62 99 ea da f6 0d 0a 46 52 01 2f c3 9c 8e 50 8c 
64 cc 89 8a 79 49 c3 5d 24 4d 14 1b 3a 79 eb 69 
```

#### Whose digest?

The documenet's digest:

```console
receiver$ ../myrsa_sha256 -i document.txt  -o document.txt.dgst
receiver$ hexdump -C document.txt.dgst 
00000000  68 05 e9 82 8e c4 9c 53  17 3b 2a 7a e5 c9 4a 8a  |h......S.;*z..J.|
00000010  b5 ae a5 aa 57 77 6c 1f  87 a5 9b 08 c7 22 c4 14  |....Wwl......"..|
00000020
```

The document's digest does not match the one from **signature**. Nevertheless,

```console
  signedAttrs:
    id_contentType: id_data
    id_signingTime: 261120100514Z
    id_messageDigest
68 05 E9 82 8E C4 9C 53 17 3B 2A 7A E5 C9 4A 8A
B5 AE A5 AA 57 77 6C 1F 87 A5 9B 08 C7 22 C4 14
```

```text
SignedAttributes ::= SET SIZE (1..MAX) OF Attribute


Attribute ::= SEQUENCE {
	attrType OBJECT IDENTIFIER,
	attrValues SET OF AttributeValue }

AttributeValue ::= ANY
```

the document's digest matches **id_messageDigest** attribute. That is because **signedAttrs** is present: Section 5.4 [RFC5652].

```text
The result of the message digest calculation process depends on
whether the signedAttrs field is present. When the field is absent,
the result is just the message digest of the content as described
above. When the field is present, however, the result is the message
digest of the complete DER encoding of the SignedAttrs value
contained in the signedAttrs field.
```

#### The **signature**'s real source

```console
receiver$ ../p7b_extract_signed_attrs -i signature.p7b -o signature.p7b.signed_attrs

receiver$ ../myrsa_sha256 -i signature.p7b.signed_attrs -o signature.p7b.signed_attrs.dgst
receiver$ hexdump -C signature.p7b.signed_attrs.dgst 
00000000  62 99 ea da f6 0d 0a 46  52 01 2f c3 9c 8e 50 8c  |b......FR./...P.|
00000010  64 cc 89 8a 79 49 c3 5d  24 4d 14 1b 3a 79 eb 69  |d...yI.]$M..:y.i|
00000020
```

**signature** is to validate **signedAttrs**. That is, **id_messageDigest** attribute is true. Same hash from the document and **id_messageDigest** attribute authenticates the document.

## Embedded document

```console
encapContentInfo:
  eContentType: id_data
  eContent:
54 68 69 73 20 69 73 20 74 68 65 20 64 6F 63 75
6D 65 6E 74 0A 
```

```console
receiver$ hexdump -C document.txt 
00000000  54 68 69 73 20 69 73 20  74 68 65 20 64 6f 63 75  |This is the docu|
00000010  6d 65 6e 74 0a                                    |ment.|
00000015
```

**eContent** is in the case here the document itself because of the '-nodetach' option. It gives some flexibility in how documents are transferred. But **eContent** is optional.


## Beyond this example

This tutorial demonstrates a scenario with only one signer. However, **PKCS#7** [PKCS#7] supports any numbers of signers. Consider the following structures [RFC5652]:

```text
DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

SignerInfos ::= SET OF SignerInfo

CertificateSet ::= SET OF CertificateChoices

RevocationInfoChoices ::= SET OF RevocationInfoChoice

SignerInfos ::= SET OF SignerInfo
```

## Complete Listing

```console
sender$ openssl req -newkey rsa:2048 -x509 -keyout private.key -outform DER -out certificate.crt -days 365 -nodes -subj="/CN=localhost"
...+....+......+............+..+...............+...+.......+........+.........+....+..+.......+++++++++++++++++++++++++++++++++++++++*..+++++++++++++++++++++++++++++++++++++++*.+..+.........++++++
...+........+.+..+............+.+.....+......+....+......+++++++++++++++++++++++++++++++++++++++*.....+...+++++++++++++++++++++++++++++++++++++++*....+........+..................+....+...++++++
-----
sender$ echo "This is the document" > document.txt
sender$ ls
certificate.crt  document.txt  private.key
sender$ openssl smime -sign -binary -in document.txt -out signature.p7b \
  -signer certificate.crt -inkey private.key -outform DER -nodetach
sender$ ls
certificate.crt  document.txt  private.key  signature.p7b
sender$ cp document.txt ../receiver/
sender$ cp signature.p7b ../receiver/
sender$ cd ../receiver/
receiver$ ls
document.txt  signature.p7b
receiver$ 7b_text -f signature.p7b
-bash: 7b_text: command not found
receiver$ ./7b_text -f signature.p7b
-bash: ./7b_text: No such file or directory
receiver$ ../7b_text -f signature.p7b 
-bash: ../7b_text: No such file or directory
receiver$ ../p7b_text -f signature.p7b 
contentType: id_signedData
version: 1
digestAlgorithms: id_sha256
encapContentInfo:
  eContentType: id_data
  eContent:
54 68 69 73 20 69 73 20 74 68 65 20 64 6F 63 75
6D 65 6E 74 0A 
certificates: present (781 bytes)
crls: not present
signerInfos:
  version: 1
  sid-issuerAndSerialNumber:
    issuer: CN=localhost
    serialNumber: 2AEB1476FB1D5DDED27AB16D10B1B1EA36F1F349
  digestAlgorithm: id_sha256
  signedAttrs:
    id_contentType: id_data
    id_signingTime: 261120100514Z
    id_messageDigest
68 05 E9 82 8E C4 9C 53 17 3B 2A 7A E5 C9 4A 8A
B5 AE A5 AA 57 77 6C 1F 87 A5 9B 08 C7 22 C4 14

    smimeCapabilities
      id-aes256-CBC
      id-aes192-CBC
      id-aes128-CBC
      des-EDE3-CBC
      rc2CBC: 128
      rc2CBC: 64
      desCBC
      rc2CBC: 40

  signatureAlgorithm: rsaEncryption
  signature:
17 64 21 B1 E4 F0 16 41 25 F8 C7 8B 8D 46 E3 5D
33 CE 00 10 BD E3 E0 0D 19 37 4C 8F B5 F0 64 52
9A F1 B9 72 1E 11 6E 8B 29 70 0E 42 EB 3B F6 DB
A6 4D DA 76 35 8D 86 0F 51 82 AF E9 0C B5 24 12
96 26 EE 2D F0 9A 78 37 DB 74 58 C6 7B 62 EB 12
BE 3F 2E E0 E0 B6 CF 19 3D 6C 4C 28 03 BE CC 70
AD BA B9 56 A1 40 E4 6A 42 A9 B4 14 7E 2A 4A E1
0C BC 76 13 1D A6 BA 3F 04 EE B9 27 16 A0 8B 3A
E8 19 4A 07 10 CA A5 05 11 D4 58 59 47 20 15 65
1F 9F CC 4E D9 C0 A8 A9 85 35 C2 1F 2C 78 8D 03
BB 9D 28 93 86 5D 94 0E 37 B3 91 38 ED 41 1C 81
5B F2 9C 93 45 B7 6A 2D DD 89 E6 35 37 7D A8 06
3B 0E FD B8 0A 9B 3F 7D 14 5E 50 41 E8 7C 60 9A
A6 EC B9 05 35 72 17 CF 79 28 77 80 7C 15 85 B9
8D 0B D4 53 CC F3 36 8B 18 1D 82 61 26 FA B1 67
5D 37 15 95 6A 31 12 2E 1C AF 07 32 2E E7 9A 6D


receiver$ ../asn1parser -f signature.p7b -v | head 
SEQUENCE  L = 1440
-OBJECT IDENTIFIER  L = 9
OID: 1.2.840.113549.1.7.2

-Context-specific 0  L = 1425
--SEQUENCE  L = 1421
---INTEGER  L = 1
01 
---SET  L = 15
----SEQUENCE  L = 13
receiver$ ../p7b_extract_sig
Usage: ../p7b_extract_sig -i <cms file> -o <signature file>
receiver$ ../p7b_extract_sig -i signature.p7b -o signature.p7b.sig
receiver$ hexdump -C signature.p7b.sig
00000000  17 64 21 b1 e4 f0 16 41  25 f8 c7 8b 8d 46 e3 5d  |.d!....A%....F.]|
00000010  33 ce 00 10 bd e3 e0 0d  19 37 4c 8f b5 f0 64 52  |3........7L...dR|
00000020  9a f1 b9 72 1e 11 6e 8b  29 70 0e 42 eb 3b f6 db  |...r..n.)p.B.;..|
00000030  a6 4d da 76 35 8d 86 0f  51 82 af e9 0c b5 24 12  |.M.v5...Q.....$.|
00000040  96 26 ee 2d f0 9a 78 37  db 74 58 c6 7b 62 eb 12  |.&.-..x7.tX.{b..|
00000050  be 3f 2e e0 e0 b6 cf 19  3d 6c 4c 28 03 be cc 70  |.?......=lL(...p|
00000060  ad ba b9 56 a1 40 e4 6a  42 a9 b4 14 7e 2a 4a e1  |...V.@.jB...~*J.|
00000070  0c bc 76 13 1d a6 ba 3f  04 ee b9 27 16 a0 8b 3a  |..v....?...'...:|
00000080  e8 19 4a 07 10 ca a5 05  11 d4 58 59 47 20 15 65  |..J.......XYG .e|
00000090  1f 9f cc 4e d9 c0 a8 a9  85 35 c2 1f 2c 78 8d 03  |...N.....5..,x..|
000000a0  bb 9d 28 93 86 5d 94 0e  37 b3 91 38 ed 41 1c 81  |..(..]..7..8.A..|
000000b0  5b f2 9c 93 45 b7 6a 2d  dd 89 e6 35 37 7d a8 06  |[...E.j-...57}..|
000000c0  3b 0e fd b8 0a 9b 3f 7d  14 5e 50 41 e8 7c 60 9a  |;.....?}.^PA.|`.|
000000d0  a6 ec b9 05 35 72 17 cf  79 28 77 80 7c 15 85 b9  |....5r..y(w.|...|
000000e0  8d 0b d4 53 cc f3 36 8b  18 1d 82 61 26 fa b1 67  |...S..6....a&..g|
000000f0  5d 37 15 95 6a 31 12 2e  1c af 07 32 2e e7 9a 6d  |]7..j1.....2...m|
00000100
receiver$ ../p7b_extract_cert -i signature.p7b -o signature.p7b.cer
receiver$ ../x509_extract_pubkey -c signature.p7b.cer -p signature.p7b.pubkey
receiver$ ../asn1parser -f signature.p7b.pubkey 
SEQUENCE  L = 266
-INTEGER  L = 257
-INTEGER  L = 3
receiver$ ../asn1parser -f signature.p7b.pubkey -v
SEQUENCE  L = 266
-INTEGER  L = 257
00 89 9d 4b f1 a0 62 79 48 6d d1 c8 f6 53 ec c0 
c7 b0 5b 71 f5 51 d1 a7 c0 58 21 77 fc d8 49 20 
4e bc f7 97 31 a9 64 04 4a f5 9b a3 e6 b2 9d 3f 
9a 6c 36 d3 6f 72 fe 39 1a 06 a1 7a 74 4b 5b f6 
0b 06 a8 de 0c 80 0e 84 26 74 fb a6 61 cb a8 57 
a4 f7 9b f6 1c e9 88 dd 30 5e 0a a1 72 08 5b c2 
da 08 41 06 16 31 d8 88 aa 35 f3 5a a8 13 fb 32 
47 74 3e 46 b4 44 bd 54 6f d7 22 39 31 17 5f 95 
f4 ef 4a 9a 20 bb 04 40 28 81 4f 4a b6 23 a7 f1 
85 65 de ee 94 94 3d 27 a9 5a 7b 0f 23 19 c7 00 
f9 b7 bd f3 c0 55 b5 44 f0 a3 be 7f fa 28 da e8 
14 ac 90 34 a7 5b 83 74 9b 7f 9f 2c 14 c8 f4 d7 
5a 82 3c c8 7d 6c f7 28 2c 21 02 49 1e 2f b7 93 
76 e0 43 4a 5e 24 a4 4c 65 d8 41 08 a0 3d 86 5a 
a0 f5 92 b1 3b ae b6 f1 99 32 7a 7e c4 8e de ae 
5f c9 7f e2 02 eb 3b f7 9c 05 86 27 d3 e3 c3 cc 
e5 
-INTEGER  L = 3
01 00 01 
receiver$ ../myrsa_trapdoor -m signature.p7b.sig -k signature.p7b.pubkey 
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
62 99 ea da f6 0d 0a 46 52 01 2f c3 9c 8e 50 8c 
64 cc 89 8a 79 49 c3 5d 24 4d 14 1b 3a 79 eb 69 

receiver$ hexdump -C document.txt 
00000000  54 68 69 73 20 69 73 20  74 68 65 20 64 6f 63 75  |This is the docu|
00000010  6d 65 6e 74 0a                                    |ment.|
00000015
receiver$ ../myrsa_sha256 -i document.txt  -o document.txt.dgst
receiver$ hexdump -C document.txt.dgst 
00000000  68 05 e9 82 8e c4 9c 53  17 3b 2a 7a e5 c9 4a 8a  |h......S.;*z..J.|
00000010  b5 ae a5 aa 57 77 6c 1f  87 a5 9b 08 c7 22 c4 14  |....Wwl......"..|
00000020
receiver$ ../p7b_extract_signed_attrs -i signature.p7b -o signature.p7b.signed_attrs
receiver$ ../asn1parser -f signature.p7b.signed_attrs -v
SET  L = 228
-SEQUENCE  L = 24
--OBJECT IDENTIFIER  L = 9
OID: 1.2.840.113549.1.9.3

--SET  L = 11
---OBJECT IDENTIFIER  L = 9
OID: 1.2.840.113549.1.7.1

-SEQUENCE  L = 28
--OBJECT IDENTIFIER  L = 9
OID: 1.2.840.113549.1.9.5

--SET  L = 15
---UTCTime  L = 13
32 36 31 31 32 30 31 30 30 35 31 34 5a 
-SEQUENCE  L = 47
--OBJECT IDENTIFIER  L = 9
OID: 1.2.840.113549.1.9.4

--SET  L = 34
---OCTET STRING  L = 32
68 05 e9 82 8e c4 9c 53 17 3b 2a 7a e5 c9 4a 8a 
b5 ae a5 aa 57 77 6c 1f 87 a5 9b 08 c7 22 c4 14 

-SEQUENCE  L = 121
--OBJECT IDENTIFIER  L = 9
OID: 1.2.840.113549.1.9.15

--SET  L = 108
---SEQUENCE  L = 106
----SEQUENCE  L = 11
-----OBJECT IDENTIFIER  L = 9
OID: 2.16.840.1.101.3.4.1.42

----SEQUENCE  L = 11
-----OBJECT IDENTIFIER  L = 9
OID: 2.16.840.1.101.3.4.1.22

----SEQUENCE  L = 11
-----OBJECT IDENTIFIER  L = 9
OID: 2.16.840.1.101.3.4.1.2

----SEQUENCE  L = 10
-----OBJECT IDENTIFIER  L = 8
OID: 1.2.840.113549.3.7

----SEQUENCE  L = 14
-----OBJECT IDENTIFIER  L = 8
OID: 1.2.840.113549.3.2

-----INTEGER  L = 2
00 80 
----SEQUENCE  L = 13
-----OBJECT IDENTIFIER  L = 8
OID: 1.2.840.113549.3.2

-----INTEGER  L = 1
40 
----SEQUENCE  L = 7
-----OBJECT IDENTIFIER  L = 5
OID: 1.3.14.3.2.7

----SEQUENCE  L = 13
-----OBJECT IDENTIFIER  L = 8
OID: 1.2.840.113549.3.2

-----INTEGER  L = 1
28 
receiver$ ../myrsa_sha256 -i signature.p7b.signed_attrs -o signature.p7b.signed_attrs.dgst
receiver$ hexdump -C signature.p7b.signed_attrs.dgst 
00000000  62 99 ea da f6 0d 0a 46  52 01 2f c3 9c 8e 50 8c  |b......FR./...P.|
00000010  64 cc 89 8a 79 49 c3 5d  24 4d 14 1b 3a 79 eb 69  |d...yI.]$M..:y.i|
00000020
receiver$ 
```

## References

1. [RFC5652] - Housley, R. (2009). RFC 5652: Cryptographic Message Syntax (CMS). Retrieved from https://www.rfc-editor.org/info/rfc5652/
2. [PKCS#7] - Kaliski, B. (1998). RFC 2315: PKCS #7: Cryptographic Message Syntax Version 1.5. Retrieved from https://www.rfc-editor.org/info/rfc2315/
3. [PKCS#1] - Moriarty, K., Kaliski, B., Jonsson, J., & Rusch, A. (2016). RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2. Retrieved from https://www.rfc-editor.org/info/rfc8017/
4. [X.509] - ITU-T Recommendation X.509: Information Technology - Open Systems Interconnection - The Directory: Public-key and attribute certificate frameworks. Retrieved from https://www.itu.int/rec/t-rec-x.509/en
5. [X.690] - ITU-T Recommendation X.690: Information Technology - ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER). Retrieved from https://www.itu.int/rec/T-REC-X.690-202102-I
6. [FIPS 180-4] - National Institute of Standards and Technology. (2015). Secure Hash Standard (SHS). Retrieved from https://csrc.nist.gov/pubs/fips/180-4/upd1/final
