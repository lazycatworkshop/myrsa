# Document signing with PKCS#7
In today's digital age, ensuring the authenticity and integrity of documents is paramount. Digital signatures offer a solution by encrypting the document's hash, thus creating a unique digital fingerprint. However, for the recipient to verify the signature, it's essential to provide detailed information about the hashing method, encryption algorithm, and the public key used.

Traditionally, sharing this information separately can be cumbersome and poses security risks. Enter Cryptographic Message Syntax (CMS) [RFC5652], an advanced protocol derived from PKCS#7. CMS streamlines the process by consolidating all necessary data into a single, secure file, typically with a .p7b extension. This not only simplifies verification but also enhances security by minimizing the chances of data mismanagement.

In this tutorial, we will delve into the practical application of Cryptographic Message Syntax.

## Sign a document

### Generate a private key and associated certificate 
```console
sender$ openssl req -newkey rsa:2048 -x509 -keyout private.key -out certificate.crt -days 365
...+.+.................+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*....+.........+......+...+..+...+.......+.........+.....+.......+...............+.....+.......+..+.+..+......................+......+..+...+...+.........+.+...........+...
:
:
:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
sender$ 
```

### The document

```console
sender$ echo "This is the document" > document.txt
sender$ ls
certificate.crt  document.txt  private.key
sender$ 
```

### Sign the document

```console
sender$ openssl smime -sign -binary -in document.txt -out signature.p7b \
  -signer certificate.crt -inkey private.key -outform DER -nodetach
Enter pass phrase for private.key:
sender$ ls
certificate.crt  document.txt  private.key  signature.p7b
sender$ 
```

### Transfer the document and associtated signature information

```console
sender$ ls -l
total 16
-rw-r--r-- 1 tester tester 1245 Mar  7 09:55 certificate.crt
-rw-r--r-- 1 tester tester   21 Mar  7 09:57 document.txt
-rw------- 1 tester tester 1854 Mar  7 09:55 private.key
-rw-r--r-- 1 tester tester 1591 Mar  7 09:59 signature.p7b
sender$ 
sender$ cp document.txt ../recipient/
sender$ cp signature.p7b ../recipient/
```

## Verify the document

The receiving part needs only two files:

```console
sender$ cd ../recipient/
recipient$ ls -l
total 8
-rw-r--r-- 1 tester tester   21 Mar  7 10:02 document.txt
-rw-r--r-- 1 tester tester 1591 Mar  7 10:02 signature.p7b
recipient$ 
```

### What does a .p7b file looks like?

The content of the .p7b file:

```console
recipient$ ../bin/p7b_text -f signature.p7b 
Content Type: id_signedData
Signed Data
  Version: v1
  Digest Algorithms: id_sha256

  encapsulatedContentInfo:
    eContent Type: id_data
    eContent:
54 68 69 73 20 69 73 20 74 68 65 20 64 6f 63 75 
6d 65 6e 74 0a 
X509 Public Key certificate

toBeSigned:
  Version: v3
  serial Number: 36 0e fb cf ba 54 17 0e 38 f5 32 e3 31 7a 67 26 c7 d7 27 42 
  signature: sha256WithRSAEncryption
  issuer: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
  validity:
      notBefore	: 7th March 2025, 01:55:57 UTC
      notAfter	: 7th March 2026, 01:55:57 UTC
  subject: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
  subjectPublicKeyInfo:
    algorithm: rsaEncryption
    subjectPublicKey:  unused bits: 0
    Modulus:
d5 7a 72 f3 4b 76 b6 4d ff cb de a1 ac ef d3 4a 
b4 76 e8 f0 e6 ce 38 01 37 f3 dd 6d a3 7f 9b f8 
9a 31 4c 18 c5 03 6e 6f d8 14 3b b2 bf 60 58 eb 
63 09 e2 09 4f 91 d0 1d fe 70 d2 ee 7a 3b 64 12 
4e 1d f2 d8 d0 81 fe 2a d0 2c 3c 6b 28 da ac ea 
af 53 24 98 fa 44 ba 13 00 68 26 44 26 7d 09 e2 
64 e3 cf c4 d3 d4 e2 c0 3a 0d d6 f2 3e f1 db c2 
ee 92 3e 9d 1a a6 d1 19 d5 64 ef 14 14 ba dc fb 
34 4f c9 4a c6 7a d4 0c 9c 6d da 42 24 dc 96 82 
c9 5c a6 5c e0 55 0e ed d9 2c 40 5d cb d4 56 2e 
72 d0 d6 5c 8d 08 30 fb 38 40 e2 e5 60 7e 24 da 
4e fe 86 f0 72 a9 f4 95 ff 7e 4a f5 23 b1 07 84 
e3 e9 dc da 03 2f a3 0c 05 e1 36 00 79 f4 45 a6 
ca 34 25 86 b6 ea ee 94 a9 bc b9 02 b2 0a 8f bf 
da 87 12 e0 ad ab a0 db a2 76 92 40 d9 30 51 86 
dd 63 47 48 ce 0e 40 17 b9 91 ef 4c 11 1c b1 83 

    Exponent:
01 00 01 
  extensions:
    id-ce-subjectKeyIdentifier: non-critical
97 e1 99 35 43 c6 12 b7 67 24 ca e3 44 0b ab 1c 
03 55 36 af 
    id-ce-authorityKeyIdentifier: non-critical
97 e1 99 35 43 c6 12 b7 67 24 ca e3 44 0b ab 1c 
03 55 36 af 
    id-ce-basicConstraints: critical
    CA: TRUE

SIGNATURE:
  algorithmidentifier: sha256WithRSAEncryption
  signature: unused bits: 0
2c 04 29 96 1e 90 04 2c e0 b4 0e ea cf 65 07 46 
4b 1f f4 12 b9 71 7f 7a 1e 85 ce 1a 0e 75 9e df 
0f 11 14 44 b7 11 4a ae ca bc e0 ce 4e c6 b3 be 
a2 89 00 a0 ff e9 33 bb b7 f0 8d 13 a1 75 3f dc 
90 d7 48 a6 24 2b 82 b0 2b 89 ec 0d 4e a8 0c 91 
36 9a 8f f2 d1 a3 5f 75 57 b8 c7 a4 7a e7 38 3a 
76 b8 06 d5 29 70 33 4d dc 2c 70 07 64 5c af 9f 
c1 42 47 58 e3 65 76 62 24 54 b0 c6 f9 f3 23 cb 
cd eb e0 25 01 c0 a9 99 fa 78 4c 37 5a d3 5a 20 
12 64 97 a0 1c cc 62 cb 21 82 f8 19 90 b5 33 b1 
24 c5 dc 75 e3 e3 ca 26 2a 12 93 a1 7d 0e fd 4b 
c7 79 f2 99 a8 54 09 a3 e9 f3 91 e2 c4 f5 f7 80 
be e1 03 9f 6b 30 37 ff 10 a6 3e 28 f6 9c a2 3e 
04 31 7b 07 6f e9 77 3f e2 a6 72 ca f0 d9 a8 6e 
c3 a3 64 42 83 64 3c 94 74 8a 12 f0 26 88 0b 0c 
c4 44 32 32 fb b5 28 f3 8e ac 82 b9 e9 c9 9a 82 

SignerInfos:
  version: v1
  sid:
    issuer: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd

    serialNumber: 360efbcfba54170e38f532e3317a6726c7d72742

  digestAlgorithm: id_sha256
  signedAttrs:
    type: id_contentType
    values:
id_data

    type: id_signingTime
    values:
7th March 2025, 01:59:42 UTC


    type: id_messageDigest
    values:
68 05 e9 82 8e c4 9c 53 17 3b 2a 7a e5 c9 4a 8a 
b5 ae a5 aa 57 77 6c 1f 87 a5 9b 08 c7 22 c4 14 


    type: smimeCapabilities
    values:
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
ab 3c 23 d0 1e 54 0a e5 dc 3a 15 62 41 e3 6a 8d 
90 ba 6d 77 ca 71 08 df f9 84 ef 30 16 ea 91 93 
fc fb 1e 66 a3 de 9a f2 b4 18 58 94 20 c6 6a de 
4c 7e 30 5d 6f 3f a6 a9 3c 37 2e bc ad 2c ec 6d 
d0 c5 c0 e7 be 30 d0 b8 6a 69 6c 4f 87 a4 a6 9d 
9a 41 6e fc eb 4f 90 14 ab d6 fe 26 b5 8a 2f 6a 
1a 3e cf 17 b8 4b e6 0f de 4f 03 60 a0 05 d3 9b 
58 e5 a9 c0 ad c2 77 7e d3 ae 43 55 06 ad f1 20 
b0 1e bb 2c fe 22 80 5e 72 48 24 d7 4a 53 c9 df 
c2 b2 f7 b3 b3 1d ed 0f 6d 9f 91 f9 ec f6 ce 4b 
2c 3c ec a3 76 40 eb 26 db 12 c9 7f 99 8a c1 1c 
62 6b 90 b9 d5 a4 b9 2b 02 e0 68 69 aa e9 f3 42 
05 7a db b6 ca 22 56 e0 6a 98 dc 98 7c c5 0e 8b 
c3 bf 74 33 d9 b7 bc 45 77 4b 95 5e 14 30 32 8a 
cc 38 bd 3c 34 d9 00 59 ea 67 97 46 82 0b 27 9d 
3a 82 63 f5 6b 7a 18 f1 c2 2f da f9 fe 29 62 f7 
recipient$ 
```

It specifies the content type at the beginning:

```text
ContentInfo ::= SEQUENCE {
	contentType ContentType,
	content [0] EXPLICIT ANY DEFINED BY contentType }

ContentType ::= OBJECT IDENTIFIER
```

This .p7b file is with Signed-data Content Type:

```console
recipient$ ../bin/asn1parse -f signature.p7b -v
SEQUENCE  L = 1587
-OBJECT IDENTIFIER  L = 9
OID: 1 2 840 113549 1 7 2  (id_signedData)
-Context-specific 0  L = 1572
--SEQUENCE  L = 1568
:
:
```

```text
5.1. SignedData Type
The following object identifier identifies the signed-data content
type:

id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }

The signed-data content type shall have ASN.1 type SignedData:

SignedData ::= SEQUENCE {
	version CMSVersion,
	digestAlgorithms DigestAlgorithmIdentifiers,
	encapContentInfo EncapsulatedContentInfo,
	certificates [0] IMPLICIT CertificateSet OPTIONAL,
	crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
	signerInfos SignerInfos }
```

signedData type provides signatures, information for signers. Multiple signers can sign in parallel. 

### Decrypt the signature

The signature and signer's the public key are the input to the decryption. 

#### Extract the signature

We can find the signature field following the signatureAlgorithm field near the bottom of the structure. Note that this is not the signature from the certificates field.

```text
SignerInfo ::= SEQUENCE {
	version CMSVersion,
	sid SignerIdentifier,
	digestAlgorithm DigestAlgorithmIdentifier,
	signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
	signatureAlgorithm SignatureAlgorithmIdentifier,
	signature SignatureValue,
	unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
```

```console
recipient$ ../bin/p7b_extract_sig -i signature.p7b -o signature.p7b.sig
recipient$ hexdump -C signature.p7b.sig
00000000  ab 3c 23 d0 1e 54 0a e5  dc 3a 15 62 41 e3 6a 8d  |.<#..T...:.bA.j.|
00000010  90 ba 6d 77 ca 71 08 df  f9 84 ef 30 16 ea 91 93  |..mw.q.....0....|
00000020  fc fb 1e 66 a3 de 9a f2  b4 18 58 94 20 c6 6a de  |...f......X. .j.|
00000030  4c 7e 30 5d 6f 3f a6 a9  3c 37 2e bc ad 2c ec 6d  |L~0]o?..<7...,.m|
00000040  d0 c5 c0 e7 be 30 d0 b8  6a 69 6c 4f 87 a4 a6 9d  |.....0..jilO....|
00000050  9a 41 6e fc eb 4f 90 14  ab d6 fe 26 b5 8a 2f 6a  |.An..O.....&../j|
00000060  1a 3e cf 17 b8 4b e6 0f  de 4f 03 60 a0 05 d3 9b  |.>...K...O.`....|
00000070  58 e5 a9 c0 ad c2 77 7e  d3 ae 43 55 06 ad f1 20  |X.....w~..CU... |
00000080  b0 1e bb 2c fe 22 80 5e  72 48 24 d7 4a 53 c9 df  |...,.".^rH$.JS..|
00000090  c2 b2 f7 b3 b3 1d ed 0f  6d 9f 91 f9 ec f6 ce 4b  |........m......K|
000000a0  2c 3c ec a3 76 40 eb 26  db 12 c9 7f 99 8a c1 1c  |,<..v@.&........|
000000b0  62 6b 90 b9 d5 a4 b9 2b  02 e0 68 69 aa e9 f3 42  |bk.....+..hi...B|
000000c0  05 7a db b6 ca 22 56 e0  6a 98 dc 98 7c c5 0e 8b  |.z..."V.j...|...|
000000d0  c3 bf 74 33 d9 b7 bc 45  77 4b 95 5e 14 30 32 8a  |..t3...EwK.^.02.|
000000e0  cc 38 bd 3c 34 d9 00 59  ea 67 97 46 82 0b 27 9d  |.8.<4..Y.g.F..'.|
000000f0  3a 82 63 f5 6b 7a 18 f1  c2 2f da f9 fe 29 62 f7  |:.c.kz.../...)b.|
00000100
recipient$ 
```

#### Extract the public key

We find the signer's public key from the certificates field.

```console
recipient$ ../bin/p7b_extract_cert -i signature.p7b -o signature.p7b.cer
recipient$ ../bin/x509_extract_pubkey -c signature.p7b.cer -p signature.p7b.pubkey
recipient$ ../bin/rsa_text_public_key -f signature.p7b.pubkey 
PKCS #1 Public Key
  Modulus:
00 d5 7a 72 f3 4b 76 b6 4d ff cb de a1 ac ef d3 
4a b4 76 e8 f0 e6 ce 38 01 37 f3 dd 6d a3 7f 9b 
f8 9a 31 4c 18 c5 03 6e 6f d8 14 3b b2 bf 60 58 
eb 63 09 e2 09 4f 91 d0 1d fe 70 d2 ee 7a 3b 64 
12 4e 1d f2 d8 d0 81 fe 2a d0 2c 3c 6b 28 da ac 
ea af 53 24 98 fa 44 ba 13 00 68 26 44 26 7d 09 
e2 64 e3 cf c4 d3 d4 e2 c0 3a 0d d6 f2 3e f1 db 
c2 ee 92 3e 9d 1a a6 d1 19 d5 64 ef 14 14 ba dc 
fb 34 4f c9 4a c6 7a d4 0c 9c 6d da 42 24 dc 96 
82 c9 5c a6 5c e0 55 0e ed d9 2c 40 5d cb d4 56 
2e 72 d0 d6 5c 8d 08 30 fb 38 40 e2 e5 60 7e 24 
da 4e fe 86 f0 72 a9 f4 95 ff 7e 4a f5 23 b1 07 
84 e3 e9 dc da 03 2f a3 0c 05 e1 36 00 79 f4 45 
a6 ca 34 25 86 b6 ea ee 94 a9 bc b9 02 b2 0a 8f 
bf da 87 12 e0 ad ab a0 db a2 76 92 40 d9 30 51 
86 dd 63 47 48 ce 0e 40 17 b9 91 ef 4c 11 1c b1 
83 

  Exponent:
01 00 01 
recipient$ 
```

#### Get the digest out of the signature

```console
recipient$ ../bin/myrsa_trapdoor -m signature.p7b.sig -k signature.p7b.pubkey 
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
4e 4f 31 a4 8e e3 41 b5 af 6c 84 9a ce 3f d3 eb 
bf 1c a6 f9 f6 fa 50 f0 53 f5 75 53 bb 7d a9 30 

recipient$ 
```

### The digest of the document

We calculate the hash of the document with the same hash method specified in the .p7b file:

```console
Signed Data
  Version: v1
  Digest Algorithms: id_sha256
```

```console
recipient$ hexdump -C document.txt
00000000  54 68 69 73 20 69 73 20  74 68 65 20 64 6f 63 75  |This is the docu|
00000010  6d 65 6e 74 0a                                    |ment.|
00000015
recipient$ ../bin/myrsa_sha256 -i document.txt -o document.txt.digest
recipient$ hexdump -C document.txt.digest
00000000  68 05 e9 82 8e c4 9c 53  17 3b 2a 7a e5 c9 4a 8a  |h......S.;*z..J.|
00000010  b5 ae a5 aa 57 77 6c 1f  87 a5 9b 08 c7 22 c4 14  |....Wwl......"..|
00000020
recipient$ 
```

The digest of received document does not match the one from the signature. Those two digest values are different as expected.

It is because that we want to protect related information included in the SignedAttrs structure which is the message actually 'signed'.

### Extract the signedAttrs

```text
SignedAttributes ::= SET SIZE (1..MAX) OF Attribute

UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute

Attribute ::= SEQUENCE {
attrType OBJECT IDENTIFIER,
attrValues SET OF AttributeValue }
```

Let's see what are the signed attributes in the signature file.

```console
recipient$ ../bin/p7b_extract_signed_attrs -i signature.p7b -o signature.p7b.signed_attrs
recipient$ ../bin/asn1parse -f signature.p7b.signed_attrs -v
SET  L = 228
-SEQUENCE  L = 24
--OBJECT IDENTIFIER  L = 9
OID: 1 2 840 113549 1 9 3  (id_contentType)
--SET  L = 11
---OBJECT IDENTIFIER  L = 9
OID: 1 2 840 113549 1 7 1  (id_data)
-SEQUENCE  L = 28
--OBJECT IDENTIFIER  L = 9
OID: 1 2 840 113549 1 9 5  (id_signingTime)
--SET  L = 15
---UTCTime  L = 13
7th March 2025, 01:59:42 UTC

-SEQUENCE  L = 47
--OBJECT IDENTIFIER  L = 9
OID: 1 2 840 113549 1 9 4  (id_messageDigest)
--SET  L = 34
---OCTET STRING  L = 32
68 05 e9 82 8e c4 9c 53 17 3b 2a 7a e5 c9 4a 8a 
b5 ae a5 aa 57 77 6c 1f 87 a5 9b 08 c7 22 c4 14 

-SEQUENCE  L = 121
--OBJECT IDENTIFIER  L = 9
OID: 1 2 840 113549 1 9 15  (smimeCapabilities)
--SET  L = 108
---SEQUENCE  L = 106
----SEQUENCE  L = 11
-----OBJECT IDENTIFIER  L = 9
OID: 2 16 840 1 101 3 4 1 42  (id-aes256-CBC)
----SEQUENCE  L = 11
-----OBJECT IDENTIFIER  L = 9
OID: 2 16 840 1 101 3 4 1 22  (id-aes192-CBC)
----SEQUENCE  L = 11
-----OBJECT IDENTIFIER  L = 9
OID: 2 16 840 1 101 3 4 1 2  (id-aes128-CBC)
----SEQUENCE  L = 10
-----OBJECT IDENTIFIER  L = 8
OID: 1 2 840 113549 3 7  (des-EDE3-CBC)
----SEQUENCE  L = 14
-----OBJECT IDENTIFIER  L = 8
OID: 1 2 840 113549 3 2  (rc2CBC)
-----INTEGER  L = 2
00 80 
----SEQUENCE  L = 13
-----OBJECT IDENTIFIER  L = 8
OID: 1 2 840 113549 3 2  (rc2CBC)
-----INTEGER  L = 1
40 
----SEQUENCE  L = 7
-----OBJECT IDENTIFIER  L = 5
OID: 1 3 14 3 2 7  (desCBC)
----SEQUENCE  L = 13
-----OBJECT IDENTIFIER  L = 8
OID: 1 2 840 113549 3 2  (rc2CBC)
-----INTEGER  L = 1
28 
recipient$ 
```

The id-messageDigest attribute contains the expected digest of the document. In this case, it matches the result from the received document.

```console
    type: id_messageDigest
    values:
68 05 e9 82 8e c4 9c 53 17 3b 2a 7a e5 c9 4a 8a 
b5 ae a5 aa 57 77 6c 1f 87 a5 9b 08 c7 22 c4 14 
```

### Check the digest of the signedAttrs field

Now that we matched the expected digest, we need just to validate the signature which was calculated from the SignedAttrs structure.

```console
recipient$ ../bin/myrsa_sha256 -i signature.p7b.signed_attrs -o signature.p7b.signed_attrs.digest
recipient$ hexdump -C signature.p7b.signed_attrs.digest 
00000000  4e 4f 31 a4 8e e3 41 b5  af 6c 84 9a ce 3f d3 eb  |NO1...A..l...?..|
00000010  bf 1c a6 f9 f6 fa 50 f0  53 f5 75 53 bb 7d a9 30  |......P.S.uS.}.0|
00000020
recipient$ 
```

We validate the signature, confirming that the id_messageDigest value matches the digest of the received document. After a series of checks, we successfully verify the document.

### Encapsulated content

The signature file has the content embedded in encapsulatedContentInfo field:

```text
EncapsulatedContentInfo ::= SEQUENCE {
	eContentType ContentType,
	eContent [0] EXPLICIT OCTET STRING OPTIONAL }

ContentType ::= OBJECT IDENTIFIER
```

```text
  encapsulatedContentInfo:
    eContent Type: id_data
    eContent:
54 68 69 73 20 69 73 20 74 68 65 20 64 6f 63 75 
6d 65 6e 74 0a 
```

And the document we received:

```console
recipient$ hexdump -C document.txt
00000000  54 68 69 73 20 69 73 20  74 68 65 20 64 6f 63 75  |This is the docu|
00000010  6d 65 6e 74 0a                                    |ment.|
00000015
recipient$ 
```

The signature files do not necessarily present the document content. If the eContent is absent, it indicates the case of "external signatures" in which the signatures are calculated but the document content does not appear in the signature file.

## Beyond this example

This tutorial demonstrates a scenario with only one signer. However, it supports any numbers of signers. Consider the following structures:

```text
DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

SignerInfos ::= SET OF SignerInfo

CertificateSet ::= SET OF CertificateChoices

RevocationInfoChoices ::= SET OF RevocationInfoChoice

SignerInfos ::= SET OF SignerInfo
```

All of these structures are encoded as SET OF XXX, which simulates the presence of multiple signatures on a document.

We present the PKCS#7 signature file separately for demonstration purposes. In practice, applications can integrate the signature data. This self-contained system ensures portability but also limits flexibility in software choices.

## References

1. [X.509] - ITU-T Recommendation X.509: Information Technology - Open Systems Interconnection - The Directory: Public-key and attribute certificate frameworks. Retrieved from https://www.itu.int/rec/T-REC-X.509
2. [RFC 5652] - Cryptographic Message Syntax (CMS). Retrieved from https://tools.ietf.org/html/rfc5652
3. [ASN.1] - Abstract Syntax Notation One (ASN.1): Specification of basic notation. Retrieved from https://www.itu.int/rec/T-REC-X.680

