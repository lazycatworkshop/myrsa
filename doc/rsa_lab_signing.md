# RSA Application Lab - Signing

# Preparation

We will use openssl utility to perform operations. Here is an example to install the package with Debian/Ubuntu:

```sh
sudo apt update
```

```sh
sudo apt install openssl
```

```sh
openssl version
```

## Generate a private key

First we ask openssl to generate an RSA private key at the length of 512 bits which is the shortest one allowed by openssl and that short key is not recommended in real applications:

```console
$ openssl genrsa -out private.key 512
$ cat private.key
-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAqPQBtfX+67xa1iEn
w6o82NPe7bF28hphQii24AoMXvZ2RXl7opH4/nYX/J4KszLIqWljT9vRSbGk5us3
mA99bwIDAQABAkBGrt7QW3ws734pO3HBYEVYiTsowif7HaI25YWssUd/qnrH2iLC
kknVc6esith9Ha0g28BglkQ4bbwmGnzuXxhhAiEA0Re+WZg1o0kGOy+jIiAFKtyj
V/oGjO64EmcUkK1yzBcCIQDO2wjZDnDCnfzD1Pe5bHwByx9Bp4Z0rUVh/HY/dIl4
aQIgCtNA3qCbvk1sjinkN0MTIWn05vwh1LATRZiinu7r75cCIQCXKy8eIRV6xKZy
HvMiyQse7GhdPKZgIjhwUWXBHdNQ8QIgPHcSThIwH3qCy0vk8O4913yZPBqFJgSy
nhLyYSiOCbA=
-----END PRIVATE KEY-----
$ 
```

This first and last line are encapsulation boundaries, EB, as defined in RFC934:

```plaintext
Definitions: a draft forwarding message consists of a header portion and a text portion.  If the text portion is present, it is separated from the header portion by a blank line.  Inside the text portion a certain character string sequence, known as an "encapsulation boundary", has special meaning.  Currently (in existing digestification agents), an encapsulation boundary (EB) is defined as a line in the message which starts with a dash (decimal code 45, "-").  Initially, no restriction is placed on the length of the encapsulation boundary, or on the characters that follow the dash.
```

This approach is adapted by RFC1421, Privacy Enhanced Mail (PEM). The structure looks like as follows:

```plaintext
-----BEGIN PRIVATE KEY-----
             :
    printable characters
             :
-----END PRIVATE KEY-----
```

Now that we know it is a PEM file, change the name accordingly:

```bash
mv private.key private_key.pem
```

### What is in the key file?

Use 'rsa -text' to print the key in text:

```console
$ openssl rsa -text -in private_key.pem -noout
Private-Key: (512 bit, 2 primes)
modulus:
    00:a8:f4:01:b5:f5:fe:eb:bc:5a:d6:21:27:c3:aa:
    3c:d8:d3:de:ed:b1:76:f2:1a:61:42:28:b6:e0:0a:
    0c:5e:f6:76:45:79:7b:a2:91:f8:fe:76:17:fc:9e:
    0a:b3:32:c8:a9:69:63:4f:db:d1:49:b1:a4:e6:eb:
    37:98:0f:7d:6f
publicExponent: 65537 (0x10001)
privateExponent:
    46:ae:de:d0:5b:7c:2c:ef:7e:29:3b:71:c1:60:45:
    58:89:3b:28:c2:27:fb:1d:a2:36:e5:85:ac:b1:47:
    7f:aa:7a:c7:da:22:c2:92:49:d5:73:a7:ac:8a:d8:
    7d:1d:ad:20:db:c0:60:96:44:38:6d:bc:26:1a:7c:
    ee:5f:18:61
prime1:
    00:d1:17:be:59:98:35:a3:49:06:3b:2f:a3:22:20:
    05:2a:dc:a3:57:fa:06:8c:ee:b8:12:67:14:90:ad:
    72:cc:17
prime2:
    00:ce:db:08:d9:0e:70:c2:9d:fc:c3:d4:f7:b9:6c:
    7c:01:cb:1f:41:a7:86:74:ad:45:61:fc:76:3f:74:
    89:78:69
exponent1:
    0a:d3:40:de:a0:9b:be:4d:6c:8e:29:e4:37:43:13:
    21:69:f4:e6:fc:21:d4:b0:13:45:98:a2:9e:ee:eb:
    ef:97
exponent2:
    00:97:2b:2f:1e:21:15:7a:c4:a6:72:1e:f3:22:c9:
    0b:1e:ec:68:5d:3c:a6:60:22:38:70:51:65:c1:1d:
    d3:50:f1
coefficient:
    3c:77:12:4e:12:30:1f:7a:82:cb:4b:e4:f0:ee:3d:
    d7:7c:99:3c:1a:85:26:04:b2:9e:12:f2:61:28:8e:
    09:b0
$ 
```

The modulus has 65 bytes instead of 64 bytes for 512-bit key because the MSB is A2 in hex which has an 1 at the most significant bit and which presents a negative number. ANS.1 rules add a leading zero to avoid ambiguity.

The publicExponent is 65537 which is commonly adapted in the industry, so we don't need a separate step to generate a public key.

The exponent1, exponent2, and coefficient are used in the Chinese Remainder Theorem (CRT) to optimize RSA decryption. openssl use CRT for its performance.

## Sign the document

### Create a hash of the document
A unique characteristic provides the proof of the document integrity as we mention in another article in which we use a checksum, CRC-32. But CRC-32 checksum is not a strong one, therefore we usually use a more sophisticate method like a Secure Hash Algorithm. Here we choose SHA-256 which will be less than the 512-bit modulus.

Use 'dgst -sha256' for the hash:

```console
$ echo Hello world! > msg.txt
$ cat msg.txt
Hello world!
$ openssl dgst -sha256 -out msg.hash msg.txt
$ hexdump -C msg.hash
00000000  53 48 41 32 2d 32 35 36  28 6d 73 67 2e 74 78 74  |SHA2-256(msg.txt|
00000010  29 3d 20 30 62 61 39 30  34 65 61 65 38 37 37 33  |)= 0ba904eae8773|
00000020  62 37 30 63 37 35 33 33  33 64 62 34 64 65 32 66  |b70c75333db4de2f|
00000030  33 61 63 34 35 61 38 61  64 34 64 64 62 61 31 62  |3ac45a8ad4ddba1b|
00000040  32 34 32 66 30 62 33 63  66 63 31 39 39 33 39 31  |242f0b3cfc199391|
00000050  64 64 38 0a                                       |dd8.|
00000054
$ cat msg.hash
SHA2-256(msg.txt)= 0ba904eae8773b70c75333db4de2f3ac45a8ad4ddba1b242f0b3cfc199391dd8
```
The number string after ')= ' is the SAH-256 hash and is usually called digest. We can also directly generate the hash in binary form:

```console

$ openssl dgst -sha256 -binary -out msg.hash msg.txt
$ hexdump -C msg.hash
00000000  0b a9 04 ea e8 77 3b 70  c7 53 33 db 4d e2 f3 ac  |.....w;p.S3.M...|
00000010  45 a8 ad 4d db a1 b2 42  f0 b3 cf c1 99 39 1d d8  |E..M...B.....9..|
00000020
$ 
```
The digest of SHA-256 has 256 bits which is 64 bytes. 


### Sign the hash
We do not sign the document, instead we sign only the particular hash:

```console
$ openssl rsautl -sign -inkey private_key.pem -in msg.hash -out msg.sig
The command rsautl was deprecated in version 3.0. Use 'pkeyutl' instead.
$ openssl pkeyutl -sign -inkey private_key.pem -in msg.hash -out msg.sig
$ cat msg.sig
?\x??&g\Xx?ݞ?ʳ9i??5I???z֡?kӼ[??sF|???]?g??Eiwq?"??Xd$ 
$ hexdump -C msg.sig
00000000  96 5c 78 cc 00 e8 26 67  5c 58 78 b5 dd 9e 9e ca  |.\x...&g\Xx.....|
00000010  b3 39 17 69 c7 ef 91 35  49 3f ee c6 7a d6 a1 b1  |.9.i...5I?..z...|
00000020  6b d3 bc 13 05 17 5b e0  cd 73 46 7c e8 13 bc 1d  |k.....[..sF|....|
00000030  8b 5d ed 67 c3 e3 45 69  77 71 ad 22 cc e6 58 64  |.].g..Eiwq."..Xd|
00000040
$ 
```

'rsautl' command is not accept in newer versions of openssl, so we go with 'pkeyutl -sign' as prompted.

'pkeyutl -sign' signs any file as a whole so we use the binary hash file and generates the binary signature. We have a 512-bit private key, means 512-bit modulus, hence the 512-bit (64 bytes) of signature.

## Verify the document

### Prepare the public key

Private keys shall not leave the safe enclaves, therefore we extract the public key information for the recipients with 'rsa -pubout':

```console
$ openssl rsa -in private_key.pem -pubout -out public_key.pem
writing RSA key
$ cat public_key.pem 
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj0AbX1/uu8WtYhJ8OqPNjT3u2xdvIa
YUIotuAKDF72dkV5e6KR+P52F/yeCrMyyKlpY0/b0UmxpObrN5gPfW8CAwEAAQ==
-----END PUBLIC KEY-----
$ 
```

The PEM file start and end with the text '-----BEGIN PUBLIC KEY-----' and '-----END PUBLIC KEY-----' which identify the purpose of the file. When the other party receives this public key information, from the document sender or a public database, the user needs to convert it to its original binary form. The raw data is generated using ASN.1 syntax and is encoded by DER, Distinguished Encoding Rules. We also use 'rsa -pubout' and add a designator '-outform' to specify the DER format:

```console
$ openssl rsa -pubout -in private_key.pem -outform DER -out public_key.der
writing RSA key
$ hexdump -C public_key.der
00000000  30 5c 30 0d 06 09 2a 86  48 86 f7 0d 01 01 01 05  |0\0...*.H.......|
00000010  00 03 4b 00 30 48 02 41  00 a8 f4 01 b5 f5 fe eb  |..K.0H.A........|
00000020  bc 5a d6 21 27 c3 aa 3c  d8 d3 de ed b1 76 f2 1a  |.Z.!'..<.....v..|
00000030  61 42 28 b6 e0 0a 0c 5e  f6 76 45 79 7b a2 91 f8  |aB(....^.vEy{...|
00000040  fe 76 17 fc 9e 0a b3 32  c8 a9 69 63 4f db d1 49  |.v.....2..icO..I|
00000050  b1 a4 e6 eb 37 98 0f 7d  6f 02 03 01 00 01        |....7..}o.....|
0000005e
$ openssl asn1parse -inform DER -in public_key.der
    0:d=0  hl=2 l=  92 cons: SEQUENCE          
    2:d=1  hl=2 l=  13 cons: SEQUENCE          
    4:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
   15:d=2  hl=2 l=   0 prim: NULL              
   17:d=1  hl=2 l=  75 prim: BIT STRING        
$ 
```

The first byte is 30h which is the identifier octet, SEQUENCE, which and the second byte is 5ch(92) which is the length octet.

According to X.509 (2019):

```plaintext
SubjectPublicKeyInfo ::= SEQUENCE {
algorithm AlgorithmIdentifier{{SupportedAlgorithms}},
subjectPublicKey BIT STRING,
... }

AlgorithmIdentifier{ALGORITHM:SupportedAlgorithms} ::= SEQUENCE {
algorithm ALGORITHM.&id({SupportedAlgorithms}),
parameters ALGORITHM.&Type({SupportedAlgorithms}{@algorithm}) OPTIONAL,
... }

The algorithm component shall be an object identifier that uniquely identifies the cryptographic algorithm being defined.
The parameters component, when present, shall specify the parameters associated with the algorithm. Some, but not all algorithms require associated parameters.
```
openssl ASN.1 parser finds the SupportedAlgorithm is rsaEncryption. What is the subjectPublicKey?

PKCK #1's definition for the public key:

```plaintext
A.1.1.  RSA Public Key Syntax

   An RSA public key should be represented with the ASN.1 type
   RSAPublicKey:

         RSAPublicKey ::= SEQUENCE {
             modulus           INTEGER,  -- n
             publicExponent    INTEGER   -- 
```

We should have the BIT STRING wrapped in a SEQUENCE containing one integer for modulus and another integer for the public exponent. Unfortunately openssl ASN.1 parser does not display the BIT STRING data. This project has a program for it:

```
$ ./asn1parse -f public_key.der
0000: SEQUENCE	L =   92
0002: 	SEQUENCE	L =   13
0004: 		OBJECT IDENTIFIER	L =    9
0015: 		NULL	L =    0
0017: 	BIT STRING	L =   75
0020: 		SEQUENCE	L =   72
0022: 			INTEGER	L =   65
0089: 			INTEGER	L =    3
$ 
```

To break down further:

```console
$ ./asn1parse -f public_key.der -v
0000: SEQUENCE	L =   92
0002: 	SEQUENCE	L =   13
0004: 		OBJECT IDENTIFIER	L =    9
OID: 1 2 840 113549 1 1 1  (rsaEncryption)
0015: 		NULL	L =    0
0017: 	BIT STRING	L =   75
0019:  0 - Unused bits
0020: 		SEQUENCE	L =   72
0022: 			INTEGER	L =   65
0024: 00 a8 f4 01 b5 f5 fe eb bc 5a d6 21 27 c3 aa 3c 
0040: d8 d3 de ed b1 76 f2 1a 61 42 28 b6 e0 0a 0c 5e 
0056: f6 76 45 79 7b a2 91 f8 fe 76 17 fc 9e 0a b3 32 
0072: c8 a9 69 63 4f db d1 49 b1 a4 e6 eb 37 98 0f 7d 
0088: 6f 
0089: 			INTEGER	L =    3
0091: 01 00 01 
$ 
```

Similar to what we did previously for the private key, We can use '-text -pubin' to extract the public key in text:

```
$ openssl rsa -text -pubin -inform DER -in public_key.der -noout
Public-Key: (512 bit)
Modulus:
    00:a8:f4:01:b5:f5:fe:eb:bc:5a:d6:21:27:c3:aa:
    3c:d8:d3:de:ed:b1:76:f2:1a:61:42:28:b6:e0:0a:
    0c:5e:f6:76:45:79:7b:a2:91:f8:fe:76:17:fc:9e:
    0a:b3:32:c8:a9:69:63:4f:db:d1:49:b1:a4:e6:eb:
    37:98:0f:7d:6f
Exponent: 65537 (0x10001)
$ 
```

### Calculate the hash
The recipient calculates the hash using the same algorithm against the receive document:

```
$ openssl dgst -sha256 -binary -out msg.hash.1 msg.txt
$ 
```

### Verify the signature
Then the recipient takes the sender's public key information, newly calculated hash and the received signature to the utility to verify authenticity with 'pkeyutl' command with '-verify' option:

```console
$ openssl pkeyutl -verify -pubin -inkey public_key.pem -in msg.hash.1 -sigfile msg.sig
Signature Verified Successfully
$ 
```

### When the file is altered
If the recipient obtains a different document:
```console
$ echo Hello, world! > msg1.txt
$ cat msg1.txt
Hello, world!
$ 
```

The check will fail because the different document, no matter how subtle the change is, generates a dissimilar hash:
```
$ openssl dgst -sha256 -binary -out msg.hash.2 msg1.txt
$ hexdump -C msg.hash.2
00000000  d9 01 4c 46 24 84 4a a5  ba c3 14 77 3d 6b 68 9a  |..LF$.J....w=kh.|
00000010  d4 67 fa 4e 1d 1a 50 a1  b8 a9 9d 5a 95 f7 2f f5  |.g.N..P....Z../.|
00000020
$ hexdump -C msg.hash.1
00000000  0b a9 04 ea e8 77 3b 70  c7 53 33 db 4d e2 f3 ac  |.....w;p.S3.M...|
00000010  45 a8 ad 4d db a1 b2 42  f0 b3 cf c1 99 39 1d d8  |E..M...B.....9..|
00000020
$ openssl pkeyutl -verify -pubin -inkey public_key.pem -in msg.hash.2 -sigfile msg.sig
Signature Verification Failure
$ 
```




