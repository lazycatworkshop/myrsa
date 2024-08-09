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

Ask openssl to generate an RSA key at the length of 512 bits:

```console
$ openssl genrsa -out private.key 512
$ cat private.key 
-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAtnE6K9zZ0mMyKsOz
xOvlHZKm5wRoAL8VtAoCEx6MMuHxPX+jsBLJjh5TJNT42C6K6hi3+3USuaXWDD14
4VWfPQIDAQABAkBPZwolSvJ2UXvlBtW3r99AtrHzO4S0RnYArJZokdP81IL4FN+j
T8p9aLZMG0+qoNyNrp922p1imt19JRSxZHvVAiEA4AC0ikCugOehCdnZowdsz3HT
e40JG6kXz+pFmVY9LkMCIQDQgL8A12SE2GYUO6ojdMGPZYmgOPJbmBQIMmfeDJjk
fwIhAN/TNJMUkImTaVFbkeEaETqzRRsmUNyHuJhzQXo3NsjbAiB2BosYhNTnxj9y
cJvM2ki/TXDse4/lfV7JjQ7yyRq7LQIhANd5OWATK4y5a4K1raqcfdy/1wVaIde6
nadVGp64b2+x
-----END PRIVATE KEY-----
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

Uncover the embedded data:

```console
$ openssl rsa -text -in private_key.pem -noout
Private-Key: (512 bit, 2 primes)
modulus:
    00:b6:71:3a:2b:dc:d9:d2:63:32:2a:c3:b3:c4:eb:
    e5:1d:92:a6:e7:04:68:00:bf:15:b4:0a:02:13:1e:
    8c:32:e1:f1:3d:7f:a3:b0:12:c9:8e:1e:53:24:d4:
    f8:d8:2e:8a:ea:18:b7:fb:75:12:b9:a5:d6:0c:3d:
    78:e1:55:9f:3d
publicExponent: 65537 (0x10001)
privateExponent:
    4f:67:0a:25:4a:f2:76:51:7b:e5:06:d5:b7:af:df:
    40:b6:b1:f3:3b:84:b4:46:76:00:ac:96:68:91:d3:
    fc:d4:82:f8:14:df:a3:4f:ca:7d:68:b6:4c:1b:4f:
    aa:a0:dc:8d:ae:9f:76:da:9d:62:9a:dd:7d:25:14:
    b1:64:7b:d5
prime1:
    00:e0:00:b4:8a:40:ae:80:e7:a1:09:d9:d9:a3:07:
    6c:cf:71:d3:7b:8d:09:1b:a9:17:cf:ea:45:99:56:
    3d:2e:43
prime2:
    00:d0:80:bf:00:d7:64:84:d8:66:14:3b:aa:23:74:
    c1:8f:65:89:a0:38:f2:5b:98:14:08:32:67:de:0c:
    98:e4:7f
exponent1:
    00:df:d3:34:93:14:90:89:93:69:51:5b:91:e1:1a:
    11:3a:b3:45:1b:26:50:dc:87:b8:98:73:41:7a:37:
    36:c8:db
exponent2:
    76:06:8b:18:84:d4:e7:c6:3f:72:70:9b:cc:da:48:
    bf:4d:70:ec:7b:8f:e5:7d:5e:c9:8d:0e:f2:c9:1a:
    bb:2d
coefficient:
    00:d7:79:39:60:13:2b:8c:b9:6b:82:b5:ad:aa:9c:
    7d:dc:bf:d7:05:5a:21:d7:ba:9d:a7:55:1a:9e:b8:
    6f:6f:b1
$ 
```

The modulus has 65 bytes instead of 64 bytes for 512-bit key because the MSB is A2 in hex which has an 1 at the most significant bit and which presents a negative number. ANS.1 rules add a leading zero to avoid ambiguity.

The publicExponent is 65537 which is commonly adapted in the industry, so we don't a separate step to generate a public key.

The exponent1, exponent2, and coefficient are used in the Chinese Remainder Theorem (CRT) to optimize RSA decryption. openssl use CRT for its performance.

## Sign the document

### Create a hash of the document
A unique characteristic provides the proof of the document integrity as we mention in another article in which we use a checksum, CRC-32. But CRC-32 checksum is not a strong one, therefore we usually use a more sophisticate method like a Secure Hash Algorithm. Here we choose SHA-256 which will be less than the 512-bit modulus.

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
$
$ openssl pkeyutl -sign -inkey private_key.pem -in msg.hash -out msg.sig
$ cat msg.sig
??F?IV?$ ?C??x?D?E??Y???߬EC???h???hp?????G??????`
$ hexdump -C msg.sig
00000000  7a 35 46 bb 56 67 f9 2a  a4 04 f7 43 82 82 78 d6  |z5F.Vg.*...C..x.|
00000010  44 ba 45 8b 89 59 be b3  d0 df ac 45 11 43 86 de  |D.E..Y.....E.C..|
00000020  dc 68 f1 3f fc 68 70 b1  fb ad 83 a0 47 fc 89 cb  |.h.?.hp.....G...|
00000030  c6 f5 e4 00 02 60 0d b0  86 46 d1 49 0e 11 56 ca  |.....`...F.I..V.|
00000040
```

'rsautl' is not accept in newer versions of openssl.
'pkeyutl' takes only the binary hash file and generates only the binary output for signature. We have a 512-bit private key, means 512-bit modulus, hence the 512-bit (64 bytes) of signature.

## Verify the document

### Prepare the public key

Private keys shall not leave the safe enclaves, therefore we extract the public key information for the recipients:

```console
$ openssl rsa -in private_key.pem -pubout -out public_key.pem
writing RSA key
$ cat public_key.pem 
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALZxOivc2dJjMirDs8Tr5R2SpucEaAC/
FbQKAhMejDLh8T1/o7ASyY4eUyTU+NguiuoYt/t1Erml1gw9eOFVnz0CAwEAAQ==
-----END PUBLIC KEY-----
```

When the other party receives this public key information, the user needs to convert it to its original binary form:

```console
$ openssl rsa -pubin -in public_key.pem -outform DER -out public_key.der
writing RSA key
$ hexdump -C public_key.der
00000000  30 5c 30 0d 06 09 2a 86  48 86 f7 0d 01 01 01 05  |0\0...*.H.......|
00000010  00 03 4b 00 30 48 02 41  00 b6 71 3a 2b dc d9 d2  |..K.0H.A..q:+...|
00000020  63 32 2a c3 b3 c4 eb e5  1d 92 a6 e7 04 68 00 bf  |c2*..........h..|
00000030  15 b4 0a 02 13 1e 8c 32  e1 f1 3d 7f a3 b0 12 c9  |.......2..=.....|
00000040  8e 1e 53 24 d4 f8 d8 2e  8a ea 18 b7 fb 75 12 b9  |..S$.........u..|
00000050  a5 d6 0c 3d 78 e1 55 9f  3d 02 03 01 00 01        |...=x.U.=.....|
0000005e
$ 
```
The raw data is generated using ASN.1 syntax and is encoded by DER, Distinguished Encoding Rules. According to X.509 (2019):

```plaintext
SubjectPublicKeyInfo ::= SEQUENCE {
algorithm AlgorithmIdentifier{{SupportedAlgorithms}},
subjectPublicKey BIT STRING,
... }
```
The first byte is 30h which is the identifier octet, SEQUENCE, which and the second byte is 5ch(92) which is the length octet.

openssl can parse the public key in ASN.1 structure:  

```console
$ openssl asn1parse -inform DER -in public_key.der
    0:d=0  hl=2 l=  92 cons: SEQUENCE          
    2:d=1  hl=2 l=  13 cons: SEQUENCE          
    4:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
   15:d=2  hl=2 l=   0 prim: NULL              
   17:d=1  hl=2 l=  75 prim: BIT STRING        
$ 
```
The algorithm is rsaEncryption. Unfortunately, openssl does not display the BIT STRING data. This project has a program for it:

```
$ ./asn1parse -f public_key.der
0000: SEQUENCE	L = 92
0002: SEQUENCE	L = 13
0004: OBJECT IDENTIFIER	L = 9
0006: 2a 86 48 86 f7 0d 01 01 01 
OID: 1 2 840 113549 1 1 1  (rsaEncryption)
0015: NULL	L = 0
0017: BIT STRING	L = 75
0019: Unused bits: 0
0020: SEQUENCE	L = 72
0022: INTEGER	L = 65
0024: 00 b6 71 3a 2b dc d9 d2 63 32 2a c3 b3 c4 eb e5 
0040: 1d 92 a6 e7 04 68 00 bf 15 b4 0a 02 13 1e 8c 32 
0056: e1 f1 3d 7f a3 b0 12 c9 8e 1e 53 24 d4 f8 d8 2e 
0072: 8a ea 18 b7 fb 75 12 b9 a5 d6 0c 3d 78 e1 55 9f 
0088: 3d 
0089: INTEGER	L = 3
0091: 01 00 01 
Done
$ 
```

PKCK #1's definition for the public key:

```plaintext
A.1.1.  RSA Public Key Syntax

   An RSA public key should be represented with the ASN.1 type
   RSAPublicKey:

         RSAPublicKey ::= SEQUENCE {
             modulus           INTEGER,  -- n
             publicExponent    INTEGER   -- 
```
So we know the first integer is the modulus while the second one is the public exponent, 65537. We can confirm this by openssl:

```
$ openssl rsa -pubin -inform DER -in public_key.der -text -noout
Public-Key: (512 bit)
Modulus:
    00:b6:71:3a:2b:dc:d9:d2:63:32:2a:c3:b3:c4:eb:
    e5:1d:92:a6:e7:04:68:00:bf:15:b4:0a:02:13:1e:
    8c:32:e1:f1:3d:7f:a3:b0:12:c9:8e:1e:53:24:d4:
    f8:d8:2e:8a:ea:18:b7:fb:75:12:b9:a5:d6:0c:3d:
    78:e1:55:9f:3d
Exponent: 65537 (0x10001)
$ 
```

### Calculate the hash
Given the document, the recipient calculates the hash using the same algorithm:
```
$ openssl dgst -sha256 -binary -out msg.hash.1 msg.txt 
$ 
```

### Verify the signature
Then newly calculated hash and the received signature to the utility to verify authenticity:

```console
$ openssl pkeyutl -verify -pubin -inkey public_key.pem -in msg.hash.1 -sigfile msg.sig
Signature Verified Successfully
$ 
```

### When the file is altered
If the recipient obtain a different document:
```console
$ echo Hello, world! > msg1.txt
$ cat msg1.txt
Hello, world!
```

The check will fail because the different document, no matter how subtle is the change, generates a dissimilar hash:
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




