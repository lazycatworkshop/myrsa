# RSA Application Lab - Signing

# Preparation

We will use openssl utility in this exercise. Here is an example to install the package with Debian/Ubuntu:

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

First we ask openssl to generate an RSA private key at the length of 512 bits which is the shortest one allowed by openssl. That short key length is only to facilitate the demonstration and is not recommended in real applications.

```console
$ openssl genrsa -out private.key 512
$ cat private.key 
-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA5oBEwTTqmPwASdJq
tzRgAW+4c39DHZiIlXd8mMTn68F71N3heXWPNUiuD9rauaCA90jlZqh5urYeEvPT
awYh+QIDAQABAkByzjxwhuy6GfoCyt0ANwQCcyTJ0f8ZxJly6LqUVK63Cwuo8q8/
5dZ4TxN06aLgxg6ebSt/In3BeW34k3D+ngTpAiEA80jNAjWRuftNc2s+jtZ+tP04
CWLZ7ZASWRq1Aq++hK8CIQDyjGyJGehU62LFCNzLzDlgZzS3dzguXmBTsLmWcck9
1wIgHkERbZLn2m8MBKxzjSPTggJzc4ddfpOKFJajp//e+3UCIQCMVgFqZioOEE+K
j3EpHZXJGI3g5UMFWSfE5IjM6jM06wIhALvk73doI//KyacRH+FCq8krqAnShypA
Wt28UNHSM34g
-----END PRIVATE KEY-----
$ 
```

This first and last line are encapsulation boundaries, EB [RFC934] and the contend is transformed by the standard of Privacy Enhanced Mail (PEM) [RFC1421].

The structure looks like as follows:

```plaintext
-----BEGIN PRIVATE KEY-----
             :
    printable characters
             :
-----END PRIVATE KEY-----
```

Printable characters can be transfer across systems which uses different data format internally , for example, attachments in emails. Now that we know it is a PEM file, change the name accordingly:

```sh
mv private.key private_key.pem
```

### What is in the key file?

Use 'rsa -text' to print the key in text:

```console
$ openssl rsa -text -in private_key.pem -noout
Private-Key: (512 bit, 2 primes)
modulus:
    00:e6:80:44:c1:34:ea:98:fc:00:49:d2:6a:b7:34:
    60:01:6f:b8:73:7f:43:1d:98:88:95:77:7c:98:c4:
    e7:eb:c1:7b:d4:dd:e1:79:75:8f:35:48:ae:0f:da:
    da:b9:a0:80:f7:48:e5:66:a8:79:ba:b6:1e:12:f3:
    d3:6b:06:21:f9
publicExponent: 65537 (0x10001)
privateExponent:
    72:ce:3c:70:86:ec:ba:19:fa:02:ca:dd:00:37:04:
    02:73:24:c9:d1:ff:19:c4:99:72:e8:ba:94:54:ae:
    b7:0b:0b:a8:f2:af:3f:e5:d6:78:4f:13:74:e9:a2:
    e0:c6:0e:9e:6d:2b:7f:22:7d:c1:79:6d:f8:93:70:
    fe:9e:04:e9
prime1:
    00:f3:48:cd:02:35:91:b9:fb:4d:73:6b:3e:8e:d6:
    7e:b4:fd:38:09:62:d9:ed:90:12:59:1a:b5:02:af:
    be:84:af
prime2:
    00:f2:8c:6c:89:19:e8:54:eb:62:c5:08:dc:cb:cc:
    39:60:67:34:b7:77:38:2e:5e:60:53:b0:b9:96:71:
    c9:3d:d7
exponent1:
    1e:41:11:6d:92:e7:da:6f:0c:04:ac:73:8d:23:d3:
    82:02:73:73:87:5d:7e:93:8a:14:96:a3:a7:ff:de:
    fb:75
exponent2:
    00:8c:56:01:6a:66:2a:0e:10:4f:8a:8f:71:29:1d:
    95:c9:18:8d:e0:e5:43:05:59:27:c4:e4:88:cc:ea:
    33:34:eb
coefficient:
    00:bb:e4:ef:77:68:23:ff:ca:c9:a7:11:1f:e1:42:
    ab:c9:2b:a8:09:d2:87:2a:40:5a:dd:bc:50:d1:d2:
    33:7e:20
$ 
```

The result has the private key: the private exponent and the modulus. The modulus has 65 bytes instead of 64 bytes for a 512-bit key because the MSB is A2 in hex which has an 1 at the most significant bit and which presents a negative number. A leading zero is to avoid ambiguity [X.690].

The publicExponent is 65537 which is commonly adapted in the industry, so we don't need a separate step to generate a public key.

The rest components are used for optimization of RSA encryptions and decryptions and are not covered in this exercise.

## Sign the document

### Create a hash of the document
A unique characteristic, similar to a fingerprint, serves as a document's identity. For example, checksums like CRC-32 map documents to 32-bit integers. However, CRC-32 is not robust enough for practical cryptographic applications due to its limited representation and vulnerability to collisions. Instead, more sophisticated methods, such as Secure Hash Algorithms (SHA), are commonly used. In this case, we choose SHA-256 [FIPS 180-4], which offers a 256-bit output. Theoretically, it would require generating approximately $2^{128}$ hashes before encountering a collision. This output is smaller than the 512-bit modulus which guarantees the correctness of the process. 

The result is a set of hash values and if we concatenate them together we have a 'digest'.

Use 'dgst -sha256' for the hash:

```console
$ echo Hello world! > msg.txt
$ cat msg.txt
Hello world!
$ openssl dgst -sha256 -out msg.dgst msg.txt
$ cat msg.dgst
SHA2-256(msg.txt)= 0ba904eae8773b70c75333db4de2f3ac45a8ad4ddba1b242f0b3cfc199391dd8
$
```
The number string after ')= ' is the SAH-256 digest. We can also directly generate the digest in binary:

```console
$ openssl dgst -sha256 -binary -out msg.dgst msg.txt
$ hexdump -C msg.dgst
00000000  0b a9 04 ea e8 77 3b 70  c7 53 33 db 4d e2 f3 ac  |.....w;p.S3.M...|
00000010  45 a8 ad 4d db a1 b2 42  f0 b3 cf c1 99 39 1d d8  |E..M...B.....9..|
00000020
$ 
```

### Sign the hash

The digest marks the fingerprint of the document but how do we know it is really from the person we expect? In the physical world, we have signatures and we can check those against the signer's writing if there are any suspicion.

Thanks to RSA, we can apply a one-way process to the fingerprint, similar to placing a signature on a document. Like the CRC-32 value previously mentioned, the signed object—a digest in this case—is treated as an integer, but much larger. This is known as a 'big number,' which is stored as a sequence of byte-sized integers, where the most significant bit is bit 7 of the first byte. It is what we see in the text version of the digest. Similarly, the keys are also big numbers.

We use openssl's pkeyutl command to sign a message, which is the digest in the case:

```console
$ openssl pkeyutl -sign -inkey private_key.pem -in msg.dgst -out msg.sig
$ hexdump -C msg.sig
00000000  a2 5f eb eb 68 65 b1 f5  b5 64 82 84 c9 0d 1b 7d  |._..he...d.....}|
00000010  fe 61 cc 91 bc 9a ad 6e  19 04 ca 8e 93 93 b7 73  |.a.....n.......s|
00000020  25 96 81 62 8f f2 6c 47  dc eb 84 d2 bb a3 59 3f  |%..b..lG......Y?|
00000030  a3 d4 6a 74 96 a9 51 e4  2c 8d 1a 64 76 b7 47 bc  |..jt..Q.,..dv.G.|
00000040
$ 
```

We have a 512-bit private key, which corresponds to a 512-bit modulus, resulting in a 512-bit (64-byte) signature.

## Verify the document

### Prepare the public key

We used the private key to sign the digest and now we need another key to do the RSA one-way function to convert the signature back to the digest. The verification takes the public key. 

The private key file generated by openssl rsa command also have the public exponent, because it is just a 'small' integer, 65537 and the modulus is common for both keys. Private keys, however, shall not leave the safe enclaves. Therefore we draw out the public key information for the recipients:

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

Similar to what we did previously for the private key, We use openssl to display the public key in text:

```console
$ openssl rsa -text -in public_key.pem -noout
Could not read private key from public_key.pem
40500BA77F000000:error:1608010C:STORE routines:ossl_store_handle_load_result:unsupported:../crypto/store/store_result.c:151:
40500BA77F000000:error:1608010C:STORE routines:ossl_store_handle_load_result:unsupported:../crypto/store/store_result.c:151:
```

Unfortunately, openssl rsa command with -text option does not take in PEM files. We ask for a file in binary format:

```console
$ openssl rsa -pubout -in private_key.pem -outform DER -out public_key.der 
writing RSA key
$ hexdump -C public_key.der
00000000  30 5c 30 0d 06 09 2a 86  48 86 f7 0d 01 01 01 05  |0\0...*.H.......|
00000010  00 03 4b 00 30 48 02 41  00 e6 80 44 c1 34 ea 98  |..K.0H.A...D.4..|
00000020  fc 00 49 d2 6a b7 34 60  01 6f b8 73 7f 43 1d 98  |..I.j.4`.o.s.C..|
00000030  88 95 77 7c 98 c4 e7 eb  c1 7b d4 dd e1 79 75 8f  |..w|.....{...yu.|
00000040  35 48 ae 0f da da b9 a0  80 f7 48 e5 66 a8 79 ba  |5H........H.f.y.|
00000050  b6 1e 12 f3 d3 6b 06 21  f9 02 03 01 00 01        |.....k.!......|
0000005e
```

DER, Distinguished Encoding Rules[X.690], which provides a notation defining the syntax of various data. The data are in binary ready for processing.

The first byte, 30 hex, is a tag of SEQUENCE:

```console
$ openssl asn1parse -inform DER -in public_key.der
    0:d=0  hl=2 l=  92 cons: SEQUENCE          
    2:d=1  hl=2 l=  13 cons: SEQUENCE          
    4:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
   15:d=2  hl=2 l=   0 prim: NULL              
   17:d=1  hl=2 l=  75 prim: BIT STRING        
$ 
```

Now we have openssl present the public key in text:

```console
$ openssl rsa -text -pubin -inform DER -in public_key.der -noout
Public-Key: (512 bit)
Modulus:
    00:e6:80:44:c1:34:ea:98:fc:00:49:d2:6a:b7:34:
    60:01:6f:b8:73:7f:43:1d:98:88:95:77:7c:98:c4:
    e7:eb:c1:7b:d4:dd:e1:79:75:8f:35:48:ae:0f:da:
    da:b9:a0:80:f7:48:e5:66:a8:79:ba:b6:1e:12:f3:
    d3:6b:06:21:f9
Exponent: 65537 (0x10001)
```

### Calculate the hash
The recipient calculates the hash using the same algorithm against the receive document:

```console
$ openssl dgst -sha256 -binary -out msg.dgst.1 msg.txt
$ hexdump -C msg.dgst.1
00000000  0b a9 04 ea e8 77 3b 70  c7 53 33 db 4d e2 f3 ac  |.....w;p.S3.M...|
00000010  45 a8 ad 4d db a1 b2 42  f0 b3 cf c1 99 39 1d d8  |E..M...B.....9..|
00000020
$ 
```

### Verify the signature
Then the recipient performs the RSA process to the signature received along with the message by the public key and compares result to the digest of the received message:

```console
$ openssl pkeyutl -verify -pubin -inkey public_key.pem -in msg.dgst.1 -sigfile msg.sig 
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

The check will fail:

```console
$ openssl dgst -sha256 -binary -out msg.dgst.2 msg1.txt
$ openssl pkeyutl -verify -pubin -inkey public_key.pem -in msg.dgst.2 -sigfile msg.sig
Signature Verification Failure
$ 
```

It is because the different document, no matter how subtle the change is, generates a dissimilar digest:

```console
$ hexdump -C msg.dgst.2
00000000  d9 01 4c 46 24 84 4a a5  ba c3 14 77 3d 6b 68 9a  |..LF$.J....w=kh.|
00000010  d4 67 fa 4e 1d 1a 50 a1  b8 a9 9d 5a 95 f7 2f f5  |.g.N..P....Z../.|
00000020
$ hexdump -C msg.dgst.1
00000000  0b a9 04 ea e8 77 3b 70  c7 53 33 db 4d e2 f3 ac  |.....w;p.S3.M...|
00000010  45 a8 ad 4d db a1 b2 42  f0 b3 cf c1 99 39 1d d8  |E..M...B.....9..|
00000020
$ hexdump -C msg.dgst
00000000  0b a9 04 ea e8 77 3b 70  c7 53 33 db 4d e2 f3 ac  |.....w;p.S3.M...|
00000010  45 a8 ad 4d db a1 b2 42  f0 b3 cf c1 99 39 1d d8  |E..M...B.....9..|
00000020
$ 
```

## References

1. OpenSSL. (n.d.). OpenSSL: The Open Source toolkit for SSL/TLS. Retrieved from https://www.openssl.org/
2. [RFC934] - Crocker, D. H. (1985). Standard for the format of ARPA Internet text messages. Retrieved from https://tools.ietf.org/html/rfc934
3. [RFC1421] - Linn, J. (1993). Privacy Enhancement for Internet Electronic Mail: Part I: Message Encryption and Authentication Procedures. Retrieved from https://tools.ietf.org/html/rfc1421
4. [X.690] - ITU-T Recommendation X.690: Information Technology - ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER). Retrieved from https://www.itu.int/rec/T-REC-X.690
5. [FIPS 180-4] - National Institute of Standards and Technology. (2015). Secure Hash Standard (SHS). Retrieved from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf


