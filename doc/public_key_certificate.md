# Public Key Certificate

## X.509 Certificate

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

It includes only the minimal requirements for RSA encryption. While this may be sufficient for exchanges between trusted parties, how can we verify the authenticity of a key obtained from public sources, such as websites? This is where Certificate Authorities (CAs) play a crucial role.

Certificate Authorities (CAs) are trusted entities responsible for issuing digital certificates used to verify the identity of websites, organizations, or individuals [RFC5280].

When we connect to a website with HTTPS, with the prefix of https, the browser uses the website’s public key, included in the digital certificate, to encrypt data exchanged with the website. The digital certificate enclose a digital signature made by the CA that issued the certificate. This signature is created using the CA’s private key.

The certificate, signed, is defined in X.509 [X.509]:

```text

SIGNATURE ::= SEQUENCE {
	algorithmIdentifier 	AlgorithmIdentifier{{SupportedAlgorithms}},
	signature 				BIT STRING,
... }

SIGNED{ToBeSigned} ::= SEQUENCE {
toBeSigned ToBeSigned,
COMPONENTS OF SIGNATURE,
...,
[[4:
altAlgorithmIdentifier AlgorithmIdentifier{{SupportedAltAlgorithms}} OPTIONAL,
altSignature BIT STRING OPTIONAL]]
} (WITH COMPONENTS {..., altAlgorithmIdentifier PRESENT, altSignature PRESENT } |
WITH COMPONENTS {..., altAlgorithmIdentifier ABSENT, altSignature ABSENT } ) }

Certificate ::= SIGNED{TBSCertificate}
TBSCertificate ::= SEQUENCE {
	version					[0]	Version DEFAULT v1,
	serialNumber 					CertificateSerialNumber,
	signature 					AlgorithmIdentifier{{SupportedAlgorithms}},
	issuer 						Name,
	validity 						Validity,
	subject 						Name,
	subjectPublicKeyInfo 		SubjectPublicKeyInfo,
	issuerUniqueIdentifier	[1]	IMPLICIT UniqueIdentifier OPTIONAL,
	...,
	[[2: -- if present, version shall be v2 or v3
	subjectUniqueIdentifier [2] IMPLICIT UniqueIdentifier OPTIONAL]],
	[[3: -- if present, version shall be v2 or v3
	extensions [3] Extensions OPTIONAL]]

	-- If present, version shall be v3]]
}
```

```console
Usage: ./get_cert [-p port] [-o output_file] hostname
$ ./get_cert -o fast.com.der fast.com
Downloading certificate from fast.com:443

Certificate Information:
========================
Format: DER (X.509)
Size:   1737 bytes
First 20 bytes of body): 308206c5308205ada00302010202100694fe6841
Certificate saved to: fast.com.der (1737 bytes)
$ ./asn1parser 
Usage: ./asn1parser -f <file> [-v]
$ ./asn1parser -f fast.com.der -v
SEQUENCE  L = 1733
-SEQUENCE  L = 1453
--Context-specific 0  L = 3
---INTEGER  L = 1
:
:
--SEQUENCE  L = 290
---SEQUENCE  L = 13
----OBJECT IDENTIFIER  L = 9
OID: 1.2.840.113549.1.1.1

----NULL  L = 0
---BIT STRING  L = 271
Unused bits: 0
30 82 01 0a 02 82 01 01 00 9f 1f fc f9 80 a5 22 
37 51 55 40 b4 2d ad 3c 50 03 df 3d 19 7a 2e b7 
42 20 56 d7 f2 a7 e3 33 33 69 b2 06 f6 bf 7c 33 
85 3f 50 d1 bc 17 5c 20 55 b0 06 2d 98 cb d2 f1 
82 60 ce 26 1c a8 d0 bc 29 46 4d bb 60 c8 20 60 
cc c2 29 50 2f 75 0d 1e fd d6 11 08 1c ca 87 c1 
21 f3 78 7a 37 2c 19 5e e2 80 29 e7 ec 6c 0d ca 
13 b0 a7 d0 c6 53 ea ec b0 83 9f 26 99 a9 ec 9e 
0d 83 7e cb b4 bb 39 3d f4 2f ff 1e 91 c6 c2 b6 
66 a8 4c 20 9d 4e d9 37 e0 19 f3 74 3a f4 77 48 
40 c4 06 b2 d5 a6 36 61 51 7b d1 09 14 bf ef 63 
3c 7f a1 73 7e 23 cb 59 08 9c 56 f7 eb 27 b0 96 
f6 18 0c 6e 59 28 50 89 34 40 72 a1 3f 70 31 7f 
55 4c 49 bb e5 13 6e 59 66 c5 f4 5d 36 b4 6b 0d 
3e 0c 7a 59 f7 36 35 7c 60 2a f3 91 a0 7d 4f 05 
d7 d1 7b a0 d7 36 08 69 f0 2b 4e 46 dd 0b 11 8c 
ec 26 37 81 23 88 34 9f cb 02 03 01 00 01 
:
:
$ 
```

Follow the ASN.1 [X.690] parsing, we expose the certificate's content. For our exercise, we find the public key first:

```console
$ ./x509_text_public_key
Usage: ./x509_text_public_key -f <file>
$ ./x509_text_public_key -f fast.com.der
X.509 Certificate:
  TBSCertificate:
:
    Signature Algorithm: sha256WithRSAEncryption
:
    Subject Public Key Info:
      Algorithm: rsaEncryption
      Subject Public Key:
Modulus:
9F 1F FC F9 80 A5 22 37 51 55 40 B4 2D AD 3C 50
03 DF 3D 19 7A 2E B7 42 20 56 D7 F2 A7 E3 33 33
69 B2 06 F6 BF 7C 33 85 3F 50 D1 BC 17 5C 20 55
B0 06 2D 98 CB D2 F1 82 60 CE 26 1C A8 D0 BC 29
46 4D BB 60 C8 20 60 CC C2 29 50 2F 75 0D 1E FD
D6 11 08 1C CA 87 C1 21 F3 78 7A 37 2C 19 5E E2
80 29 E7 EC 6C 0D CA 13 B0 A7 D0 C6 53 EA EC B0
83 9F 26 99 A9 EC 9E 0D 83 7E CB B4 BB 39 3D F4
2F FF 1E 91 C6 C2 B6 66 A8 4C 20 9D 4E D9 37 E0
19 F3 74 3A F4 77 48 40 C4 06 B2 D5 A6 36 61 51
7B D1 09 14 BF EF 63 3C 7F A1 73 7E 23 CB 59 08
9C 56 F7 EB 27 B0 96 F6 18 0C 6E 59 28 50 89 34
40 72 A1 3F 70 31 7F 55 4C 49 BB E5 13 6E 59 66
C5 F4 5D 36 B4 6B 0D 3E 0C 7A 59 F7 36 35 7C 60
2A F3 91 A0 7D 4F 05 D7 D1 7B A0 D7 36 08 69 F0
2B 4E 46 DD 0B 11 8C EC 26 37 81 23 88 34 9F CB

Exponent: 65537
:
:
  Signature:
    Algorithm: sha256WithRSAEncryption
    Signature:
0D F4 66 F0 3C 2F FA D9 84 C0 4E 62 55 8E AC F0
40 BC E2 F8 5C B5 1C 28 8F C7 1D C9 B5 C5 E1 DA
76 A9 31 C9 50 46 06 A4 9A 7D 6C DF 24 E7 9D BB
9C A3 30 FA ED 78 86 1D 26 0B F7 D0 BD 87 0D 7C
A9 14 AE F5 5B 0B 58 88 B1 5E C9 33 67 A2 1A 6A
05 B8 8C 34 86 CB 97 87 5C 32 C1 F8 C3 9A DC 5C
EF 84 D0 D9 AD 50 DC 94 D2 AC 24 7F CF DA AE B8
2F 54 C1 6C A3 82 64 58 8E 54 1F CC D3 97 ED 27
B9 D9 21 D2 7C 30 06 B4 DD E1 44 DD 8C 42 DE DC
9C 2E 40 8A CD 61 FB 2B 66 3D E0 F5 0D C1 34 3C
BE A3 8B 11 92 85 34 93 59 CF 85 69 39 C5 E0 7B
3B EF 01 05 9A 08 7F 2F 0E 17 9E 1C 5C FD DC 74
61 24 08 F8 36 75 67 27 93 0C 6D F9 03 4B A8 E8
74 0E F3 2E 3A AE 5D 69 9F CB D4 99 F0 7D 28 91
D4 FD 26 65 0B 0D C8 95 15 7F BE F1 15 9B A1 E9
CB 05 82 53 A7 95 EC 5A 06 E7 56 D2 8C E6 8A 6D
$ 
```
## Authenticate the certificate

The certificate is signed using the algorithm specified by **signature**. It is 
sha256WithRSAEncryption: taking the SHA-256 [FIPS 180-4] hash against **TBSCertificate** result in a digest (fingerprint) and process it with the issuer's private RSA key.

### Find the CA's public key

The CA is *DigiCert Global G2 TLS RSA SHA256 2020 CA1*:

```console
$ ./x509_text_public_key -f fast.com.der | grep CN=
    Issuer: C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
    Subject: C=US, ST=California, L=Los Gatos, O=Netflix, CN=fast.com
$ ./x509_text_public_key -f fast.com.der | grep id-ad-caIssuers
  id-ad-caIssuers: http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt
$ curl -o DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1228  100  1228    0     0  20099      0 --:--:-- --:--:-- --:--:-- 20466
```

The public key is provided in **subjectPublicKeyInfo** [RFC5280].

```console
$ ./x509_extract_pubkey 
Usage: ./x509_extract_pubkey -c <input_cert.der> -p <output_pubkey.der>
$ ./x509_extract_pubkey -c DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt -p DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt.pubkey
$ ./asn1parser -f DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt.pubkey 
SEQUENCE  L = 266
-INTEGER  L = 257
-INTEGER  L = 3
$ ./asn1parser -f DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt.pubkey -v
SEQUENCE  L = 266
-INTEGER  L = 257
00 cc f7 10 62 4f a6 bb 63 6f ed 90 52 56 c5 6d 
27 7b 7a 12 56 8a f1 f4 f9 d6 e7 e1 8f bd 95 ab 
f2 60 41 15 70 db 12 00 fa 27 0a b5 57 38 5b 7d 
b2 51 93 71 95 0e 6a 41 94 5b 35 1b fa 7b fa bb 
c5 be 24 30 fe 56 ef c4 f3 7d 97 e3 14 f5 14 4d 
cb a7 10 f2 16 ea ab 22 f0 31 22 11 61 69 90 26 
ba 78 d9 97 1f e3 7d 66 ab 75 44 95 73 c8 ac ff 
ef 5d 0a 8a 59 43 e1 ac b2 3a 0f f3 48 fc d7 6b 
37 c1 63 dc de 46 d6 db 45 fe 7d 23 fd 90 e8 51 
07 1e 51 a3 5f ed 49 46 54 7f 2c 88 c5 f4 13 9c 
97 15 3c 03 e8 a1 39 dc 69 0c 32 c1 af 16 57 4c 
94 47 42 7c a2 c8 9c 7d e6 d4 4d 54 af 42 99 a8 
c1 04 c2 77 9c d6 48 e4 ce 11 e0 2a 80 99 f0 43 
70 cf 3f 76 6b d1 4c 49 ab 24 5e c2 0d 82 fd 46 
a8 ab 6c 93 cc 62 52 42 75 92 f8 9a fa 5e 5e b2 
b0 61 e5 1f 1f b9 7f 09 98 e8 3d fa 83 7f 47 69 
a1 
-INTEGER  L = 3
01 00 01 
```

The e is 65537, a common public key exponent.

### Get hashed data from the signature
The signature is done by process **TBSCertificate**'s hash with the CA's private key. So applying the CA's public key to the signature gets the hash.

```console
$ ./x509_extract_sig 
Usage: ./x509_extract_sig -c <input_cert.der> -s <output_sig.der>
$ ./x509_extract_sig -c fast.com.der -s fast.com.der.sig
$ hexdump -C fast.com.der.sig
00000000  0d f4 66 f0 3c 2f fa d9  84 c0 4e 62 55 8e ac f0  |..f.</....NbU...|
00000010  40 bc e2 f8 5c b5 1c 28  8f c7 1d c9 b5 c5 e1 da  |@...\..(........|
00000020  76 a9 31 c9 50 46 06 a4  9a 7d 6c df 24 e7 9d bb  |v.1.PF...}l.$...|
00000030  9c a3 30 fa ed 78 86 1d  26 0b f7 d0 bd 87 0d 7c  |..0..x..&......||
00000040  a9 14 ae f5 5b 0b 58 88  b1 5e c9 33 67 a2 1a 6a  |....[.X..^.3g..j|
00000050  05 b8 8c 34 86 cb 97 87  5c 32 c1 f8 c3 9a dc 5c  |...4....\2.....\|
00000060  ef 84 d0 d9 ad 50 dc 94  d2 ac 24 7f cf da ae b8  |.....P....$.....|
00000070  2f 54 c1 6c a3 82 64 58  8e 54 1f cc d3 97 ed 27  |/T.l..dX.T.....'|
00000080  b9 d9 21 d2 7c 30 06 b4  dd e1 44 dd 8c 42 de dc  |..!.|0....D..B..|
00000090  9c 2e 40 8a cd 61 fb 2b  66 3d e0 f5 0d c1 34 3c  |..@..a.+f=....4<|
000000a0  be a3 8b 11 92 85 34 93  59 cf 85 69 39 c5 e0 7b  |......4.Y..i9..{|
000000b0  3b ef 01 05 9a 08 7f 2f  0e 17 9e 1c 5c fd dc 74  |;....../....\..t|
000000c0  61 24 08 f8 36 75 67 27  93 0c 6d f9 03 4b a8 e8  |a$..6ug'..m..K..|
000000d0  74 0e f3 2e 3a ae 5d 69  9f cb d4 99 f0 7d 28 91  |t...:.]i.....}(.|
000000e0  d4 fd 26 65 0b 0d c8 95  15 7f be f1 15 9b a1 e9  |..&e............|
000000f0  cb 05 82 53 a7 95 ec 5a  06 e7 56 d2 8c e6 8a 6d  |...S...Z..V....m|
00000100
$ ./myrsa_trapdoor 
Usage: ./myrsa_trapdoor -m <message file> -k <keyfile>
$ ./myrsa_trapdoor -m fast.com.der.sig -k DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt.pubkey
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
1b 6c 69 ba 57 1b 4d b7 f4 e6 62 ed 23 7e cb c1 
91 f8 3c 6f bb aa 3e 46 c0 27 a2 1e 73 65 69 55 
```
The reversed signature is an encoded message, EM, made by the method of EMSA-PKCS1-v1_5 [PKCS#1]:

```text
Steps:
   1.  Apply the hash function to the message M to produce a hash
       value H:
H = Hash(M).
       If the hash function outputs "message too long", output
       "message too long" and stop.
   2.  Encode the algorithm ID for the hash function and the hash
       value into an ASN.1 value of type DigestInfo (see
       Appendix A.2.4) with the DER, where the type DigestInfo has
       the syntax
            DigestInfo ::= SEQUENCE {
                digestAlgorithm AlgorithmIdentifier,
                digest OCTET STRING
}
       The first field identifies the hash function and the second
       contains the hash value.  Let T be the DER encoding of the
       DigestInfo value (see the notes below), and let tLen be the
       length in octets of T.
   3.  If emLen < tLen + 11, output "intended encoded message length
       too short" and stop.
   4.  Generate an octet string PS consisting of emLen - tLen - 3
       octets with hexadecimal value 0xff.  The length of PS will be
       at least 8 octets.
   5.  Concatenate PS, the DER encoding T, and other padding to form
       the encoded message EM as
          EM = 0x00 || 0x01 || PS || 0x00 || T.
6. Output EM.
```

### Take the hash

```console
$ ./x509_extract_tbs
Usage: ./x509_extract_tbs -c <input_cert.der> -t <output_tbs.der>
$ ./x509_extract_tbs -c fast.com.der -t fast.com.der.tbs
$ ./asn1parser -f fast.com.der.tbs
SEQUENCE  L = 1453
-Context-specific 0  L = 3
--INTEGER  L = 1
-INTEGER  L = 16
-SEQUENCE  L = 13
--OBJECT IDENTIFIER  L = 9
--NULL  L = 0
:
:
$ 
```

The toBeSigned part, **TBSCertificate**, includes the top level SEQUENCE.

Calculate TBSCertificate's hash:

```console
$ ./myrsa_sha256 
Usage: myrsa_sha256 -i <input file> -o <output file>
$ ./myrsa_sha256 -i fast.com.der.tbs -o fast.com.der.tbs.dgst
$ hexdump -C fast.com.der.tbs.dgst 
00000000  1b 6c 69 ba 57 1b 4d b7  f4 e6 62 ed 23 7e cb c1  |.li.W.M...b.#~..|
00000010  91 f8 3c 6f bb aa 3e 46  c0 27 a2 1e 73 65 69 55  |..<o..>F.'..seiU|
00000020
```

## Certificate chain of trust

```console
$ ./x509_text_public_key -f DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt | grep CN=    Issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2
    Subject: C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
$ 
```
The CA's certificate also has an issuer, that is, the CA's certificate is signed by another CA.

```console
$  ./x509_text_public_key -f DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt | grep CN=
    Issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2
    Subject: C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
$ ./x509_text_public_key -f DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt | grep id-ad-caIssuers
  id-ad-caIssuers: http://cacerts.digicert.com/DigiCertGlobalRootG2.crt
$ curl -o DigiCertGlobalRootG2.crt http://cacerts.digicert.com/DigiCertGlobalRootG2.crt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   914  100   914    0     0   3000      0 --:--:-- --:--:-- --:--:--  2996
$ ./x509_text_public_key -f DigiCertGlobalRootG2.crt | grep CN=
    Issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2
    Subject: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2
$  C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2
$ 
```
The second CA's issuer is itself which means it is a self-signed certificate and hence a root CA [RFC5280].

In this case we have three certificates in the chain of trust:

-**Leaf Certificate**: fast.com.der
-**Intermediate CA**: DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt
-**Root CA**: DigiCertGlobalRootG2.crt

## The subject's public key
Once a certificate is authenticated, we can use the inclosed public key safely.

```console 
$ ./x509_extract_pubkey -c fast.com.der -p fast.com.der.pubkey
$ ./asn1parser -f fast.com.der.pubkey -v
SEQUENCE  L = 266
-INTEGER  L = 257
00 9f 1f fc f9 80 a5 22 37 51 55 40 b4 2d ad 3c 
50 03 df 3d 19 7a 2e b7 42 20 56 d7 f2 a7 e3 33 
33 69 b2 06 f6 bf 7c 33 85 3f 50 d1 bc 17 5c 20 
55 b0 06 2d 98 cb d2 f1 82 60 ce 26 1c a8 d0 bc 
29 46 4d bb 60 c8 20 60 cc c2 29 50 2f 75 0d 1e 
fd d6 11 08 1c ca 87 c1 21 f3 78 7a 37 2c 19 5e 
e2 80 29 e7 ec 6c 0d ca 13 b0 a7 d0 c6 53 ea ec 
b0 83 9f 26 99 a9 ec 9e 0d 83 7e cb b4 bb 39 3d 
f4 2f ff 1e 91 c6 c2 b6 66 a8 4c 20 9d 4e d9 37 
e0 19 f3 74 3a f4 77 48 40 c4 06 b2 d5 a6 36 61 
51 7b d1 09 14 bf ef 63 3c 7f a1 73 7e 23 cb 59 
08 9c 56 f7 eb 27 b0 96 f6 18 0c 6e 59 28 50 89 
34 40 72 a1 3f 70 31 7f 55 4c 49 bb e5 13 6e 59 
66 c5 f4 5d 36 b4 6b 0d 3e 0c 7a 59 f7 36 35 7c 
60 2a f3 91 a0 7d 4f 05 d7 d1 7b a0 d7 36 08 69 
f0 2b 4e 46 dd 0b 11 8c ec 26 37 81 23 88 34 9f 
cb 
-INTEGER  L = 3
01 00 01 
$ 
```

The modulus and exponent components are both encoded as ASN.1 INTEGER which big numbers [X.690]. The leading 0 of the modulus is used to indicate that it is a positive number when msb is set. 

## EXPLICIT/IMPLICIT tagging

When designing complex data structures like X.509 certificates, fields often need context-specific labels (e.g., distinguishing between different optional fields in a sequence). This is where EXPLICIT and IMPLICIT tagging come in. They define how context-specific tags are applied to a data type.

With implicit tagging, the original tag following the context-specific tag is completely replaced by the new context-specific tag. The context-specific tag in this case does not have the constructed bit set [X.690].

X.509 specifies EXPLICIT TAGS globally by default [X.509].

```text
AuthenticationFramework
{joint-iso-itu-t ds(5) module(1) authenticationFramework(7) 9}
DEFINITIONS ::=

- - - X.690 ASN.1 
The "TagDefault" is taken as EXPLICIT TAGS if it is "empty".
- - -
```

However, different tagging can be used when a field's data type needs to remain transparent or when dealing with complex choices where the exact underlying type might otherwise be ambiguous during parsing. This flexible tagging scheme leads to complicate parse designs.

We demonstrate the complexity in two different handlings of the GeneralName and AuthorityKeyIdentifier structures [RFC5280]:

- Assume nothing except for good data:

```c
static void X509_print_general_name(const ASN1Object *general_name)
{
	/* 
	 * GeneralName ::= CHOICE {
	 *     otherName                       [0]     OtherName,
	 *     rfc822Name                      [1]     IA5String,
	 *     dNSName                         [2]     IA5String,
	 *     x400Address                     [3]     ORAddress,
	 *     directoryName                   [4]     Name,
	 *     ediPartyName                    [5]     EDIPartyName,
	 *     uniformResourceIdentifier       [6]     IA5String,
	 *     iPAddress                       [7]     OCTET STRING,
	 *     registeredID                    [8]     OBJECT IDENTIFIER
	 * }
	 * 
	 * IMPLICIT tagging is checked at the constructed bit.
	 */
	uint8_t tag = asn1_get_tag(general_name->tag);
	/* Assume IMPLICIT tagging  */
	const uint8_t *p = general_name->value;
	size_t len = general_name->length;
	ASN1Object obj;
	if (asn1_is_constructed(general_name->tag)) { /* Explicit */
		struct memfp mp;
		memfp_open(&mp, general_name->value, general_name->length);
		if (asn1_load(&mp, &obj) == 0) {
			p = obj.value;
			len = obj.length;
		} else {
			fprintf(stderr, "Error: Unable to load GeneralName\n");
			exit(EXIT_FAILURE);
		}
		memfp_close(&mp); /* Clear the memory */
	}
	switch (tag) {
	case ASN1_TAG_CONTEXT_SPECIFIC_1:
	case ASN1_TAG_CONTEXT_SPECIFIC_2:
	case ASN1_TAG_CONTEXT_SPECIFIC_6:
		print_printable_string(p, len);
		break;
	case ASN1_TAG_CONTEXT_SPECIFIC_4:
	default:
		fprintf(stderr, "Error: Not a supported GeneralName\n");
		exit(EXIT_FAILURE);
	}
}
```

- With knowledge of the tagging scheme:

```c
static void X509_print_authority_key_identifier(const ASN1Object *extension)
{
	/* 
	 * AuthorityKeyIdentifier ::= SEQUENCE {
	 *     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
	 *     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
	 *     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
	 * }
	 */
	if (asn1_get_tag(extension->tag) != ASN1_TAG_SEQUENCE) {
		fprintf(stderr, "Error: Not a valid AuthorityKeyIdentifier\n");
		exit(EXIT_FAILURE);
	}

	struct memfp mp;
	memfp_open(&mp, extension->value, extension->length);
	int len = extension->length;

	ASN1Object obj;
	while (len > 0) {
		long offset1 = mtell(&mp);
		uint8_t tag = asn1_get_tag(mpeekc(&mp));
		switch (tag) {
		case ASN1_TAG_CONTEXT_SPECIFIC_0:
			/* KeyIdentifier ::= OCTET STRING */
			if (asn1_load(&mp, &obj) == 0) {
				X509_dump8(obj.value, obj.length);
			} else {
				fprintf(stderr,
					"Error: Unable to load KeyIdentifier\n");
				exit(EXIT_FAILURE);
			}
			break;
```

## Complete listing

The listing shows the certificate extensions [RFC5280], including the embedded Signed Certificate Timestamps (SCTs) [RFC6962].

```console
$ ./get_cert
Usage: ./get_cert [-p port] [-o output_file] hostname
$ ./get_cert -o fast.com.der fast.com
Downloading certificate from fast.com:443

Certificate Information:
========================
Format: DER (X.509)
Size:   1737 bytes
First 20 bytes of body): 308206c5308205ada00302010202100694fe6841
Certificate saved to: fast.com.der (1737 bytes)
$ ./asn1parser 
Usage: ./asn1parser -f <file> [-v]
$ ./asn1parser -f fast.com.der -v
SEQUENCE  L = 1733
-SEQUENCE  L = 1453
--Context-specific 0  L = 3
---INTEGER  L = 1
02 
--INTEGER  L = 16
06 94 fe 68 41 6e dc b7 0b 29 09 98 0e 18 c5 57 

--SEQUENCE  L = 13
---OBJECT IDENTIFIER  L = 9
OID: 1.2.840.113549.1.1.11

---NULL  L = 0
--SEQUENCE  L = 89
---SET  L = 11
----SEQUENCE  L = 9
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.4.6

-----PrintableString  L = 2
US

---SET  L = 21
----SEQUENCE  L = 19
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.4.10

-----PrintableString  L = 12
DigiCert Inc

---SET  L = 51
----SEQUENCE  L = 49
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.4.3

-----PrintableString  L = 42
DigiCert Global G2 TLS RSA SHA256 2020 CA1

--SEQUENCE  L = 30
---UTCTime  L = 13
32 36 30 39 33 30 30 30 30 30 30 30 5a 
---UTCTime  L = 13
32 37 30 34 31 36 32 33 35 39 35 39 5a 
--SEQUENCE  L = 91
---SET  L = 11
----SEQUENCE  L = 9
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.4.6

-----PrintableString  L = 2
US

---SET  L = 19
----SEQUENCE  L = 17
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.4.8

-----PrintableString  L = 10
California

---SET  L = 18
----SEQUENCE  L = 16
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.4.7

-----PrintableString  L = 9
Los Gatos

---SET  L = 16
----SEQUENCE  L = 14
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.4.10

-----PrintableString  L = 7
Netflix

---SET  L = 17
----SEQUENCE  L = 15
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.4.3

-----PrintableString  L = 8
fast.com

--SEQUENCE  L = 290
---SEQUENCE  L = 13
----OBJECT IDENTIFIER  L = 9
OID: 1.2.840.113549.1.1.1

----NULL  L = 0
---BIT STRING  L = 271
Unused bits: 0
30 82 01 0a 02 82 01 01 00 9f 1f fc f9 80 a5 22 
37 51 55 40 b4 2d ad 3c 50 03 df 3d 19 7a 2e b7 
42 20 56 d7 f2 a7 e3 33 33 69 b2 06 f6 bf 7c 33 
85 3f 50 d1 bc 17 5c 20 55 b0 06 2d 98 cb d2 f1 
82 60 ce 26 1c a8 d0 bc 29 46 4d bb 60 c8 20 60 
cc c2 29 50 2f 75 0d 1e fd d6 11 08 1c ca 87 c1 
21 f3 78 7a 37 2c 19 5e e2 80 29 e7 ec 6c 0d ca 
13 b0 a7 d0 c6 53 ea ec b0 83 9f 26 99 a9 ec 9e 
0d 83 7e cb b4 bb 39 3d f4 2f ff 1e 91 c6 c2 b6 
66 a8 4c 20 9d 4e d9 37 e0 19 f3 74 3a f4 77 48 
40 c4 06 b2 d5 a6 36 61 51 7b d1 09 14 bf ef 63 
3c 7f a1 73 7e 23 cb 59 08 9c 56 f7 eb 27 b0 96 
f6 18 0c 6e 59 28 50 89 34 40 72 a1 3f 70 31 7f 
55 4c 49 bb e5 13 6e 59 66 c5 f4 5d 36 b4 6b 0d 
3e 0c 7a 59 f7 36 35 7c 60 2a f3 91 a0 7d 4f 05 
d7 d1 7b a0 d7 36 08 69 f0 2b 4e 46 dd 0b 11 8c 
ec 26 37 81 23 88 34 9f cb 02 03 01 00 01 
--Context-specific 3  L = 901
---SEQUENCE  L = 897
----SEQUENCE  L = 31
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.29.35

-----OCTET STRING  L = 24
30 16 80 14 74 85 80 c0 66 c7 df 37 de cf bd 29 
37 aa 03 1d be ed cd 17 
----SEQUENCE  L = 29
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.29.14

-----OCTET STRING  L = 22
04 14 60 fa 14 94 74 2d 29 25 86 10 dd 4f 28 2b 
84 e0 84 2c d3 b4 
----SEQUENCE  L = 33
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.29.17

-----OCTET STRING  L = 26
30 18 82 08 66 61 73 74 2e 63 6f 6d 82 0c 77 77 
77 2e 66 61 73 74 2e 63 6f 6d 
----SEQUENCE  L = 62
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.29.32

-----OCTET STRING  L = 55
30 35 30 33 06 06 67 81 0c 01 02 02 30 29 30 27 
06 08 2b 06 01 05 05 07 02 01 16 1b 68 74 74 70 
3a 2f 2f 77 77 77 2e 64 69 67 69 63 65 72 74 2e 
63 6f 6d 2f 43 50 53 
----SEQUENCE  L = 14
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.29.15

-----BOOLEAN  L = 1
BOOLEAN: TRUE

-----OCTET STRING  L = 4
03 02 05 a0 
----SEQUENCE  L = 19
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.29.37

-----OCTET STRING  L = 12
30 0a 06 08 2b 06 01 05 05 07 03 01 
----SEQUENCE  L = 159
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.29.31

-----OCTET STRING  L = 151
30 81 94 30 48 a0 46 a0 44 86 42 68 74 74 70 3a 
2f 2f 63 72 6c 33 2e 64 69 67 69 63 65 72 74 2e 
63 6f 6d 2f 44 69 67 69 43 65 72 74 47 6c 6f 62 
61 6c 47 32 54 4c 53 52 53 41 53 48 41 32 35 36 
32 30 32 30 43 41 31 2d 31 2e 63 72 6c 30 48 a0 
46 a0 44 86 42 68 74 74 70 3a 2f 2f 63 72 6c 34 
2e 64 69 67 69 63 65 72 74 2e 63 6f 6d 2f 44 69 
67 69 43 65 72 74 47 6c 6f 62 61 6c 47 32 54 4c 
53 52 53 41 53 48 41 32 35 36 32 30 32 30 43 41 
31 2d 31 2e 63 72 6c 
----SEQUENCE  L = 135
-----OBJECT IDENTIFIER  L = 8
OID: 1.3.6.1.5.5.7.1.1

-----OCTET STRING  L = 123
30 79 30 24 06 08 2b 06 01 05 05 07 30 01 86 18 
68 74 74 70 3a 2f 2f 6f 63 73 70 2e 64 69 67 69 
63 65 72 74 2e 63 6f 6d 30 51 06 08 2b 06 01 05 
05 07 30 02 86 45 68 74 74 70 3a 2f 2f 63 61 63 
65 72 74 73 2e 64 69 67 69 63 65 72 74 2e 63 6f 
6d 2f 44 69 67 69 43 65 72 74 47 6c 6f 62 61 6c 
47 32 54 4c 53 52 53 41 53 48 41 32 35 36 32 30 
32 30 43 41 31 2d 31 2e 63 72 74 
----SEQUENCE  L = 12
-----OBJECT IDENTIFIER  L = 3
OID: 2.5.29.19

-----BOOLEAN  L = 1
BOOLEAN: TRUE

-----OCTET STRING  L = 2
30 00 
----SEQUENCE  L = 379
-----OBJECT IDENTIFIER  L = 10
OID: 1.3.6.1.4.1.11129.2.4.2

-----OCTET STRING  L = 363
04 82 01 67 01 65 00 75 00 4c 63 dc 98 e5 9c 1d 
ab 88 f6 1e 8a 3d de ae 8f ab 44 a3 37 7b 5f 9b 
94 c3 fb a1 9c fc c1 be 26 00 00 01 a0 f4 8e 36 
5c 00 00 04 03 00 46 30 44 02 20 00 d0 08 74 79 
ce 03 26 b6 a0 7b b5 48 1c 83 7d e3 98 dc a2 fa 
88 2c 45 f1 3d 99 91 d4 e3 60 53 02 20 32 33 1a 
7e 24 88 7a 96 87 ae 24 d1 fd e6 7f a8 52 6d 9f 
06 a3 d7 f9 a6 f4 33 e4 a8 8f b9 f9 b8 00 75 00 
d6 d5 8d a9 d0 17 53 f3 6a 4a a0 c7 57 49 02 af 
eb c7 dc 2c d3 8c d9 f7 64 c8 0c 89 19 1e 9f 02 
00 00 01 a0 f4 8e 36 5c 00 00 04 03 00 46 30 44 
02 20 29 02 21 21 80 bf 57 67 66 49 de 68 fe 57 
a0 6f 85 85 9a d3 cd 23 f5 80 1b da 0c 0b 85 a8 
b0 c1 02 20 5c 53 09 0b 00 7e 82 a7 8d 00 d0 0d 
35 48 b1 db 2e 5c 90 b6 e0 de c5 37 93 6c 7e 29 
65 5e 34 8b 00 75 00 44 c2 bd 0c e9 14 0e 64 a5 
c9 4a 01 93 0a 5a a1 bb 35 97 0e 00 ee 11 16 89 
68 2a 1c 44 d7 b5 66 00 00 01 a0 f4 8e 36 8e 00 
00 04 03 00 46 30 44 02 20 3b 25 9a cc 54 79 ba 
3b a5 8f b8 5e 81 e8 69 b5 ea 21 74 8d c9 c6 66 
1e 9e db c7 53 fd e5 ef d9 02 20 17 ea bc 62 05 
de d4 cc 50 c8 b8 56 18 e4 90 e5 0b 41 96 7f 20 
26 c9 54 f3 40 44 fc 25 c8 ef 4c 
-SEQUENCE  L = 13
--OBJECT IDENTIFIER  L = 9
OID: 1.2.840.113549.1.1.11

--NULL  L = 0
-BIT STRING  L = 257
Unused bits: 0
0d f4 66 f0 3c 2f fa d9 84 c0 4e 62 55 8e ac f0 
40 bc e2 f8 5c b5 1c 28 8f c7 1d c9 b5 c5 e1 da 
76 a9 31 c9 50 46 06 a4 9a 7d 6c df 24 e7 9d bb 
9c a3 30 fa ed 78 86 1d 26 0b f7 d0 bd 87 0d 7c 
a9 14 ae f5 5b 0b 58 88 b1 5e c9 33 67 a2 1a 6a 
05 b8 8c 34 86 cb 97 87 5c 32 c1 f8 c3 9a dc 5c 
ef 84 d0 d9 ad 50 dc 94 d2 ac 24 7f cf da ae b8 
2f 54 c1 6c a3 82 64 58 8e 54 1f cc d3 97 ed 27 
b9 d9 21 d2 7c 30 06 b4 dd e1 44 dd 8c 42 de dc 
9c 2e 40 8a cd 61 fb 2b 66 3d e0 f5 0d c1 34 3c 
be a3 8b 11 92 85 34 93 59 cf 85 69 39 c5 e0 7b 
3b ef 01 05 9a 08 7f 2f 0e 17 9e 1c 5c fd dc 74 
61 24 08 f8 36 75 67 27 93 0c 6d f9 03 4b a8 e8 
74 0e f3 2e 3a ae 5d 69 9f cb d4 99 f0 7d 28 91 
d4 fd 26 65 0b 0d c8 95 15 7f be f1 15 9b a1 e9 
cb 05 82 53 a7 95 ec 5a 06 e7 56 d2 8c e6 8a 6d 

$ ./x509_text_public_key 
Usage: ./x509_text_public_key -f <file>
$ ./x509_text_public_key -f fast.com.der
X.509 Certificate:
  TBSCertificate:
    Version: v3
    Serial Number: 0694FE68416EDCB70B2909980E18C557
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
    Validity:
      Not Before: 260930000000Z
      Not After : 270416235959Z
    Subject: C=US, ST=California, L=Los Gatos, O=Netflix, CN=fast.com
    Subject Public Key Info:
      Algorithm: rsaEncryption
      Subject Public Key:
Modulus:
9F 1F FC F9 80 A5 22 37 51 55 40 B4 2D AD 3C 50
03 DF 3D 19 7A 2E B7 42 20 56 D7 F2 A7 E3 33 33
69 B2 06 F6 BF 7C 33 85 3F 50 D1 BC 17 5C 20 55
B0 06 2D 98 CB D2 F1 82 60 CE 26 1C A8 D0 BC 29
46 4D BB 60 C8 20 60 CC C2 29 50 2F 75 0D 1E FD
D6 11 08 1C CA 87 C1 21 F3 78 7A 37 2C 19 5E E2
80 29 E7 EC 6C 0D CA 13 B0 A7 D0 C6 53 EA EC B0
83 9F 26 99 A9 EC 9E 0D 83 7E CB B4 BB 39 3D F4
2F FF 1E 91 C6 C2 B6 66 A8 4C 20 9D 4E D9 37 E0
19 F3 74 3A F4 77 48 40 C4 06 B2 D5 A6 36 61 51
7B D1 09 14 BF EF 63 3C 7F A1 73 7E 23 CB 59 08
9C 56 F7 EB 27 B0 96 F6 18 0C 6E 59 28 50 89 34
40 72 A1 3F 70 31 7F 55 4C 49 BB E5 13 6E 59 66
C5 F4 5D 36 B4 6B 0D 3E 0C 7A 59 F7 36 35 7C 60
2A F3 91 A0 7D 4F 05 D7 D1 7B A0 D7 36 08 69 F0
2B 4E 46 DD 0B 11 8C EC 26 37 81 23 88 34 9F CB

Exponent: 65537
    Extensions:
id-ce-authorityKeyIdentifier
74 85 80 C0 66 C7 DF 37 DE CF BD 29 37 AA 03 1D
BE ED CD 17 
id-ce-subjectKeyIdentifier
60 FA 14 94 74 2D 29 25 86 10 DD 4F 28 2B 84 E0
84 2C D3 B4 
id-ce-subjectAltName
  fast.com
  www.fast.com
id-ce-certificatePolicies
  organization-validated

id-ce-keyUsage, critical
  digitalSignature, keyEncipherment
id-ce-extKeyUsage
  id-kp-serverAuth
id-ce-cRLDistributionPoints
  http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl
  http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl
id-pe-authorityInfoAccess
  id-ad-ocsp: http://ocsp.digicert.com
  id-ad-caIssuers: http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt
id-ce-basicConstraints, critical
  cA: FALSE
embedded-scts
  SCT:
    version: v1
    log_id:
4C 63 DC 98 E5 9C 1D AB 88 F6 1E 8A 3D DE AE 8F
AB 44 A3 37 7B 5F 9B 94 C3 FB A1 9C FC C1 BE 26
    timestamp: Wed Sep 30 23:02:35 2026

    extensions: none
    signature:
      hash_alg: SHA256
      sig_alg: ECDSA
      sig_len: 70
30 44 02 20 00 D0 08 74 79 CE 03 26 B6 A0 7B B5
48 1C 83 7D E3 98 DC A2 FA 88 2C 45 F1 3D 99 91
D4 E3 60 53 02 20 32 33 1A 7E 24 88 7A 96 87 AE
24 D1 FD E6 7F A8 52 6D 9F 06 A3 D7 F9 A6 F4 33
E4 A8 8F B9 F9 B8 
  SCT:
    version: v1
    log_id:
D6 D5 8D A9 D0 17 53 F3 6A 4A A0 C7 57 49 02 AF
EB C7 DC 2C D3 8C D9 F7 64 C8 0C 89 19 1E 9F 02
    timestamp: Wed Sep 30 23:02:35 2026

    extensions: none
    signature:
      hash_alg: SHA256
      sig_alg: ECDSA
      sig_len: 70
30 44 02 20 29 02 21 21 80 BF 57 67 66 49 DE 68
FE 57 A0 6F 85 85 9A D3 CD 23 F5 80 1B DA 0C 0B
85 A8 B0 C1 02 20 5C 53 09 0B 00 7E 82 A7 8D 00
D0 0D 35 48 B1 DB 2E 5C 90 B6 E0 DE C5 37 93 6C
7E 29 65 5E 34 8B 
  SCT:
    version: v1
    log_id:
44 C2 BD 0C E9 14 0E 64 A5 C9 4A 01 93 0A 5A A1
BB 35 97 0E 00 EE 11 16 89 68 2A 1C 44 D7 B5 66
    timestamp: Wed Sep 30 23:02:35 2026

    extensions: none
    signature:
      hash_alg: SHA256
      sig_alg: ECDSA
      sig_len: 70
30 44 02 20 3B 25 9A CC 54 79 BA 3B A5 8F B8 5E
81 E8 69 B5 EA 21 74 8D C9 C6 66 1E 9E DB C7 53
FD E5 EF D9 02 20 17 EA BC 62 05 DE D4 CC 50 C8
B8 56 18 E4 90 E5 0B 41 96 7F 20 26 C9 54 F3 40
44 FC 25 C8 EF 4C 

  Signature:
    Algorithm: sha256WithRSAEncryption
    Signature:
0D F4 66 F0 3C 2F FA D9 84 C0 4E 62 55 8E AC F0
40 BC E2 F8 5C B5 1C 28 8F C7 1D C9 B5 C5 E1 DA
76 A9 31 C9 50 46 06 A4 9A 7D 6C DF 24 E7 9D BB
9C A3 30 FA ED 78 86 1D 26 0B F7 D0 BD 87 0D 7C
A9 14 AE F5 5B 0B 58 88 B1 5E C9 33 67 A2 1A 6A
05 B8 8C 34 86 CB 97 87 5C 32 C1 F8 C3 9A DC 5C
EF 84 D0 D9 AD 50 DC 94 D2 AC 24 7F CF DA AE B8
2F 54 C1 6C A3 82 64 58 8E 54 1F CC D3 97 ED 27
B9 D9 21 D2 7C 30 06 B4 DD E1 44 DD 8C 42 DE DC
9C 2E 40 8A CD 61 FB 2B 66 3D E0 F5 0D C1 34 3C
BE A3 8B 11 92 85 34 93 59 CF 85 69 39 C5 E0 7B
3B EF 01 05 9A 08 7F 2F 0E 17 9E 1C 5C FD DC 74
61 24 08 F8 36 75 67 27 93 0C 6D F9 03 4B A8 E8
74 0E F3 2E 3A AE 5D 69 9F CB D4 99 F0 7D 28 91
D4 FD 26 65 0B 0D C8 95 15 7F BE F1 15 9B A1 E9
CB 05 82 53 A7 95 EC 5A 06 E7 56 D2 8C E6 8A 6D

$ ./x509_extract_tbs
Usage: ./x509_extract_tbs -c <input_cert.der> -t <output_tbs.der>
$ ./x509_extract_tbs -c fast.com.der -t fast.com.der.tbs
$ ./asn1parser -f fast.com.der.tbs
SEQUENCE  L = 1453
-Context-specific 0  L = 3
--INTEGER  L = 1
-INTEGER  L = 16
-SEQUENCE  L = 13
--OBJECT IDENTIFIER  L = 9
--NULL  L = 0
-SEQUENCE  L = 89
--SET  L = 11
---SEQUENCE  L = 9
----OBJECT IDENTIFIER  L = 3
----PrintableString  L = 2
--SET  L = 21
---SEQUENCE  L = 19
----OBJECT IDENTIFIER  L = 3
----PrintableString  L = 12
--SET  L = 51
---SEQUENCE  L = 49
----OBJECT IDENTIFIER  L = 3
----PrintableString  L = 42
-SEQUENCE  L = 30
--UTCTime  L = 13
--UTCTime  L = 13
-SEQUENCE  L = 91
--SET  L = 11
---SEQUENCE  L = 9
----OBJECT IDENTIFIER  L = 3
----PrintableString  L = 2
--SET  L = 19
---SEQUENCE  L = 17
----OBJECT IDENTIFIER  L = 3
----PrintableString  L = 10
--SET  L = 18
---SEQUENCE  L = 16
----OBJECT IDENTIFIER  L = 3
----PrintableString  L = 9
--SET  L = 16
---SEQUENCE  L = 14
----OBJECT IDENTIFIER  L = 3
----PrintableString  L = 7
--SET  L = 17
---SEQUENCE  L = 15
----OBJECT IDENTIFIER  L = 3
----PrintableString  L = 8
-SEQUENCE  L = 290
--SEQUENCE  L = 13
---OBJECT IDENTIFIER  L = 9
---NULL  L = 0
--BIT STRING  L = 271
-Context-specific 3  L = 901
--SEQUENCE  L = 897
---SEQUENCE  L = 31
----OBJECT IDENTIFIER  L = 3
----OCTET STRING  L = 24
---SEQUENCE  L = 29
----OBJECT IDENTIFIER  L = 3
----OCTET STRING  L = 22
---SEQUENCE  L = 33
----OBJECT IDENTIFIER  L = 3
----OCTET STRING  L = 26
---SEQUENCE  L = 62
----OBJECT IDENTIFIER  L = 3
----OCTET STRING  L = 55
---SEQUENCE  L = 14
----OBJECT IDENTIFIER  L = 3
----BOOLEAN  L = 1
----OCTET STRING  L = 4
---SEQUENCE  L = 19
----OBJECT IDENTIFIER  L = 3
----OCTET STRING  L = 12
---SEQUENCE  L = 159
----OBJECT IDENTIFIER  L = 3
----OCTET STRING  L = 151
---SEQUENCE  L = 135
----OBJECT IDENTIFIER  L = 8
----OCTET STRING  L = 123
---SEQUENCE  L = 12
----OBJECT IDENTIFIER  L = 3
----BOOLEAN  L = 1
----OCTET STRING  L = 2
---SEQUENCE  L = 379
----OBJECT IDENTIFIER  L = 10
----OCTET STRING  L = 363
$ ./x509_text_public_key -f fast.com.der | grep CN=
    Issuer: C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
    Subject: C=US, ST=California, L=Los Gatos, O=Netflix, CN=fast.com
$ ./x509_text_public_key -f fast.com.der | grep id-ad-caIssuers
  id-ad-caIssuers: http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt
$ curl -o DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1228  100  1228    0     0  20099      0 --:--:-- --:--:-- --:--:-- 20466
$ ./x509_extract_pubkey 
Usage: ./x509_extract_pubkey -c <input_cert.der> -p <output_pubkey.der>
$ ./x509_extract_pubkey -c DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt -p DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt.pubkey
$ ./asn1parser -f DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt.pubkey 
SEQUENCE  L = 266
-INTEGER  L = 257
-INTEGER  L = 3
$ ./asn1parser -f DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt.pubkey -v
SEQUENCE  L = 266
-INTEGER  L = 257
00 cc f7 10 62 4f a6 bb 63 6f ed 90 52 56 c5 6d 
27 7b 7a 12 56 8a f1 f4 f9 d6 e7 e1 8f bd 95 ab 
f2 60 41 15 70 db 12 00 fa 27 0a b5 57 38 5b 7d 
b2 51 93 71 95 0e 6a 41 94 5b 35 1b fa 7b fa bb 
c5 be 24 30 fe 56 ef c4 f3 7d 97 e3 14 f5 14 4d 
cb a7 10 f2 16 ea ab 22 f0 31 22 11 61 69 90 26 
ba 78 d9 97 1f e3 7d 66 ab 75 44 95 73 c8 ac ff 
ef 5d 0a 8a 59 43 e1 ac b2 3a 0f f3 48 fc d7 6b 
37 c1 63 dc de 46 d6 db 45 fe 7d 23 fd 90 e8 51 
07 1e 51 a3 5f ed 49 46 54 7f 2c 88 c5 f4 13 9c 
97 15 3c 03 e8 a1 39 dc 69 0c 32 c1 af 16 57 4c 
94 47 42 7c a2 c8 9c 7d e6 d4 4d 54 af 42 99 a8 
c1 04 c2 77 9c d6 48 e4 ce 11 e0 2a 80 99 f0 43 
70 cf 3f 76 6b d1 4c 49 ab 24 5e c2 0d 82 fd 46 
a8 ab 6c 93 cc 62 52 42 75 92 f8 9a fa 5e 5e b2 
b0 61 e5 1f 1f b9 7f 09 98 e8 3d fa 83 7f 47 69 
a1 
-INTEGER  L = 3
01 00 01 
$ ./x509_extract_sig 
Usage: ./x509_extract_sig -c <input_cert.der> -s <output_sig.der>
$ ./x509_extract_sig -c fast.com.der -s fast.com.der.sig
$ hexdump -C fast.com.der.sig
00000000  0d f4 66 f0 3c 2f fa d9  84 c0 4e 62 55 8e ac f0  |..f.</....NbU...|
00000010  40 bc e2 f8 5c b5 1c 28  8f c7 1d c9 b5 c5 e1 da  |@...\..(........|
00000020  76 a9 31 c9 50 46 06 a4  9a 7d 6c df 24 e7 9d bb  |v.1.PF...}l.$...|
00000030  9c a3 30 fa ed 78 86 1d  26 0b f7 d0 bd 87 0d 7c  |..0..x..&......||
00000040  a9 14 ae f5 5b 0b 58 88  b1 5e c9 33 67 a2 1a 6a  |....[.X..^.3g..j|
00000050  05 b8 8c 34 86 cb 97 87  5c 32 c1 f8 c3 9a dc 5c  |...4....\2.....\|
00000060  ef 84 d0 d9 ad 50 dc 94  d2 ac 24 7f cf da ae b8  |.....P....$.....|
00000070  2f 54 c1 6c a3 82 64 58  8e 54 1f cc d3 97 ed 27  |/T.l..dX.T.....'|
00000080  b9 d9 21 d2 7c 30 06 b4  dd e1 44 dd 8c 42 de dc  |..!.|0....D..B..|
00000090  9c 2e 40 8a cd 61 fb 2b  66 3d e0 f5 0d c1 34 3c  |..@..a.+f=....4<|
000000a0  be a3 8b 11 92 85 34 93  59 cf 85 69 39 c5 e0 7b  |......4.Y..i9..{|
000000b0  3b ef 01 05 9a 08 7f 2f  0e 17 9e 1c 5c fd dc 74  |;....../....\..t|
000000c0  61 24 08 f8 36 75 67 27  93 0c 6d f9 03 4b a8 e8  |a$..6ug'..m..K..|
000000d0  74 0e f3 2e 3a ae 5d 69  9f cb d4 99 f0 7d 28 91  |t...:.]i.....}(.|
000000e0  d4 fd 26 65 0b 0d c8 95  15 7f be f1 15 9b a1 e9  |..&e............|
000000f0  cb 05 82 53 a7 95 ec 5a  06 e7 56 d2 8c e6 8a 6d  |...S...Z..V....m|
00000100
$ ./myrsa_trapdoor 
Usage: ./myrsa_trapdoor -m <message file> -k <keyfile>
$ ./myrsa_trapdoor -m fast.com.der.sig -k DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt.pubkey
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
1b 6c 69 ba 57 1b 4d b7 f4 e6 62 ed 23 7e cb c1 
91 f8 3c 6f bb aa 3e 46 c0 27 a2 1e 73 65 69 55 

$ ./myrsa_sha256 
Usage: myrsa_sha256 -i <input file> -o <output file>
$ ./myrsa_sha256 -i fast.com.der.tbs -o fast.com.der.tbs.dgst
$ hexcump -C fast.com.der.tbs.dgst 
-bash: hexcump: command not found
$ hexdump -C fast.com.der.tbs.dgst 
00000000  1b 6c 69 ba 57 1b 4d b7  f4 e6 62 ed 23 7e cb c1  |.li.W.M...b.#~..|
00000010  91 f8 3c 6f bb aa 3e 46  c0 27 a2 1e 73 65 69 55  |..<o..>F.'..seiU|
00000020
$  ./x509_text_public_key -f DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt | grep CN=
    Issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2
    Subject: C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
$ ./x509_text_public_key -f DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt | grep id-ad-caIssuers
  id-ad-caIssuers: http://cacerts.digicert.com/DigiCertGlobalRootG2.crt
$ curl -o DigiCertGlobalRootG2.crt http://cacerts.digicert.com/DigiCertGlobalRootG2.crt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   914  100   914    0     0   6294      0 --:--:-- --:--:-- --:--:--  6347
$ curl -o DigiCertGlobalRootG2.crt http://cacerts.digicert.com/DigiCertGlobalRootG2.crt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   914  100   914    0     0   3000      0 --:--:-- --:--:-- --:--:--  2996
$ ./x509_text_public_key -f DigiCertGlobalRootG2.crt | grep CN=
    Issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2
    Subject: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2
$ 
$ ./x509_extract_pubkey -c fast.com.der -p fast.com.der.pubkey
$ ./asn1parser -f fast.com.der.pubkey -v
SEQUENCE  L = 266
-INTEGER  L = 257
00 9f 1f fc f9 80 a5 22 37 51 55 40 b4 2d ad 3c 
50 03 df 3d 19 7a 2e b7 42 20 56 d7 f2 a7 e3 33 
33 69 b2 06 f6 bf 7c 33 85 3f 50 d1 bc 17 5c 20 
55 b0 06 2d 98 cb d2 f1 82 60 ce 26 1c a8 d0 bc 
29 46 4d bb 60 c8 20 60 cc c2 29 50 2f 75 0d 1e 
fd d6 11 08 1c ca 87 c1 21 f3 78 7a 37 2c 19 5e 
e2 80 29 e7 ec 6c 0d ca 13 b0 a7 d0 c6 53 ea ec 
b0 83 9f 26 99 a9 ec 9e 0d 83 7e cb b4 bb 39 3d 
f4 2f ff 1e 91 c6 c2 b6 66 a8 4c 20 9d 4e d9 37 
e0 19 f3 74 3a f4 77 48 40 c4 06 b2 d5 a6 36 61 
51 7b d1 09 14 bf ef 63 3c 7f a1 73 7e 23 cb 59 
08 9c 56 f7 eb 27 b0 96 f6 18 0c 6e 59 28 50 89 
34 40 72 a1 3f 70 31 7f 55 4c 49 bb e5 13 6e 59 
66 c5 f4 5d 36 b4 6b 0d 3e 0c 7a 59 f7 36 35 7c 
60 2a f3 91 a0 7d 4f 05 d7 d1 7b a0 d7 36 08 69 
f0 2b 4e 46 dd 0b 11 8c ec 26 37 81 23 88 34 9f 
cb 
-INTEGER  L = 3
01 00 01 
$ 
```

## References

1. [X.509] - ITU-T Recommendation X.509: Information Technology - Open Systems Interconnection - The Directory: Public-key and attribute certificate frameworks. Retrieved from https://www.itu.int/rec/t-rec-x.509/en
2. [X.690] - ITU-T Recommendation X.690: Information Technology - ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER). Retrieved from https://www.itu.int/rec/T-REC-X.690-202102-I
3. [PKCS#1] - Moriarty, K., Kaliski, B., Jonsson, J., & Rusch, A. (2016). RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2. Retrieved from https://www.rfc-editor.org/rfc/rfc8017
4. [RFC5280] - Cooper, D., et al. (2008). RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile. Retrieved from https://www.rfc-editor.org/info/rfc5280/
5. [RFC6962] - Laurie, B., Langley, A., & Kasper, E. (2013). RFC 6962: Certificate Transparency. Retrieved from https://www.rfc-editor.org/info/rfc6962/
6. [FIPS 180-4] - National Institute of Standards and Technology. (2015). Secure Hash Standard (SHS). Retrieved from https://csrc.nist.gov/pubs/fips/180-4/upd1/final
