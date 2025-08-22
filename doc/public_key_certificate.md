# What is a public key certificate

# Public key certificate

We can generate a public key using openssl and send it along with signed documents.

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

Certificate Authorities (CAs) are trusted entities responsible for issuing digital certificates used to verify the identity of websites, organizations, or individuals.

When we connect to a website with HTTPS, with the prefix of https, the browser uses the website’s public key, included in the digital certificate, to encrypt data exchanged with the website. The digital certificate enclose a digital signature made by the CA that issued the certificate. This signature is created using the CA’s private key. A lock icon appears at the address bar when the browser verified the certificate with the associated public key from the CA.

Clicking the lock icon next to the URL in the address bar shows the information of the certificate and we can also make a copy of it. Below is a certificate from www.apple.com:

```console
$ ../bin/x509_text_public_key -f www.apple.com.cer 
X509 Public Key certificate

toBeSigned:
  Version: v3
  serial Number: 14 47 cf b2 1a bf a9 a8 f6 65 ff 18 fe f5 60 52 
  signature: sha256WithRSAEncryption
  issuer: C=US, O=Apple Inc., CN=Apple Public EV Server RSA CA 2 - G1, 
  validity:
    notBefore	: 23rd August 2024, 17:30:11 UTC
    notAfter	: 21st November 2024, 17:40:11 UTC
  subject: BC=Private Organization, jC=US, jST=California, SN=C0806592, C=US, ST=California, L=Cupertino, O=Apple Inc., CN=www.apple.com, 
  subjectPublicKeyInfo:
    algorithm: rsaEncryption
    subjectPublicKey:
      modulus: 2048 bits
00 c8 a2 02 8a c1 1c a7 9a ee 58 49 9b 10 3c 41 
8d bf ef 6f 23 7e 64 05 e9 b9 20 57 3b 36 5b 9e 
d2 f9 64 de f9 5a af 84 2c 10 c1 08 d1 ec e4 d2 
74 d7 1e 2b c3 ba c4 17 7e b1 c8 9f 5d 34 1b e3 
c8 06 f9 c8 db bb c3 af 16 46 6a 04 22 54 c8 14 
2d 43 61 21 ec c4 d5 94 ff ba 2d df 4e 63 fe 9d 
76 bf ac aa 49 ca 3b a4 25 1f 8b 52 6b 61 ea 9d 
f2 80 57 62 b2 5a bb 35 32 8c ff 7a 75 3f 4b fb 
b9 77 c0 a9 ba 8d b4 b4 35 b1 ba d8 2e 96 e1 b7 
07 c5 da b9 50 f4 c8 54 90 e3 aa 26 d9 7a 43 1f 
62 73 3f 88 eb 5c b7 1f d2 74 2b c7 39 d0 73 ca 
5d 4a b3 4b 59 22 d1 54 c5 41 df a6 a5 c1 2a 39 
c5 31 48 39 83 ea ea 2d 77 3b 51 44 92 af a6 79 
46 8e 82 8e ef b0 3d 6b 14 bf 16 74 40 09 2f bc 
19 a5 21 8d b5 bc 35 2c 51 0b fb 66 c6 a2 24 56 
38 58 ee 98 fb 3b b7 29 95 4e 36 ee 0d f2 63 d0 
09 
      publicExponent:
01 00 01 
  extensions:
    id-ce-basicConstraints:  critical
CA:FALSE
    id-ce-authorityKeyIdentifier: 
50 55 ab 43 a1 af a9 48 2b 5a c1 a2 87 89 04 e4 7a 0e ca da 
    id-pe-authorityInfoAccess: 
id-ad-caIssuers: http://certs.apple.com/apevsrsa2g1.der
id-ad-ocsp: http://ocsp.apple.com/ocsp03-apevsrsa2g101
    id-ce-subjectAltName: 
www.apple.com
    id-ce-certificatePolicies: 
ev-guidelines
id-qt-cps
https://www.apple.com/certificateauthority/public
ev-ssl-certificates(2) 1
    id-ce-extKeyUsage: 
id-kp-serverAuth,
    id-ce-RLDistributionPoints: 
http://crl.apple.com/apevsrsa2g1.crl
    id-ce-subjectKeyIdentifier: 
9d 84 23 7d 6c 98 c4 da 21 49 94 22 09 1e e8 37 28 6c 76 e1 
    id-ce-keyUsage:  critical
digitalSignature, keyEncipherment, 
    appleSecurity(6)?(86): 
05 00 
    embedded-scts: 
      version: v1
      log_id:3f 17 4b 4f d7 22 47 58 94 1d 65 1c 84 be 0d 12 
ed 90 37 7f 1f 85 6a eb c1 bf 28 85 ec f8 64 6e 
      timestamp: Fri Aug 23 17:40:12 2024
      extensions: none
      hash_alg: SHA256
      sig_alg: ECDSA
      sig_len: 71
30 45 02 21 00 f6 16 d4 d6 2f 7f 15 63 6d e2 ee 
55 eb 6e 5e 5c 99 2c 33 4a 34 d3 8f 93 f0 c8 0c 
ff ee 95 6f ac 02 20 63 35 ec 4b 71 4e 87 be c5 
49 4a c9 3d 49 7a 6e 0a 03 1e 28 4f 78 d9 d9 81 
52 c9 8d 1f 53 e0 0b 
      version: v1
      log_id:da b6 bf 6b 3f b5 b6 22 9f 9b c2 bb 5c 6b e8 70 
91 71 6c bb 51 84 85 34 bd a4 3d 30 48 d7 fb ab 
      timestamp: Fri Aug 23 17:40:12 2024
      extensions: none
      hash_alg: SHA256
      sig_alg: ECDSA
      sig_len: 72
30 46 02 21 00 df 32 ea 70 66 14 58 c1 e9 6a f7 
41 91 2b ce 2a 29 c8 ea 6a ce d3 e7 7a 00 20 5c 
62 ca 5a 0c f2 02 21 00 e7 7c 8f 57 d2 87 44 94 
5e 99 9d 5b b7 36 3b f8 3b 3b b5 41 77 7b 7b 39 
d8 31 b3 19 31 20 89 54 
      version: v1
      log_id:ee cd d0 64 d5 db 1a ce c5 5c b7 9d b4 cd 13 a2 
32 87 46 7c bc ec de c3 51 48 59 46 71 1f b5 9b 
      timestamp: Fri Aug 23 17:40:12 2024
      extensions: none
      hash_alg: SHA256
      sig_alg: ECDSA
      sig_len: 71
30 45 02 20 1c 8a ff 73 8e da 0f 22 a2 49 2f 3c 
ed ae 4c a6 6e 90 f4 51 85 bf 59 3f 0b b8 ad dd 
a8 3b d4 a6 02 21 00 af d4 7b 1d 5c f7 50 16 6e 
57 08 dc 1e ff 4b 29 6a a8 43 96 74 97 43 db e5 
8c 8f 67 5e e1 f6 47 
      version: v1
      log_id:19 98 10 71 09 f0 d6 52 2e 30 80 d2 9e 3f 64 bb 
83 6e 28 cc f9 0f 52 8e ee df ce 4a 3f 16 b4 ca 
      timestamp: Fri Aug 23 17:40:12 2024
      extensions: none
      hash_alg: SHA256
      sig_alg: ECDSA
      sig_len: 70
30 44 02 20 22 6c d2 d3 10 e5 c5 24 15 71 c6 08 
8a 57 df 74 4b f4 9a 9e 85 04 f7 e2 8a a2 4a 94 
88 04 b4 8e 02 20 32 59 d8 d4 52 57 9e ab bc aa 
44 49 5e b1 44 68 77 72 92 c0 f3 3e fb de e1 16 
c8 f1 15 a6 4b 42 

SIGNATURE:
  algorithmIdentifier: sha256WithRSAEncryption
  signature:
00 4c b3 ea a2 c8 da 8e f5 d1 27 85 7d 7f 06 f5 
5c c0 d2 5f 88 02 18 aa 9d 72 ca 36 ab b0 bc 90 
34 c7 50 27 6e bb 80 74 4b fa 61 21 b2 44 f9 3a 
ed 8c 76 8d c0 63 bc a1 91 b6 ae df 6e ed 74 2f 
9e 2b 2b 67 04 79 9c 06 4c 69 6e cc 82 0b 2e 81 
69 21 c6 5f 83 4e 16 d2 25 76 52 c1 de 38 82 7f 
7e 1e 3a cd 26 4a 9d 9f e4 74 ee ac 46 76 a7 b8 
8a 8d 9b 79 66 35 29 f6 3c 64 51 64 85 25 6d 69 
0b c4 6f 42 e3 1e 1f d8 4a 2d 14 cd 4b 9a 28 81 
f2 bb 0c d0 28 4f f7 38 56 64 4a c5 5a 03 88 71 
b8 9d 28 30 f3 d5 7a 19 9c 8a 7e 1d 63 b3 c4 b4 
e6 58 4d c5 26 39 f5 b7 36 ff 9c 76 08 e3 f3 8b 
47 e6 ea d2 6e a3 74 09 d6 8e 1b 8c 5d 08 3a 8c 
84 58 17 68 82 f6 34 67 d0 31 39 8f 57 a8 c2 78 
ea 66 ff c0 7f 5e 86 83 fe bb 9f 63 27 f2 23 d1 
fb f6 f4 b0 41 0c fd aa 84 b2 f4 3e 5d cc d5 ef 
b0 
$
```

A public key certificate is defined[X.509] as follows:

```text
SIGNATURE ::= SEQUENCE {
algorithmIdentifier AlgorithmIdentifier{{SupportedAlgorithms}},
signature BIT STRING,
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
```

## Signed certificate
Verifying the signature is in the check list against a certificate. The public key portion, toBeSigned, is signed and the signature goes to the end of the certificate.

```console
$ ../bin/asn1parse -f www.apple.com.cer
0000: SEQUENCE  L = 1914
0004: -SEQUENCE  L = 1634
0008: --CONTEXT SPECIFIC 0  L =    3
0010: ---INTEGER  L =    1
0013: --INTEGER  L =   16
0031: --SEQUENCE  L =   13
0033: ---OBJECT IDENTIFIER  L =    9
0044: ---NULL  L =    0
0046: --SEQUENCE  L =   81
0048: ---SET  L =   11
0050: ----SEQUENCE  L =    9
0052: -----OBJECT IDENTIFIER  L =    3
0057: -----PRINTABLE STRING  L =    2
0061: ---SET  L =   19
0063: ----SEQUENCE  L =   17
0065: -----OBJECT IDENTIFIER  L =    3
0070: -----PRINTABLE STRING  L =   10
0082: ---SET  L =   45
0084: ----SEQUENCE  L =   43
0086: -----OBJECT IDENTIFIER  L =    3
0091: -----PRINTABLE STRING  L =   36
0129: --SEQUENCE  L =   30
0131: ---UTC TIME  L =   13
0146: ---UTC TIME  L =   13
0161: --SEQUENCE  L =  199
0164: ---SET  L =   29
0166: ----SEQUENCE  L =   27
0168: -----OBJECT IDENTIFIER  L =    3
0173: -----UTF8 STRING  L =   20
0195: ---SET  L =   19
0197: ----SEQUENCE  L =   17
0199: -----OBJECT IDENTIFIER  L =   11
0212: -----PRINTABLE STRING  L =    2
0216: ---SET  L =   27
0218: ----SEQUENCE  L =   25
0220: -----OBJECT IDENTIFIER  L =   11
0233: -----UTF8 STRING  L =   10
0245: ---SET  L =   17
0247: ----SEQUENCE  L =   15
0249: -----OBJECT IDENTIFIER  L =    3
0254: -----PRINTABLE STRING  L =    8
0264: ---SET  L =   11
0266: ----SEQUENCE  L =    9
0268: -----OBJECT IDENTIFIER  L =    3
0273: -----PRINTABLE STRING  L =    2
0277: ---SET  L =   19
0279: ----SEQUENCE  L =   17
0281: -----OBJECT IDENTIFIER  L =    3
0286: -----UTF8 STRING  L =   10
0298: ---SET  L =   18
0300: ----SEQUENCE  L =   16
0302: -----OBJECT IDENTIFIER  L =    3
0307: -----UTF8 STRING  L =    9
0318: ---SET  L =   19
0320: ----SEQUENCE  L =   17
0322: -----OBJECT IDENTIFIER  L =    3
0327: -----UTF8 STRING  L =   10
0339: ---SET  L =   22
0341: ----SEQUENCE  L =   20
0343: -----OBJECT IDENTIFIER  L =    3
0348: -----UTF8 STRING  L =   13
0363: --SEQUENCE  L =  290
0367: ---SEQUENCE  L =   13
0369: ----OBJECT IDENTIFIER  L =    9
0380: ----NULL  L =    0
0382: ---BIT STRING  L =  271
0657: --CONTEXT SPECIFIC 3  L =  981
0661: ---SEQUENCE  L =  977
0665: ----SEQUENCE  L =   12
0667: -----OBJECT IDENTIFIER  L =    3
0672: -----BOOLEAN  L =    1
0675: -----OCTET STRING  L =    2
0679: ----SEQUENCE  L =   31
0681: -----OBJECT IDENTIFIER  L =    3
0686: -----OCTET STRING  L =   24
0712: ----SEQUENCE  L =  122
0714: -----OBJECT IDENTIFIER  L =    8
0724: -----OCTET STRING  L =  110
0836: ----SEQUENCE  L =   60
0838: -----OBJECT IDENTIFIER  L =    3
0843: -----OCTET STRING  L =   53
0898: ----SEQUENCE  L =   96
0900: -----OBJECT IDENTIFIER  L =    3
0905: -----OCTET STRING  L =   89
0996: ----SEQUENCE  L =   19
0998: -----OBJECT IDENTIFIER  L =    3
1003: -----OCTET STRING  L =   12
1017: ----SEQUENCE  L =   53
1019: -----OBJECT IDENTIFIER  L =    3
1024: -----OCTET STRING  L =   46
1072: ----SEQUENCE  L =   29
1074: -----OBJECT IDENTIFIER  L =    3
1079: -----OCTET STRING  L =   22
1103: ----SEQUENCE  L =   14
1105: -----OBJECT IDENTIFIER  L =    3
1110: -----BOOLEAN  L =    1
1113: -----OCTET STRING  L =    4
1119: ----SEQUENCE  L =   15
1121: -----OBJECT IDENTIFIER  L =    9
1132: -----OCTET STRING  L =    2
1136: ----SEQUENCE  L =  502
1140: -----OBJECT IDENTIFIER  L =   10
1152: -----OCTET STRING  L =  486
1642: -SEQUENCE  L =   13
1644: --OBJECT IDENTIFIER  L =    9
1655: --NULL  L =    0
1657: -BIT STRING  L =  257
$ 
```

Go inside the top level SEQUENCE value, the first SEQUENCE value is the toBeSigned part followed by the COMPONENTS OF SIGNATURE.

```console
$ ../bin/x509_extract_tbs
Usage: ../bin/x509_extract_tbs -c <cert_file> -p <pub_key_file>
$ ../bin/x509_extract_tbs -c www.apple.com.cer -p www.apple.com.tbs.der
$ ../bin/x509_extract_sig 
Usage: ../bin/x509_extract_sig -c <cert_file> -s <sig_file>
$ ../bin/x509_extract_sig -c www.apple.com.cer -s www.apple.com.sig.bin
$ hexdump -C www.apple.com.sig.bin 
00000000  4c b3 ea a2 c8 da 8e f5  d1 27 85 7d 7f 06 f5 5c  |L........'.}...\|
00000010  c0 d2 5f 88 02 18 aa 9d  72 ca 36 ab b0 bc 90 34  |.._.....r.6....4|
00000020  c7 50 27 6e bb 80 74 4b  fa 61 21 b2 44 f9 3a ed  |.P'n..tK.a!.D.:.|
00000030  8c 76 8d c0 63 bc a1 91  b6 ae df 6e ed 74 2f 9e  |.v..c......n.t/.|
00000040  2b 2b 67 04 79 9c 06 4c  69 6e cc 82 0b 2e 81 69  |++g.y..Lin.....i|
00000050  21 c6 5f 83 4e 16 d2 25  76 52 c1 de 38 82 7f 7e  |!._.N..%vR..8..~|
00000060  1e 3a cd 26 4a 9d 9f e4  74 ee ac 46 76 a7 b8 8a  |.:.&J...t..Fv...|
00000070  8d 9b 79 66 35 29 f6 3c  64 51 64 85 25 6d 69 0b  |..yf5).<dQd.%mi.|
00000080  c4 6f 42 e3 1e 1f d8 4a  2d 14 cd 4b 9a 28 81 f2  |.oB....J-..K.(..|
00000090  bb 0c d0 28 4f f7 38 56  64 4a c5 5a 03 88 71 b8  |...(O.8VdJ.Z..q.|
000000a0  9d 28 30 f3 d5 7a 19 9c  8a 7e 1d 63 b3 c4 b4 e6  |.(0..z...~.c....|
000000b0  58 4d c5 26 39 f5 b7 36  ff 9c 76 08 e3 f3 8b 47  |XM.&9..6..v....G|
000000c0  e6 ea d2 6e a3 74 09 d6  8e 1b 8c 5d 08 3a 8c 84  |...n.t.....].:..|
000000d0  58 17 68 82 f6 34 67 d0  31 39 8f 57 a8 c2 78 ea  |X.h..4g.19.W..x.|
000000e0  66 ff c0 7f 5e 86 83 fe  bb 9f 63 27 f2 23 d1 fb  |f...^.....c'.#..|
000000f0  f6 f4 b0 41 0c fd aa 84  b2 f4 3e 5d cc d5 ef b0  |...A......>]....|
00000100
$ 
```

```text
  signature: sha256WithRSAEncryption
  ```
 It indicates the fingerprint was done with SHA-256 [SHA-256] and was signed with RSA.

 Compute the digest:

```console
$ ../bin/myrsa_sha256 
Usage: myrsa_sha256 -i <input file> -o <output file>
$ ../bin/myrsa_sha256 -i www.apple.com.tbs.der -o www.apple.com.dgst
$ hexdump -C www.apple.com.dgst 
00000000  4f a4 e3 35 0c 68 d9 82  21 9f 03 38 d8 f9 8f b0  |O..5.h..!..8....|
00000010  87 55 41 c9 1b b0 9c 74  b2 02 fa e3 8c 93 34 e1  |.UA....t......4.|
00000020
```

# Verify the public key certificate

We can get the link to the CA's public key for this certificate from Authority Information Access extension:

```text
    id-pe-authorityInfoAccess: 
id-ad-caIssuers: http://certs.apple.com/apevsrsa2g1.der
```
```console
$ curl -O  http://certs.apple.com/apevsrsa2g1.der
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1334  100  1334    0     0   8198      0 --:--:-- --:--:-- --:--:--  8234
$ ../bin/x509_text_public_key -f apevsrsa2g1.der 
X509 Public Key certificate

toBeSigned:
  Version: v3
  serial Number: 07 17 79 11 00 5d 22 67 f6 88 92 f6 8f 8b 50 58 
  signature: sha256WithRSAEncryption
  issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA, 
  validity:
    notBefore	: 29th April 2020, 12:54:50 UTC
    notAfter	: 10th April 2030, 23:59:59 UTC
  subject: C=US, O=Apple Inc., CN=Apple Public EV Server RSA CA 2 - G1, 
  subjectPublicKeyInfo:
    algorithm: rsaEncryption
    subjectPublicKey:
      modulus: 2048 bits
00 e2 00 fd a5 df 5f b9 38 71 49 eb ba 93 d8 c3 
4d 33 dc 5c 14 ea 70 2f c1 ea 53 3b cb 9e 51 c0 
54 b2 64 06 a6 97 31 e4 17 84 ca 78 2f 67 c3 d2 
89 e1 f4 18 71 ca ed 19 c7 6e 02 c2 87 2a 27 d8 
7f 44 a6 06 28 ec d4 35 ca b7 02 e5 31 ef a3 75 
6b 94 03 fa 53 be 3a 39 14 83 c5 46 db bf 8c f5 
e6 40 2c ca f0 01 50 21 62 f1 2e c8 5e 4c c3 22 
38 4e 20 23 6b 03 c7 d7 52 95 0a 6c 87 1c 23 62 
6f 33 3e d1 bf 0e 46 78 6e dc 69 ad ae fa f4 88 
dd 39 81 9f 03 1c 8d 5a a5 b1 27 2a 63 ab 5b 13 
f8 e2 ec 2f d7 0f 0e f0 52 93 07 c9 a4 0c 54 63 
ce ee 62 5f 8b 4f d0 6e 25 0f 5b 09 c2 24 f6 00 
a8 fa 6f 05 58 de 06 1d 1a bd 40 86 68 fd 99 b5 
97 36 26 7b 35 0b c8 7d 79 b2 46 f9 9d da c1 d8 
01 a9 03 d8 0f 62 3e 7f 2f da 06 d9 d3 3a 48 67 
04 9b 62 f2 3c 61 d5 38 4d 57 ae 52 f5 2b 9c 65 
e7 
      publicExponent:
01 00 01 
  extensions:
    id-ce-subjectKeyIdentifier: 
50 55 ab 43 a1 af a9 48 2b 5a c1 a2 87 89 04 e4 7a 0e ca da 
    id-ce-authorityKeyIdentifier: 
b1 3e c3 69 03 f8 bf 47 01 d4 98 26 1a 08 02 ef 63 64 2b c3 
    id-ce-keyUsage:  critical
digitalSignature, contentCommitment, cRLSign, 
    id-ce-extKeyUsage: 
id-kp-serverAuth,id-kp-clientAuth ,
    id-ce-basicConstraints:  critical
CA:TRUE, pathLenConstraint:0
    id-pe-authorityInfoAccess: 
id-ad-ocsp: http://ocsp.digicert.com
    id-ce-RLDistributionPoints: 
http://crl3.digicert.com/DigiCertHighAssuranceEVRootCA.crl
    id-ce-certificatePolicies: 
ev-ssl-certificates(2) 1
id-qt-cps
https://www.digicert.com/CPS
id-qt-unotice
Any use of this Certificate constitutes acceptance of the Relying Party Agreement located at https://www.digicert.com/rpa-ua
ev-guidelines

SIGNATURE:
  algorithmIdentifier: sha256WithRSAEncryption
  signature:
00 a6 5e 6c 50 b6 65 5c 2b 4e 3f ae ea 70 e8 dc 
ed 37 7b 4f e0 fe 13 7e e9 4e 62 03 b5 fd 74 11 
a6 43 1d c2 ec d9 0f 34 05 74 99 4a 1a 92 5b 1c 
78 80 48 43 f6 c2 ee eb 5d 83 09 d2 29 39 e6 e4 
77 55 8a 90 12 c8 b9 68 53 b4 cf da 30 2d 0d 07 
40 c4 16 af 98 b9 c5 c1 cc 17 06 9e a7 d7 bb 8b 
a7 eb 8f 53 80 d9 82 e6 cc f7 a2 f2 51 08 a5 52 
56 04 45 b8 2e eb aa c2 2b 5f 23 46 6a 1b 0e f1 
53 f0 4e f5 a1 4d 77 a3 53 9e ff 55 94 1c 56 d3 
ca 74 64 29 6e f7 24 37 76 ad 9d b5 3e 29 bb 2c 
42 55 63 73 9c 46 6b 58 34 76 8c fe 5b a7 63 1d 
59 43 ed 1f c3 b1 dc e4 9f f1 47 bb e5 46 2b b2 
3f e7 c9 f6 e7 2e 0d 8b a9 2e 0d f7 dc 38 b9 47 
b2 59 21 f9 d7 e3 67 9c 5f 40 dd d3 02 1e b8 58 
f4 1c 18 c7 e9 cd b9 15 4a 2f fc 56 b9 66 3a f4 
54 f8 e6 9a 03 7a 3e 7a 0c 02 b5 19 5c 39 10 7b 
73 
$ 
```

It may be used to verify public-key certificate
signatures:

```text
    id-ce-basicConstraints:  critical
CA:TRUE, pathLenConstraint:0
```

Retrieve the public key:

```console
$ ../bin/x509_extract_pubkey
Usage: ../bin/x509_extract_pubkey -c <cert_file> -p <pub_key_file>
$ ../bin/x509_extract_pubkey -c apevsrsa2g1.der -p apevsrsa2g1.pub_key.der
$ ../bin/asn1parse -f apevsrsa2g1.pub_key.der 
0000: SEQUENCE  L =  290
0004: -SEQUENCE  L =   13
0006: --OBJECT IDENTIFIER  L =    9
0017: --NULL  L =    0
0019: -BIT STRING  L =  271
$ ../bin/asn1parse -f apevsrsa2g1.pub_key.der -v
0000: SEQUENCE  L =  290
0004: -SEQUENCE  L =   13
0006: --OBJECT IDENTIFIER  L =    9
OID: 1 2 840 113549 1 1 1  (rsaEncryption)
0017: --NULL  L =    0
0019: -BIT STRING  L =  271
0023:  0 - Unused bits
0024: 30 82 01 0a 02 82 01 01 00 e2 00 fd a5 df 5f b9 
0040: 38 71 49 eb ba 93 d8 c3 4d 33 dc 5c 14 ea 70 2f 
0056: c1 ea 53 3b cb 9e 51 c0 54 b2 64 06 a6 97 31 e4 
0072: 17 84 ca 78 2f 67 c3 d2 89 e1 f4 18 71 ca ed 19 
0088: c7 6e 02 c2 87 2a 27 d8 7f 44 a6 06 28 ec d4 35 
0104: ca b7 02 e5 31 ef a3 75 6b 94 03 fa 53 be 3a 39 
0120: 14 83 c5 46 db bf 8c f5 e6 40 2c ca f0 01 50 21 
0136: 62 f1 2e c8 5e 4c c3 22 38 4e 20 23 6b 03 c7 d7 
0152: 52 95 0a 6c 87 1c 23 62 6f 33 3e d1 bf 0e 46 78 
0168: 6e dc 69 ad ae fa f4 88 dd 39 81 9f 03 1c 8d 5a 
0184: a5 b1 27 2a 63 ab 5b 13 f8 e2 ec 2f d7 0f 0e f0 
0200: 52 93 07 c9 a4 0c 54 63 ce ee 62 5f 8b 4f d0 6e 
0216: 25 0f 5b 09 c2 24 f6 00 a8 fa 6f 05 58 de 06 1d 
0232: 1a bd 40 86 68 fd 99 b5 97 36 26 7b 35 0b c8 7d 
0248: 79 b2 46 f9 9d da c1 d8 01 a9 03 d8 0f 62 3e 7f 
0264: 2f da 06 d9 d3 3a 48 67 04 9b 62 f2 3c 61 d5 38 
0280: 4d 57 ae 52 f5 2b 9c 65 e7 02 03 01 00 01 
$ 
```

Verify the signature:
```console
$ hexdump -C www.apple.com.dgst 
00000000  4f a4 e3 35 0c 68 d9 82  21 9f 03 38 d8 f9 8f b0  |O..5.h..!..8....|
00000010  87 55 41 c9 1b b0 9c 74  b2 02 fa e3 8c 93 34 e1  |.UA....t......4.|
00000020
$ ../bin/myrsa_trapdoor 
Usage: ../bin/myrsa_trapdoor -m <message file> -k <key file>
$ ../bin/myrsa_trapdoor -m www.apple.com.sig.bin -k apevsrsa2g1.pub_key.der 
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
4f a4 e3 35 0c 68 d9 82 21 9f 03 38 d8 f9 8f b0 
87 55 41 c9 1b b0 9c 74 b2 02 fa e3 8c 93 34 e1 

$ 
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

## Find a certificate from a public source

The Authority Information Access extension of the CA's public key does not show the link for the public key for its own authentication, so we need to find it from a public source. First, get the issuer information:

```text
issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA, 
```
Then we search the internet for the CN, common name:

```text
https://cacerts.digicert.com/DigiCertHighAssuranceEVRootCA.crt
```

```console
$ ../bin/x509_text_public_key -f DigiCertHighAssuranceEVRootCA.crt 
X509 Public Key certificate

toBeSigned:
  Version: v3
  serial Number: 02 ac 5c 26 6a 0b 40 9b 8f 0b 79 f2 ae 46 25 77 
  signature: sha1WithRSAEncryption
  issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA, 
  validity:
    notBefore	: 10th November 2006, 00:00:00 UTC
    notAfter	: 10th November 2031, 00:00:00 UTC
  subject: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA, 
  subjectPublicKeyInfo:
    algorithm: rsaEncryption
    subjectPublicKey:
      modulus: 2048 bits
00 c6 cc e5 73 e6 fb d4 bb e5 2d 2d 32 a6 df e5 
81 3f c9 cd 25 49 b6 71 2a c3 d5 94 34 67 a2 0a 
1c b0 5f 69 a6 40 b1 c4 b7 b2 8f d0 98 a4 a9 41 
59 3a d3 dc 94 d6 3c db 74 38 a4 4a cc 4d 25 82 
f7 4a a5 53 12 38 ee f3 49 6d 71 91 7e 63 b6 ab 
a6 5f c3 a4 84 f8 4f 62 51 be f8 c5 ec db 38 92 
e3 06 e5 08 91 0c c4 28 41 55 fb cb 5a 89 15 7e 
71 e8 35 bf 4d 72 09 3d be 3a 38 50 5b 77 31 1b 
8d b3 c7 24 45 9a a7 ac 6d 00 14 5a 04 b7 ba 13 
eb 51 0a 98 41 41 22 4e 65 61 87 81 41 50 a6 79 
5c 89 de 19 4a 57 d5 2e e6 5d 1c 53 2c 7e 98 cd 
1a 06 16 a4 68 73 d0 34 04 13 5c a1 71 d3 5a 7c 
55 db 5e 64 e1 37 87 30 56 04 e5 11 b4 29 80 12 
f1 79 39 88 a2 02 11 7c 27 66 b7 88 b7 78 f2 ca 
0a a8 38 ab 0a 64 c2 bf 66 5d 95 84 c1 a1 25 1e 
87 5d 1a 50 0b 20 12 cc 41 bb 6e 0b 51 38 b8 4b 
cb 
      publicExponent:
01 00 01 
  extensions:
    id-ce-keyUsage:  critical
digitalSignature, contentCommitment, cRLSign, 
    id-ce-basicConstraints:  critical
CA:TRUE, 
    id-ce-subjectKeyIdentifier: 
b1 3e c3 69 03 f8 bf 47 01 d4 98 26 1a 08 02 ef 63 64 2b c3 
    id-ce-authorityKeyIdentifier: 
b1 3e c3 69 03 f8 bf 47 01 d4 98 26 1a 08 02 ef 63 64 2b c3 

SIGNATURE:
  algorithmIdentifier: sha1WithRSAEncryption
  signature:
00 1c 1a 06 97 dc d7 9c 9f 3c 88 66 06 08 57 21 
db 21 47 f8 2a 67 aa bf 18 32 76 40 10 57 c1 8a 
f3 7a d9 11 65 8e 35 fa 9e fc 45 b5 9e d9 4c 31 
4b b8 91 e8 43 2c 8e b3 78 ce db e3 53 79 71 d6 
e5 21 94 01 da 55 87 9a 24 64 f6 8a 66 cc de 9c 
37 cd a8 34 b1 69 9b 23 c8 9e 78 22 2b 70 43 e3 
55 47 31 61 19 ef 58 c5 85 2f 4e 30 f6 a0 31 16 
23 c8 e7 e2 65 16 33 cb bf 1a 1b a0 3d f8 ca 5e 
8b 31 8b 60 08 89 2d 0c 06 5c 52 b7 c4 f9 0a 98 
d1 15 5f 9f 12 be 7c 36 63 38 bd 44 a4 7f e4 26 
2b 0a c4 97 69 0d e9 8c e2 c0 10 57 b8 c8 76 12 
91 55 f2 48 69 d8 bc 2a 02 5b 0f 44 d4 20 31 db 
f4 ba 70 26 5d 90 60 9e bc 4b 17 09 2f b4 cb 1e 
43 68 c9 07 27 c1 d2 5c f7 ea 21 b9 68 12 9c 3c 
9c bf 9e fc 80 5c 9b 63 cd ec 47 aa 25 27 67 a0 
37 f3 00 82 7d 54 d7 a9 f8 e9 2e 13 a3 77 e8 1f 
4a 
$ 
```

Verify the first CA certificate:

```console
$ ../bin/x509_extract_tbs -c apevsrsa2g1.der -p apevsrsa2g1.tbs.der
$ ../bin/x509_extract_sig -c apevsrsa2g1.der -s apevsrsa2g1.sig.bin
$ ../bin/x509_extract_pubkey -c DigiCertHighAssuranceEVRootCA.crt -p DigiCertHighAssuranceEVRootCA.pub_key.der
$ ../bin/myrsa_trapdoor -m apevsrsa2g1.sig.bin -k DigiCertHighAssuranceEVRootCA.pub_key.der 
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
f5 08 e5 ff 71 b9 13 38 3f 3b d9 d5 1e 99 e5 9e 
f6 5c cf ea 30 60 cf 9a c1 e9 8d bf 73 45 b1 99 

$ ../bin/myrsa_sha256 -i apevsrsa2g1.tbs.der -o apevsrsa2g1.dgst
$ hexdump -C apevsrsa2g1.dgst
00000000  f5 08 e5 ff 71 b9 13 38  3f 3b d9 d5 1e 99 e5 9e  |....q..8?;......|
00000010  f6 5c cf ea 30 60 cf 9a  c1 e9 8d bf 73 45 b1 99  |.\..0`......sE..|
00000020
$
```

## Self-signed certificate

The last CA certificate is a self-signed certificate:

```text
  issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA, 
  validity:
    notBefore	: 10th November 2006, 00:00:00 UTC
    notAfter	: 10th November 2031, 00:00:00 UTC
  subject: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA, 
```
The issuer and subject components are the same meaning the certificate was signed with its own private key and this is typically a root of trust. This root certificate has a SHA-1 digest:

```consoled
$ ../bin/x509_extract_tbs -c DigiCertHighAssuranceEVRootCA.crt -p DigiCertHighAssuranceEVRootCA.tbs.der
$ ../bin/x509_extract_sig -c DigiCertHighAssuranceEVRootCA.crt -s DigiCertHighAssuranceEVRootCA.sig.bin
$ ../bin/myrsa_trapdoor -m DigiCertHighAssuranceEVRootCA.sig.bin -k DigiCertHighAssuranceEVRootCA.pub_key.der 
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
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 
ff ff ff ff ff ff ff ff ff ff ff ff 00 30 21 30 
09 06 05 2b 0e 03 02 1a 05 00 04 14 e3 5e f0 8d 
88 4f 0a 0a de 2f 75 e9 63 01 ce 62 30 f2 13 a8 

$ ../bin/myrsa_sha1 -i DigiCertHighAssuranceEVRootCA.tbs.der -o DigiCertHighAssuranceEVRootCA.dgst
$ hexdump -C DigiCertHighAssuranceEVRootCA.dgst
00000000  e3 5e f0 8d 88 4f 0a 0a  de 2f 75 e9 63 01 ce 62  |.^...O.../u.c..b|
00000010  30 f2 13 a8                                       |0...|
00000014
$ 
```

## Chain of trust

The chain of trust ensures that the entity presenting the certificate (e.g., a website) is genuine and verified by a trusted Certificate Authority. In our example here:

-**Root Certificate Authority (Root CA)**: DigiCert High Assurance EV Root CA
-**Intermediate Certificate Authority (Intermediate CA)**: Apple Public EV Server RSA CA 2 - G1
-**End-Entity Certificate (Leaf Certificate)**: www.apple.com

## References

1. [X.509] - ITU-T Recommendation X.509: Information Technology - Open Systems Interconnection - The Directory: Public-key and attribute certificate frameworks. Retrieved from https://www.itu.int/rec/T-REC-X.509

