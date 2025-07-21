# Code-signing with a self-signed certificate

Malicious software, commonly referred to as malware, dates back to the 1970s, with the term "virus" becoming even more widespread. In response, people have relied on antivirus software to detect and eliminate such threats, only to discover that these programs themselves are sometimes Trojan horses. If we could assign a unique ID to each piece of software, similar to how passports are used at immigration checkpoints, it could provide greater peace of mind.

Today, electronic documents are often protected by digital signatures, ensuring their authenticity and integrity. We can apply the same concept to software to enhance its identification and verification.

To achieve maximum security, it is generally preferred to obtain a certificate from a Certificate Authority (CA), trusted organizations or entities responsible for issuing digital certificates. However, in certain limited access environments, it can be as simple as using a self-signed certificate. This approach is often used to verify that code comes from the same publisher throughout the development and testing stages or for internal deployments. In this tutorial, we will use a self-signed certificate for educational purposes to demonstrate the process.

## Generate a self-signed certificate
### Generate a private key
Signing a code or documents requires a private key:

```console
$ openssl genrsa -out private_key.pem 2048
$ ls
private_key.pem
$
$ openssl rsa -text -in private_key.pem -noout
Private-Key: (2048 bit, 2 primes)
modulus:
    00:c8:55:aa:50:1d:23:91:a2:c4:8d:81:88:cf:7a:
    38:b7:c2:87:5a:77:d7:80:c2:2b:76:ab:7b:24:0d:
    94:5a:82:15:7b:62:8e:5c:32:07:87:60:35:bc:60:
    da:dd:b7:49:8c:66:a3:3f:0d:12:9b:3b:88:5b:b8:
    a5:87:22:58:a5:09:fc:d9:49:ad:96:05:11:2c:30:
    25:9b:e5:2c:cd:8b:9c:55:d2:a0:e4:f9:cc:78:8c:
    5d:74:2e:51:ee:91:47:6f:f8:fd:d2:f1:ca:68:2c:
    7b:9f:5a:da:69:92:fc:7a:9e:88:48:a0:df:5d:fa:
    a3:28:e8:66:df:6f:63:d1:10:bd:4a:05:03:dd:26:
    01:a3:1a:ff:48:d5:80:51:ad:9f:f9:25:26:9e:97:
    da:cb:4d:c2:ee:68:cf:b2:2c:8e:bb:90:64:a2:8d:
    47:0e:cb:1c:12:56:c6:a1:80:2a:ab:34:36:4f:88:
    08:60:05:e4:b4:eb:f5:29:44:a3:e2:86:d1:cd:23:
    13:aa:28:6e:0d:c5:e3:cb:8a:75:e2:31:a2:4d:c6:
    b9:c7:fa:d7:11:a0:a6:7c:d9:dc:2f:da:5e:1d:d3:
    b8:d6:f7:bd:ce:e1:82:02:c3:42:32:4d:0b:4a:1d:
    c7:5f:ba:91:3e:d3:76:7e:06:82:2a:56:91:39:f5:
    18:2b
publicExponent: 65537 (0x10001)
privateExponent:
    47:e8:fc:18:02:c5:a4:3e:b5:68:07:f1:b8:6b:ea:
    55:07:d6:37:22:a2:6f:fd:02:c5:f7:9a:dd:9f:a4:
    3b:72:cb:4c:3d:5d:d5:79:3d:db:99:ac:e0:40:31:
    ff:f9:0d:45:01:08:a3:16:c9:b1:80:06:9b:c9:e5:
    5c:e2:f6:c7:d3:14:78:58:aa:9f:19:95:86:f3:87:
    64:74:b8:86:d5:90:d9:fb:9f:b6:61:76:44:65:3a:
    1c:7c:8d:fb:61:19:af:f7:44:01:46:ba:7d:77:4e:
    2e:ae:d9:8c:a0:ee:d1:02:fb:ef:7a:13:83:b3:f6:
    82:36:1d:cb:21:3c:46:ac:24:59:df:23:94:ef:79:
    dd:d7:53:ba:cf:d9:8e:d2:be:f7:84:48:a0:29:85:
    72:d3:ce:98:65:a0:cc:f3:0f:db:53:33:f8:e5:b9:
    c6:85:73:ce:23:f8:ce:76:1f:b2:ae:5e:c4:d5:98:
    6d:44:e2:d5:11:12:1b:33:34:95:25:90:bb:92:b8:
    8f:52:34:01:b7:1e:ce:e3:c7:20:53:87:a3:98:34:
    88:26:71:b7:76:bf:b1:37:84:56:10:1a:74:dc:1b:
    c8:f9:6e:0e:77:9d:b6:8b:ae:ea:d2:b8:40:1a:ef:
    bf:4e:cf:bd:9f:57:bd:3d:71:e6:28:4f:a6:2c:d8:
    11
prime1:
    00:fe:b3:04:cb:bd:c6:ac:88:2e:81:4f:e6:87:95:
    be:fc:32:89:a7:34:41:1d:4e:6b:38:53:f6:e5:50:
    5e:78:28:73:7a:a7:f8:e7:80:70:70:ee:95:98:7b:
    a3:18:db:be:be:8d:16:cd:22:7f:06:0f:7f:c0:54:
    32:4a:bc:81:41:bf:54:48:93:14:4f:4e:44:43:ff:
    7b:9b:73:8a:74:5d:5f:87:9f:2a:b3:db:56:0d:0a:
    71:5a:30:aa:96:7b:0f:19:6a:36:69:3d:1e:83:12:
    ed:17:0b:ea:78:fc:f2:27:e6:2c:23:4b:bc:dc:38:
    2c:e6:02:f6:b6:5b:55:c8:d1
prime2:
    00:c9:5b:92:a8:32:c0:ca:70:97:a5:ce:31:47:59:
    e8:25:33:85:18:52:a1:54:de:08:9b:c3:2e:2a:73:
    59:47:ad:3c:35:49:da:d2:be:02:b6:e5:9e:88:1c:
    c4:48:91:10:8a:6d:04:98:a6:58:cf:34:6a:b2:82:
    3b:80:7d:52:b9:8a:84:e5:53:ac:75:1c:54:ab:56:
    6f:a1:0d:e8:6f:74:56:05:b7:c1:e3:7f:54:01:63:
    a9:15:26:c6:e9:a0:82:60:16:cf:63:d1:0a:4c:ca:
    d5:22:98:ae:17:f9:c9:d4:bd:aa:f9:21:0c:74:d7:
    a6:11:ed:13:68:bb:26:d0:3b
exponent1:
    00:a1:6a:56:f9:c0:75:ee:d6:07:93:10:4e:2b:53:
    6d:cc:6b:42:ed:e2:a1:f9:ae:bf:28:dd:9d:b5:4a:
    af:f4:3a:be:a4:d7:5b:59:6b:fe:d6:b3:7d:bf:3b:
    6b:eb:cf:28:1d:9f:50:fa:04:88:b8:10:8e:88:17:
    54:20:25:43:4d:a5:b2:06:a4:9f:d4:7a:e7:ac:a8:
    77:6f:d7:53:c1:d7:83:39:72:58:1f:d0:3b:c2:dc:
    01:66:85:3d:37:4d:1a:0e:a3:4f:84:76:a5:a5:b0:
    12:ed:ee:31:55:28:09:57:db:f9:d1:0c:a8:ce:70:
    13:94:5a:00:7d:25:79:42:61
exponent2:
    2c:e9:aa:0a:ae:57:66:50:3a:e3:16:dc:d3:07:70:
    ca:6b:75:72:79:6b:d6:dc:37:9b:56:ab:c3:78:3b:
    1f:cb:ba:34:40:a6:f8:7e:bd:68:42:4b:5c:1c:de:
    83:39:28:31:58:23:c0:50:ca:5a:5d:5c:b7:38:69:
    41:3d:b2:e8:03:c7:a4:c7:47:1e:50:15:6a:aa:3a:
    f7:f7:7c:32:f0:06:07:fc:76:d8:e1:9b:c1:3b:93:
    89:4e:3e:eb:f9:8b:5b:17:7b:66:ce:47:b7:dd:3e:
    31:1b:51:29:b3:e3:9a:fa:3b:5a:9a:4e:86:f9:5a:
    e7:80:b3:e5:96:69:0f:e5
coefficient:
    00:d2:48:07:6d:d6:d6:c3:8b:e6:22:bd:5e:8a:d4:
    6d:be:ab:00:dc:99:d9:3b:42:44:52:81:b3:da:18:
    50:94:52:5f:16:1e:99:06:32:d8:9c:a0:75:38:f2:
    5b:70:c1:0d:9b:bd:28:97:be:c0:e0:aa:17:27:3c:
    5b:a5:b9:d3:90:2c:e3:63:5c:1a:3f:75:de:c5:69:
    98:26:bc:a0:64:bd:ee:05:66:50:5a:d7:e1:ee:30:
    09:52:be:1e:8d:f9:80:51:1a:38:75:55:c9:a6:e6:
    31:20:58:9d:fa:13:eb:01:fc:b4:d2:29:45:f7:01:
    5e:11:02:b1:35:92:a0:87:3c
$ 
```

### Generate Certificate Signing Request (CSR)
We create a Certificate Signing Request (CSR) to send to the CA, which in this case is ourselves:

```console
$ openssl req -new -key private_key.pem -out code_signing.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:California
Locality Name (eg, city) []:Sunnyvale
Organization Name (eg, company) [Internet Widgits Pty Ltd]:MyCompany
Organizational Unit Name (eg, section) []:section
Common Name (e.g. server FQDN or YOUR name) []:MyCompany Code  Signing
Email Address []:contact@mycompany.com

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:1234
An optional company name []:None
$$ ls
code_signing.csr  private_key.pem
```

The CSR, like the certificates, is encoded with ASN.1 [PKCS #10]:

```console
$ cat code_signing.csr 
-----BEGIN CERTIFICATE REQUEST-----
MIIDFDCCAfwCAQAwgaQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlh
MRIwEAYDVQQHDAlTdW5ueXZhbGUxEjAQBgNVBAoMCU15Q29tcGFueTEQMA4GA1UE
CwwHc2VjdGlvbjEgMB4GA1UEAwwXTXlDb21wYW55IENvZGUgIFNpZ25pbmcxJDAi
BgkqhkiG9w0BCQEWFWNvbnRhY3RAbXljb21wYW55LmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMhVqlAdI5GixI2BiM96OLfCh1p314DCK3areyQN
lFqCFXtijlwyB4dgNbxg2t23SYxmoz8NEps7iFu4pYciWKUJ/NlJrZYFESwwJZvl
LM2LnFXSoOT5zHiMXXQuUe6RR2/4/dLxymgse59a2mmS/HqeiEig3136oyjoZt9v
Y9EQvUoFA90mAaMa/0jVgFGtn/klJp6X2stNwu5oz7IsjruQZKKNRw7LHBJWxqGA
Kqs0Nk+ICGAF5LTr9SlEo+KG0c0jE6oobg3F48uKdeIxok3Gucf61xGgpnzZ3C/a
Xh3TuNb3vc7hggLDQjJNC0odx1+6kT7Tdn4GgipWkTn1GCsCAwEAAaAqMBMGCSqG
SIb3DQEJAjEGDAROb25lMBMGCSqGSIb3DQEJBzEGDAQxMjM0MA0GCSqGSIb3DQEB
CwUAA4IBAQBZDgkh5iEuaVbvK1k/aD1l39EieLsQW3Zwbgx7L7rztRTUyqQgmWPU
9XDY4oMdtKXKc8bebpv+6aVoV5//4ct19+cixWCP2yBoUfJKIEcdS3U1lp3d+CVC
V/e2zoGL+ihG6x6cJ24Uzg1d5TIqzlpAUyYQ6I/BB4KGRiUiXqnXoswBBhxeG1iE
y536qvP615NEA5jZmIbTDgzPGyMkuTvGlGCiBk+fck2VJ0f8n4xB6HUCxEWWNg95
6QsahfeAsJGikU1/9g3+HFdGFDKFHlk2sBK/0C2aF1z1QAk3/VGqj1nfGb7fZnsb
de4dpzQOzFc9qTf9cEIsIxL/jGw83U61
-----END CERTIFICATE REQUEST-----
$ ../myrsa/bin/pem2der -p code_signing.csr -d code_signing_csr.der
$ ../myrsa/bin/asn1parse -f code_signing_csr.der -v
0000: SEQUENCE  L =  788
0004: -SEQUENCE  L =  508
0008: --INTEGER  L =    1
0010: 00 
0011: --SEQUENCE  L =  164
0014: ---SET  L =   11
0016: ----SEQUENCE  L =    9
0018: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 6  (id-at-countryName)
0023: -----PRINTABLE STRING  L =    2
0025: US
0027: ---SET  L =   19
0029: ----SEQUENCE  L =   17
0031: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 8  (id-at-stateOrProvinceName)
0036: -----UTF8 STRING  L =   10
0038: 43 61 6c 69 66 6f 72 6e 69 61 
0048: ---SET  L =   18
0050: ----SEQUENCE  L =   16
0052: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 7  (id-at-localityName)
0057: -----UTF8 STRING  L =    9
0059: 53 75 6e 6e 79 76 61 6c 65 
0068: ---SET  L =   18
0070: ----SEQUENCE  L =   16
0072: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 10  (id-at-organizationName)
0077: -----UTF8 STRING  L =    9
0079: 4d 79 43 6f 6d 70 61 6e 79 
0088: ---SET  L =   16
0090: ----SEQUENCE  L =   14
0092: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 11  (id-at-organizationalUnitName)
0097: -----UTF8 STRING  L =    7
0099: 73 65 63 74 69 6f 6e 
0106: ---SET  L =   32
0108: ----SEQUENCE  L =   30
0110: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 3  (id-at-commonName)
0115: -----UTF8 STRING  L =   23
0117: 4d 79 43 6f 6d 70 61 6e 79 20 43 6f 64 65 20 20 
0133: 53 69 67 6e 69 6e 67 
0140: ---SET  L =   36
0142: ----SEQUENCE  L =   34
0144: -----OBJECT IDENTIFIER  L =    9
OID: 1 2 840 113549 1 9 1  (pkcs-9-ub-emailAddress)
0155: -----IA5 STRING  L =   21
0157: contact@mycompany.com
0178: --SEQUENCE  L =  290
0182: ---SEQUENCE  L =   13
0184: ----OBJECT IDENTIFIER  L =    9
OID: 1 2 840 113549 1 1 1  (rsaEncryption)
0195: ----NULL  L =    0
0197: ---BIT STRING  L =  271
0201:  0 - Unused bits
0202: 30 82 01 0a 02 82 01 01 00 c8 55 aa 50 1d 23 91 
0218: a2 c4 8d 81 88 cf 7a 38 b7 c2 87 5a 77 d7 80 c2 
0234: 2b 76 ab 7b 24 0d 94 5a 82 15 7b 62 8e 5c 32 07 
0250: 87 60 35 bc 60 da dd b7 49 8c 66 a3 3f 0d 12 9b 
0266: 3b 88 5b b8 a5 87 22 58 a5 09 fc d9 49 ad 96 05 
0282: 11 2c 30 25 9b e5 2c cd 8b 9c 55 d2 a0 e4 f9 cc 
0298: 78 8c 5d 74 2e 51 ee 91 47 6f f8 fd d2 f1 ca 68 
0314: 2c 7b 9f 5a da 69 92 fc 7a 9e 88 48 a0 df 5d fa 
0330: a3 28 e8 66 df 6f 63 d1 10 bd 4a 05 03 dd 26 01 
0346: a3 1a ff 48 d5 80 51 ad 9f f9 25 26 9e 97 da cb 
0362: 4d c2 ee 68 cf b2 2c 8e bb 90 64 a2 8d 47 0e cb 
0378: 1c 12 56 c6 a1 80 2a ab 34 36 4f 88 08 60 05 e4 
0394: b4 eb f5 29 44 a3 e2 86 d1 cd 23 13 aa 28 6e 0d 
0410: c5 e3 cb 8a 75 e2 31 a2 4d c6 b9 c7 fa d7 11 a0 
0426: a6 7c d9 dc 2f da 5e 1d d3 b8 d6 f7 bd ce e1 82 
0442: 02 c3 42 32 4d 0b 4a 1d c7 5f ba 91 3e d3 76 7e 
0458: 06 82 2a 56 91 39 f5 18 2b 02 03 01 00 01 
0472: --CONTEXT SPECIFIC 0  L =   42
0474: ---SEQUENCE  L =   19
0476: ----OBJECT IDENTIFIER  L =    9
OID: 1 2 840 113549 1 9 2  (pkcs-9-ub-unstructuredName)
0487: ----SET  L =    6
0489: -----UTF8 STRING  L =    4
0491: 4e 6f 6e 65 
0495: ---SEQUENCE  L =   19
0497: ----OBJECT IDENTIFIER  L =    9
OID: 1 2 840 113549 1 9 7  (pkcs-9-at-challengePassword)
0508: ----SET  L =    6
0510: -----UTF8 STRING  L =    4
0512: 31 32 33 34 
0516: -SEQUENCE  L =   13
0518: --OBJECT IDENTIFIER  L =    9
OID: 1 2 840 113549 1 1 11  (sha256WithRSAEncryption)
0529: --NULL  L =    0
0531: -BIT STRING  L =  257
0535:  0 - Unused bits
0536: 59 0e 09 21 e6 21 2e 69 56 ef 2b 59 3f 68 3d 65 
0552: df d1 22 78 bb 10 5b 76 70 6e 0c 7b 2f ba f3 b5 
0568: 14 d4 ca a4 20 99 63 d4 f5 70 d8 e2 83 1d b4 a5 
0584: ca 73 c6 de 6e 9b fe e9 a5 68 57 9f ff e1 cb 75 
0600: f7 e7 22 c5 60 8f db 20 68 51 f2 4a 20 47 1d 4b 
0616: 75 35 96 9d dd f8 25 42 57 f7 b6 ce 81 8b fa 28 
0632: 46 eb 1e 9c 27 6e 14 ce 0d 5d e5 32 2a ce 5a 40 
0648: 53 26 10 e8 8f c1 07 82 86 46 25 22 5e a9 d7 a2 
0664: cc 01 06 1c 5e 1b 58 84 cb 9d fa aa f3 fa d7 93 
0680: 44 03 98 d9 98 86 d3 0e 0c cf 1b 23 24 b9 3b c6 
0696: 94 60 a2 06 4f 9f 72 4d 95 27 47 fc 9f 8c 41 e8 
0712: 75 02 c4 45 96 36 0f 79 e9 0b 1a 85 f7 80 b0 91 
0728: a2 91 4d 7f f6 0d fe 1c 57 46 14 32 85 1e 59 36 
0744: b0 12 bf d0 2d 9a 17 5c f5 40 09 37 fd 51 aa 8f 
0760: 59 df 19 be df 66 7b 1b 75 ee 1d a7 34 0e cc 57 
0776: 3d a9 37 fd 70 42 2c 23 12 ff 8c 6c 3c dd 4e b5 
$ 
```

The top level of CSR structure is as follows:

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

Our example looks as follows:

```console
$ ../myrsa/bin/csr_text -f code_signing_csr.der 
PKCS #10 Certificate Request

  version: v1
  subject: C=US, ST=California, L=Sunnyvale, O=MyCompany, OU=section, CN=MyCompany Code  Signing, E=contact@mycompany.com, 
  subjectPKInfo:
    algorithm: rsaEncryption
    subjectPublicKey:
      modulus: 2048 bits
00 c8 55 aa 50 1d 23 91 a2 c4 8d 81 88 cf 7a 38 
b7 c2 87 5a 77 d7 80 c2 2b 76 ab 7b 24 0d 94 5a 
82 15 7b 62 8e 5c 32 07 87 60 35 bc 60 da dd b7 
49 8c 66 a3 3f 0d 12 9b 3b 88 5b b8 a5 87 22 58 
a5 09 fc d9 49 ad 96 05 11 2c 30 25 9b e5 2c cd 
8b 9c 55 d2 a0 e4 f9 cc 78 8c 5d 74 2e 51 ee 91 
47 6f f8 fd d2 f1 ca 68 2c 7b 9f 5a da 69 92 fc 
7a 9e 88 48 a0 df 5d fa a3 28 e8 66 df 6f 63 d1 
10 bd 4a 05 03 dd 26 01 a3 1a ff 48 d5 80 51 ad 
9f f9 25 26 9e 97 da cb 4d c2 ee 68 cf b2 2c 8e 
bb 90 64 a2 8d 47 0e cb 1c 12 56 c6 a1 80 2a ab 
34 36 4f 88 08 60 05 e4 b4 eb f5 29 44 a3 e2 86 
d1 cd 23 13 aa 28 6e 0d c5 e3 cb 8a 75 e2 31 a2 
4d c6 b9 c7 fa d7 11 a0 a6 7c d9 dc 2f da 5e 1d 
d3 b8 d6 f7 bd ce e1 82 02 c3 42 32 4d 0b 4a 1d 
c7 5f ba 91 3e d3 76 7e 06 82 2a 56 91 39 f5 18 
2b 
      publicExponent:
01 00 01 

  attributes:
    pkcs-9-ub-unstructuredName: None
    pkcs-9-at-challengePassword: 1234

  algorithmIdentifier: sha256WithRSAEncryption
  signature:
00 59 0e 09 21 e6 21 2e 69 56 ef 2b 59 3f 68 3d 
65 df d1 22 78 bb 10 5b 76 70 6e 0c 7b 2f ba f3 
b5 14 d4 ca a4 20 99 63 d4 f5 70 d8 e2 83 1d b4 
a5 ca 73 c6 de 6e 9b fe e9 a5 68 57 9f ff e1 cb 
75 f7 e7 22 c5 60 8f db 20 68 51 f2 4a 20 47 1d 
4b 75 35 96 9d dd f8 25 42 57 f7 b6 ce 81 8b fa 
28 46 eb 1e 9c 27 6e 14 ce 0d 5d e5 32 2a ce 5a 
40 53 26 10 e8 8f c1 07 82 86 46 25 22 5e a9 d7 
a2 cc 01 06 1c 5e 1b 58 84 cb 9d fa aa f3 fa d7 
93 44 03 98 d9 98 86 d3 0e 0c cf 1b 23 24 b9 3b 
c6 94 60 a2 06 4f 9f 72 4d 95 27 47 fc 9f 8c 41 
e8 75 02 c4 45 96 36 0f 79 e9 0b 1a 85 f7 80 b0 
91 a2 91 4d 7f f6 0d fe 1c 57 46 14 32 85 1e 59 
36 b0 12 bf d0 2d 9a 17 5c f5 40 09 37 fd 51 aa 
8f 59 df 19 be df 66 7b 1b 75 ee 1d a7 34 0e cc 
57 3d a9 37 fd 70 42 2c 23 12 ff 8c 6c 3c dd 4e 
b5 
$ 
```

Submit the request:

```console
$ openssl x509 -req -days 365 -in code_signing.csr -signkey private_key.pem -out code_signing_cert.pem
Certificate request self-signature ok
subject=C = US, ST = California, L = Sunnyvale, O = MyCompany, OU = section, CN = MyCompany Code  Signing, emailAddress = contact@mycompany.com
$ ../myrsa/bin/asn1parse -f code_signing_cert.der -v
0000: SEQUENCE  L =  977
0004: -SEQUENCE  L =  697
0008: --INTEGER  L =   20
0010: 19 0f 6b a2 31 29 42 75 47 2a dc 07 96 18 c8 43 
0026: 85 d7 11 88 
0030: --SEQUENCE  L =   13
0032: ---OBJECT IDENTIFIER  L =    9
OID: 1 2 840 113549 1 1 11  (sha256WithRSAEncryption)
0043: ---NULL  L =    0
0045: --SEQUENCE  L =  164
0048: ---SET  L =   11
0050: ----SEQUENCE  L =    9
0052: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 6  (id-at-countryName)
0057: -----PRINTABLE STRING  L =    2
0059: US
0061: ---SET  L =   19
0063: ----SEQUENCE  L =   17
0065: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 8  (id-at-stateOrProvinceName)
0070: -----UTF8 STRING  L =   10
0072: 43 61 6c 69 66 6f 72 6e 69 61 
0082: ---SET  L =   18
0084: ----SEQUENCE  L =   16
0086: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 7  (id-at-localityName)
0091: -----UTF8 STRING  L =    9
0093: 53 75 6e 6e 79 76 61 6c 65 
0102: ---SET  L =   18
0104: ----SEQUENCE  L =   16
0106: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 10  (id-at-organizationName)
0111: -----UTF8 STRING  L =    9
0113: 4d 79 43 6f 6d 70 61 6e 79 
0122: ---SET  L =   16
0124: ----SEQUENCE  L =   14
0126: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 11  (id-at-organizationalUnitName)
0131: -----UTF8 STRING  L =    7
0133: 73 65 63 74 69 6f 6e 
0140: ---SET  L =   32
0142: ----SEQUENCE  L =   30
0144: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 3  (id-at-commonName)
0149: -----UTF8 STRING  L =   23
0151: 4d 79 43 6f 6d 70 61 6e 79 20 43 6f 64 65 20 20 
0167: 53 69 67 6e 69 6e 67 
0174: ---SET  L =   36
0176: ----SEQUENCE  L =   34
0178: -----OBJECT IDENTIFIER  L =    9
OID: 1 2 840 113549 1 9 1  (pkcs-9-ub-emailAddress)
0189: -----IA5 STRING  L =   21
0191: contact@mycompany.com
0212: --SEQUENCE  L =   30
0214: ---UTC TIME  L =   13
0216: 240929160246Z
0229: ---UTC TIME  L =   13
0231: 250929160246Z
0244: --SEQUENCE  L =  164
0247: ---SET  L =   11
0249: ----SEQUENCE  L =    9
0251: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 6  (id-at-countryName)
0256: -----PRINTABLE STRING  L =    2
0258: US
0260: ---SET  L =   19
0262: ----SEQUENCE  L =   17
0264: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 8  (id-at-stateOrProvinceName)
0269: -----UTF8 STRING  L =   10
0271: 43 61 6c 69 66 6f 72 6e 69 61 
0281: ---SET  L =   18
0283: ----SEQUENCE  L =   16
0285: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 7  (id-at-localityName)
0290: -----UTF8 STRING  L =    9
0292: 53 75 6e 6e 79 76 61 6c 65 
0301: ---SET  L =   18
0303: ----SEQUENCE  L =   16
0305: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 10  (id-at-organizationName)
0310: -----UTF8 STRING  L =    9
0312: 4d 79 43 6f 6d 70 61 6e 79 
0321: ---SET  L =   16
0323: ----SEQUENCE  L =   14
0325: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 11  (id-at-organizationalUnitName)
0330: -----UTF8 STRING  L =    7
0332: 73 65 63 74 69 6f 6e 
0339: ---SET  L =   32
0341: ----SEQUENCE  L =   30
0343: -----OBJECT IDENTIFIER  L =    3
OID: 2 5 4 3  (id-at-commonName)
0348: -----UTF8 STRING  L =   23
0350: 4d 79 43 6f 6d 70 61 6e 79 20 43 6f 64 65 20 20 
0366: 53 69 67 6e 69 6e 67 
0373: ---SET  L =   36
0375: ----SEQUENCE  L =   34
0377: -----OBJECT IDENTIFIER  L =    9
OID: 1 2 840 113549 1 9 1  (pkcs-9-ub-emailAddress)
0388: -----IA5 STRING  L =   21
0390: contact@mycompany.com
0411: --SEQUENCE  L =  290
0415: ---SEQUENCE  L =   13
0417: ----OBJECT IDENTIFIER  L =    9
OID: 1 2 840 113549 1 1 1  (rsaEncryption)
0428: ----NULL  L =    0
0430: ---BIT STRING  L =  271
0434:  0 - Unused bits
0435: 30 82 01 0a 02 82 01 01 00 c8 55 aa 50 1d 23 91 
0451: a2 c4 8d 81 88 cf 7a 38 b7 c2 87 5a 77 d7 80 c2 
0467: 2b 76 ab 7b 24 0d 94 5a 82 15 7b 62 8e 5c 32 07 
0483: 87 60 35 bc 60 da dd b7 49 8c 66 a3 3f 0d 12 9b 
0499: 3b 88 5b b8 a5 87 22 58 a5 09 fc d9 49 ad 96 05 
0515: 11 2c 30 25 9b e5 2c cd 8b 9c 55 d2 a0 e4 f9 cc 
0531: 78 8c 5d 74 2e 51 ee 91 47 6f f8 fd d2 f1 ca 68 
0547: 2c 7b 9f 5a da 69 92 fc 7a 9e 88 48 a0 df 5d fa 
0563: a3 28 e8 66 df 6f 63 d1 10 bd 4a 05 03 dd 26 01 
0579: a3 1a ff 48 d5 80 51 ad 9f f9 25 26 9e 97 da cb 
0595: 4d c2 ee 68 cf b2 2c 8e bb 90 64 a2 8d 47 0e cb 
0611: 1c 12 56 c6 a1 80 2a ab 34 36 4f 88 08 60 05 e4 
0627: b4 eb f5 29 44 a3 e2 86 d1 cd 23 13 aa 28 6e 0d 
0643: c5 e3 cb 8a 75 e2 31 a2 4d c6 b9 c7 fa d7 11 a0 
0659: a6 7c d9 dc 2f da 5e 1d d3 b8 d6 f7 bd ce e1 82 
0675: 02 c3 42 32 4d 0b 4a 1d c7 5f ba 91 3e d3 76 7e 
0691: 06 82 2a 56 91 39 f5 18 2b 02 03 01 00 01 
0705: -SEQUENCE  L =   13
0707: --OBJECT IDENTIFIER  L =    9
OID: 1 2 840 113549 1 1 11  (sha256WithRSAEncryption)
0718: --NULL  L =    0
0720: -BIT STRING  L =  257
0724:  0 - Unused bits
0725: 97 c7 b8 ed c9 d8 96 ed d5 a9 82 8b 76 42 74 89 
0741: 54 ec c9 a7 da ce 6f 63 33 93 82 03 27 82 f9 09 
0757: 93 73 ac e4 da 17 36 b1 7d be 5e 92 04 e8 05 1d 
0773: 27 34 69 fd ed a7 3b 0e 54 19 ca b9 85 5a 7d d7 
0789: 57 6f 65 c6 83 77 06 56 5d 02 5d e2 7d 54 81 a8 
0805: bf b4 b5 f9 94 3f 94 6f c8 eb 6e ba f9 e4 21 3d 
0821: 88 c7 ce 1e 37 06 9d c9 6b 58 8e 54 b8 5f a0 c9 
0837: f8 29 af 26 05 dc c8 8c 8f 7b 90 0b da 90 11 c3 
0853: 7b 56 fc a6 2f 9d e5 a4 00 07 fe a5 e2 69 99 1f 
0869: a7 aa 8f e5 78 e1 0b e3 1a 3b d5 0c 0d 16 3c e2 
0885: ba 02 95 cf c2 42 1d c1 96 8b 5d cc 8f bd 3d c0 
0901: 15 be 76 c8 5b 69 26 14 0a 27 63 7c b8 99 cc f6 
0917: 83 02 d2 e7 96 84 78 54 3b 87 da 54 f3 fa e7 0e 
0933: a5 ec f7 97 38 f2 69 52 64 1e fb a2 ab 56 b3 13 
0949: 58 6e 61 63 30 8a dc e9 61 49 0b d3 91 5d 85 40 
0965: e3 da d9 a9 e0 45 41 73 5f 79 8c 1e 6e 43 17 60 
$ 
```

This certificate does not have the version field, implying a v1 version [X.509, 1988] that does not have the fields of issuerUniqueIdentifier, subjectUniqueIdentifier, and extensions:

```text
Certificate ::= SIGNED SEQUENCE{
version         [0]Version DEFAULT 1988,
serialNumber    SerialNumber,
signature       Algorithmidentifier
issuer          Name
validity        Validity,
subject         subjectPublicKeyInfo}
```

```console
$ ../myrsa/bin/x509_text_public_key -f code_signing_cert.der
X509 Public Key certificate

toBeSigned:
  Version: v1
  serial Number: 19 0f 6b a2 31 29 42 75 47 2a dc 07 96 18 c8 43 85 d7 11 88 
  signature: sha256WithRSAEncryption
  issuer: C=US, ST=California, L=Sunnyvale, O=MyCompany, OU=section, CN=MyCompany Code  Signing, E=contact@mycompany.com, 
  validity:
    notBefore	: 29th September 2024, 16:02:46 UTC
    notAfter	: 29th September 2025, 16:02:46 UTC
  subject: C=US, ST=California, L=Sunnyvale, O=MyCompany, OU=section, CN=MyCompany Code  Signing, E=contact@mycompany.com, 
  subjectPublicKeyInfo:
    algorithm: rsaEncryption
    subjectPublicKey:
      modulus: 2048 bits
00 c8 55 aa 50 1d 23 91 a2 c4 8d 81 88 cf 7a 38 
b7 c2 87 5a 77 d7 80 c2 2b 76 ab 7b 24 0d 94 5a 
82 15 7b 62 8e 5c 32 07 87 60 35 bc 60 da dd b7 
49 8c 66 a3 3f 0d 12 9b 3b 88 5b b8 a5 87 22 58 
a5 09 fc d9 49 ad 96 05 11 2c 30 25 9b e5 2c cd 
8b 9c 55 d2 a0 e4 f9 cc 78 8c 5d 74 2e 51 ee 91 
47 6f f8 fd d2 f1 ca 68 2c 7b 9f 5a da 69 92 fc 
7a 9e 88 48 a0 df 5d fa a3 28 e8 66 df 6f 63 d1 
10 bd 4a 05 03 dd 26 01 a3 1a ff 48 d5 80 51 ad 
9f f9 25 26 9e 97 da cb 4d c2 ee 68 cf b2 2c 8e 
bb 90 64 a2 8d 47 0e cb 1c 12 56 c6 a1 80 2a ab 
34 36 4f 88 08 60 05 e4 b4 eb f5 29 44 a3 e2 86 
d1 cd 23 13 aa 28 6e 0d c5 e3 cb 8a 75 e2 31 a2 
4d c6 b9 c7 fa d7 11 a0 a6 7c d9 dc 2f da 5e 1d 
d3 b8 d6 f7 bd ce e1 82 02 c3 42 32 4d 0b 4a 1d 
c7 5f ba 91 3e d3 76 7e 06 82 2a 56 91 39 f5 18 
2b 
      publicExponent:
01 00 01 
  extensions: None
SIGNATURE:
  algorithmIdentifier: sha256WithRSAEncryption
  signature:
00 97 c7 b8 ed c9 d8 96 ed d5 a9 82 8b 76 42 74 
89 54 ec c9 a7 da ce 6f 63 33 93 82 03 27 82 f9 
09 93 73 ac e4 da 17 36 b1 7d be 5e 92 04 e8 05 
1d 27 34 69 fd ed a7 3b 0e 54 19 ca b9 85 5a 7d 
d7 57 6f 65 c6 83 77 06 56 5d 02 5d e2 7d 54 81 
a8 bf b4 b5 f9 94 3f 94 6f c8 eb 6e ba f9 e4 21 
3d 88 c7 ce 1e 37 06 9d c9 6b 58 8e 54 b8 5f a0 
c9 f8 29 af 26 05 dc c8 8c 8f 7b 90 0b da 90 11 
c3 7b 56 fc a6 2f 9d e5 a4 00 07 fe a5 e2 69 99 
1f a7 aa 8f e5 78 e1 0b e3 1a 3b d5 0c 0d 16 3c 
e2 ba 02 95 cf c2 42 1d c1 96 8b 5d cc 8f bd 3d 
c0 15 be 76 c8 5b 69 26 14 0a 27 63 7c b8 99 cc 
f6 83 02 d2 e7 96 84 78 54 3b 87 da 54 f3 fa e7 
0e a5 ec f7 97 38 f2 69 52 64 1e fb a2 ab 56 b3 
13 58 6e 61 63 30 8a dc e9 61 49 0b d3 91 5d 85 
40 e3 da d9 a9 e0 45 41 73 5f 79 8c 1e 6e 43 17 
60 
$ 
```

It is a self-signed certificate, we verify it with the public key included in the certificate.

```console
$ ../myrsa/bin/x509_extract_pubkey -c code_signing_cert.der -p code_signing_pubkey.der
$ ../myrsa/bin/rsa_text_public_key -f code_signing_pubkey.der 
PKCS #1 Public Key
  Modulus:
00 c8 55 aa 50 1d 23 91 a2 c4 8d 81 88 cf 7a 38 
b7 c2 87 5a 77 d7 80 c2 2b 76 ab 7b 24 0d 94 5a 
82 15 7b 62 8e 5c 32 07 87 60 35 bc 60 da dd b7 
49 8c 66 a3 3f 0d 12 9b 3b 88 5b b8 a5 87 22 58 
a5 09 fc d9 49 ad 96 05 11 2c 30 25 9b e5 2c cd 
8b 9c 55 d2 a0 e4 f9 cc 78 8c 5d 74 2e 51 ee 91 
47 6f f8 fd d2 f1 ca 68 2c 7b 9f 5a da 69 92 fc 
7a 9e 88 48 a0 df 5d fa a3 28 e8 66 df 6f 63 d1 
10 bd 4a 05 03 dd 26 01 a3 1a ff 48 d5 80 51 ad 
9f f9 25 26 9e 97 da cb 4d c2 ee 68 cf b2 2c 8e 
bb 90 64 a2 8d 47 0e cb 1c 12 56 c6 a1 80 2a ab 
34 36 4f 88 08 60 05 e4 b4 eb f5 29 44 a3 e2 86 
d1 cd 23 13 aa 28 6e 0d c5 e3 cb 8a 75 e2 31 a2 
4d c6 b9 c7 fa d7 11 a0 a6 7c d9 dc 2f da 5e 1d 
d3 b8 d6 f7 bd ce e1 82 02 c3 42 32 4d 0b 4a 1d 
c7 5f ba 91 3e d3 76 7e 06 82 2a 56 91 39 f5 18 
2b 

  Exponent:
01 00 01 
$ ../myrsa/bin/x509_extract_sig -c code_signing_cert.der -s code_signing_cert.sig.bin
$ ../myrsa/bin/myrsa_trapdoor -m code_signing_cert.sig.bin -k code_signing_pubkey.der 
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
93 9e be f6 fc e4 36 f0 0b 59 87 ee f9 33 3e 1b 
c0 29 c1 f8 2b c3 86 c0 f2 a9 02 65 84 00 51 97 

$ ../myrsa/bin/x509_extract_tbs -c code_signing_cert.der -p code_signing_cert_tbs.der
$ ../myrsa/bin/myrsa_sha256 -i code_signing_cert_tbs.der -o code_signing_cert.dgst
$ hexdump -C code_signing_cert.dgst
00000000  93 9e be f6 fc e4 36 f0  0b 59 87 ee f9 33 3e 1b  |......6..Y...3>.|
00000010  c0 29 c1 f8 2b c3 86 c0  f2 a9 02 65 84 00 51 97  |.)..+......e..Q.|
00000020
$ 
```

## Hardware key storage

From ssl.com:

```text
Starting June 1, 2023, SSL.com’s Organization Validation (OV) and Individual Validation (IV) Code Signing Certificates will only be issued either on Federal Information Processing Standard 140-2 (FIPS 140-2) USB tokens or through our eSigner cloud code signing service.
```

This highlights the importance of securing private keys in a secure enclave, such as a hardware token.

In this example, we use an YubiKey NFC FIPS [YubiKey] as the secure token. We start with installing Yubico’s YubiKey Manager CLI:

```bash
sudo update
sudo apt install yubikey-manager
```

Test the connection:

```console
$ ykman info
Device type: YubiKey 5 NFC FIPS
Serial number: 28989286
Firmware version: 5.4.3
Form factor: Keychain (USB-A)
Enabled USB interfaces: OTP, FIDO, CCID
NFC transport is enabled.

Applications	USB    	NFC    
FIDO2       	Enabled	Enabled	
OTP         	Enabled	Enabled	
FIDO U2F    	Enabled	Enabled	
OATH        	Enabled	Enabled	
YubiHSM Auth	Enabled	Enabled	
OpenPGP     	Enabled	Enabled	
PIV         	Enabled	Enabled	
$ 
```

Save the code-signing key to the hardware at slot 9a which is the position designated for code-signing purpose:

```consoled
$ ykman piv keys import 9a private_key.pem
Enter a management key [blank to use default key]: 
$ 
```

Also, store the associated certificate into the token:

```console
$ ykman piv certificates import 9a code_signing_cert.der
Enter a management key [blank to use default key]: 
$ 
```

Applications access the token via a cryptographic token interface [PKCS #11]. Install OpenSC for PKCS #11 operations:

```console
$ sudo apt install opensc
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  opensc-pkcs11
The following NEW packages will be installed:
  opensc opensc-pkcs11
:
:
```

Verify the token slots:

```console
$ pkcs11-tool -T
Available slots:
Slot 0 (0x0): Yubico YubiKey OTP+FIDO+CCID 00 00
  token label        : MyCompany Code  Signing
  token manufacturer : piv_II
  token model        : PKCS#15 emulated
  token flags        : login required, rng, token initialized, PIN initialized
  hardware version   : 0.0
  firmware version   : 0.0
  serial num         : 4c1e90a9636de846
  pin min/max        : 4/8

```

Yubico's slot numbers (e.g., 9a) map to PKCS #11 slots (starting from 1). Use the following command to view objects in the slots:

```console
$ pkcs11-tool -O
Using slot 0 with a present token (0x0)
Public Key Object; RSA 2048 bits
  label:      PIV AUTH pubkey
  ID:         01
  Usage:      encrypt, verify, wrap
  Access:     none
Certificate Object; type = X.509 cert
  label:      Certificate for PIV Authentication
  subject:    DN: C=US, ST=California, L=Sunnyvale, O=MyCompany, OU=section, CN=MyCompany Code  Signing/emailAddress=contact@mycompany.com
  serial:     190F6BA231294275472ADC079618C84385D71188
  ID:         01
Data object 2858936448
  label:          'Card Capability Container'
  application:    'Card Capability Container'
  app_id:         2.16.840.1.101.3.7.1.219.0
  flags:          <empty>
  :
  :
  ```

At this point, we can safely remove the private key and the certificate from the local drives.

## Create a code

Create a simple C program as the signing target:

```console
$ echo -e '#include <stdio.h>\n\nint main() {\n    printf("Hello, World!\\n");\n    return 0;\n}' > hello.c
$ cat hello.c
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
$ gcc hello.c -o hello
$ ./hello
Hello, World!
```

Sign the executable using the private key stored on the YubiKey:

```console
$ pkcs11-tool --sign --id 1 --mechanism SHA256-RSA-PKCS -i hello -o hello.sig
Using slot 0 with a present token (0x0)
Logging in to "MyCompany Code  Signing".
Please enter User PIN: 
Using signature algorithm SHA256-RSA-PKCS
$ hexdump -C hello.sig
00000000  c7 88 a1 5a 74 8d 7a a8  e4 0b da 05 b4 11 b7 70  |...Zt.z........p|
00000010  a3 0b a0 11 df c5 37 4f  c9 b2 e8 6f 5f 5a 57 b7  |......7O...o_ZW.|
00000020  d9 3d 1b c5 f7 44 c4 23  c4 06 ca f1 20 77 3c e3  |.=...D.#.... w<.|
00000030  c0 25 ed 6f d2 0f 19 8f  3f 69 c7 26 87 d8 81 4f  |.%.o....?i.&...O|
00000040  c3 55 32 1f c4 56 d5 6e  2b ad 68 dd a4 7e cb 7c  |.U2..V.n+.h..~.||
00000050  14 4f d7 d0 d8 34 7c 49  7e 10 71 72 98 ee e0 12  |.O...4|I~.qr....|
00000060  7d fb 35 2d 8c 99 11 2e  19 63 66 bb 0b 57 f9 4c  |}.5-.....cf..W.L|
00000070  23 53 1c 85 2c 70 6a 9b  cc 6a c8 0a c8 dd 23 22  |#S..,pj..j....#"|
00000080  fc 05 57 ba cb 03 17 d4  ca fb 8a c3 e6 3d 87 4e  |..W..........=.N|
00000090  2c 09 c6 38 45 74 ab d2  2c 95 2c 97 dc 38 2a 94  |,..8Et..,.,..8*.|
000000a0  17 d1 0a 7b c8 67 79 da  36 3e 88 29 fc 80 5a ba  |...{.gy.6>.)..Z.|
000000b0  78 da d4 d0 2e c0 89 3b  21 1e 89 b0 4a b4 a5 39  |x......;!...J..9|
000000c0  f5 92 bb 86 db e0 60 55  6c 97 eb 8f 06 48 91 07  |......`Ul....H..|
000000d0  31 a8 38 dd 07 d3 ad 17  89 31 0d 18 02 97 cd ad  |1.8......1......|
000000e0  5a 3f e1 bc 4a c1 78 16  d7 12 d9 14 d3 73 fb fb  |Z?..J.x......s..|
000000f0  6f 28 4f fe 26 48 c2 dc  aa 90 77 2a d9 a2 27 82  |o(O.&H....w*..'.|
00000100
$ 
```
--id: the ID for the private key.
--mechanism: SHA-256 for the hash, RSA for the encryption, and padding the result with EMSA-PKCS1-v1_5 method.

## Prepare the publish
Install Yubico's tool for more functionalities:

```bash
$ sudo apt install yubico-piv-tool
```

Read the certificate from the token:

```consol
$ yubico-piv-tool -a read-cert -s 9a
-----BEGIN CERTIFICATE-----
MIID0TCCArkCFBkPa6IxKUJ1RyrcB5YYyEOF1xGIMA0GCSqGSIb3DQEBCwUAMIGk
MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJU3Vu
bnl2YWxlMRIwEAYDVQQKDAlNeUNvbXBhbnkxEDAOBgNVBAsMB3NlY3Rpb24xIDAe
BgNVBAMMF015Q29tcGFueSBDb2RlICBTaWduaW5nMSQwIgYJKoZIhvcNAQkBFhVj
b250YWN0QG15Y29tcGFueS5jb20wHhcNMjQwOTI5MTYwMjQ2WhcNMjUwOTI5MTYw
MjQ2WjCBpDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNV
BAcMCVN1bm55dmFsZTESMBAGA1UECgwJTXlDb21wYW55MRAwDgYDVQQLDAdzZWN0
aW9uMSAwHgYDVQQDDBdNeUNvbXBhbnkgQ29kZSAgU2lnbmluZzEkMCIGCSqGSIb3
DQEJARYVY29udGFjdEBteWNvbXBhbnkuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAyFWqUB0jkaLEjYGIz3o4t8KHWnfXgMIrdqt7JA2UWoIVe2KO
XDIHh2A1vGDa3bdJjGajPw0SmzuIW7ilhyJYpQn82UmtlgURLDAlm+UszYucVdKg
5PnMeIxddC5R7pFHb/j90vHKaCx7n1raaZL8ep6ISKDfXfqjKOhm329j0RC9SgUD
3SYBoxr/SNWAUa2f+SUmnpfay03C7mjPsiyOu5Bkoo1HDsscElbGoYAqqzQ2T4gI
YAXktOv1KUSj4obRzSMTqihuDcXjy4p14jGiTca5x/rXEaCmfNncL9peHdO41ve9
zuGCAsNCMk0LSh3HX7qRPtN2fgaCKlaROfUYKwIDAQABMA0GCSqGSIb3DQEBCwUA
A4IBAQCXx7jtydiW7dWpgot2QnSJVOzJp9rOb2Mzk4IDJ4L5CZNzrOTaFzaxfb5e
kgToBR0nNGn97ac7DlQZyrmFWn3XV29lxoN3BlZdAl3ifVSBqL+0tfmUP5RvyOtu
uvnkIT2Ix84eNwadyWtYjlS4X6DJ+CmvJgXcyIyPe5AL2pARw3tW/KYvneWkAAf+
peJpmR+nqo/leOEL4xo71QwNFjziugKVz8JCHcGWi13Mj709wBW+dshbaSYUCidj
fLiZzPaDAtLnloR4VDuH2lTz+ucOpez3lzjyaVJkHvuiq1azE1huYWMwitzpYUkL
05FdhUDj2tmp4EVBc195jB5uQxdg
-----END CERTIFICATE-----
$ yubico-piv-tool -a read-cert -s 9a > hello_code_sign_cert.pem
$ 
```
The certificate was put off in PEM format which is suitable for many transportation vehicles. 

Publish the executable, the signature file, and the certificate. 

## Verify the signature

First we verify the identity of the publisher by applying RSA process to the signature with the public key from the certificate:

```console
$ ../myrsa/bin/pem2der -p hello_code_sign_cert.pem -d hello_code_sign_cert.der
$ ../myrsa/bin/x509_extract_pubkey -c hello_code_sign_cert.der -p hello_code_sign_pubkey.der
$ ../myrsa/bin/myrsa_trapdoor -m hello.sig -k hello_code_sign_pubkey.der 
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
ec af 71 d2 d9 25 70 16 0e ca 10 7d 92 3f 60 68 
f1 0a 29 c5 2f c0 72 d8 c5 8b 56 5d c5 9b 2a c9 

$
```

This output follows the expected pattern. Now, check the digest:

```console
$ ../myrsa/bin/myrsa_sha256 -i hello -o hello.dgst
$ hexdump -C hello.dgst
00000000  ec af 71 d2 d9 25 70 16  0e ca 10 7d 92 3f 60 68  |..q..%p....}.?`h|
00000010  f1 0a 29 c5 2f c0 72 d8  c5 8b 56 5d c5 9b 2a c9  |..)./.r...V]..*.|
00000020
$ 
```

## References

1. **[PKCS #10]**: Certification Request Syntax Specification Version 1.7
   RSA Laboratories, November 1, 1993.  
   [https://datatracker.ietf.org/doc/html/rfc2986](https://datatracker.ietf.org/doc/html/rfc2986)

2. **[X.509, 1988]**: Information technology - Open Systems Interconnection - The Directory: Authentication Framework
   International Telecommunication Union, 1988.
   [https://www.itu.int/rec/T-REC-X.509-198811-I/en](https://www.itu.int/rec/T-REC-X.509-198811-I/en)

3. **[PKCS #11]**: Cryptographic Token Interface Standard
   RSA Laboratories, June 28, 2004.  
   [https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)

4. **[YubiKey]**: YubiKey Hardware Authentication Device
   Yubico, 2021.  
   [https://www.yubico.com/product/yubikey-5-nfc/](https://www.yubico.com/product/yubikey-5-nfc/)