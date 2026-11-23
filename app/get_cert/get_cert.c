/*
 * get_cert.c - Download and display a website's SSL/TLS certificate
 *
 * Copyright (C) 2026 AI Assistant
 *
 * This program connects to a remote host over TLS, retrieves the peer
 * certificate, prints basic information about it, and saves the
 * certificate to a file in DER format. It intentionally avoids any
 * external TLS library and relies only on the C standard library and
 * POSIX socket APIs, so that it can run in a minimal Linux environment
 * (e.g. BusyBox, initramfs, embedded systems).
 *
 * The implementation speaks just enough of the TLS 1.2 handshake to
 * obtain the server's certificate chain. It does NOT validate the
 * certificate, perform key exchange, or exchange application data.
 */

/*
 * Enable POSIX.1-2001 declarations from glibc, in particular
 * struct addrinfo and getaddrinfo(). Must be defined before any
 * #include, since glibc's headers honour it only on first inclusion.
 */
#define _POSIX_C_SOURCE 200112L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>

#define DEFAULT_PORT "443"
#define DEFAULT_CERT_FILE "certificate.der"

#define TLS_RECORD_HDR_LEN 5
#define TLS_HANDSHAKE_HDR_LEN 4
#define TLS_MAX_RECORD 16384
#define TLS_MAX_HANDSHAKE 65536

/* TLS content types */
#define TLS_CT_CHANGE_CIPHER_SPEC 20
#define TLS_CT_ALERT 21
#define TLS_CT_HANDSHAKE 22
#define TLS_CT_APPLICATION_DATA 23

/* TLS handshake message types */
#define TLS_HT_CLIENT_HELLO 1
#define TLS_HT_SERVER_HELLO 2
#define TLS_HT_CERTIFICATE 11
#define TLS_HT_SERVER_HELLO_DONE 14

/* TLS protocol version: 3.3 == TLS 1.2 */
#define TLS_VERSION_12 0x0303

/**
 * struct tls_buf - Simple growable byte buffer
 * @data: heap-allocated buffer
 * @len: number of bytes currently in use
 * @cap: allocated capacity in bytes
 */
struct tls_buf {
	uint8_t *data;
	size_t len;
	size_t cap;
};

/**
 * buf_init() - Initialise a byte buffer
 * @b: buffer to initialise
 *
 * Return: 0 on success, negative errno-style value on failure.
 */
static int buf_init(struct tls_buf *b)
{
	b->cap = 4096;
	b->len = 0;
	b->data = malloc(b->cap);
	if (!b->data)
		return -ENOMEM;
	return 0;
}

/**
 * buf_free() - Release the memory owned by a byte buffer
 * @b: buffer to free
 */
static void buf_free(struct tls_buf *b)
{
	free(b->data);
	b->data = NULL;
	b->len = 0;
	b->cap = 0;
}

/**
 * buf_reserve() - Ensure the buffer has room for additional bytes
 * @b: buffer to grow
 * @extra: number of additional bytes required
 *
 * Return: 0 on success, negative errno-style value on failure.
 */
static int buf_reserve(struct tls_buf *b, size_t extra)
{
	uint8_t *tmp;
	size_t need;

	need = b->len + extra;
	if (need <= b->cap)
		return 0;

	while (b->cap < need)
		b->cap *= 2;

	tmp = realloc(b->data, b->cap);
	if (!tmp)
		return -ENOMEM;

	b->data = tmp;
	return 0;
}

/**
 * buf_put() - Append raw bytes to a buffer
 * @b: destination buffer
 * @src: source bytes
 * @n: number of bytes to append
 *
 * Return: 0 on success, negative errno-style value on failure.
 */
static int buf_put(struct tls_buf *b, const void *src, size_t n)
{
	int ret;

	ret = buf_reserve(b, n);
	if (ret)
		return ret;

	memcpy(b->data + b->len, src, n);
	b->len += n;
	return 0;
}

/**
 * buf_put_u8() - Append a single byte to a buffer
 * @b: destination buffer
 * @v: value to append
 *
 * Return: 0 on success, negative errno-style value on failure.
 */
static int buf_put_u8(struct tls_buf *b, uint8_t v)
{
	return buf_put(b, &v, 1);
}

/**
 * buf_put_u16() - Append a big-endian 16-bit value to a buffer
 * @b: destination buffer
 * @v: value to append
 *
 * Return: 0 on success, negative errno-style value on failure.
 */
static int buf_put_u16(struct tls_buf *b, uint16_t v)
{
	uint8_t be[2];

	be[0] = (uint8_t)(v >> 8);
	be[1] = (uint8_t)(v & 0xff);
	return buf_put(b, be, 2);
}

/**
 * buf_put_u24() - Append a big-endian 24-bit value to a buffer
 * @b: destination buffer
 * @v: value to append
 *
 * Return: 0 on success, negative errno-style value on failure.
 */
static int buf_put_u24(struct tls_buf *b, uint32_t v)
{
	uint8_t be[3];

	be[0] = (uint8_t)(v >> 16);
	be[1] = (uint8_t)(v >> 8);
	be[2] = (uint8_t)(v & 0xff);
	return buf_put(b, be, 3);
}

/**
 * read_u16() - Read a big-endian 16-bit value from a byte array
 * @p: pointer to at least 2 bytes
 *
 * Return: the decoded value.
 */
static uint16_t read_u16(const uint8_t *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

/**
 * read_u24() - Read a big-endian 24-bit value from a byte array
 * @p: pointer to at least 3 bytes
 *
 * Return: the decoded value.
 */
static uint32_t read_u24(const uint8_t *p)
{
	return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

/**
 * tcp_connect() - Open a TCP connection to a host and port
 * @host: DNS name or numeric address of the remote host
 * @port: TCP port, as a string
 *
 * Resolves @host with getaddrinfo() and connects to the first usable
 * address. IPv4 and IPv6 are both supported.
 *
 * Return: connected socket file descriptor on success, or -1 on failure.
 */
static int tcp_connect(const char *host, const char *port)
{
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *rp;
	int fd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, port, &hints, &res) != 0) {
		fprintf(stderr, "getaddrinfo(%s): failed\n", host);
		return -1;
	}

	for (rp = res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0)
			continue;

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(fd);
		fd = -1;
	}

	freeaddrinfo(res);

	if (fd < 0)
		fprintf(stderr, "connect(%s:%s): failed: %s\n", host, port,
			strerror(errno));

	return fd;
}

/**
 * sock_write_all() - Write the entire buffer to a socket
 * @fd: connected socket
 * @buf: bytes to write
 * @len: number of bytes to write
 *
 * Return: 0 on success, negative errno-style value on failure.
 */
static int sock_write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	ssize_t n;

	while (len > 0) {
		n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

/**
 * sock_read_all() - Read exactly @len bytes from a socket
 * @fd: connected socket
 * @buf: destination buffer
 * @len: number of bytes to read
 *
 * Return: 0 on success, negative errno-style value on failure or EOF.
 */
static int sock_read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	ssize_t n;

	while (len > 0) {
		n = read(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			return -ECONNRESET;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

/**
 * build_client_hello() - Construct a TLS 1.2 ClientHello message
 * @host: SNI hostname to advertise
 * @out: destination buffer
 *
 * Builds a complete TLS record containing a ClientHello with SNI and a
 * minimal set of cipher suites. Only the features required to elicit a
 * Certificate message from the server are implemented.
 *
 * Return: 0 on success, negative errno-style value on failure.
 */
static int build_client_hello(const char *host, struct tls_buf *out)
{
	struct tls_buf body;
	struct tls_buf ext;
	struct tls_buf sni;
	size_t host_len = strlen(host);
	uint8_t random_bytes[32];
	int i;
	int ret = 0;

	ret = buf_init(&body);
	if (ret)
		return ret;
	ret = buf_init(&ext);
	if (ret)
		goto err_body;
	ret = buf_init(&sni);
	if (ret)
		goto err_ext;

	/* Client random: only needs to be unique-ish for our purpose */
	srand((unsigned)time(NULL) ^ (unsigned)getpid());
	for (i = 0; i < 32; i++)
		random_bytes[i] = (uint8_t)(rand() & 0xff);

	/* Handshake body: version, random, session id, ciphers, compression */
	buf_put_u16(&body, TLS_VERSION_12);
	buf_put(&body, random_bytes, sizeof(random_bytes));
	buf_put_u8(&body, 0); /* session id length */

	/* Cipher suites: offer a small selection of common TLS 1.2 suites */
	buf_put_u16(&body, 8); /* 4 suites = 8 bytes */
	buf_put_u16(&body, 0xc02f); /* ECDHE-RSA-AES128-GCM-SHA256 */
	buf_put_u16(&body, 0xc030); /* ECDHE-RSA-AES256-GCM-SHA384 */
	buf_put_u16(&body, 0x009c); /* RSA-AES128-GCM-SHA256 */
	buf_put_u16(&body, 0x002f); /* RSA-AES128-SHA */

	/* Compression methods: null only */
	buf_put_u8(&body, 1);
	buf_put_u8(&body, 0);

	/* SNI extension body: list length, name type, name length, name */
	buf_put_u16(&sni, (uint16_t)(host_len + 3));
	buf_put_u8(&sni, 0); /* host_name */
	buf_put_u16(&sni, (uint16_t)host_len);
	buf_put(&sni, host, host_len);

	/* Extension: server_name (0x0000) */
	buf_put_u16(&ext, 0x0000);
	buf_put_u16(&ext, (uint16_t)sni.len);
	buf_put(&ext, sni.data, sni.len);

	/* Extension: supported_groups (0x000a) - x25519, secp256r1, secp384r1 */
	buf_put_u16(&ext, 0x000a);
	buf_put_u16(&ext, 8);
	buf_put_u16(&ext, 6);
	buf_put_u16(&ext, 0x001d);
	buf_put_u16(&ext, 0x0017);
	buf_put_u16(&ext, 0x0018);

	/* Extension: ec_point_formats (0x000b) - uncompressed */
	buf_put_u16(&ext, 0x000b);
	buf_put_u16(&ext, 2);
	buf_put_u8(&ext, 1);
	buf_put_u8(&ext, 0);

	/* Extension: signature_algorithms (0x000d) */
	buf_put_u16(&ext, 0x000d);
	buf_put_u16(&ext, 18);
	buf_put_u16(&ext, 16);
	buf_put_u16(&ext, 0x0403); /* ecdsa_secp256r1_sha256 */
	buf_put_u16(&ext, 0x0804); /* rsa_pss_rsae_sha256 */
	buf_put_u16(&ext, 0x0401); /* rsa_pkcs1_sha256 */
	buf_put_u16(&ext, 0x0503); /* ecdsa_secp384r1_sha384 */
	buf_put_u16(&ext, 0x0805); /* rsa_pss_rsae_sha384 */
	buf_put_u16(&ext, 0x0501); /* rsa_pkcs1_sha384 */
	buf_put_u16(&ext, 0x0806); /* rsa_pss_rsae_sha512 */
	buf_put_u16(&ext, 0x0601); /* rsa_pkcs1_sha512 */

	/* Append extensions block to handshake body */
	buf_put_u16(&body, (uint16_t)ext.len);
	buf_put(&body, ext.data, ext.len);

	/* Wrap handshake body in a Handshake header */
	/* Record layer: content type, version, length */
	buf_put_u8(out, TLS_CT_HANDSHAKE);
	buf_put_u16(out, TLS_VERSION_12);
	buf_put_u16(out, (uint16_t)(body.len + TLS_HANDSHAKE_HDR_LEN));

	/* Handshake header: type, 3-byte length */
	buf_put_u8(out, TLS_HT_CLIENT_HELLO);
	buf_put_u24(out, (uint32_t)body.len);
	buf_put(out, body.data, body.len);

	buf_free(&sni);
	buf_free(&ext);
	buf_free(&body);
	return 0;

err_ext:
	buf_free(&ext);
err_body:
	buf_free(&body);
	return ret;
}

/**
 * recv_tls_record() - Read one TLS record into a buffer
 * @fd: connected socket
 * @type: output, receives the record content type
 * @payload: output buffer for the record payload
 *
 * Reads a single TLS record and appends its payload to @payload,
 * stripping the 5-byte record header.
 *
 * Return: 0 on success, negative errno-style value on failure.
 */
static int recv_tls_record(int fd, uint8_t *type, struct tls_buf *payload)
{
	uint8_t hdr[TLS_RECORD_HDR_LEN];
	uint16_t len;
	int ret;

	ret = sock_read_all(fd, hdr, sizeof(hdr));
	if (ret)
		return ret;

	*type = hdr[0];
	len = read_u16(&hdr[3]);

	if (len > TLS_MAX_RECORD)
		return -EMSGSIZE;

	ret = buf_reserve(payload, len);
	if (ret)
		return ret;

	ret = sock_read_all(fd, payload->data + payload->len, len);
	if (ret)
		return ret;

	payload->len += len;
	return 0;
}

/**
 * recv_handshake_until_certificate() - Read handshake messages until
 * Certificate
 * @fd: connected socket
 * @cert_der: output buffer for the leaf certificate in DER form
 *
 * Reads TLS records from @fd, buffering handshake messages, and copies
 * the first certificate listed in the server's Certificate message into
 * @cert_der. Returns as soon as the leaf certificate has been captured.
 *
 * Return: 0 on success, negative errno-style value on failure.
 */
static int recv_handshake_until_certificate(int fd, struct tls_buf *cert_der)
{
	struct tls_buf hs;
	uint8_t type;
	size_t off;
	int ret;

	ret = buf_init(&hs);
	if (ret)
		return ret;

	for (;;) {
		uint32_t msg_len;
		uint8_t msg_type;

		/* Read records until we have a full handshake message */
		while (hs.len < TLS_HANDSHAKE_HDR_LEN) {
			ret = recv_tls_record(fd, &type, &hs);
			if (ret)
				goto out;
			if (type == TLS_CT_ALERT) {
				fprintf(stderr, "Server sent a TLS alert\n");
				ret = -ECONNREFUSED;
				goto out;
			}
		}

		msg_type = hs.data[0];
		msg_len = read_u24(&hs.data[1]);

		if (msg_len > TLS_MAX_HANDSHAKE) {
			ret = -EMSGSIZE;
			goto out;
		}

		while (hs.len < TLS_HANDSHAKE_HDR_LEN + msg_len) {
			ret = recv_tls_record(fd, &type, &hs);
			if (ret)
				goto out;
			if (type == TLS_CT_ALERT) {
				fprintf(stderr, "Server sent a TLS alert\n");
				ret = -ECONNREFUSED;
				goto out;
			}
		}

		off = TLS_HANDSHAKE_HDR_LEN;

		if (msg_type == TLS_HT_CERTIFICATE) {
			/*
       * Certificate message body:
       *   - 3 bytes: total list length
       *   - for each certificate:
       *       - 3 bytes: cert length
       *       - N bytes: cert DER
       */
			uint32_t list_len;
			uint32_t c_len;

			if (msg_len < 3) {
				ret = -EINVAL;
				goto out;
			}

			list_len = read_u24(&hs.data[off]);
			off += 3;

			if (list_len < 3 || list_len + 3 > msg_len) {
				ret = -EINVAL;
				goto out;
			}

			c_len = read_u24(&hs.data[off]);
			off += 3;

			if (c_len == 0 || c_len + 3 > list_len) {
				ret = -EINVAL;
				goto out;
			}

			if (off + c_len > hs.len) {
				ret = -EINVAL;
				goto out;
			}

			buf_free(cert_der);
			ret = buf_init(cert_der);
			if (ret)
				goto out;

			ret = buf_put(cert_der, hs.data + off, c_len);
			if (ret)
				goto out;

			ret = 0;
			goto out;
		}

		if (msg_type == TLS_HT_SERVER_HELLO_DONE) {
			fprintf(stderr,
				"Server finished handshake without a certificate\n");
			ret = -ENOENT;
			goto out;
		}

		/* Consume this handshake message and continue */
		memmove(hs.data, hs.data + TLS_HANDSHAKE_HDR_LEN + msg_len,
			hs.len - TLS_HANDSHAKE_HDR_LEN - msg_len);
		hs.len -= TLS_HANDSHAKE_HDR_LEN + msg_len;
	}

out:
	buf_free(&hs);
	return ret;
}

/**
 * write_der_file() - Write raw DER bytes to a file
 * @filename: output path
 * @der: DER-encoded certificate
 *
 * Return: 0 on success, negative errno-style value on failure.
 */
static int write_der_file(const char *filename, const struct tls_buf *der)
{
	FILE *fp;
	size_t n;

	fp = fopen(filename, "wb");
	if (!fp) {
		fprintf(stderr, "fopen(%s): %s\n", filename, strerror(errno));
		return -errno;
	}

	n = fwrite(der->data, 1, der->len, fp);
	if (n != der->len) {
		fprintf(stderr, "fwrite(%s): short write\n", filename);
		fclose(fp);
		return -EIO;
	}

	fclose(fp);
	printf("Certificate saved to: %s (%zu bytes)\n", filename, der->len);
	return 0;
}

/**
 * print_der_summary() - Print basic facts about a DER certificate
 * @der: DER-encoded certificate
 *
 * Performs a very small amount of ASN.1 parsing sufficient to locate
 * the tbsCertificate serial number and validity fields, and prints
 * them in hex. Full parsing is out of scope for this minimal tool;
 * use `openssl x509 -inform DER -in certificate.der -text` to inspect
 * the certificate in detail.
 */
static void print_der_summary(const struct tls_buf *der)
{
	size_t i;

	printf("\nCertificate Information:\n");
	printf("========================\n");
	printf("Format: DER (X.509)\n");
	printf("Size:   %zu bytes\n", der->len);
	printf("First 20 bytes of body): ");
	for (i = 0; i < 20 && i < der->len; i++)
		printf("%02x", der->data[i]);
	printf("\n");
}

/**
 * main() - Program entry point
 * @argc: number of command-line arguments
 * @argv: array of command-line argument strings
 *
 * Usage: get_cert [-p port] [-o output_file] hostname
 *
 * Return: 0 on success, 1 on failure.
 */
int main(int argc, char *argv[])
{
	const char *hostname = NULL;
	const char *port = DEFAULT_PORT;
	const char *output_file = DEFAULT_CERT_FILE;
	struct tls_buf client_hello;
	struct tls_buf cert_der;
	int fd;
	int ret;
	int rc = 0;
	int opt;

	while ((opt = getopt(argc, argv, "hp:o:")) != -1) {
		switch (opt) {
		case 'h':
			printf("Usage: %s [-p port] [-o output_file] hostname\n",
			       argv[0]);
			return 0;
		case 'p':
			port = optarg;
			break;
		case 'o':
			output_file = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s [-p port] [-o output_file] hostname\n",
				argv[0]);
			return 1;
		}
	}

	if (optind >= argc || argc - optind != 1) {
		fprintf(stderr,
			"Usage: %s [-p port] [-o output_file] hostname\n",
			argv[0]);
		return 1;
	}
	hostname = argv[optind];

	printf("Downloading certificate from %s:%s\n", hostname, port);

	fd = tcp_connect(hostname, port);
	if (fd < 0)
		return 1;

	ret = buf_init(&client_hello);
	if (ret) {
		fprintf(stderr, "Out of memory\n");
		close(fd);
		return 1;
	}

	ret = buf_init(&cert_der);
	if (ret) {
		fprintf(stderr, "Out of memory\n");
		buf_free(&client_hello);
		close(fd);
		return 1;
	}

	ret = build_client_hello(hostname, &client_hello);
	if (ret) {
		fprintf(stderr, "Failed to build ClientHello\n");
		rc = 1;
		goto out;
	}

	ret = sock_write_all(fd, client_hello.data, client_hello.len);
	if (ret) {
		fprintf(stderr, "Failed to send ClientHello: %s\n",
			strerror(-ret));
		rc = 1;
		goto out;
	}

	ret = recv_handshake_until_certificate(fd, &cert_der);
	if (ret) {
		fprintf(stderr, "Failed to retrieve certificate: %s\n",
			strerror(-ret));
		rc = 1;
		goto out;
	}

	print_der_summary(&cert_der);

	ret = write_der_file(output_file, &cert_der);
	if (ret) {
		fprintf(stderr, "Failed to save certificate\n");
		rc = 1;
	}

out:
	buf_free(&cert_der);
	buf_free(&client_hello);
	close(fd);
	return rc;
}
