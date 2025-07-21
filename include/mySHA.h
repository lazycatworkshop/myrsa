/** SHA.h - header file for SHA library
 * Reference:  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */
#ifndef SHA_H
#define SHA_H

#include <stdint.h>

/***** SHA-256 *****/
enum {
	SHA256_BLOCK_SIZE = 512, /* bits */
	SHA256_WORD_SIZE = 32, /* bits */
	SHA256_DIGEST_SIZE = 256, /* bits */
	SHA256_WORD_COUNT = (SHA256_DIGEST_SIZE / SHA256_WORD_SIZE)
};

void SHA256_compute_hash(char msg[], size_t len, uint32_t H[]);

/* SHA-1 */
enum {
	SHA1_BLOCK_SIZE = 512, /* bits */
	SHA1_WORD_SIZE = 32, /* bits */
	SHA1_DIGEST_SIZE = 160, /* bits */
	SHA1_WORD_COUNT = (SHA1_DIGEST_SIZE / SHA1_WORD_SIZE)
};

void SHA1_compute_hash(char msg[], size_t len, uint32_t H[]);
void SHA1_get_digest(uint32_t H[], uint8_t digest[]);

#endif /* SHA_H */