/* pem_der.h - Header for PEM to DER conversion functions */
#ifndef PEM_DER_H
#define PEM_DER_H
#include <stddef.h> /* for size_t */

#define MAX_PEM_LINE_LENGTH 1024
#define MAX_DER_BUFFER_SIZE 64

int pem2der(const char *pem, uint8_t der[], size_t *der_len);

#endif /* PEM_DER_H */