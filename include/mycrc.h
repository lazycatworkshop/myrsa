/* mycrc.h - Bitwise CRC-16 (CCITT) and CRC-32 */
#ifndef MYCRC_H
#define MYCRC_H

#include <stddef.h>
#include <stdint.h>

/* CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no final XOR.
 * Check value for "123456789" is 0x29B1.
 */
uint16_t crc16_ccitt(const uint8_t *data, size_t len);

/* CRC-32 (IEEE 802.3, as used by zip/PNG/Ethernet): poly 0x04C11DB7
 * (reflected 0xEDB88320), init 0xFFFFFFFF, reflected, final XOR 0xFFFFFFFF.
 * Check value for "123456789" is 0xCBF43926.
 */
uint32_t crc32(const uint8_t *data, size_t len);

#endif /* MYCRC_H */
