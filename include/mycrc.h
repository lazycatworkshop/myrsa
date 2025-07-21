/**
 * mycrc.h - Header file for CRC functions.
 */

uint16_t crc16_ccitt(const char *data, size_t len);
uint32_t crc32(const char *data, size_t len);