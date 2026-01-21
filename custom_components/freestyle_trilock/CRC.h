#pragma once
#include <cstdint>

// Standard reflected CRC-32 for the lock protocol
uint32_t calcCRC32(const uint8_t *data, uint32_t length,
                   uint32_t polynomial = 0x04C11DB7,
                   uint32_t initial = 0x00000000,
                   uint32_t final_xor = 0xFFFFFFFF,
                   bool reflect_in = true, bool reflect_out = true);