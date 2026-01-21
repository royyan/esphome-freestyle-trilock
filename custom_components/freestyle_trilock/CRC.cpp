#include "CRC.h"

static uint32_t reflect(uint32_t data, int nBits)
{
    uint32_t reflection = 0x00000000;
    for (int bit = 0; bit < nBits; ++bit)
    {
        if (data & 0x01)
            reflection |= (1 << ((nBits - 1) - bit));
        data = (data >> 1);
    }
    return reflection;
}

uint32_t calcCRC32(const uint8_t *data, uint32_t length,
                   uint32_t polynomial,
                   uint32_t initial,
                   uint32_t final_xor,
                   bool reflect_in, bool reflect_out)
{
    uint32_t crc = initial;
    for (uint32_t i = 0; i < length; i++)
    {
        uint8_t byte = data[i];
        if (reflect_in)
            byte = reflect(byte, 8);
        crc ^= ((uint32_t)byte) << 24;
        for (int j = 0; j < 8; j++)
        {
            if (crc & 0x80000000)
                crc = (crc << 1) ^ polynomial;
            else
                crc = (crc << 1);
        }
    }
    if (reflect_out)
        crc = reflect(crc, 32);
    return (crc ^ final_xor);
}