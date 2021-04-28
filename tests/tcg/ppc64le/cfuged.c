#include <assert.h>

#define TEST_CFUGED(src, mask, result)                              \
    do {                                                            \
        unsigned long int ra, rs = src, rb = mask;                  \
        asm("cfuged %1, %0, %2" : "=r" (ra) : "r" (rs), "r" (rb));  \
        assert(ra == result);                                       \
    } while (0)

int main(void)
{
    TEST_CFUGED(0x0000A1B2C3D4E5F6, 0x0000FFFFFFFFFFFF, 0x0000A1B2C3D4E5F6);
    TEST_CFUGED(0x0000A1B2C3D4E5F6, 0x0000000000000000, 0x0000A1B2C3D4E5F6);
    TEST_CFUGED(0x0000A1B2C3D4E5F6, 0x0000F0F0F0F0F0F0, 0x0000123456ABCDEF);
    TEST_CFUGED(0x0000A1B2C3D4E5F6, 0x0000383838383838, 0x00008CB7CEFA60A6);
    TEST_CFUGED(0x0000A1B2C3D4E5F6, 0x00007C7C7C7C7C7C, 0x0000BBCB90C8573D);

    TEST_CFUGED(0xA1B2C3D4E5F60000, 0xFFFFFFFFFFFF0000, 0x0000A1B2C3D4E5F6);
    TEST_CFUGED(0xA1B2C3D4E5F60000, 0x0000000000000000, 0xA1B2C3D4E5F60000);
    TEST_CFUGED(0xA1B2C3D4E5F60000, 0xF0F0F0F0F0F00000, 0x1234560000ABCDEF);
    TEST_CFUGED(0xA1B2C3D4E5F60000, 0x3838383838380000, 0x8CB7CEF8000260A6);
    TEST_CFUGED(0xA1B2C3D4E5F60000, 0x7C7C7C7C7C7C0000, 0xBBCB800010C8573D);

    TEST_CFUGED(0xA1B2C3D4E5F6A7B9, 0xFFFFFFFFFFFFFFFF, 0xA1B2C3D4E5F6A7B9);
    TEST_CFUGED(0xA1B2C3D4E5F6A7B9, 0x0000000000000000, 0xA1B2C3D4E5F6A7B9);
    TEST_CFUGED(0xA1B2C3D4E5F6A7B9, 0xF0F0F0F0F0F0F0F0, 0x12345679ABCDEFAB);
    TEST_CFUGED(0xA1B2C3D4E5F6A7B9, 0x3838383838383838, 0x8CB7CEFAF19829A7);
    TEST_CFUGED(0xA1B2C3D4E5F6A7B9, 0x7C7C7C7C7C7C7C7C, 0xBBCBBD43215CF52E);

    return 0;
}
