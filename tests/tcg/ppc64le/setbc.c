#include <assert.h>

#define LT 0
#define GT 1
#define EQ 2
#define SO 3
#define CRF_BIT(field, cond) (4*(field)+(cond))

#define CMP_TEST_INSN(insn, field, val, imm, op, exp_res)                       \
    do {                                                                        \
            long int var;                                                       \
            asm(" li   %0, 0                        \n"                         \
                " mtcr %0                           \n"                         \
                " li   %0, %2                       \n"                         \
                " cmpi %1, 1, %0, %3                \n"                         \
                " " insn " %0, %4                   \n"                         \
                : "=r" (var)                                                    \
                : "i" (field), "i" (val), "i" (imm), "i" (CRF_BIT(field, op))   \
                : );                                                            \
            assert(var == exp_res);                                             \
    } while (0)

#define ADD_TEST_INSN(insn, val_a, val_b, exp_res)  \
    do {                                            \
            long int a = val_a, b = val_b;          \
            asm(" li   3, 0       \n"               \
                " mtcr 3          \n"               \
                " addo. %0, %0, %1   \n"            \
                " " insn " %0, %2   \n"             \
                : "+r" (a)                          \
                : "r" (b), "i" (CRF_BIT(0, SO))     \
                : "r3" );                           \
            assert(a == exp_res);                   \
    } while (0)

int main(void)
{
    /* LT */
    CMP_TEST_INSN("setbc",   2, 3, 2, LT, 0);
    CMP_TEST_INSN("setbcr",  2, 3, 2, LT, 1);
    CMP_TEST_INSN("setnbc",  2, 3, 2, LT, 0);
    CMP_TEST_INSN("setnbcr", 2, 3, 2, LT, -1);

    CMP_TEST_INSN("setbc",   2, 2, 3, LT, 1);
    CMP_TEST_INSN("setbcr",  2, 2, 3, LT, 0);
    CMP_TEST_INSN("setnbc",  2, 2, 3, LT, -1);
    CMP_TEST_INSN("setnbcr", 2, 2, 3, LT, 0);

    /* GT */
    CMP_TEST_INSN("setbc",   2, 3, 3, GT, 0);
    CMP_TEST_INSN("setbcr",  2, 3, 3, GT, 1);
    CMP_TEST_INSN("setnbc",  2, 3, 3, GT, 0);
    CMP_TEST_INSN("setnbcr", 2, 3, 3, GT, -1);

    CMP_TEST_INSN("setbc",   2, 3, 2, GT, 1);
    CMP_TEST_INSN("setbcr",  2, 3, 2, GT, 0);
    CMP_TEST_INSN("setnbc",  2, 3, 2, GT, -1);
    CMP_TEST_INSN("setnbcr", 2, 3, 2, GT, 0);

    /* EQ */
    CMP_TEST_INSN("setbc",   2, 2, 3, EQ, 0);
    CMP_TEST_INSN("setbcr",  2, 2, 3, EQ, 1);
    CMP_TEST_INSN("setnbc",  2, 2, 3, EQ, 0);
    CMP_TEST_INSN("setnbcr", 2, 2, 3, EQ, -1);

    CMP_TEST_INSN("setbc",   2, 3, 3, EQ, 1);
    CMP_TEST_INSN("setbcr",  2, 3, 3, EQ, 0);
    CMP_TEST_INSN("setnbc",  2, 3, 3, EQ, -1);
    CMP_TEST_INSN("setnbcr", 2, 3, 3, EQ, 0);

    /* SO */
    ADD_TEST_INSN("setbc",   0x7FFFFFFFFFFFFFFE, 1, 0);
    ADD_TEST_INSN("setbcr",  0x7FFFFFFFFFFFFFFE, 1, 1);
    ADD_TEST_INSN("setnbc",  0x7FFFFFFFFFFFFFFE, 1, 0);
    ADD_TEST_INSN("setnbcr", 0x7FFFFFFFFFFFFFFE, 1, -1);

    ADD_TEST_INSN("setbc",   0x7FFFFFFFFFFFFFFF, 1, 1);
    ADD_TEST_INSN("setbcr",  0x7FFFFFFFFFFFFFFF, 1, 0);
    ADD_TEST_INSN("setnbc",  0x7FFFFFFFFFFFFFFF, 1, -1);
    ADD_TEST_INSN("setnbcr", 0x7FFFFFFFFFFFFFFF, 1, 0);

    return 0;
}
