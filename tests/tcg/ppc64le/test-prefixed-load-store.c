#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define PST_CALL(op, RS, RA, D, R)      \
    do {                                \
        asm(" " op " %1,%2(%0),%3"      \
        : "+r" (RA)                     \
        : "r" (RS), "i" (D), "i" (R));  \
    } while(0)

#define PL_CALL(op, RA, RT, D, R)           \
    do {                                    \
        asm(" " op " %0,%2(%1),%3"          \
            : "+r" (RT)                     \
            : "r" (RA), "i" (D), "i" (R));  \
    } while (0)

void check_pst(uint64_t src, uint64_t dest, uint64_t dest_orig, int width) {
    uint64_t dest_orig_mask;
    uint64_t src_mask = (width == 8) ? -1UL : (1UL << (8*width)) - 1;

#if LE
    dest_orig_mask = -1UL << (8*width);
    assert(dest == ((dest_orig & dest_orig_mask) | ((src & src_mask))));
#else
    dest_orig_mask = (-1UL << (8*width)) >> (8*width);
    assert(dest == ((dest_orig & dest_orig_mask) | ((src & src_mask) << (8*(8-width)))));
#endif
}

void test_pst_offset(int width) {
    uint64_t dest_orig = 0x2726252423222120;
    uint64_t src = 0x1716151413111110;
    uint64_t dest = dest_orig;
    void *dest_ptr, *dest_ptr_offset;

    dest_ptr = &dest;

    switch (width) {
    case 1:
        dest_ptr_offset = dest_ptr - 1;
        PST_CALL("pstb", src, dest_ptr_offset, 1, 0);
        check_pst(src, dest, dest_orig, width);
        dest_ptr_offset = dest_ptr - 0xFFFF;
        PST_CALL("pstb", src, dest_ptr_offset, 0x0FFFF, 0);
        check_pst(src, dest, dest_orig, width);
        dest_ptr_offset = dest_ptr + 1;
        PST_CALL("pstb", src, dest_ptr_offset, -1, 0);
        check_pst(src, dest, dest_orig, width);
        dest_ptr_offset = dest_ptr - 0x1FFFFFFFF;
        PST_CALL("pstb", src, dest_ptr_offset, 0x1FFFFFFFF, 0);
        check_pst(src, dest, dest_orig, width);
        break;
    case 2:
        dest_ptr_offset = dest_ptr - 1;
        PST_CALL("psth", src, dest_ptr_offset, 1, 0);
        check_pst(src, dest, dest_orig, width);
        dest_ptr_offset = dest_ptr - 0xFFFF;
        PST_CALL("psth", src, dest_ptr_offset, 0x0FFFF, 0);
        check_pst(src, dest, dest_orig, width);
        dest_ptr_offset = dest_ptr + 1;
        PST_CALL("psth", src, dest_ptr_offset, -1, 0);
        check_pst(src, dest, dest_orig, width);
        dest_ptr_offset = dest_ptr - 0x1FFFFFFFF;
        PST_CALL("psth", src, dest_ptr_offset, 0x1FFFFFFFF, 0);
        check_pst(src, dest, dest_orig, width);
        break;
    case 4:
        dest_ptr_offset = dest_ptr - 1;
        PST_CALL("pstw", src, dest_ptr_offset, 1, 0);
        check_pst(src, dest, dest_orig, width);
        dest_ptr_offset = dest_ptr - 0xFFFF;
        PST_CALL("pstw", src, dest_ptr_offset, 0x0FFFF, 0);
        check_pst(src, dest, dest_orig, width);
        dest_ptr_offset = dest_ptr + 1;
        PST_CALL("pstw", src, dest_ptr_offset, -1, 0);
        check_pst(src, dest, dest_orig, width);
        dest_ptr_offset = dest_ptr - 0x1FFFFFFFF;
        PST_CALL("pstw", src, dest_ptr_offset, 0x1FFFFFFFF, 0);
        check_pst(src, dest, dest_orig, width);
        break;
    case 8:
        dest_ptr_offset = dest_ptr - 1;
        PST_CALL("pstd", src, dest_ptr_offset, 1, 0);
        check_pst(src, dest, dest_orig, width);
        dest_ptr_offset = dest_ptr - 0xFFFF;
        PST_CALL("pstd", src, dest_ptr_offset, 0x0FFFF, 0);
        check_pst(src, dest, dest_orig, width);
        dest_ptr_offset = dest_ptr + 1;
        PST_CALL("pstd", src, dest_ptr_offset, -1, 0);
        check_pst(src, dest, dest_orig, width);
        dest_ptr_offset = dest_ptr - 0x1FFFFFFFF;
        PST_CALL("pstd", src, dest_ptr_offset, 0x1FFFFFFFF, 0);
        check_pst(src, dest, dest_orig, width);
        break;
    default:
        assert(false);
    }
}

void test_pst(int width) {
    uint64_t dest_orig = 0x2726252423222120;
    uint64_t src = 0x1716151413111110;
    uint64_t dest, dest_copy;
    void *dest_ptr = &dest;
    void *dest_copy_ptr = &dest_copy;

    /* sanity check against non-prefixed ops */
    dest_copy = dest_orig;
    switch (width) {
    case 1:
        asm(
            "stb %1, 0(%0)"
            : "+r" (dest_copy_ptr)
            : "r" (src));
        break;
    case 2:
        asm(
            "sth %1, 0(%0)"
            : "+r" (dest_copy_ptr)
            : "r" (src));
        break;
    case 4:
        asm(
            "stw %1, 0(%0)"
            : "+r" (dest_copy_ptr)
            : "r" (src));
        break;
    case 8:
        asm(
            "std %1, 0(%0)"
            : "+r" (dest_copy_ptr)
            : "r" (src));
        break;
    default:
        assert(false);
    }

    dest = dest_orig;
    switch (width) {
    case 1:
        PST_CALL("pstb", src, dest_ptr, 0, 0);
        break;
    case 2:
        PST_CALL("psth", src, dest_ptr, 0, 0);
        break;
    case 4:
        PST_CALL("pstw", src, dest_ptr, 0, 0);
        break;
    case 8:
        PST_CALL("pstd", src, dest_ptr, 0, 0);
        break;
    default:
        assert(false);
    }

    assert(dest == dest_copy);
    check_pst(src, dest, dest_orig, width);
}

void test_pstb(void) {
    test_pst(1);
    test_pst_offset(1);
}

void test_psth(void) {
    test_pst(2);
    test_pst_offset(2);
}

void test_pstw(void) {
    test_pst(4);
    test_pst_offset(4);
}

void test_pstd(void) {
    test_pst(8);
    test_pst_offset(8);
}

void check_pl_z(uint64_t src, uint64_t dest, int width) {
    uint64_t src_mask;

#if LE
    src_mask = (width == 8) ? -1UL : (1UL << (8*width)) - 1;
    assert(dest == (src & src_mask));
#else
    src_mask = (width == 8) ? -1UL : -1UL << (8*(8-width));
    assert(dest == (src & src_mask) >> (8*(8-width)));
#endif
}

void check_pl_a(uint64_t src, uint64_t dest, int width) {
    uint64_t src_mask, sign_mask;

    /* TODO: docs suggest testing high-order bit of src byte/halfword/etc, but
     * QEMU seems to use high-order bit of src double in every case?
     *
     * but for le, it's based on the former? afa qemu goes???
     */
#if LE
    sign_mask = (src & (1UL << (width*8-1))) ? -1UL << (8*width) : 0;
    src_mask = (width == 8) ? -1UL : (1UL << (8*width)) - 1;
    assert(dest == ((src & src_mask) | sign_mask));
#else
    sign_mask = (src & (1UL << 63)) ? -1UL << (8*width) : 0;
    src_mask = (width == 8) ? -1UL : -1UL << (8*(8-width));
    assert(dest == (((src & src_mask) >> (8*(8-width))) | sign_mask));
#endif
}

void test_pl_a(int width, uint64_t src, uint64_t dest_orig) {
    uint64_t dest = 0, dest_copy;
    void *src_ptr = &src;
    void *src_ptr_offset;

    /* sanity check against non-prefixed ops */
    dest_copy = dest_orig;

    switch (width) {
    case 2:
        asm(
            "lha %0, 0(%2)"
            : "+r" (dest_copy)
            : "r" (src), "r" (src_ptr));
        break;
    case 4:
        asm(
            "lwa %0, 0(%2)"
            : "+r" (dest_copy)
            : "r" (src), "r" (src_ptr));
        break;
    case 8:
        asm(
            "ld %0, 0(%2)"
            : "+r" (dest_copy)
            : "r" (src), "r" (src_ptr));
        break;
    default:
        assert(false);
    }

    switch (width) {
    case 2:
        dest = dest_orig;
        src_ptr_offset = src_ptr;
        PL_CALL("plha", src_ptr_offset, dest, 0, 0);
        check_pl_a(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 1;
        PL_CALL("plha", src_ptr_offset, dest, 1, 0);
        check_pl_a(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0xFFFF;
        PL_CALL("plha", src_ptr_offset, dest, 0x0FFFF, 0);
        check_pl_a(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr + 1;
        PL_CALL("plha", src_ptr_offset, dest, -1, 0);
        check_pl_a(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0x1FFFFFFFF;
        PL_CALL("plha", src_ptr_offset, dest, 0x1FFFFFFFF, 0);
        check_pl_a(src, dest, width);
        break;
    case 4:
        dest = dest_orig;
        src_ptr_offset = src_ptr;
        PL_CALL("plwa", src_ptr_offset, dest, 0, 0);
        check_pl_a(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 1;
        PL_CALL("plwa", src_ptr_offset, dest, 1, 0);
        check_pl_a(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0xFFFF;
        PL_CALL("plwa", src_ptr_offset, dest, 0x0FFFF, 0);
        check_pl_a(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr + 1;
        PL_CALL("plwa", src_ptr_offset, dest, -1, 0);
        check_pl_a(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0x1FFFFFFFF;
        PL_CALL("plwa", src_ptr_offset, dest, 0x1FFFFFFFF, 0);
        check_pl_a(src, dest, width);
        break;
    case 8:
        dest = dest_orig;
        src_ptr_offset = src_ptr;
        PL_CALL("pld", src_ptr_offset, dest, 0, 0);
        check_pl_a(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 1;
        PL_CALL("pld", src_ptr_offset, dest, 1, 0);
        check_pl_a(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0xFFFF;
        PL_CALL("pld", src_ptr_offset, dest, 0x0FFFF, 0);
        check_pl_a(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr + 1;
        PL_CALL("pld", src_ptr_offset, dest, -1, 0);
        check_pl_a(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0x1FFFFFFFF;
        PL_CALL("pld", src_ptr_offset, dest, 0x1FFFFFFFF, 0);
        check_pl_a(src, dest, width);
        break;
    default:
        assert(false);
    }

    assert(dest == dest_copy);
}

void test_pl_z(int width, uint64_t src, uint64_t dest_orig) {
    uint64_t dest = 0, dest_copy;
    void *src_ptr = &src;
    void *src_ptr_offset;

    /* sanity check against non-prefixed ops */
    dest_copy = dest_orig;

    switch (width) {
    case 1:
        asm(
            "lbz %0, 0(%2)"
            : "+r" (dest_copy)
            : "r" (src), "r" (src_ptr));
        break;
    case 2:
        asm(
            "lhz %0, 0(%2)"
            : "+r" (dest_copy)
            : "r" (src), "r" (src_ptr));
        break;
    case 4:
        asm(
            "lwz %0, 0(%2)"
            : "+r" (dest_copy)
            : "r" (src), "r" (src_ptr));
        break;
    case 8:
        asm(
            "ld %0, 0(%2)"
            : "+r" (dest_copy)
            : "r" (src), "r" (src_ptr));
        break;
    default:
        assert(false);
    }

    dest = dest_orig;
    switch (width) {
    case 1:
        dest = dest_orig;
        src_ptr_offset = src_ptr;
        PL_CALL("plbz", src_ptr_offset, dest, 0, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 1;
        PL_CALL("plbz", src_ptr_offset, dest, 1, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0xFFFF;
        PL_CALL("plbz", src_ptr_offset, dest, 0x0FFFF, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr + 1;
        PL_CALL("plbz", src_ptr_offset, dest, -1, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0x1FFFFFFFF;
        PL_CALL("plbz", src_ptr_offset, dest, 0x1FFFFFFFF, 0);
        check_pl_z(src, dest, width);
        break;
    case 2:
        dest = dest_orig;
        src_ptr_offset = src_ptr;
        PL_CALL("plhz", src_ptr_offset, dest, 0, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 1;
        PL_CALL("plhz", src_ptr_offset, dest, 1, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0xFFFF;
        PL_CALL("plhz", src_ptr_offset, dest, 0x0FFFF, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr + 1;
        PL_CALL("plhz", src_ptr_offset, dest, -1, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0x1FFFFFFFF;
        PL_CALL("plhz", src_ptr_offset, dest, 0x1FFFFFFFF, 0);
        check_pl_z(src, dest, width);
        break;
    case 4:
        dest = dest_orig;
        src_ptr_offset = src_ptr;
        PL_CALL("plwz", src_ptr_offset, dest, 0, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 1;
        PL_CALL("plwz", src_ptr_offset, dest, 1, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0xFFFF;
        PL_CALL("plwz", src_ptr_offset, dest, 0x0FFFF, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr + 1;
        PL_CALL("plwz", src_ptr_offset, dest, -1, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0x1FFFFFFFF;
        PL_CALL("plwz", src_ptr_offset, dest, 0x1FFFFFFFF, 0);
        check_pl_z(src, dest, width);
        break;
    case 8:
        dest = dest_orig;
        src_ptr_offset = src_ptr;
        PL_CALL("pld", src_ptr_offset, dest, 0, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 1;
        PL_CALL("pld", src_ptr_offset, dest, 1, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0xFFFF;
        PL_CALL("pld", src_ptr_offset, dest, 0x0FFFF, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr + 1;
        PL_CALL("pld", src_ptr_offset, dest, -1, 0);
        check_pl_z(src, dest, width);
        dest = dest_orig;
        src_ptr_offset = src_ptr - 0x1FFFFFFFF;
        PL_CALL("pld", src_ptr_offset, dest, 0x1FFFFFFFF, 0);
        check_pl_z(src, dest, width);
        break;
    default:
        assert(false);
    }

    assert(dest == dest_copy);
}

void test_plbz(void) {
    test_pl_z(1, 0x8716151413111110, 0x0726252423222120);
    test_pl_z(1, 0x1716151413111110, 0x0726252423222120);
    test_pl_z(1, 0x1716151413111180, 0x0726252423222120);
}

void test_plhz(void) {
    test_pl_z(2, 0x8716151483111110, 0x0726252423222120);
    test_pl_z(1, 0x1716151413111110, 0x0726252423222120);
    test_pl_z(1, 0x1716151413118110, 0x0726252423222120);
}

void test_plha(void) {
    test_pl_a(2, 0x8716151483111110, 0x0726252423222120);
    test_pl_a(2, 0x1716151413111110, 0x0726252423222120);
    test_pl_a(2, 0x1716151413118110, 0x0726252423222120);
}

void test_plwz(void) {
    test_pl_z(4, 0x8716151483111110, 0x0726252423222120);
    test_pl_z(4, 0x1716151413111110, 0x0726252423222120);
    test_pl_z(4, 0x1716151483111110, 0x0726252423222120);
}

void test_plwa(void) {
    test_pl_a(4, 0x8716151483111110, 0x0726252423222120);
    test_pl_a(4, 0x1716151413111110, 0x0726252423222120);
    test_pl_a(4, 0x1716151483111110, 0x0726252423222120);
}

void test_pld(void) {
    test_pl_a(8, 0x8716151483111110, 0x0726252423222120);
    test_pl_a(8, 0x1716151413111110, 0x0726252423222120);
}

#define QUADWORD_HI 0x0f0e0d0c0b0a0908
#define QUADWORD_LO 0x0706050403020100

void test_pstq(void) {
    register uint64_t rs0 asm("r22");
    register uint64_t rs1 asm("r23");
    uint64_t storage[2] = { 0 };
    void *src_ptr = storage;

#if LE
    /*
     * MEM(EA, 16) <- RSp+1||RSp
     * where RQ[15..0] = RSp+1||RSp = rs1[7..0] || rs0[7..0]
     */
    rs0 = QUADWORD_LO;
    rs1 = QUADWORD_HI;
#else
    /*
     * MEM(EA, 16) <- RSp||RSp+1
     * where RQ[0..15] = RSp||RSp+1 = rs0[0..7] || rs1[0..7]
     */
    rs0 = QUADWORD_HI;
    rs1 = QUADWORD_LO;
#endif

    asm("pstq 22, 0(%0)"
        : "+r" (src_ptr)
        : "r" (rs0), "r" (rs1));

#if LE
    assert(storage[0] == QUADWORD_LO);
    assert(storage[1] == QUADWORD_HI);
#else
    assert(storage[0] == QUADWORD_HI);
    assert(storage[1] == QUADWORD_LO);
#endif

    /* sanity check against stq */
    asm(
        "stq 22, 0(%0)"
        : "+r" (src_ptr)
        : "r" (rs0), "r" (rs1));

#if LE
    assert(storage[0] == QUADWORD_HI);
    assert(storage[1] == QUADWORD_LO);
#else
    assert(storage[0] == QUADWORD_HI);
    assert(storage[1] == QUADWORD_LO);
#endif
}

void test_plq(void) {
    register uint64_t rdest0 asm("r20") = 7;
    register uint64_t rdest1 asm("r21") = 8;
    uint64_t dest0a = 7;
    uint64_t dest0b = 7;
    uint64_t dest1a = 7;
    uint64_t dest1b = 7;
    uint8_t src[16];
    void *src_ptr = &src;
    int i;

    for (i = 0; i < 16; i++) {
        src[i] = i;
    }

    /*
     * PLQ:
     *
     * loads to RTp+1||RTp for little-endian
     *          RTp||RTp+1 for big-endian
     *
     * so we'd expect:
     *
     * value: 0x0f0e..08 || 0706..00
     *
     * little-endian:
     *
     * uint64_t storage[2] = { 0x0706050403020100,
     *                         0x0f0e0d0c0b0a0908 };
     * plq 20,0(storage):
     *   r21[0..7]         || r20[0..7]
     *   0x0001020304050607   0x08090a0b0c0d0e0f
     *
     * big-endian:
     *
     * uint64_t storage[2] = { 0x0f0e0d0c0b0a0908,
     *                         0x0706050403020100 };
     *
     * plq 20,0(storage):
     *   r20[0..7]         || r21[0..7]
     *   0x0f0e0d0c0b0a0908   0x0706050403020100
     *
     * Note: According to spec, for GPRs at least, GPR byte ordering is always
     * big-endian with regard to loads/stores. Hence the need to "reverse load"
     * in the case of loading little-endian value into a register, as opposed to
     * simply assuming both the storage and the register would both use
     * host-endian.
     *
     * But, this is just as far as the documentation goes, which is always
     * left-to-right/big-endian byte ordering. The actual hardware register
     * stores byte 0 in a little-endian to value to byte 0 in the register, so
     * registers are loaded host-endian even though the documentation sort of
     * suggests otherwise in some cases.
     */
    asm("plq 20, 0(%2)"
        : "=r" (rdest0), "=r" (rdest1)
        : "r" (src_ptr));

    dest0a = rdest0;
    dest1a = rdest1;

    /* loads to dest0||dest1 for both endians */
    asm(
        "lq 20, 0(%2)"
        : "=r" (rdest0), "=r" (rdest1)
        : "r" (src_ptr));

    dest0b = rdest0;
    dest1b = rdest1;

        assert(dest0a == ((uint64_t*)src)[0]);
        assert(dest1a == ((uint64_t*)src)[1]);
#if LE
        assert(dest0a == dest1b);
        assert(dest1a == dest0b);
#else
        assert(dest0a == dest0b);
        assert(dest1a == dest1b);
#endif

    /* TODO: PC-relative and negative offsets just like all the others */
}

void test_plq2(void) {
    register uint64_t rdest0 asm("r20") = 7;
    register uint64_t rdest1 asm("r21") = 8;
    register uint64_t rdest0b asm("r22") = 7;
    register uint64_t rdest1b asm("r23") = 8;
    uint64_t storage[2];
    void *src_ptr = storage;

#if LE
        storage[0] = QUADWORD_LO;
        storage[1] = QUADWORD_HI;
#else
        storage[0] = QUADWORD_HI;
        storage[1] = QUADWORD_LO;
#endif

    /*
     * PLQ:
     *
     * loads to RTp+1||RTp for little-endian
     *          RTp||RTp+1 for big-endian
     *
     * loads into register using host-endian encoding
     * calls it "reverse-order" for little-endian, but
     * the byte-ordering is switched based on endianess
     * so we still copy mem[0] to reg[0], etc., in all
     * cases. i.e. storage endian encoding is maintained
     * in the register encoding after load, even though
     * documentation might still call it reverse and
     * reference left-to-right byte ordering in some
     * cases even for little-endian
     *
     * so we'd expect:
     *
     * value: 0x0f0e..08 || 0706..00
     *
     * little-endian:
     *
     * uint64_t storage[2] = { 0x0706050403020100,
     *                         0x0f0e0d0c0b0a0908 };
     * plq 20,0(storage):
     *   RTquad[15..0] = r21[7..0] || r20[7..0]
     *   r21[7..0]         || r20[7..0]
     *   0x0f0e0d0c0b0a0908   0x0706050403020100
     *
     * big-endian:
     *
     * uint64_t storage[2] = { 0x0f0e0d0c0b0a0908,
     *                         0x0706050403020100 };
     *
     * plq 20,0(storage):
     *   RTquad[0..15] = r20[0..7] || r21[0..7]
     *   r20[0..7]         || r21[0..7]
     *   0x0f0e0d0c0b0a0908   0x0706050403020100
     **/
    asm("plq 20, 0(%2)"
        : "=r" (rdest0), "=r" (rdest1)
        : "r" (src_ptr));

#if LE
        assert(rdest0 == QUADWORD_LO);
        assert(rdest1 == QUADWORD_HI);
#else
        assert(rdest0 == QUADWORD_HI);
        assert(rdest1 == QUADWORD_LO);
#endif

    /* sanity check against lq */
    asm(
        "lq 22, 0(%2)"
        : "=r" (rdest0b), "=r" (rdest1b)
        : "r" (src_ptr));

#if LE
        assert(rdest0 == rdest1b);
        assert(rdest1 == rdest0b);
#else
        assert(rdest0 == rdest0b);
        assert(rdest1 == rdest1b);
#endif
}

void test_plbz_cia(void) {
    uint64_t dest = 0;

    asm(
        "plbz %0, 8+4\n" /* skip plbz + skip b */
        "b 1f\n"
        ".byte 0x1a\n"
        ".byte 0x1b\n"
        ".byte 0x1c\n"
        ".byte 0x1d\n"
        "1: nop\n"
        : "+r" (dest));

    assert(dest == 0x1a);
}

void test_plhz_cia(void) {
    uint64_t dest = 0;

    asm(
        "plhz %0, 8+4\n" /* skip plhz + skip b */
        "b 1f\n"
        ".byte 0x1a\n"
        ".byte 0x1b\n"
        ".byte 0x1c\n"
        ".byte 0x1d\n"
        "1: nop\n"
        : "+r" (dest));

#if LE
        assert(dest == 0x1b1a);
#else
        assert(dest == 0x1a1b);
#endif
}

void test_plha_cia(void) {
    uint64_t dest = 0;

    asm(
        "plha %0, 8+4\n" /* skip plha + skip b */
        "b 1f\n"
        ".byte 0x8a\n"
        ".byte 0x8b\n"
        ".byte 0x1c\n"
        ".byte 0x1d\n"
        ".byte 0x2a\n"
        ".byte 0x2b\n"
        ".byte 0x2c\n"
        ".byte 0x2d\n"
        "1: nop\n"
        : "+r" (dest));

#if LE
        assert(dest == 0xFFFFFFFFFFFF8b8a);
#else
        assert(dest == 0xFFFFFFFFFFFF8a8b);
#endif
}

void test_plwz_cia(void) {
    uint64_t dest = 0;

    asm(
        "plwz %0, 8+4\n" /* skip plwz + skip b */
        "b 1f\n"
        ".byte 0x1a\n"
        ".byte 0x1b\n"
        ".byte 0x1c\n"
        ".byte 0x1d\n"
        "1: nop\n"
        : "+r" (dest));

#if LE
        assert(dest == 0x1d1c1b1a);
#else
        assert(dest == 0x1a1b1c1d);
#endif
}

void test_plwa_cia(void) {
    uint64_t dest = 0;

    asm(
        "plwa %0, 8+4\n" /* skip plwa + skip b */
        "b 1f\n"
        ".byte 0x8a\n"
        ".byte 0x1b\n"
        ".byte 0x1c\n"
        ".byte 0x8d\n"
        ".byte 0x2a\n"
        ".byte 0x2b\n"
        ".byte 0x2c\n"
        ".byte 0x2d\n"
        "1: nop\n"
        : "+r" (dest));

#if LE
        assert(dest == 0xFFFFFFFF8d1c1b8a);
#else
        assert(dest == 0xFFFFFFFF8a1b1c8d);
#endif
}

void test_pld_cia(void) {
    uint64_t dest = 0;

    asm(
        "pld %0, 8+4\n" /* skip pld + skip b */
        "b 1f\n"
        ".byte 0x1a\n"
        ".byte 0x1b\n"
        ".byte 0x1c\n"
        ".byte 0x1d\n"
        ".byte 0x2a\n"
        ".byte 0x2b\n"
        ".byte 0x2c\n"
        ".byte 0x2d\n"
        "1: nop\n"
        : "+r" (dest));

#if LE
        assert(dest == 0x2d2c2b2a1d1c1b1a);
#else
        assert(dest == 0x1a1b1c1d2a2b2c2d);
#endif
}

int main(int argc, char **argv)
{
    test_pstb();
    test_psth();
    test_pstw();
    test_pstd();
    test_plbz();
    test_plhz();
    test_plha();
    test_psth();
    test_pld();

//    test_pstq();
//    test_plq();
//    test_plq2();

    test_plbz_cia();
    test_plhz_cia();
    test_plha_cia();
    test_plwz_cia();
    test_plwa_cia();
    test_pld_cia();

    return 0;
}
