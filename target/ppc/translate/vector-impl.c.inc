static bool trans_VCFUGED(DisasContext *ctx, arg_VCFUGED *a)
{
    TCGv tgt, src, mask;

    if (unlikely(!ctx->altivec_enabled)) {
        gen_exception(ctx, POWERPC_EXCP_VPU);
        return true;
    }

    tgt = tcg_temp_new();
    src = tcg_temp_new();
    mask = tcg_temp_new();

    // centrifuge lower double word
    get_cpu_vsrl(src, a->vra+32);
    get_cpu_vsrl(mask, a->vrb+32);
    gen_helper_cfuged(tgt, src, mask);
    set_cpu_vsrl(a->vrt+32, tgt);

    // centrifuge higher double word
    get_cpu_vsrh(src, a->vra+32);
    get_cpu_vsrh(mask, a->vrb+32);
    gen_helper_cfuged(tgt, src, mask);
    set_cpu_vsrh(a->vrt+32, tgt);

    tcg_temp_free(tgt);
    tcg_temp_free(src);
    tcg_temp_free(mask);

    return true;
}
