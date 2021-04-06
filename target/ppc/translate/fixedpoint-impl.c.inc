static bool trans_pld(DisasContext *ctx, arg_pld *a)
{
    /* TODO LP: implement */

    return true;
}

static bool trans_pstb(DisasContext *ctx, arg_pstb *a)
{
    /* TODO LP: implement */

    return true;
}

static bool trans_paddi_impl(DisasContext *ctx, arg_paddi *a)
{
    if (a->r == 1) {
        if(a->ra == 0) {
            tcg_gen_movi_tl(cpu_gpr[a->rt], ctx->base.pc_first);
            tcg_gen_addi_tl(cpu_gpr[a->rt], cpu_gpr[a->rt], a->si);
        } else {
            gen_inval_exception(ctx, POWERPC_EXCP_INVAL_INVAL);
        }
    } else if (a->ra == 0) {
        /* li case */
        tcg_gen_movi_tl(cpu_gpr[a->rt], a->si);
    } else {
        tcg_gen_addi_tl(cpu_gpr[a->rt],
                        cpu_gpr[a->ra], a->si);
    }

    return true;
}

static bool trans_paddi(DisasContext *ctx, arg_paddi *a)
{
    return trans_paddi_impl(ctx, a);
}

static bool trans_addi(DisasContext *ctx, arg_addi *a)
{
    return trans_paddi_impl(ctx, (arg_paddi *)a);
}

static bool trans_setbc(DisasContext *ctx, arg_setbc *a)
{
    TCGv tval = tcg_const_tl(a->n?-1:1), fval = tcg_const_tl(0),
         temp = tcg_temp_new();

    tcg_gen_extu_i32_tl(temp, cpu_crf[a->bi/4]);
    tcg_gen_andi_tl(temp, temp, 1<<(a->bi%4));
    tcg_gen_movcond_tl(a->r?TCG_COND_EQ:TCG_COND_NE, cpu_gpr[a->rt], temp, fval, tval, fval);

    tcg_temp_free(tval);
    tcg_temp_free(fval);
    tcg_temp_free(temp);

    return true;
}
