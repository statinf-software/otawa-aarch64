/* Generated by gliss-attr ($(date)) copyright (c) 2016 IRIT - UPS */

#include <$(proc)/api.h>
#include <$(proc)/id.h>
#include <$(proc)/macros.h>
#include <$(proc)/grt.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*condition_fun_t)($(proc)_inst_t *inst);

/*** function definition ***/

static int otawa_condition_UNKNOWN($(proc)_inst_t *inst) {
	return 0;
}

$(foreach instructions)
static int otawa_condition_$(IDENT)($(proc)_inst_t *inst) {
	$(otawa_condition)
};

$(end)


/*** function table ***/
static condition_fun_t cond_funs[] = {
	otawa_condition_UNKNOWN$(foreach instructions),
	otawa_condition_$(IDENT)$(end)
};

/**
 * Get the OTAWA condition of the instruction.
 * @return OTAWA condition.
 */
int $(proc)_condition($(proc)_inst_t *inst) {
	return cond_funs[inst->ident](inst);
}

#ifdef __cplusplus
}
#endif
