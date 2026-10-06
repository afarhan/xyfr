#pragma once
// Fill the kernel config from XYFR_* environment variables. Host only, called
// before kernel_init or before the first mount. See config_env.c.
#ifdef __cplusplus
extern "C" {
#endif
void config_from_env(void);
#ifdef __cplusplus
}
#endif
