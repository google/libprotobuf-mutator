#ifndef SRC_AFLPLUSPLUS_AFLPLUSPLUS_MUTATE_WRAPPER_H_
#define SRC_AFLPLUSPLUS_AFLPLUSPLUS_MUTATE_WRAPPER_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t aflplusplus_mutate_wrapper(void* afl, uint8_t* buf, uint32_t len,
                                    uint32_t steps, int is_text,
                                    int is_exploration, uint8_t* splice_buf,
                                    uint32_t splice_len, uint32_t max_len);

#ifdef __cplusplus
}
#endif

#endif  // SRC_AFLPLUSPLUS_AFLPLUSPLUS_MUTATE_WRAPPER_H_
