#include "src/aflplusplus/aflplusplus_mutate_wrapper.h"

#include "config.h"
#include "types.h"
#include "afl-fuzz.h"
#include "afl-mutations.h"

uint32_t aflplusplus_mutate_wrapper(void* afl, uint8_t* buf, uint32_t len,
                                    uint32_t steps, int is_text,
                                    int is_exploration, uint8_t* splice_buf,
                                    uint32_t splice_len, uint32_t max_len) {
  return afl_mutate((afl_state_t*)afl, buf, len, steps, is_text, is_exploration,
                    splice_buf, splice_len, max_len);
}
