#ifndef SRC_AFLPLUSPLUS_AFLPLUSPLUS_MUTATOR_H_
#define SRC_AFLPLUSPLUS_AFLPLUSPLUS_MUTATOR_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>

#include "port/protobuf.h"
#include "src/mutator.h"

namespace protobuf_mutator {
namespace aflplusplus {

class Mutator : public protobuf_mutator::Mutator {
 public:
  static Mutator* Create(void* afl_state, unsigned int seed, bool binary);

  Mutator(void* afl_state, bool binary);
  ~Mutator() override;

  size_t Fuzz(const uint8_t* buf, size_t buf_size, uint8_t** out_buf,
              const uint8_t* add_buf, size_t add_buf_size, size_t max_size,
              protobuf::Message* input1, protobuf::Message* input2);


  int InitTrim(const uint8_t* buf, size_t buf_size, protobuf::Message* scratch);
  size_t Trim(uint8_t** out_buf);
  int PostTrim(bool success);

  int64_t GetRandom(size_t min, size_t max);

 protected:
  int32_t MutateInt32(int32_t value) override;
  int64_t MutateInt64(int64_t value) override;
  uint32_t MutateUInt32(uint32_t value) override;
  uint64_t MutateUInt64(uint64_t value) override;
  float MutateFloat(float value) override;
  double MutateDouble(double value) override;
  std::string MutateString(const std::string& value,
                           int size_increase_hint) override;

 private:
  bool Reserve(size_t size);
  size_t CopyToTrimBuffer(const std::string& data, uint8_t** out_buf);
  bool BuildDropCandidate();
  bool BuildShrinkCandidate();

  void* afl_ = nullptr;
  bool binary_ = false;
  uint8_t* out_buf_ = nullptr;
  uint8_t* trim_buf_ = nullptr;

  std::unique_ptr<protobuf::Message> trim_message_;
  std::unique_ptr<protobuf::Message> trim_candidate_;
  std::string trim_serialized_;
  std::string trim_candidate_serialized_;
  size_t trim_index_ = 0;
  size_t trim_steps_ = 0;
  size_t trim_progress_ = 0;
  size_t trim_give_up_ = 0;
  bool trim_had_success_ = false;
  bool trim_exhausted_ = false;
  bool shrinking_ = false;
  size_t shrink_index_ = 0;
  size_t shrink_remove_len_ = 0;
  size_t shrink_min_len_ = 0;
  size_t shrink_remove_pos_ = 0;
};

}  // namespace aflplusplus
}  // namespace protobuf_mutator

#endif  // SRC_AFLPLUSPLUS_AFLPLUSPLUS_MUTATOR_H_
