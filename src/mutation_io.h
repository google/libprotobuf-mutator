#ifndef SRC_MUTATION_IO_H_
#define SRC_MUTATION_IO_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include "port/protobuf.h"
#include "src/mutator.h"

namespace protobuf_mutator {

class InputReader {
 public:
  InputReader(const uint8_t* data, size_t size) : data_(data), size_(size) {}
  virtual ~InputReader() = default;

  virtual bool Read(protobuf::Message* message) const = 0;

  const uint8_t* data() const { return data_; }
  size_t size() const { return size_; }

 private:
  const uint8_t* data_;
  size_t size_;
};

class OutputWriter {
 public:
  OutputWriter(uint8_t* data, size_t size) : data_(data), size_(size) {}
  virtual ~OutputWriter() = default;

  virtual size_t Write(const protobuf::Message& message) = 0;

  uint8_t* data() const { return data_; }
  size_t size() const { return size_; }

 private:
  uint8_t* data_;
  size_t size_;
};

class TextInputReader : public InputReader {
 public:
  using InputReader::InputReader;
  bool Read(protobuf::Message* message) const override;
};

class TextOutputWriter : public OutputWriter {
 public:
  using OutputWriter::OutputWriter;
  size_t Write(const protobuf::Message& message) override;
};

class BinaryInputReader : public InputReader {
 public:
  using InputReader::InputReader;
  bool Read(protobuf::Message* message) const override;
};

class BinaryOutputWriter : public OutputWriter {
 public:
  using OutputWriter::OutputWriter;
  size_t Write(const protobuf::Message& message) override;
};

class LastMutationCache {
 public:
  void Store(const uint8_t* data, size_t size, protobuf::Message* message);
  bool LoadIfSame(const uint8_t* data, size_t size, protobuf::Message* message);

 private:
  std::vector<uint8_t> data_;
  std::unique_ptr<protobuf::Message> message_;
};

LastMutationCache* GetCache();

size_t GetMaxSize(const InputReader& input, const OutputWriter& output,
                  const protobuf::Message& message);

size_t MutateMessage(bool binary, Mutator* mutator, uint8_t* data, size_t size,
                     size_t max_size, protobuf::Message* message);
size_t CrossOverMessages(bool binary, Mutator* mutator, const uint8_t* data1,
                         size_t size1, const uint8_t* data2, size_t size2,
                         uint8_t* out, size_t max_out_size,
                         protobuf::Message* message1,
                         protobuf::Message* message2);

bool LoadProtoInput(bool binary, const uint8_t* data, size_t size,
                    Mutator* mutator, protobuf::Message* input);

bool ParseMessage(bool binary, const uint8_t* data, size_t size,
                  protobuf::Message* message);
std::string SaveMessage(bool binary, const protobuf::Message& message);

namespace macro_internal {

template <typename T>
struct GetFirstParam;

template <class Arg>
struct GetFirstParam<void (*)(Arg)> {
  using type = typename std::remove_const<
      typename std::remove_reference<Arg>::type>::type;
};

}  // namespace macro_internal

}  // namespace protobuf_mutator

#endif  // SRC_MUTATION_IO_H_
