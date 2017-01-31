// Copyright 2017 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <getopt.h>

#include <fstream>
#include <iostream>

#include "src/libfuzzer_protobuf_mutator.h"
#include "src/xml/xml_writer.h"
#include "xml.pb.h"  // NOLINT

using protobuf_mutator::xml::Input;

namespace {
google::protobuf::LogSilencer log_silincer;

struct option const kLongOptions[] = {{"verbose", no_argument, NULL, 'v'},
                                      {"help", no_argument, NULL, 'h'},
                                      {NULL, 0, NULL, 0}};

void PrintUsage() {
  std::cerr << "Usage: proto_to_xml [OPTION]... [INFILE [OUTFILE]]\n"
            << "Converts protobuf used by fuzzer to XML.\n\n"
            << "\t-h, --help\tPrint this help\n"
            << "\t-v, --verbose\tPrint input\n";
}

bool ParseOptions(int argc, char** argv, bool* verbose, std::string* in_file,
                  std::string* out_file) {
  int c = 0;
  while ((c = getopt_long(argc, argv, "hv", kLongOptions, nullptr)) != -1) {
    switch (c) {
      case 'v':
        *verbose = true;
        break;
      case 'h':
      default:
        return false;
    }
  }

  int i = optind;
  if (i < argc) *in_file = argv[i++];
  if (i < argc) *out_file = argv[i++];
  if (i != argc) return false;

  return true;
}

}  // namespace

int main(int argc, char** argv) {
  bool verbose = false;
  std::string in_file;
  std::string out_file;
  if (!ParseOptions(argc, argv, &verbose, &in_file, &out_file)) {
    PrintUsage();
    return 1;
  }

  std::istream* cin = &std::cin;
  std::ostream* cout = &std::cout;

  std::ifstream in_file_stream;
  if (!in_file.empty()) {
    in_file_stream.open(in_file);
    cin = &in_file_stream;
  }

  std::ofstream out_file_stream;
  if (!out_file.empty()) {
    out_file_stream.open(out_file);
    cout = &out_file_stream;
  }

  std::string input;
  std::vector<char> buff(1 << 20);
  while (auto size = cin->readsome(buff.data(), buff.size())) {
    input += std::string(buff.data(), size);
  }
  std::string output;
  Input message;
  bool is_proto = protobuf_mutator::ParseTextMessage(
      reinterpret_cast<const uint8_t*>(input.data()), input.size(), &message);
  if (is_proto) {
    output = MessageToXml(message.document());
    if (verbose) std::cerr << "Input is protobuf:\n";
  } else {
    if (verbose) std::cerr << "Input is not protobuf, assume xml:\n";
    output = input;
  }

  if (verbose) {
    std::cerr << input << "\n\n";
    std::cerr.flush();
  }
  *cout << output;

  return is_proto ? 0 : 2;
}
