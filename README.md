# libprotobuf-mutator

## Overview
libprotobuf-mutator is the library to randomly mutate protobuffers. 
The main purpose of this library is to use is together with guided
fuzzing engines, such as [libFuzzer](http://libfuzzer.info).

## Quick start on Debian/Ubuntu

Install prerequisites:

```
sudo apt-get update
sudo apt-get install binutils cmake ninja-build
```

Compile and test everything:

```
mkdir build
cd build
cmake ../cmake/ -GNinja -DCMAKE_BUILD_TYPE=Debug
ninja check
```

Compile only the library:

```
ninja libprotobuf-mutator.a
```

## Integration with another project

### Linking

You can either link libprotobuf-mutator.a or just include sources into your own
build files.

### Redefining ProtobufMutator methods

Class implements very basic mutations of fields. E.g. it just flips bits for
integers, floats and strings. Also it increases, decreases size of strings only
by one. For better results users should override ProtobufMutator::Mutate*
methods with more useful logic, e.g. using library like libFuzzer.

### Mutating protobuffers

Assuming that class which redefines ProtobufMutator methods is MyProtobufMutator
come may looks like following:

```
void Mutate(MyMessage* message) {
  MyProtobufMutator mutator(my_random_seed);
  mutator.Mutate(message, 100, 200);
}
```

Another example is ProtobufMutatorMessagesTest.UsageExample test from
[protobuf_mutator_test.cc](/protobuf_mutator_test.cc).

