#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"

#include <vector>
#include <string_view>

#include "macho.h"
#include "types.h"

namespace {

static constexpr int kMinMachOSizeForBlindFuzz = 0x4000;

static constexpr absl::string_view kCorpusPath = "tests/testdata";

TEST(MachOTest, BasicMachOFileParses) {

}

void MachOFuzzWithKnownSize(std::vector<char> buffer) {
  char *buf = reinterpret_cast<char*>(buffer.data());
  xnu::macho::Header64 *header = reinterpret_cast<xnu::macho::Header64*>(buf);
  xnu::mach::VmAddress address = reinterpret_cast<xnu::mach::VmAddress>(header);
  MachO macho(buf, header, address, 0);
}

void MachOFuzzWithUnknownSize(std::vector<char> buffer) {
  MachO macho;
  if (buffer.size() >= kMinMachOSizeForBlindFuzz) {
      macho.InitWithBase(reinterpret_cast<xnu::mach::VmAddress>(buffer.data()), 0);
  }
}

void MachOFuzzWithCorpus(std::string input) {
  std::vector<char> buffer(input.begin(), input.end());
  MachOFuzzWithKnownSize(buffer);
  MachOFuzzWithUnknownSize(buffer);
}


FUZZ_TEST(MachOTest, MachOFuzzWithCorpus)
  .WithSeeds(fuzztest::ReadFilesFromDirectory(
        absl::StrCat(std::getenv("TEST_SRCDIR"), kCorpusPath)));

FUZZ_TEST(MachOTest, MachOFuzzWithKnownSize)
  .WithDomains(fuzztest::Arbitrary<std::vector<char>>());

FUZZ_TEST(MachOTest, MachOFuzzWithUnknownSize)
  .WithDomains(fuzztest::Arbitrary<std::vector<char>>());

}
