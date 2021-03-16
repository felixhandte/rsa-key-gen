
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <iostream>

#include <openssl/sha.h>


void set_timestamp(std::string& packet, const uint32_t timestamp) {
  packet[4] = timestamp >> 24;
  packet[5] = (timestamp >> 16) & 0xFF;
  packet[6] = (timestamp >> 8) & 0xFF;
  packet[7] = timestamp & 0xFF;
}

void fingerprint(const std::string& input, std::string& output) {
  SHA1(reinterpret_cast<const unsigned char*>(input.data()), input.size(), reinterpret_cast<unsigned char*>(output.data()));
}

void usage() {
  fprintf(stderr, "Incorrect arguments.\n");
  fprintf(stderr, "Return Value:\n");
  fprintf(stderr, "  Returns 0 on successful run (whether or not it found a match).\n");
  fprintf(stderr, "  Returns 1 when incorrectly invoked.\n");
  // TODO
}

std::string read_file(const std::string& filename) {
  std::ifstream stream;
  stream.open(filename, std::ios_base::in | std::ios_base::binary);
  std::string contents;
  while (!stream.eof() && !stream.bad()) {
    size_t size = contents.size();
    contents.resize(size + 1024);
    stream.read(contents.data() + size, 1024);
    contents.resize(size + stream.gcount());
  }
  if (stream.bad()) {
    throw std::runtime_error("Failed to read file.");
  }
  return contents;
}

void print_digest(const std::string& digest) {
  for (const uint8_t c : digest) {
    fprintf(stdout, "%02x", c);
  }
  fprintf(stdout, "\n");
}

void print_timestamp(const uint32_t ts) {
  fprintf(stdout, "%u\n", ts);
}

bool suffix_matches(const std::string& str, const std::string& suffix) {
  assert(suffix.size() > str.size());
  return !memcmp(str.data() + str.size() - suffix.size(), suffix.data(), suffix.size());
}

/**
 * Expected args:
 * 1. The filename of a file containing a serialized public key in the PGP V4
 *    format described here: https://tools.ietf.org/html/rfc4880#section-12.2.
 * 2. The target fingerprint suffix, in hex. E.g., "12345678".
 * 3. The minimum timestamp value.
 * 4. The maximum timestamp value.
 */
int main(int argc, char* argv[]) {
  (void)argc;
  (void)argv;

  if (argc != 5) {
    usage();
    return 1;
  }

  const uint32_t min_ts = strtol(argv[3], nullptr, 10);
  const uint32_t max_ts = strtol(argv[4], nullptr, 10);
  if (min_ts > max_ts) {
    usage();
    return 1;
  }


  auto target_suffix_hex = std::string(argv[2]);
  if (target_suffix_hex.size() % 2 == 1) {
    usage();
    return 1;
  }

  std::string target_suffix;
  for (size_t i = 0; i < target_suffix_hex.size(); i += 2) {
    char* start = target_suffix_hex.data() + i;
    char* end = nullptr;
    char pair[3] = { start[0], start[1], '\0' };
    uint8_t byte = strtol(pair, &end, 16);
    if (end != pair + 2) {
      usage();
      return 1;
    }
    target_suffix.push_back((char)byte);
  }
  // print_digest(target_suffix);

  const auto key_file_name = std::string(argv[1]);

  std::string input = read_file(key_file_name);

  std::string digest;
  digest.resize(20);

  for (uint32_t ts = min_ts; ts <= max_ts; ts++) {
    set_timestamp(input, ts);
    fingerprint(input, digest);
    // print_digest(digest);

    if (suffix_matches(digest, target_suffix)) {
      print_timestamp(ts);
      // print_digest(digest);
    }
  }

  return 0;
}
