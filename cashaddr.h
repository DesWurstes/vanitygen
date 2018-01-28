#include <cstdint>
#include <string>
#include <vector>
#include "cashaddr.c"

namespace cashaddr {

/**
 * Encode a cashaddr string. Returns the empty string in case of failure.
 */
std::string Encode(const int isMainNet, const std::vector<char> &payload, char type);
}
