#include <cstdint>
#include <string>
#include <vector>

namespace cashaddr {

/**
 * Encode a cashaddr string. Returns the empty string in case of failure.
 */
std::string Encode(const int isMainNet, const std::vector<uint8_t> &payload, uint8_t type);
}
