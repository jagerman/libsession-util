#include <charconv>
#include <session/comms/sn_list.hpp>

namespace session::comms {

std::array<uint8_t, 4> service_node_contact::split_ipv4(std::string_view ip) {
    std::array<uint8_t, 4> quad;
    auto nums = split(ip, ".");
    if (nums.size() != 4)
        throw "Invalid IPv4 address";
    for (int i = 0; i < 4; i++) {
        auto end = nums[i].data() + nums[i].size();
        if (auto [p, ec] = std::from_chars(nums[i].data(), end, quad[i]);
            ec != std::errc{} || p != end)
            throw "Invalid malformed IPv4 address";
    }

    return quad;
}

}  // namespace session::comms
