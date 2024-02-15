#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "../onionreq/key_types.hpp"

namespace session::comms {

using onionreq::ed25519_pubkey;
using onionreq::legacy_pubkey;
using onionreq::x25519_pubkey;

/** Struct containing the pertinent info we need to make contact with (or through) a service node.
 */
struct service_node_contact {
    legacy_pubkey sn_pubkey;
    ed25519_pubkey ed_pubkey;
    x25519_pubkey x_pubkey;
    std::array<uint8_t, 4> ip;
    uint16_t quic_port;

    service_node_contact(
            std::string_view sn_pk_hex,
            std::string_view sn_ed_hex,
            std::string_view sn_x_hex,
            std::string_view ip,
            uint16_t quic_port) :
            sn_pubkey{legacy_pubkey::from_hex(sn_pk_hex)},
            ed_pubkey{ed25519_pubkey::from_hex(sn_ed_hex)},
            x_pubkey{x25519_pubkey::from_hex(sn_x_hex)},
            ip{split_ipv4(ip)},
            quic_port{quic_port} {}

    // Same as above, but uses the sn_ed_hex for both legacy pk and ed pk, which is the norm for new
    // SNs created since late 2020 (Oxen 8+).
    service_node_contact(
            std::string_view sn_ed_hex,
            std::string_view sn_x_hex,
            std::string ip,
            uint16_t quic_port) :
            service_node_contact{sn_ed_hex, sn_ed_hex, sn_x_hex, std::move(ip), quic_port} {}

  private:
    static std::array<uint8_t, 4> split_ipv4(std::string_view ip);
};

struct service_node_list {
    std::vector<service_node_contact> service_nodes;

    // Returns a random sample of service nodes of the given length <= 8 that begins with `entry`
    // and ends on `target`.  (Either one can be given as std::nullopt to select a random node for
    // that position).  The mask is the netmask size for de-duplicating selection: for example, the
    // default 24 ensures that each returned node is on a different /24 IP range (i.e. no SNs
    // included that have the same first three octets in the address).  A mask of 32 requires
    // distinct IPs.  If mask is 0 then no IP checking happens at all (and so the path might contain
    // SNs on different ports on the same IP).  Note that IP checking is not applied to the
    // entry/target nodes, if given (that is: the contacts for entry and target could have the same
    // or similar IPs, regardless of the `mask` value, when a specific entry/target was requested).
    //
    // Throws on errors:
    // - `std::out_of_range` if `target` is given but is not a SN we know about.
    // - `std::length_error` if we do not know of enough SNs to build a path of the given length
    //   satisfying the mask requirement.
    // - `std::invalid_argument` if length or mask are invalid (length < 2 or > 8; mask > 32 or
    //   negative).
    std::vector<service_node_contact> path(
            std::optional<legacy_pubkey> entry,
            std::optional<legacy_pubkey> target,
            size_t length = 4,
            int mask = 24);
};

}  // namespace session::comms
