#pragma once

#include "session/config/namespaces.hpp"
#include "session/util.hpp"

namespace session::protos {

struct WebSocketMessage {
    uint64_t request_id;
    std::string headers;
    std::string body;
};

struct WebSocketRequest : public WebSocketMessage {
    std::string verb;
    std::string path;
};

struct WebSocketResponse : public WebSocketMessage {
    uint32_t status;
    std::string message;
};

ustring handle_incoming(ustring_view data);

ustring handle_incoming(ustring data);

ustring handle_outgoing(ustring_view data, int64_t seqno, config::Namespace t);

ustring handle_outgoing(ustring data, int64_t seqno, config::Namespace t);

}  // namespace session::protos

/*

in base: virtual method
    New types: always binary
    Old types: try-protobuf on incoming, protobuf on outgoing

    Old types in some future release: try-protobuf on incoming, binary on outgoing
    Old types in distance future release: always binary

::merge()
    ustring_view input = ...;
    ustring parsed;
    if (accepts_protobuf()) {
    try {
    parsed = parse_protobuf(input);
    input = parsed;
    } catch (...) {} // ignore
    }
    // Load binary here

::push()
    middle return value is constructed protobuf

*/
