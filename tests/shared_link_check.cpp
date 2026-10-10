// Linked as a shared object, which is how applications take libsession in -- a Node addon, an
// Android JNI library, an iOS framework -- and never run.  An object in libsession or in any static
// dependency it pulls in that is not position-independent fails this link, where an executable
// would not notice.

#include <session/client.hpp>
#include <session/image/thumbhash.hpp>

extern "C" __attribute__((visibility("default"))) bool session_shared_link_check(
        const char* db, const std::byte* hash, size_t hash_len) {
    if (!session::image::thumbhash::valid({hash, hash_len}))
        return false;
    session::client::Client client{std::filesystem::path{db}};
    return client.attachment_thumbnail(0, 0, session::await).empty();
}
