#include <sodium/utils.h>

#include <session/util.hpp>

namespace session {
void* sodium_buffer_allocate(size_t length) {
    if (auto* p = sodium_malloc(length))
        return p;
    throw std::bad_alloc{};
}

void sodium_buffer_deallocate(void* p) {
    if (p)
        sodium_free(p);
}

void sodium_zero_buffer(void* ptr, size_t size) {
    if (ptr)
        sodium_memzero(ptr, size);
}

std::vector<std::string_view> split(std::string_view str, const std::string_view delim, bool trim) {
    std::vector<std::string_view> results;
    // Special case for empty delimiter: splits on each character boundary:
    if (delim.empty()) {
        results.reserve(str.size());
        for (size_t i = 0; i < str.size(); i++)
            results.emplace_back(str.data() + i, 1);
        return results;
    }

    for (size_t pos = str.find(delim); pos != std::string_view::npos; pos = str.find(delim)) {
        if (!trim || !results.empty() || pos > 0)
            results.push_back(str.substr(0, pos));
        str.remove_prefix(pos + delim.size());
    }
    if (!trim || str.size())
        results.push_back(str);
    else
        while (!results.empty() && results.back().empty())
            results.pop_back();
    return results;
}

std::vector<std::string_view> split_any(
        std::string_view str, const std::string_view delims, bool trim) {
    if (delims.empty())
        return split(str, delims, trim);
    std::vector<std::string_view> results;
    for (size_t pos = str.find_first_of(delims); pos != std::string_view::npos;
         pos = str.find_first_of(delims)) {
        if (!trim || !results.empty() || pos > 0)
            results.push_back(str.substr(0, pos));
        size_t until = str.find_first_not_of(delims, pos + 1);
        if (until == std::string_view::npos)
            str.remove_prefix(str.size());
        else
            str.remove_prefix(until);
    }
    if (!trim || str.size())
        results.push_back(str);
    else
        while (!results.empty() && results.back().empty())
            results.pop_back();
    return results;
}

}  // namespace session
