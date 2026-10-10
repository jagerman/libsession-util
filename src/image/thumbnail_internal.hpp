#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "session/image/source.hpp"

namespace session::image::detail {

// What transparency is drawn over.  `white` exists for the benchmark that justifies the
// checkerboard's cost; thumbnails are always made on the checkerboard.
enum class Backdrop { checkerboard, white };

std::optional<std::vector<std::byte>> thumbnail(Source& source, uint32_t edge, Backdrop backdrop);

}  // namespace session::image::detail
