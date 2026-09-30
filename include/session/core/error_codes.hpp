#pragma once

#include <string_view>

/// The `Error::code` values Core reports, on the same terms as `client::err`: dotted, grouped by
/// the object that failed, and an open set a caller falls back to the message for.
///
/// Client reports some of these too, when what failed was Core's to do, and names them in
/// `client::err` alongside its own.
namespace session::core::err {

/// There is no network attached, so nothing that needs one can be done.
inline constexpr std::string_view network_unavailable = "network.unavailable";

}  // namespace session::core::err
