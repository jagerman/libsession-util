#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "source.hpp"

namespace session::image {

/// The range `thumbnail` clamps its `edge` to.  The top keeps a decoded thumbnail to 4 MiB
/// (1024² RGBA), which is what makes it cheap enough to draw a screenful of.
inline constexpr uint32_t min_thumbnail_edge = 64;
inline constexpr uint32_t max_thumbnail_edge = 1024;

/// The JPEG quality thumbnails are encoded at.
inline constexpr int thumbnail_quality = 90;

/// API: image/thumbnail
///
/// A square JPEG of the image in `source`, for drawing it small: the image scaled to cover a
/// `side × side` square and cropped to its centre, where `side` is `edge` clamped to
/// [`min_thumbnail_edge`, `max_thumbnail_edge`] and then to the image's own shorter side -- a
/// thumbnail is never larger than the picture it stands for, so an image smaller than `edge` gives
/// a smaller thumbnail rather than an upscaled one.
///
/// - EXIF orientation is applied, so the thumbnail is upright however the original was stored.
/// - An animation gives its first frame.
/// - Transparency is drawn over a checkerboard of 8px squares, #FFFFFF and #CCCCCC, since JPEG has
///   no alpha: on a plain background a transparent image's subject can vanish into it.  The squares
///   are 8 thumbnail pixels whatever the image's size, being composited after the scaling.
/// - The result is 8-bit sRGB at `thumbnail_quality`, encoded with jpegli where the build has it,
///   and carries no metadata at all.
///
/// Returns nullopt for anything that is not an image we accept: what `probe` refuses, a format
/// this build cannot decode (HEIC outside Apple platforms), and an image over `max_frame_pixels`.
///
/// Throws std::runtime_error if the source cannot be read -- an encrypted source that turns out to
/// be corrupt, say -- or an image that probed as acceptable fails to decode.
std::optional<std::vector<std::byte>> thumbnail(Source& source, uint32_t edge);

}  // namespace session::image
