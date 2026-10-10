#pragma once

#include <vips/vips.h>

#include <cstddef>
#include <vector>

namespace session::image::detail {

enum class Subsampling {
    // Chroma at half resolution in both directions: what photos want, and much smaller.
    yuv420,
    // Full-resolution chroma, for very high quality output.
    yuv444,
};

// Encodes `image` with jpegli as a progressive JPEG with no metadata.
//
// The image is converted to 8-bit sRGB as part of encoding; a single-band image stays greyscale.
//
// `quality` is libjpeg-style, 1 to 100.  jpegli maps it onto its own perceptual scale, so the same
// number gives a smaller file than libjpeg-turbo at about the same perceived quality: sizes are not
// comparable between the two encoders at equal `quality`.
//
// Throws std::invalid_argument if `quality` is out of range, or if the image has an alpha channel:
// JPEG cannot store one, and whether to flatten it or use another format is the caller's decision.
// Throws std::runtime_error if conversion or encoding fails.
std::vector<std::byte> encode_jpeg(
        VipsImage* image, int quality, Subsampling subsampling = Subsampling::yuv420);

}  // namespace session::image::detail
