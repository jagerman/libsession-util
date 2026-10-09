#include "session/image/thumbnail.hpp"

#include <vips/vips.h>

#include <algorithm>
#include <memory>

#include "jpeg_encode.hpp"
#include "platform.hpp"
#include "session/image/probe.hpp"
#include "source_internal.hpp"
#include "thumbnail_internal.hpp"
#include "vips_internal.hpp"

namespace session::image {

namespace detail {

    namespace {

        constexpr int CHECKER_SQUARE = 8;
        constexpr unsigned CHECKER_LIGHT = 0xFF, CHECKER_DARK = 0xCC;

        image_ptr to_srgb8(VipsImage* img) {
            VipsImage* out;
            if (vips_colourspace(img, &out, VIPS_INTERPRETATION_sRGB, nullptr))
                throw_vips_error("thumbnail: colour conversion failed");
            image_ptr srgb{out};
            if (srgb->BandFmt != VIPS_FORMAT_UCHAR) {
                if (vips_cast_uchar(srgb.get(), &out, nullptr))
                    throw_vips_error("thumbnail: conversion to 8 bits failed");
                srgb.reset(out);
            }
            return srgb;
        }

        // Blended by hand rather than with vips_composite: at thumbnail size the pixels fit in a
        // few MiB, and one pass over them beats building a second image for libvips to blend.
        image_ptr over_checkerboard(VipsImage* in) {
            auto img = to_srgb8(in);
            if (img->Bands != 4)
                throw std::runtime_error{"thumbnail: expected RGBA after conversion"};

            size_t len = 0;
            std::unique_ptr<uint8_t, decltype(&g_free)> rgba{
                    static_cast<uint8_t*>(vips_image_write_to_memory(img.get(), &len)), &g_free};
            if (!rgba)
                throw_vips_error("thumbnail: decoding failed");

            int w = img->Xsize, h = img->Ysize;
            std::vector<uint8_t> rgb(size_t(w) * h * 3);
            const uint8_t* src = rgba.get();
            uint8_t* dst = rgb.data();
            for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++, src += 4, dst += 3) {
                    unsigned bg = ((x / CHECKER_SQUARE + y / CHECKER_SQUARE) & 1) ? CHECKER_DARK
                                                                                  : CHECKER_LIGHT;
                    unsigned a = src[3];
                    for (int c = 0; c < 3; c++)
                        dst[c] = static_cast<uint8_t>((src[c] * a + bg * (255 - a) + 127) / 255);
                }

            VipsImage* raw = vips_image_new_from_memory_copy(
                    rgb.data(), rgb.size(), w, h, 3, VIPS_FORMAT_UCHAR);
            if (!raw)
                throw_vips_error("thumbnail: cannot wrap the composited pixels");
            image_ptr out{raw};
            VipsImage* tagged;
            if (vips_copy(out.get(), &tagged, "interpretation", VIPS_INTERPRETATION_sRGB, nullptr))
                throw_vips_error("thumbnail: setting the colour space failed");
            return image_ptr{tagged};
        }

        image_ptr over_white(VipsImage* in) {
            auto img = to_srgb8(in);
            VipsArrayDouble* white = vips_array_double_newv(3, 255.0, 255.0, 255.0);
            VipsImage* out;
            int rc = vips_flatten(img.get(), &out, "background", white, nullptr);
            vips_area_unref(VIPS_AREA(white));
            if (rc)
                throw_vips_error("thumbnail: flattening failed");
            return image_ptr{out};
        }

        // Scaled to cover side x side and cropped to its centre.  vips_thumbnail applies EXIF
        // orientation, loads only the first frame of an animation, and shrinks on load where the
        // format allows (JPEG, WebP, HEIF), so a 12 MP photo is never decoded at full size.
        image_ptr cover(Source& source, const Info& info, uint32_t side) {
            VipsImage* out = nullptr;
            int rc;
            if (platform_decodes(info.format)) {
                // Decoded at the size whose shorter side is `side`; the platform may round that a
                // pixel short, which the cover below then scales back up by that pixel.
                uint64_t longer = std::max(info.width, info.height),
                         shorter = std::min(info.width, info.height);
                auto decoded = platform_decode(
                        source,
                        info.format,
                        static_cast<uint32_t>((longer * side + shorter - 1) / shorter));
                rc = vips_thumbnail_image(
                        decoded.get(),
                        &out,
                        static_cast<int>(side),
                        "height",
                        static_cast<int>(side),
                        "crop",
                        VIPS_INTERESTING_CENTRE,
                        nullptr);
            } else {
                VipsSource* vsrc = source_access::vips(source);
                if (vips_source_rewind(vsrc)) {
                    source_access::rethrow_error(source);
                    throw_vips_error("thumbnail: cannot rewind the source");
                }
                rc = vips_thumbnail_source(
                        vsrc,
                        &out,
                        static_cast<int>(side),
                        "height",
                        static_cast<int>(side),
                        "crop",
                        VIPS_INTERESTING_CENTRE,
                        nullptr);
                source_access::rethrow_error(source);
            }
            if (rc)
                throw_vips_error("thumbnail: scaling failed");
            return image_ptr{out};
        }

    }  // namespace

    std::optional<std::vector<std::byte>> thumbnail(
            Source& source, uint32_t edge, Backdrop backdrop) {
        auto info = probe(source);
        if (!info || !info->decodable || !info->within_pixel_limits(false) || !info->width ||
            !info->height)
            return std::nullopt;

        edge = std::clamp(edge, min_thumbnail_edge, max_thumbnail_edge);
        uint32_t side = std::min({edge, info->width, info->height});

        // libvips evaluates lazily, so a read of an encrypted source can fail anywhere from here
        // to the end of encoding; its own exception, rather than libvips' generic read error, is
        // what the caller needs.
        try {
            auto img = cover(source, *info, side);
            if (vips_image_hasalpha(img.get()))
                img = backdrop == Backdrop::checkerboard ? over_checkerboard(img.get())
                                                         : over_white(img.get());
            return encode_jpeg(img.get(), thumbnail_quality);
        } catch (...) {
            source_access::rethrow_error(source);
            throw;
        }
    }

}  // namespace detail

std::optional<std::vector<std::byte>> thumbnail(Source& source, uint32_t edge) {
    return detail::thumbnail(source, edge, detail::Backdrop::checkerboard);
}

}  // namespace session::image
