#include <oxenc/hex.h>
#include <vips/vips.h>

#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <session/attachments.hpp>
#include <session/image/thumbnail.hpp>
#include <session/image/vips.hpp>
#include <session/random.hpp>
#include <string>
#include <vector>

#include "../src/image/thumbnail_internal.hpp"
#include "../src/image/vips_internal.hpp"

namespace image = session::image;
using image::detail::image_ptr;

namespace {

using rgba = std::array<uint8_t, 4>;

constexpr rgba RED{255, 0, 0, 255}, BLUE{0, 0, 255, 255}, GREEN{0, 255, 0, 255};

// A w x h RGBA image (or RGB, if `bands` is 3) whose pixel at (x, y) is `px(x, y)`; `frames` of
// them stacked vertically, as libvips holds animation, frame `f` drawn by `px(x, y + f * h)`.
image_ptr draw(
        int w, int h, const std::function<rgba(int, int)>& px, int bands = 3, int frames = 1) {
    image::init();
    std::vector<uint8_t> data(size_t(w) * h * frames * bands);
    for (int y = 0; y < h * frames; y++)
        for (int x = 0; x < w; x++) {
            auto p = px(x, y);
            std::copy_n(p.begin(), bands, data.begin() + (size_t(y) * w + x) * bands);
        }
    VipsImage* raw = vips_image_new_from_memory_copy(
            data.data(), data.size(), w, h * frames, bands, VIPS_FORMAT_UCHAR);
    REQUIRE(raw);
    image_ptr raw_ptr{raw};
    VipsImage* out;
    REQUIRE(vips_copy(raw, &out, "interpretation", VIPS_INTERPRETATION_sRGB, nullptr) == 0);
    image_ptr img{out};
    if (frames > 1)
        vips_image_set_int(img.get(), "page-height", h);
    return img;
}

std::vector<std::byte> save(VipsImage* img, const char* suffix) {
    void* buf = nullptr;
    size_t len = 0;
    REQUIRE(vips_image_write_to_buffer(img, suffix, &buf, &len, nullptr) == 0);
    std::vector<std::byte> out{static_cast<std::byte*>(buf), static_cast<std::byte*>(buf) + len};
    g_free(buf);
    return out;
}

std::optional<std::vector<std::byte>> thumb(std::span<const std::byte> data, uint32_t edge) {
    image::Source src{data};
    return image::thumbnail(src, edge);
}

// Decoded to memory, so the pixels can be read and the buffer can go.
image_ptr decode_jpeg(const std::vector<std::byte>& jpeg) {
    VipsImage* img = vips_image_new_from_buffer(jpeg.data(), jpeg.size(), "", nullptr);
    REQUIRE(img);
    image_ptr lazy{img};
    std::string loader;
    if (const char* name; vips_image_get_string(img, "vips-loader", &name) == 0)
        loader = name;
    CHECK(loader == "jpegload_buffer");
    VipsImage* decoded = vips_image_copy_memory(img);
    REQUIRE(decoded);
    return image_ptr{decoded};
}

rgba pixel(VipsImage* img, int x, int y) {
    auto* p = VIPS_IMAGE_ADDR(img, x, y);
    return {p[0], p[1], p[2], 255};
}

// JPEG is lossy: a colour is right if every channel is near it.
bool near(rgba got, rgba want, int tolerance = 24) {
    for (int c = 0; c < 3; c++)
        if (std::abs(int(got[c]) - int(want[c])) > tolerance)
            return false;
    return true;
}

bool has_marker(const std::vector<std::byte>& jpeg, uint8_t marker) {
    // Markers before the scan only: entropy-coded data can contain anything.
    for (size_t i = 2; i + 4 <= jpeg.size();) {
        if (jpeg[i] != std::byte{0xFF})
            return false;
        auto m = static_cast<uint8_t>(jpeg[i + 1]);
        if (m == marker)
            return true;
        if (m == 0xDA)
            return false;
        i += 2 + ((size_t(jpeg[i + 2]) << 8) | size_t(jpeg[i + 3]));
    }
    return false;
}

struct temp_file {
    std::filesystem::path path =
            std::filesystem::temp_directory_path() /
            ("libsession-thumbnail-test-" + oxenc::to_hex(session::random::random(8)));
    ~temp_file() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
};

}  // namespace

TEST_CASE("thumbnail makes a square JPEG with no metadata", "[image][thumbnail]") {
    auto photo = draw(640, 480, [](int x, int y) {
        return rgba{uint8_t(x * 255 / 640), uint8_t(y * 255 / 480), 128, 255};
    });
    // An orientation is written as EXIF, which the thumbnail must not carry.
    vips_image_set_int(photo.get(), "orientation", 1);
    auto jpeg = save(photo.get(), ".jpg");
    REQUIRE(has_marker(jpeg, 0xE1));

    auto out = thumb(jpeg, 128);
    REQUIRE(out);
    REQUIRE(out->size() > 2);
    CHECK((*out)[0] == std::byte{0xFF});
    CHECK((*out)[1] == std::byte{0xD8});
    CHECK_FALSE(has_marker(*out, 0xE1));  // APP1: EXIF or XMP
    CHECK_FALSE(has_marker(*out, 0xE2));  // APP2: ICC
    CHECK_FALSE(has_marker(*out, 0xFE));  // COM

    auto img = decode_jpeg(*out);
    CHECK(img->Xsize == 128);
    CHECK(img->Ysize == 128);
    CHECK(img->Bands == 3);
}

TEST_CASE("thumbnail converts a wide-gamut picture to sRGB", "[image][thumbnail]") {
    // sRGB's pure red, in Display P3's numbers: drawn as if they were sRGB, a duller red.
    auto photo = draw(64, 64, [](int, int) { return rgba{234, 51, 35, 255}; });
    VipsBlob* p3;
    REQUIRE(vips_profile_load("p3", &p3, nullptr) == 0);
    REQUIRE(p3);
    size_t len;
    auto* icc = vips_blob_get(p3, &len);
    vips_image_set_blob_copy(photo.get(), VIPS_META_ICC_NAME, icc, len);
    vips_area_unref(VIPS_AREA(p3));
    auto jpeg = save(photo.get(), ".jpg");
    REQUIRE(has_marker(jpeg, 0xE2));

    auto out = thumb(jpeg, 32);
    REQUIRE(out);
    CHECK_FALSE(has_marker(*out, 0xE2));
    auto img = decode_jpeg(*out);
    CHECK(near(pixel(img.get(), 16, 16), RED, 8));
}

TEST_CASE("thumbnail edge is clamped and never upscales", "[image][thumbnail]") {
    auto big = save(draw(2000, 1500, [](int, int) { return BLUE; }).get(), ".jpg");
    auto small = save(draw(50, 40, [](int, int) { return BLUE; }).get(), ".png");

    auto size_of = [](const std::optional<std::vector<std::byte>>& jpeg) {
        REQUIRE(jpeg);
        auto img = decode_jpeg(*jpeg);
        CHECK(img->Xsize == img->Ysize);
        return img->Xsize;
    };
    CHECK(size_of(thumb(big, 10)) == int(image::min_thumbnail_edge));
    CHECK(size_of(thumb(big, 5000)) == int(image::max_thumbnail_edge));
    CHECK(size_of(thumb(big, 300)) == 300);
    // Its shorter side, rather than the 128 asked for.
    CHECK(size_of(thumb(small, 128)) == 40);
}

TEST_CASE("thumbnail draws transparency over a checkerboard", "[image][thumbnail]") {
    // Transparent everywhere but a solid red square in the middle.
    auto png =
            save(draw(
                         256,
                         256,
                         [](int x, int y) {
                             bool middle = x >= 96 && x < 160 && y >= 96 && y < 160;
                             return middle ? RED : rgba{0, 255, 0, 0};
                         },
                         4)
                         .get(),
                 ".png");

    auto out = thumb(png, 128);
    REQUIRE(out);
    auto img = decode_jpeg(*out);
    REQUIRE(img->Xsize == 128);
    REQUIRE(img->Bands == 3);

    constexpr rgba LIGHT{0xFF, 0xFF, 0xFF, 255}, DARK{0xCC, 0xCC, 0xCC, 255};
    // The centre of each 8px square, which is where JPEG's blur at the edges cannot reach.
    CHECK(near(pixel(img.get(), 4, 4), LIGHT, 12));
    CHECK(near(pixel(img.get(), 12, 4), DARK, 12));
    CHECK(near(pixel(img.get(), 4, 12), DARK, 12));
    CHECK(near(pixel(img.get(), 12, 12), LIGHT, 12));
    CHECK(near(pixel(img.get(), 124, 124), LIGHT, 12));
    // The hidden colour of transparent pixels does not show through.
    CHECK(near(pixel(img.get(), 64, 64), RED));
}

TEST_CASE("thumbnail of an animation is its first frame", "[image][thumbnail]") {
    for (const char* suffix : {".gif", ".webp"}) {
        INFO(suffix);
        auto anim = save(
                draw(80, 60, [](int, int y) { return y < 60 ? RED : BLUE; }, 3, 2).get(), suffix);
        auto out = thumb(anim, 64);
        REQUIRE(out);
        auto img = decode_jpeg(*out);
        CHECK(img->Xsize == 60);
        CHECK(img->Ysize == 60);
        CHECK(near(pixel(img.get(), 30, 30), RED));
    }
}

TEST_CASE("thumbnail applies EXIF orientation", "[image][thumbnail]") {
    // Stored 400x200, red on the left and blue on the right.
    auto stored = draw(400, 200, [](int x, int) { return x < 200 ? RED : BLUE; });

    SECTION("upright") {
        auto out = thumb(save(stored.get(), ".jpg"), 64);
        REQUIRE(out);
        auto img = decode_jpeg(*out);
        CHECK(near(pixel(img.get(), 8, 32), RED));
        CHECK(near(pixel(img.get(), 56, 32), BLUE));
    }

    SECTION("orientation 6: displayed a quarter turn clockwise, so the left edge is on top") {
        vips_image_set_int(stored.get(), "orientation", 6);
        auto out = thumb(save(stored.get(), ".jpg"), 64);
        REQUIRE(out);
        auto img = decode_jpeg(*out);
        CHECK(img->Xsize == 64);
        CHECK(img->Ysize == 64);
        CHECK(near(pixel(img.get(), 32, 8), RED));
        CHECK(near(pixel(img.get(), 32, 56), BLUE));
    }
}

TEST_CASE("thumbnail of a panorama is its centre", "[image][thumbnail]") {
    // 100:1, green only across the middle 100 pixels: exactly the square a cover crop keeps.
    auto pano = save(
            draw(10000, 100, [](int x, int) { return x >= 4950 && x < 5050 ? GREEN : RED; }).get(),
            ".png");
    auto out = thumb(pano, 64);
    REQUIRE(out);
    auto img = decode_jpeg(*out);
    CHECK(img->Xsize == 64);
    CHECK(img->Ysize == 64);
    for (auto [x, y] : {std::pair{4, 4}, {59, 4}, {4, 59}, {59, 59}, {32, 32}})
        CHECK(near(pixel(img.get(), x, y), GREEN, 40));
}

TEST_CASE("thumbnail refuses what it will not decode", "[image][thumbnail]") {
    std::string_view text = "not an image";
    CHECK_FALSE(thumb(std::as_bytes(std::span{text}), 128));

    std::string_view svg = R"(<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4"/>)";
    CHECK_FALSE(thumb(std::as_bytes(std::span{svg}), 128));

    // A JPEG whose header claims 20000x20000: 400 million pixels, over max_frame_pixels.
    auto jpeg = save(draw(64, 48, [](int, int) { return RED; }).get(), ".jpg");
    const std::array<std::byte, 2> sof0{std::byte{0xFF}, std::byte{0xC0}};
    auto sof = std::search(jpeg.begin(), jpeg.end(), sof0.begin(), sof0.end());
    REQUIRE(sof != jpeg.end());
    for (int i : {5, 7}) {
        sof[i] = std::byte{20000 >> 8};
        sof[i + 1] = std::byte{20000 & 0xff};
    }
    CHECK_FALSE(thumb(jpeg, 128));
}

TEST_CASE("thumbnail reads an encrypted file", "[image][thumbnail]") {
    auto png = save(draw(300, 200, [](int, int) { return BLUE; }).get(), ".png");
    auto seed = session::random::random(32);
    temp_file f;
    auto key = session::attachment::encrypt(
            std::as_bytes(std::span{seed}), png, session::attachment::Domain::ATTACHMENT, f.path);
    image::Source src{f.path, key};
    auto out = image::thumbnail(src, 100);
    REQUIRE(out);
    auto img = decode_jpeg(*out);
    CHECK(img->Xsize == 100);
    CHECK(near(pixel(img.get(), 50, 50), BLUE));
}

// Not run by default: `testAll "[thumbnail-bench]"`.  What drawing transparency over the
// checkerboard costs against a plain white flatten, on a large transparent PNG and on a 12 MP JPEG
// (which has no alpha, so the two should be the same and this measures the thumbnail itself).
TEST_CASE("thumbnail backdrop benchmark", "[.][thumbnail-bench]") {
    using clock = std::chrono::steady_clock;
    auto noisy = [](int bands) {
        return [bands](int x, int y) {
            auto h = uint32_t(x) * 2654435761u ^ uint32_t(y) * 2246822519u;
            return rgba{
                    uint8_t(h),
                    uint8_t(h >> 8),
                    uint8_t(x ^ y),
                    uint8_t(bands == 4 ? (x + y) % 256 : 255)};
        };
    };
    struct input {
        const char* name;
        std::vector<std::byte> bytes;
    };
    std::vector<input> inputs;
    inputs.push_back({"4000x3000 RGBA PNG", save(draw(4000, 3000, noisy(4), 4).get(), ".png")});
    inputs.push_back({"4000x3000 JPEG", save(draw(4000, 3000, noisy(3)).get(), ".jpg")});

    constexpr int RUNS = 5;
    for (const auto& in : inputs)
        for (uint32_t edge : {240u, 480u, 1024u})
            for (auto backdrop :
                 {image::detail::Backdrop::checkerboard, image::detail::Backdrop::white}) {
                std::vector<double> ms;
                for (int i = 0; i < RUNS; i++) {
                    image::Source src{in.bytes};
                    auto start = clock::now();
                    auto out = image::detail::thumbnail(src, edge, backdrop);
                    ms.push_back(std::chrono::duration<double, std::milli>(clock::now() - start)
                                         .count());
                    REQUIRE(out);
                }
                std::ranges::sort(ms);
                std::printf(
                        "%-20s edge %4u %-12s median %8.1f ms  min %8.1f ms\n",
                        in.name,
                        edge,
                        backdrop == image::detail::Backdrop::checkerboard ? "checkerboard"
                                                                          : "white",
                        ms[RUNS / 2],
                        ms[0]);
            }
}
