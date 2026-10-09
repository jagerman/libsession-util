#include <vips/vips.h>

#include <session/client/error_codes.hpp>
#include <session/image/thumbnail.hpp>
#include <session/image/vips.hpp>
#include <session/network/backends/session_file_server.hpp>

#include "../../src/client/download_cache.hpp"
#include "../utils.hpp"
#include "common.hpp"

namespace cache = session::client::cache;

namespace {

// A w x h picture, encoded as `suffix` says (".png", ".jpg"), in one colour with a stripe so that
// it compresses to something of a realistic size rather than to nothing.
std::vector<std::byte> picture(int w, int h, const char* suffix = ".png") {
    image::init();
    std::vector<uint8_t> px(size_t(w) * h * 3);
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            auto* p = &px[(size_t(y) * w + x) * 3];
            p[0] = uint8_t(x * 255 / w);
            p[1] = uint8_t(y * 255 / h);
            p[2] = (x / 16 + y / 16) % 2 ? 200 : 40;
        }
    VipsImage* img =
            vips_image_new_from_memory_copy(px.data(), px.size(), w, h, 3, VIPS_FORMAT_UCHAR);
    REQUIRE(img);
    void* buf = nullptr;
    size_t len = 0;
    int rc = vips_image_write_to_buffer(img, suffix, &buf, &len, nullptr);
    g_object_unref(img);
    REQUIRE(rc == 0);
    std::vector<std::byte> out{static_cast<std::byte*>(buf), static_cast<std::byte*>(buf) + len};
    g_free(buf);
    return out;
}

// The width and height of an encoded JPEG.
std::pair<int, int> jpeg_size(const std::vector<std::byte>& jpeg) {
    REQUIRE(jpeg.size() > 2);
    CHECK(jpeg[0] == std::byte{0xFF});
    CHECK(jpeg[1] == std::byte{0xD8});
    VipsImage* img = vips_image_new_from_buffer(jpeg.data(), jpeg.size(), "", nullptr);
    REQUIRE(img);
    std::pair size{img->Xsize, img->Ysize};
    g_object_unref(img);
    return size;
}

bool eventually(const std::function<bool()>& done, std::chrono::milliseconds timeout = 20s) {
    auto until = std::chrono::steady_clock::now() + timeout;
    while (!done()) {
        if (std::chrono::steady_clock::now() > until)
            return false;
        std::this_thread::sleep_for(5ms);
    }
    return true;
}

// Waits until no thumbnail is queued or being made, and everything that finishing one posted has
// run.
void settle(Client& c) {
    sync(c);
    REQUIRE(eventually([&] { return TestHelper::thumbnails_idle(c); }));
    sync(c);
}

std::optional<std::string_view> error_code(const std::function<void()>& f) {
    try {
        f();
    } catch (const session::error& e) {
        return e.err().code;
    }
    return std::nullopt;
}

// One conversation that fetches everything it is sent, over a mock network, with a cache.
struct Fixture {
    TempCacheDir dir;
    Recorder rec;
    TempClient c;
    SenderKeys peer;
    ConversationId convo = ConversationId::dm(peer.session_id);
    MockNetwork* net;
    std::vector<std::byte> seed = random::random(32);
    int sent = 0;

    template <ClientOption... Opts>
    explicit Fixture(Opts&&... opts) : c{rec.handlers(), std::forward<Opts>(opts)...} {
        net = attach_mock_network(c->core);
        c->set_cache_dir(dir.path);
        c->open_dm(convo, await);
        c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);
    }

    // Delivers `data` as one attachment of `content_type`, lets it download, and returns the
    // message's id and the attachment's url.
    std::pair<int64_t, std::string> arrive(
            std::span<const std::byte> data, std::string_view content_type = "image/png") {
        auto [ct, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
        auto file_id = "f{}"_format(sent);
        net->served[file_id] = ct;
        auto url = network::file_server::generate_download_url(file_id, {}, true);
        deliver(*c,
                peer,
                "",
                from_epoch_ms(1000 + sent),
                "h{}"_format(sent),
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(1);
                    a->set_url(url);
                    a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                    a->set_size(data.size());
                    a->set_contenttype(std::string{content_type});
                });
        sent++;
        sync(*c);
        REQUIRE(serve_downloads(*net) == 1);
        settle(*c);
        return {c->conversation(convo, await)->messages(await)[0].id, url};
    }

    Attachment attachment(int64_t id) { return c->message(id, await)->attachments.at(0); }

    std::filesystem::path file(const std::string& url) {
        return TestHelper::cache_path(*c, cache::ATTACHMENT_DIR, url);
    }
    std::filesystem::path thumb_file(const std::string& url) {
        auto f = file(url);
        f += cache::THUMBNAIL_SUFFIX;
        return f;
    }

    template <typename T = int64_t, typename... Bind>
    T db_get(const std::string& query, const Bind&... bind) {
        return TestHelper::on_loop(
                c->core, [&] { return c->core.database().conn().prepared_get<T>(query, bind...); });
    }
};

}  // namespace

TEST_CASE("Client: a downloaded picture gets a thumbnail", "[client][thumbnail]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(800, 600));

    auto a = f.attachment(id);
    CHECK(a.availability == AttachmentAvailability::cached);
    CHECK(a.has_thumbnail);

    // Told, through the report every other change to the message goes through.
    bool reported = false;
    for (const auto& m : Recorder::messages(f.rec.msg_updated))
        if (m.id == id && !m.attachments.empty() && m.attachments[0].has_thumbnail)
            reported = true;
    CHECK(reported);

    // Square, at the default edge, and beside the file it was made from.
    auto jpeg = f.c->attachment_thumbnail(id, 0, await);
    CHECK(jpeg_size(jpeg) == std::pair{int(DEFAULT_THUMBNAIL_EDGE), int(DEFAULT_THUMBNAIL_EDGE)});
    REQUIRE(std::filesystem::exists(f.thumb_file(url)));

    // Encrypted like the file, so the bytes on disk are not the JPEG.
    auto on_disk = std::filesystem::file_size(f.thumb_file(url));
    CHECK(on_disk > jpeg.size());

    // One entry, counting both files.
    CHECK(f.db_get("SELECT count(*) FROM attachment_cache") == 1);
    CHECK(f.c->attachment_cache_size(await) ==
          static_cast<int64_t>(std::filesystem::file_size(f.file(url)) + on_disk));

    // The handler form answers the same, through the dispatcher.
    std::promise<Expected<std::vector<std::byte>>> got;
    f.c->attachment_thumbnail(id, 0, [&](auto r) { got.set_value(std::move(r)); });
    auto r = got.get_future().get();
    REQUIRE(r);
    CHECK(*r == jpeg);
}

TEST_CASE("Client: only a picture gets a thumbnail", "[client][thumbnail]") {
    Fixture f;

    std::vector<std::byte> pdf(3000);
    random::fill(pdf);
    auto [doc, doc_url] = f.arrive(pdf, "application/pdf");
    // Labelled as a picture, but not one: there is nothing to make a thumbnail of.
    auto [fake, fake_url] = f.arrive(pdf, "image/png");
    // A picture, but of a type Session does not display as one.
    auto [svg, svg_url] = f.arrive(picture(100, 100), "image/svg+xml");

    for (const auto& [id, url] : std::vector<std::pair<int64_t, std::string>>{
                 {doc, doc_url}, {fake, fake_url}, {svg, svg_url}}) {
        INFO(url);
        auto a = f.attachment(id);
        CHECK(a.availability == AttachmentAvailability::cached);
        CHECK_FALSE(a.has_thumbnail);
        CHECK_FALSE(std::filesystem::exists(f.thumb_file(url)));
        CHECK(error_code([&] { f.c->attachment_thumbnail(id, 0, await); }) == err::no_thumbnail);
    }

    CHECK(error_code([&] { f.c->attachment_thumbnail(doc + 1000, 0, await); }) ==
          err::message_not_found);
    CHECK(error_code([&] { f.c->attachment_thumbnail(doc, 1, await); }) ==
          err::attachment_not_found);
}

TEST_CASE("Client: a picture that is not cached has no thumbnail", "[client][thumbnail]") {
    TempClient c;
    SenderKeys peer;
    deliver(*c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_url("http://fs.example/file/111#d");
                a->set_key(std::string(32, 'k'));
                a->set_contenttype("image/png");
            });
    auto msgs = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await);
    REQUIRE(msgs.size() == 1);
    CHECK_FALSE(msgs[0].attachments[0].has_thumbnail);
    CHECK(error_code([&] { c->attachment_thumbnail(msgs[0].id, 0, await); }) == err::no_thumbnail);
}

TEST_CASE("Client: evicting a picture takes its thumbnail with it", "[client][thumbnail][evict]") {
    ScopedClockOffset clock{0s};
    Fixture f;
    auto [first, first_url] = f.arrive(picture(400, 300));
    REQUIRE(f.attachment(first).has_thumbnail);
    REQUIRE(std::filesystem::exists(f.thumb_file(first_url)));

    // Room for one entry, so the next arrival pushes the first out.
    AdjustedClock::set_offset(1s);
    f.c->set_attachment_cache_limit(1, await);
    f.rec.msg_updated.clear();
    auto [second, second_url] = f.arrive(picture(300, 400));

    CHECK_FALSE(std::filesystem::exists(f.file(first_url)));
    CHECK_FALSE(std::filesystem::exists(f.thumb_file(first_url)));
    auto a = f.attachment(first);
    CHECK(a.availability == AttachmentAvailability::absent);
    CHECK_FALSE(a.has_thumbnail);
    CHECK(error_code([&] { f.c->attachment_thumbnail(first, 0, await); }) == err::no_thumbnail);

    // And the message was told.
    bool reported = false;
    for (const auto& m : Recorder::messages(f.rec.msg_updated))
        if (m.id == first && !m.attachments[0].has_thumbnail)
            reported = true;
    CHECK(reported);

    // The one that did the pushing keeps both of its files.
    CHECK(f.attachment(second).has_thumbnail);
    CHECK(std::filesystem::exists(f.thumb_file(second_url)));
    CHECK(f.db_get("SELECT count(*) FROM attachment_cache") == 1);
}

TEST_CASE("Client: a file we send gets a thumbnail", "[client][thumbnail][send]") {
    TempCacheDir cache;
    TempClient c;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(cache.path);
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_outgoing", 7);
    std::filesystem::create_directories(dir);
    auto path = dir / "picture.jpg";
    auto bytes = picture(640, 480, ".jpg");
    {
        std::ofstream out{path, std::ios::binary};
        out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }

    // A gallery, which is kept as it is sent.
    auto id = c->send_message(
            ConversationId::dm(me),
            {.attachments = {OutgoingAttachment{.path = path, .content_type = "image/jpeg"}}},
            await);
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);
    settle(*c);

    auto a = c->message(id, await)->attachments.at(0);
    CHECK(a.availability == AttachmentAvailability::cached);
    CHECK(a.has_thumbnail);
    CHECK(jpeg_size(c->attachment_thumbnail(id, 0, await)) == std::pair{240, 240});

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: the thumbnail edge", "[client][thumbnail][edge]") {
    SECTION("defaults to 240") {
        TempClient c;
        CHECK(c->thumbnail_edge(await) == DEFAULT_THUMBNAIL_EDGE);
        CHECK(DEFAULT_THUMBNAIL_EDGE == 240);
    }

    SECTION("a stored value wins over the constructor's, at every open") {
        TempClient c{default_thumbnail_edge{100}};
        CHECK(c->thumbnail_edge(await) == 100);
        c->set_thumbnail_edge(300, await);
        CHECK(c->thumbnail_edge(await) == 300);

        c.reopen(default_thumbnail_edge{100});
        CHECK(c->thumbnail_edge(await) == 300);

        // Cleared, it goes back to what this run was constructed with.
        c->set_thumbnail_edge(std::nullopt, await);
        CHECK(c->thumbnail_edge(await) == 100);
    }

    SECTION("is clamped") {
        TempClient c{default_thumbnail_edge{2}};
        CHECK(c->thumbnail_edge(await) == image::min_thumbnail_edge);
        c->set_thumbnail_edge(5000, await);
        CHECK(c->thumbnail_edge(await) == image::max_thumbnail_edge);
        c->set_thumbnail_edge(10, await);
        CHECK(c->thumbnail_edge(await) == image::min_thumbnail_edge);
    }

    SECTION("a change applies to new thumbnails, and leaves the old ones") {
        Fixture f{default_thumbnail_edge{64}};
        auto [before, before_url] = f.arrive(picture(400, 300));
        CHECK(jpeg_size(f.c->attachment_thumbnail(before, 0, await)) == std::pair{64, 64});

        f.c->set_thumbnail_edge(128, await);
        auto [after, after_url] = f.arrive(picture(300, 400));
        CHECK(jpeg_size(f.c->attachment_thumbnail(after, 0, await)) == std::pair{128, 128});
        CHECK(jpeg_size(f.c->attachment_thumbnail(before, 0, await)) == std::pair{64, 64});
    }
}

TEST_CASE("Client: the startup pass fills in what was cached before", "[client][thumbnail]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(400, 300));
    REQUIRE(f.attachment(id).has_thumbnail);

    // What a cache filled by a version that made no thumbnails looks like: the file, and an entry
    // with no thumbnail.
    auto strip = [&] {
        TestHelper::on_loop(f.c->core, [&] {
            f.c->core.database().conn().prepared_exec(
                    "UPDATE attachment_cache SET size = size - thumbnail, thumbnail = NULL");
        });
        std::filesystem::remove(f.thumb_file(url));
    };
    strip();
    TestHelper::on_loop(f.c->core, [&] { f.c->core.globals.erase("client:thumbnail_pass"); });
    REQUIRE_FALSE(f.attachment(id).has_thumbnail);

    auto reopen = [&] {
        f.c.reopen();
        f.c->set_cache_dir(f.dir.path);
        settle(*f.c);
    };
    reopen();
    CHECK(f.attachment(id).has_thumbnail);
    CHECK(std::filesystem::exists(f.thumb_file(url)));

    // Once only: the next open finds the pass done, and leaves an entry without one alone.
    strip();
    reopen();
    CHECK_FALSE(f.attachment(id).has_thumbnail);
    CHECK_FALSE(std::filesystem::exists(f.thumb_file(url)));
}

TEST_CASE("Client: the sweep reconciles thumbnails", "[client][thumbnail][evict]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(400, 300));
    REQUIRE(f.attachment(id).has_thumbnail);
    auto size = f.c->attachment_cache_size(await);

    // A thumbnail whose entry has none: what a crash between writing and recording one leaves.
    auto stray = f.file("http://fs.example/file/ghost");
    stray += cache::THUMBNAIL_SUFFIX;
    std::ofstream{stray, std::ios::binary} << "no entry claims this";

    // And one gone from under its entry, which is taken out of the entry and made again: the file
    // it was made from is still good.
    std::filesystem::remove(f.thumb_file(url));
    f.rec.msg_updated.clear();

    f.c->set_cache_dir(f.dir.path);
    REQUIRE(eventually([&] { return std::filesystem::exists(f.thumb_file(url)); }));
    settle(*f.c);
    CHECK_FALSE(std::filesystem::exists(stray));
    CHECK(f.attachment(id).has_thumbnail);
    CHECK(f.c->attachment_cache_size(await) == size);

    // Reported as gone, and then as back.
    std::vector<bool> told;
    for (const auto& m : Recorder::messages(f.rec.msg_updated))
        if (m.id == id)
            told.push_back(m.attachments[0].has_thumbnail);
    CHECK(told == std::vector{false, true});
}

TEST_CASE("Client: a thumbnail found missing is made again", "[client][thumbnail]") {
    Fixture f;
    auto [id, url] = f.arrive(picture(400, 300));
    REQUIRE(f.attachment(id).has_thumbnail);
    std::filesystem::remove(f.thumb_file(url));

    CHECK(error_code([&] { f.c->attachment_thumbnail(id, 0, await); }) == err::no_thumbnail);
    settle(*f.c);
    CHECK(f.attachment(id).has_thumbnail);
    CHECK(jpeg_size(f.c->attachment_thumbnail(id, 0, await)) == std::pair{240, 240});
}

TEST_CASE("Client: the waiting cache reads answer on Core's loop", "[client][thumbnail]") {
    // Leaked if a read never answers: Core's loop is then blocked for good, and tearing the Client
    // down would wait on it, so the test would hang rather than fail.
    auto f = std::make_unique<Fixture>();
    auto data = picture(400, 300);
    auto [id, url] = f->arrive(data);
    auto thumb = f->c->attachment_thumbnail(id, 0, await);

    // Both reads, and then the thumbnail's again with its file gone, which answers by writing.
    using answers = std::
            tuple<std::vector<std::byte>, std::vector<std::byte>, std::optional<std::string_view>>;
    auto answered = std::make_shared<std::promise<answers>>();
    std::thread{[c = &*f->c, id, thumb_file = f->thumb_file(url), answered] {
        try {
            answered->set_value(TestHelper::on_loop(c->core, [&] {
                auto t = c->attachment_thumbnail(id, 0, await);
                auto d = c->attachment_data_cached(id, 0, await);
                std::filesystem::remove(thumb_file);
                return answers{std::move(t), std::move(d), error_code([&] {
                                   c->attachment_thumbnail(id, 0, await);
                               })};
            }));
        } catch (...) {
            answered->set_exception(std::current_exception());
        }
    }}.detach();

    auto got = answered->get_future();
    if (got.wait_for(10s) != std::future_status::ready) {
        (void)f.release();
        FAIL("a waiting read on Core's loop never answered");
    }
    auto [t, d, missing] = got.get();
    CHECK(t == thumb);
    CHECK(d == data);
    CHECK(missing == err::no_thumbnail);
    settle(*f->c);
    CHECK(f->attachment(id).has_thumbnail);
}
