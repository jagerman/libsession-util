#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <session/clock.hpp>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/core/error_codes.hpp>
#include <session/core/globals.hpp>
#include <session/xed25519.hpp>
#include <set>
#include <thread>

#include "test_helper.hpp"
#include "utils.hpp"

using namespace session;
using namespace session::core;
using namespace std::literals;

namespace {

/// A Core whose account was *restored* rather than generated, and which therefore owes no device
/// group: this is the state a device is in before it has joined one.
///
/// A plain `TempCore` generates its account, which now establishes a group with itself as the only
/// member -- so anything asserting on an unregistered device has to say which of the two it means.
TempCore restored_core() {
    std::array<std::byte, 32> seed{};
    random::fill(seed);
    return TempCore{core::predefined_seed{std::span<const std::byte, 32>{seed}}};
}

}  // namespace

TEST_CASE("Devices - identity", "[core][devices]") {
    TempCore c;

    SECTION("device_id is the id in hex") {
        auto id = c->devices.device_id();
        REQUIRE(id.size() == 2 * device::ID_SIZE);
        CHECK(std::all_of(id.begin(), id.end(), [](char ch) {
            return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        }));
    }

    SECTION("device_id is stable") {
        CHECK(c->devices.device_id() == c->devices.device_id());
    }

    SECTION("two independent cores have different device IDs") {
        TempCore c2;
        CHECK(c->devices.device_id() != c2->devices.device_id());
    }
}

TEST_CASE("Devices - initial state", "[core][devices]") {
    auto c = restored_core();

    SECTION("device_info defaults") {
        auto [info, is_registered] = c->devices.device_info(await);
        // Nothing held for it anywhere, so what it would publish first.
        CHECK(info.seqno == 1);
        CHECK(info.description.empty());
        CHECK_FALSE(is_registered);
    }

    SECTION("devices() is empty") {
        CHECK(c->devices.devices(true, true, true).empty());
    }

    SECTION("needs_push is false") {
        auto np = c->devices.needs_push();
        CHECK_FALSE(np.device_group);
        CHECK_FALSE(np.account_pubkey);
    }
}

TEST_CASE("Devices - update_info and same_user_fields", "[core][devices]") {
    auto c = restored_core();

    SECTION("update_info persists fields") {
        device::Info info{};
        info.type = device::Type::Session_iOS;
        info.description = "test phone";
        info.version = {1, 2, 3};

        c->devices.update_info(info, await);

        auto [got, is_registered] = c->devices.device_info(await);
        CHECK(got.seqno == 1);
        CHECK(got.type == device::Type::Session_iOS);
        CHECK(got.description == "test phone");
        CHECK(got.version == std::array<int, 3>{1, 2, 3});
        CHECK(got.state == device::State::Unregistered);
        CHECK_FALSE(is_registered);

        // Across a restart too: it is this device's own, not anything a group holds.
        auto path = c.path;
        c.core.reset();
        c.core = std::make_unique<core::Core>(path);
        CHECK(c->devices.device_info(await).first.description == "test phone");
    }

    SECTION("extra fields round-trip") {
        device::Info info{};
        info.extra["custom_key"] = std::string{"hello"};
        c->devices.update_info(info, await);

        auto [got, _] = c->devices.device_info(await);
        REQUIRE(got.extra.count("custom_key"));
        CHECK(std::get<std::string>(got.extra.at("custom_key")) == "hello");
    }

    SECTION("same_user_fields ignores state/seqno/pk_*") {
        device::Info a{}, b{};
        a.type = device::Type::Session_iOS;
        a.description = "foo";
        a.version = {1, 2, 3};
        b = a;

        CHECK(a.same_user_fields(b));

        // Differ in seqno — should still be "same" user fields
        b.seqno = 99;
        CHECK(a.same_user_fields(b));

        // Differ in description — not same
        b.seqno = a.seqno;
        b.description = "bar";
        CHECK_FALSE(a.same_user_fields(b));
    }

    SECTION("a device outside a group describing itself puts nothing in the group's list") {
        device::Info info{};
        info.description = "my device";
        c->devices.update_info(info, await);

        CHECK(c->devices.devices(true, true, true).empty());
        CHECK(c->devices.device_info(await).first.description == "my device");
    }
}

TEST_CASE(
        "Devices - this device's seqno counts on from what the swarm holds for it",
        "[core][devices]") {
    TempCore c;
    auto seqno = [&] { return c->devices.device_info(await).first.seqno; };
    auto owed = [&] { return c->devices.needs_push().device_group; };
    auto push = [&] {
        c->devices.mark_device_group_pushed(c->devices.build_device_group_message(), "h");
    };

    // Nothing held yet, so the first record is 1 however often it is described before it goes out.
    device::Info info{};
    info.description = "first";
    c->devices.update_info(info, await);
    CHECK(seqno() == 1);
    info.description = "second";
    c->devices.update_info(info, await);
    CHECK(seqno() == 1);
    push();
    CHECK(seqno() == 1);
    CHECK_FALSE(owed());

    // Each change makes the next record one past what is held, once however often it is made, and
    // a change back to what is held is no change at all.
    int64_t n = 1;
    auto changed = [&](auto&& change) {
        change();
        CHECK(seqno() == n + 1);
        CHECK(owed());
        change();
        CHECK(seqno() == n + 1);
        push();
        CHECK(seqno() == ++n);
        CHECK_FALSE(owed());
    };
    changed([&] {
        info.description = "third";
        c->devices.update_info(info, await);
    });
    changed([&] {
        info.type = device::Type::Session_Desktop;
        c->devices.update_info(info, await);
    });
    changed([&] {
        info.version = {2, 0, 0};
        c->devices.update_info(info, await);
    });
    changed([&] {
        info.extra["custom_key"] = std::string{"hello"};
        c->devices.update_info(info, await);
    });
    info.description = "fourth";
    c->devices.update_info(info, await);
    CHECK(seqno() == n + 1);
    info.description = "third";
    c->devices.update_info(info, await);
    CHECK(seqno() == n);
    CHECK_FALSE(owed());

    // New keys are a new record too.
    c->devices.rotate_device_keys();
    CHECK(seqno() == n + 1);
    CHECK(owed());
    push();
    CHECK(seqno() == n + 1);

    // And what the group holds for it is what it said.
    auto self = c->devices.device_info(await).first;
    auto held = c->devices.devices(true, false, false, self.id).at(self.id);
    CHECK(held.description == "third");
    CHECK(held.type == device::Type::Session_Desktop);
    CHECK(held.pk_x25519 == c->devices.active_device_keys().front().x25519_pub);
}

TEST_CASE("Devices - device keys", "[core][devices]") {
    TempCore c;

    SECTION("active_device_keys returns at least one key with correct sizes") {
        auto keys = c->devices.active_device_keys();
        REQUIRE_FALSE(keys.empty());
        CHECK(keys.front().x25519_pub.size() == 32);
        CHECK(keys.front().mlkem768_pub.size() == 1184);
        CHECK_FALSE(keys.front().rotated.has_value());
    }

    SECTION("rotate_device_keys produces a distinct key") {
        auto before = c->devices.active_device_keys();
        REQUIRE_FALSE(before.empty());

        c->devices.rotate_device_keys();
        auto after = c->devices.active_device_keys();

        CHECK(after.front().x25519_pub != before.front().x25519_pub);
        CHECK(after.front().mlkem768_pub != before.front().mlkem768_pub);
        CHECK_FALSE(after.front().rotated.has_value());
    }

    SECTION("after one rotation active_device_keys has two entries") {
        auto initial = c->devices.active_device_keys();  // ensure initial key exists
        REQUIRE(initial.size() == 1);
        c->devices.rotate_device_keys();
        auto keys = c->devices.active_device_keys();
        CHECK(keys.size() == 2);
        CHECK_FALSE(keys.front().rotated.has_value());
        CHECK(keys.back().rotated.has_value());
    }

    SECTION("after two rotations only the current key and the one before it are kept") {
        auto first = c->devices.active_device_keys().front().x25519_pub;
        auto second = c->devices.rotate_device_keys().x25519_pub;
        auto third = c->devices.rotate_device_keys().x25519_pub;
        auto keys = c->devices.active_device_keys();
        REQUIRE(keys.size() == 2);
        CHECK(keys[0].x25519_pub == third);
        CHECK_FALSE(keys[0].rotated.has_value());
        CHECK(keys[1].x25519_pub == second);
        CHECK(keys[1].rotated.has_value());
        CHECK(first != second);
    }
}

TEST_CASE("Devices - device group payload padding", "[core][devices]") {
    TempCore c;

    // Real keys, not random bytes: ML-KEM encapsulation is performed against each device's pubkey.
    // Rotating produces distinct valid keypairs, and the last of them stays this device's own, so
    // this Core can also decrypt whatever it encrypts below to that one.
    std::vector<device::Info> infos;
    for (int i = 0; i < 5; i++) {
        auto k = c->devices.rotate_device_keys();
        auto& info = infos.emplace_back();
        random::fill(info.id);
        info.seqno = 1;
        info.timestamp = clock_now_s();
        info.type = device::Type::Session_Desktop;
        info.description = "test device";
        info.state = device::State::Registered;
        info.version = {1, 0, 0};
        info.pk_x25519 = k.x25519_pub;
        info.pk_mlkem768 = k.mlkem768_pub;
    }

    auto encrypted_size = [&](size_t n) {
        device::map m;
        for (size_t i = 0; i < n; i++)
            m.emplace(infos[i].id, infos[i]);
        return TestHelper::encrypt_device_data(c->devices, m).size();
    };

    SECTION("the payload is padded to 2300 + 6400N") {
        device::map m;
        m.emplace(infos[0].id, infos[0]);
        auto enc = TestHelper::encrypt_device_data(c->devices, m);

        // The encrypted payload sits in the envelope's "d" field, and is the padded plaintext plus
        // the poly1305 tag.  One device is one bucket, on top of the account key allowance.
        oxenc::bt_dict_consumer env{to_string_view(enc)};
        REQUIRE(env.skip_until("d"));
        auto payload = env.consume_string_view();
        CHECK(payload.size() == 2300 + 6400 + 16);
    }

    SECTION("groups of up to 4 devices are indistinguishable by size") {
        auto one = encrypted_size(1);
        CHECK(encrypted_size(2) == one);
        CHECK(encrypted_size(3) == one);
        CHECK(encrypted_size(4) == one);

        // The 5th device crosses into the next bucket, which is expected and unavoidable — the
        // guarantee is bucketing, not constant size.
        CHECK(encrypted_size(5) > one);
    }

    SECTION("padding round-trips off again") {
        device::map m;
        for (size_t i = 2; i < 5; i++)
            m.emplace(infos[i].id, infos[i]);

        auto enc = TestHelper::encrypt_device_data(c->devices, m);
        auto plaintext = TestHelper::decrypt_device_data(c->devices, enc);

        // A bt-encoded dict always ends in 'e'; if any padding survived, it would not.
        REQUIRE_FALSE(plaintext.empty());
        CHECK(plaintext.back() == std::byte{'e'});

        // And the recovered payload really is the device dict, not a truncation of it.
        oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
        REQUIRE(btdc.skip_until("D"));
        auto devs = btdc.consume_dict_consumer();
        int count = 0;
        while (!devs.is_finished()) {
            devs.skip_until(devs.key());
            devs.consume_dict_consumer();
            count++;
        }
        CHECK(count == 3);
    }

    SECTION("a kicked device is named in the payload but is not a recipient") {
        auto ciphertexts_size = [](std::span<const std::byte> msg) {
            oxenc::bt_dict_consumer outer{msg};
            return outer.require_span<std::byte>("C").size();
        };

        device::map m;
        for (size_t i = 0; i < 4; i++)
            m.emplace(infos[i].id, infos[i]);
        auto four_registered = ciphertexts_size(TestHelper::encrypt_device_data(c->devices, m));

        // A fifth entry, kicked rather than registered.
        auto kicked = infos[4];
        kicked.state = device::State::Kicked;
        kicked.kicked = clock_now_s();
        m.emplace(kicked.id, kicked);

        auto with_kicked = TestHelper::encrypt_device_data(c->devices, m);

        // Five entries, but still only four recipients, so the ciphertext list stays in the 4
        // bucket.  Were the kicked device handed a key it would cross into the 8 bucket and grow --
        // which is what makes this an assertion about the recipient set rather than about padding.
        CHECK(ciphertexts_size(with_kicked) == four_registered);

        // And it is still named in the payload: that is how every other device learns it is gone.
        auto plaintext = TestHelper::decrypt_device_data(c->devices, with_kicked);
        oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
        REQUIRE(btdc.skip_until("D"));
        auto devs = btdc.consume_dict_consumer();
        std::string_view kicked_key{
                reinterpret_cast<const char*>(kicked.id.data()), kicked.id.size()};
        CHECK(devs.skip_until(kicked_key));
    }
}

TEST_CASE("Devices - account keys", "[core][devices]") {
    // Restored: two sections here are about what the rotation timers say for a device that is *not*
    // in a group, and a generated account is in one from the moment it exists.
    auto c = restored_core();

    SECTION("active_account_keys returns at least one key with correct sizes") {
        auto keys = c->devices.active_account_keys();
        REQUIRE_FALSE(keys.empty());
        CHECK(keys.front().x25519_pub.size() == 32);
        CHECK(keys.front().mlkem768_pub.size() == 1184);
        CHECK_FALSE(keys.front().rotated.has_value());
    }

    SECTION("rotate_account_keys produces a distinct key: newer timestamp wins") {
        auto before = c->devices.active_account_keys();
        REQUIRE(before.size() == 1);

        // Advance clock by 1s so the new key has a strictly later created timestamp and
        // deterministically wins tie-breaking (created DESC, seed ASC).
        ScopedClockOffset adv{1s};
        c->devices.rotate_account_keys();
        auto after = c->devices.active_account_keys();

        REQUIRE(after.size() == 2);
        CHECK_FALSE(after.front().rotated.has_value());
        CHECK(after.back().rotated.has_value());
        CHECK(after.front().x25519_pub != before.front().x25519_pub);
    }

    SECTION("a rotation within the same second as the key it replaces still supersedes it") {
        // Pinned to the start of a second so that both keys are created within it.
        ScopedClockOffset pin_to_next_second{
                (clock_now_s() + 1s) - std::chrono::system_clock::now()};

        // Whichever seed is lower: a rotation that a tie could undo would, after a removal, leave
        // current the key the removed device holds.  Eight in a row, since any one of them wins a
        // seed tie half the time by luck alone.
        auto before = c->devices.active_account_keys();
        REQUIRE(before.size() == 1);
        for (size_t n = 2; n <= 9; n++) {
            c->devices.rotate_account_keys();
            auto keys = c->devices.active_account_keys();
            REQUIRE(keys.size() == n);
            CHECK(keys.front().x25519_pub != before.front().x25519_pub);
            CHECK_FALSE(keys.front().rotated.has_value());
            before = keys;
        }
    }

    SECTION("keys created in the same second settle on the lower seed, in either order") {
        // What two devices' rotations crossing looks like once both have merged: the same created
        // time from different seeds.  Every device must settle on the same one.
        for (bool reversed : {false, true}) {
            auto conn = c->database().conn();
            conn.prepared_exec("DELETE FROM device_account_keys");
            std::array<std::byte, 32> low, high;
            low.fill(std::byte{0x01});
            high.fill(std::byte{0xff});
            for (auto* seed : reversed ? std::array{&low, &high} : std::array{&high, &low})
                conn.prepared_exec(
                        "INSERT INTO device_account_keys"
                        " (created, seed, pubkey_mlkem768, pubkey_x25519)"
                        " VALUES (1700000000, ?, zeroblob(1184), zeroblob(32))",
                        *seed);
            auto active = conn.prepared_get<sqlite::blob_guts<std::array<std::byte, 32>>>(
                    "SELECT seed FROM device_account_keys WHERE rotated IS NULL");
            CHECK(active == low);
        }
    }

    SECTION("after one rotation active_account_keys has two entries") {
        c->devices.active_account_keys();  // ensure initial key exists
        c->devices.rotate_account_keys();
        auto keys = c->devices.active_account_keys();
        CHECK(keys.size() == 2);
        CHECK_FALSE(keys.front().rotated.has_value());
        CHECK(keys.back().rotated.has_value());
    }

    SECTION("old key pruned after ACCOUNT_KEY_RETENTION") {
        c->devices.active_account_keys();  // ensure initial key exists
        c->devices.rotate_account_keys();
        {
            auto keys = c->devices.active_account_keys();
            CHECK(keys.size() == 2);
        }

        // Advance clock past retention window: old rotated key should be pruned.  Two seconds,
        // because a rotation made within the second its predecessor was created is stamped a
        // second ahead, and the old key's rotation time with it.
        ScopedClockOffset advance_past_retention{Devices::ACCOUNT_KEY_RETENTION + 2s};
        auto keys = c->devices.active_account_keys();
        CHECK(keys.size() == 1);
        CHECK_FALSE(keys.front().rotated.has_value());
    }

    SECTION("next_account_rotation returns nullopt when not in device group") {
        CHECK_FALSE(c->devices.next_account_rotation().has_value());
        CHECK_FALSE(c->devices.account_rotation_due());
    }

    SECTION("next_device_rotation returns nullopt when not in device group") {
        CHECK_FALSE(c->devices.next_device_rotation().has_value());
        CHECK_FALSE(c->devices.device_rotation_due());
    }
}

TEST_CASE(
        "Devices - a push confirmed after its keys were forgotten distributes no other",
        "[core][devices]") {
    TempCore c;
    auto push = c->devices.build_device_group_message();
    REQUIRE_FALSE(push.keys.empty());

    // What leaving the group does to them, while the push is still in flight.
    c->database().conn().prepared_exec("DELETE FROM device_account_keys");
    c->devices.rotate_account_keys();

    c->devices.mark_device_group_pushed(push, "h");
    CHECK(c->database().conn().prepared_get<int64_t>(
                  "SELECT distributed FROM device_account_keys") == 0);
}

TEST_CASE("Devices - link request SAS", "[core][devices][sas]") {
    SECTION("indices into Matrix's table, as the emoji were before") {
        std::array<std::byte, 16> seed;
        for (size_t i = 0; i < seed.size(); i++)
            seed[i] = std::byte(i);
        auto sas = sas_from_seed(seed);
        CHECK(sas == Sas{0, 4, 32, 0, 3, 16, 16, 1, 6, 28, 0, 2, 9, 40, 48, 2, 12, 52, 32, 3, 15});

        std::vector<std::string_view> emoji;
        for (auto i : sas)
            emoji.push_back(sas_emoji(i).emoji);
        CHECK(emoji == std::vector{"🐶"sv, "🦄"sv, "🎩"sv, "🐶"sv, "🐎"sv, "🌳"sv, "🌳"sv,
                                   "🐱"sv, "🐘"sv, "🎂"sv, "🐶"sv, "🦁"sv, "🐓"sv, "🎁"sv,
                                   "🔨"sv, "🦁"sv, "🐟"sv, "🚲"sv, "🎩"sv, "🐎"sv, "🌷"sv});
    }

    SECTION("each emoji with Matrix's description") {
        CHECK(sas_emoji(0).emoji == "🐶");
        CHECK(sas_emoji(0).description == "Dog");
        CHECK(sas_emoji(36).description == "Thumbs Up");
        CHECK(sas_emoji(63).emoji == "📌");
        CHECK(sas_emoji(63).description == "Pin");
        std::set<std::string_view> descriptions;
        for (uint8_t i = 0; i < 64; i++)
            descriptions.insert(sas_emoji(i).description);
        CHECK(descriptions.size() == 64);
        CHECK_THROWS_AS(sas_emoji(64), std::out_of_range);
    }

    SECTION("Argon2id at 64 MiB and 2 passes, as the spec says") {
        CHECK(SAS_ARGON2_OPSLIMIT == 2);
        CHECK(SAS_ARGON2_MEMLIMIT == 64 * 1024 * 1024);
        // Computed independently, from libsodium's Argon2id through PyNaCl, with the salt from
        // hashlib's BLAKE2b.
        auto plaintext = "SessionLinkEmoji test plaintext"sv;
        CHECK(oxenc::to_hex(derive_sas_seed(to_span<std::byte>(plaintext))) ==
              "419dcb7bc15bd4a8b281dee155e27bb6");
    }
}

TEST_CASE("Devices - build_link_request", "[core][devices]") {
    // Restored, not generated: asking to join a group only makes sense for a device that adopted
    // an existing account's seed.  A device that generated the account *is* the group.
    auto c = restored_core();
    TempCore group;  // only its link key is used, to encrypt to

    SECTION("returns non-empty message and 21-entry SAS") {
        auto result = TestHelper::build_link_request(*c, *group);
        CHECK_FALSE(result.message.empty());
        CHECK(result.sas.size() == 21);
        for (auto s : result.sas)
            CHECK(s < 64);
    }

    SECTION("consecutive calls produce different messages") {
        auto r1 = TestHelper::build_link_request(*c, *group);
        auto r2 = TestHelper::build_link_request(*c, *group);
        CHECK(r1.message != r2.message);
    }
}

TEST_CASE("Devices - build_account_pubkey_message", "[core][devices]") {
    TempCore c;

    SECTION("non-empty output with correct structure") {
        auto msg = c->devices.build_account_pubkey_message();
        REQUIRE_FALSE(msg.empty());

        auto dict = oxenc::bt_dict_consumer{msg};

        // "M" — mlkem768 pubkey (1184 bytes)
        CHECK(dict.require<std::string_view>("M").size() == 1184);

        // "X" — x25519 pubkey (32 bytes)
        CHECK(dict.require<std::string_view>("X").size() == 32);

        // "~" — XEd25519 signature (64 bytes)
        CHECK(dict.require<std::string_view>("~").size() == 64);
    }

    SECTION("M and X match active account keys") {
        auto keys = c->devices.active_account_keys();
        REQUIRE_FALSE(keys.empty());

        auto msg = c->devices.build_account_pubkey_message();
        auto dict = oxenc::bt_dict_consumer{msg};

        auto M = dict.require<std::string_view>("M");
        auto X = dict.require<std::string_view>("X");

        CHECK(std::memcmp(M.data(), keys.front().mlkem768_pub.data(), 1184) == 0);
        CHECK(std::memcmp(X.data(), keys.front().x25519_pub.data(), 32) == 0);
    }

    SECTION("signature verifies against account x25519 pubkey") {
        auto msg = c->devices.build_account_pubkey_message();
        auto dict = oxenc::bt_dict_consumer{msg};

        dict.require<std::string_view>("M");
        dict.require<std::string_view>("X");

        // Use require_signature to correctly extract the signed body (everything in the dict
        // before the "~" key) and the signature value.
        auto x25519_pub = c->globals.session_id().template subspan<1>();  // skip 0x05 prefix
        bool sig_valid = false;
        dict.require_signature(
                "~", [&](std::span<const std::byte> body, std::span<const std::byte> sig) {
                    sig_valid =
                            sig.size() == 64 && xed25519::verify(sig.first<64>(), x25519_pub, body);
                });
        CHECK(sig_valid);
    }
}

TEST_CASE("Devices - establishing the group", "[core][devices]") {

    SECTION("a generated account establishes a group with itself") {
        TempCore c;

        auto [info, registered] = c->devices.device_info(await);
        CHECK(registered);
        CHECK(info.state == device::State::Registered);
        CHECK(info.id == c->devices.device_info(await).first.id);

        // Exactly one device, and it is us.
        auto devs = c->devices.devices(true, true, true);
        REQUIRE(devs.size() == 1);
        CHECK(devs.begin()->first == info.id);

        // The whole point: a registered device is one that `needs_push` will speak for.  Before
        // this existed, nothing ever registered a device, so nothing was ever owed a push and no
        // group could come into being.
        CHECK(c->devices.needs_push().device_group);

        // The group payload carries the account's shared key seeds, so one is minted here.
        auto keys = c->devices.active_account_keys();
        REQUIRE(keys.size() == 1);
        CHECK_FALSE(keys.front().rotated.has_value());
    }

    SECTION("a restored account does not") {
        auto c = restored_core();

        auto [info, registered] = c->devices.device_info(await);
        CHECK_FALSE(registered);
        CHECK(c->devices.devices(true, true, true).empty());
        CHECK_FALSE(c->devices.needs_push().device_group);
    }

    SECTION("it survives a restart, and does not happen twice") {
        std::optional<device::Id> first_id;
        int64_t first_seqno = 0;
        auto path = std::filesystem::temp_directory_path() /
                    fmt::format("{}.db", random::unique_id("test_estab", 7));
        {
            Core c{path};
            auto [info, registered] = c.devices.device_info(await);
            REQUIRE(registered);
            first_id = info.id;
            first_seqno = info.seqno;
        }
        {
            // Reopened: the flag was cleared the first time, so this must not re-register or
            // re-mint anything -- a second establish would bump the seqno and mint a second key.
            Core c{path};
            auto [info, registered] = c.devices.device_info(await);
            CHECK(registered);
            CHECK(info.id == *first_id);
            CHECK(info.seqno == first_seqno);
            CHECK(c.devices.active_account_keys().size() == 1);
        }
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
}

TEST_CASE("Devices - a removal cannot be undone by a message", "[core][devices]") {
    TempCore c;

    // A second device, with keys this core holds so that what we encrypt below is readable back.
    auto k = c->devices.rotate_device_keys();
    device::Info other{};
    random::fill(other.id);
    other.seqno = 1;
    other.timestamp = clock_now_s();
    other.type = device::Type::Session_Android;
    other.description = "other device";
    other.state = device::State::Registered;
    other.version = {1, 0, 0};
    other.pk_x25519 = k.x25519_pub;
    other.pk_mlkem768 = k.mlkem768_pub;

    auto [self, registered] = c->devices.device_info(await);
    REQUIRE(registered);

    auto deliver = [&](const device::map& m) {
        TestHelper::receive_device_group_message(
                c->devices, TestHelper::encrypt_device_data(c->devices, m));
    };
    auto state_of = [&](const device::Id& id) {
        auto devs = c->devices.devices(true, true, true);
        auto found = devs.find(id);
        REQUIRE(found != devs.end());
        return found->second;
    };

    // It joins.
    deliver({{self.id, self}, {other.id, other}});
    REQUIRE(state_of(other.id).state == device::State::Registered);

    // It is removed, a while ago.
    auto kicked_at = clock_now_s() - 1h;
    auto gone = other;
    gone.state = device::State::Kicked;
    gone.kicked = kicked_at;
    deliver({{self.id, self}, {gone.id, gone}});

    auto after_kick = state_of(other.id);
    REQUIRE(after_kick.state == device::State::Kicked);
    REQUIRE(after_kick.kicked == kicked_at);

    // Now it pushes itself back in with a higher seqno, which it can do: it still holds the account
    // seed, so it can sign and encrypt a message everyone accepts.
    auto returning = other;
    returning.seqno = 5;
    returning.description = "back again";
    deliver({{self.id, self}, {returning.id, returning}});

    auto after = state_of(other.id);

    // Refused: still removed, and none of its claims adopted.
    CHECK(after.state == device::State::Kicked);
    CHECK(after.description == "other device");

    // And restated rather than merely ignored: the tombstone moves to the front of the removed
    // list, and we owe a push so that devices which never saw the removal learn of it.
    REQUIRE(after.kicked.has_value());
    CHECK(*after.kicked > kicked_at);
    CHECK(c->devices.needs_push().device_group);
}

TEST_CASE(
        "Devices - two records at one seqno settle the same way either way round",
        "[core][devices]") {
    // Only a bug or a forgery produces two different records at the same state and seqno -- a
    // device bumps its own seqno whenever it changes.  What matters is that two devices seeing them
    // in opposite orders still end up holding the same thing, rather than each keeping whichever
    // arrived first and disagreeing from then on.
    auto make_variant = [](const device::Info& base, std::string description) {
        auto v = base;
        v.description = std::move(description);
        return v;
    };

    // Every field fixed, including the pubkeys: the tie is broken on the encoded record, so a
    // record that differs between the two runs is two different questions rather than one asked
    // twice. These keys are never used to decrypt anything -- this core reads the message as
    // itself.
    auto settle = [&](bool reversed) {
        TempCore c;

        device::Info other{};
        for (size_t i = 0; i < other.id.size(); i++)
            other.id[i] = std::byte{static_cast<unsigned char>(i)};
        other.seqno = 1;
        other.timestamp = std::chrono::sys_seconds{1700000000s};
        other.type = device::Type::Session_Android;
        other.state = device::State::Registered;
        other.version = {1, 0, 0};
        other.pk_x25519.fill(std::byte{0x11});
        other.pk_mlkem768.fill(std::byte{0x22});

        auto [self, registered] = c->devices.device_info(await);
        REQUIRE(registered);

        auto a = make_variant(other, "first description");
        auto b = make_variant(other, "second description");
        if (reversed)
            std::swap(a, b);

        for (const auto& v : {a, b})
            TestHelper::receive_device_group_message(
                    c->devices,
                    TestHelper::encrypt_device_data(c->devices, {{self.id, self}, {v.id, v}}));

        auto devs = c->devices.devices(true, true, true);
        auto found = devs.find(other.id);
        REQUIRE(found != devs.end());
        return found->second.description;
    };

    CHECK(settle(false) == settle(true));
}

TEST_CASE("Devices - a tombstone for an unknown device is kept", "[core][devices]") {
    TempCore c;

    // Keys this core holds, so that the message we build is readable back and the returning record
    // below is a usable recipient.
    auto k = c->devices.rotate_device_keys();

    auto [self, registered] = c->devices.device_info(await);
    REQUIRE(registered);

    auto deliver = [&](const device::map& m) {
        TestHelper::receive_device_group_message(
                c->devices, TestHelper::encrypt_device_data(c->devices, m));
    };
    auto state_of = [&](const device::Id& id) {
        auto devs = c->devices.devices(true, true, true);
        auto found = devs.find(id);
        REQUIRE(found != devs.end());
        return found->second;
    };

    // A removal for a device we have never held a record of -- which is what a device joining after
    // the removal sees, since the group carries the tombstone but nothing else about it.
    auto kicked_at = clock_now_s() - 1h;
    device::Info gone{};
    random::fill(gone.id);
    gone.state = device::State::Kicked;
    gone.kicked = kicked_at;
    deliver({{self.id, self}, {gone.id, gone}});

    // Stored, rather than dropped for want of a row to update: the tombstone is the whole point of
    // the entry, and needs no details to do its job.
    auto after_kick = state_of(gone.id);
    CHECK(after_kick.state == device::State::Kicked);
    CHECK(after_kick.kicked == kicked_at);

    // And it does its job: the removed device cannot talk its way back in, exactly as it could not
    // for a device that saw the removal first.
    auto returning = gone;
    returning.state = device::State::Registered;
    returning.kicked.reset();
    returning.seqno = 5;
    returning.timestamp = clock_now_s();
    returning.description = "back again";
    returning.type = device::Type::Session_Android;
    returning.version = {1, 0, 0};
    returning.pk_x25519 = k.x25519_pub;
    returning.pk_mlkem768 = k.mlkem768_pub;
    deliver({{self.id, self}, {returning.id, returning}});

    auto after = state_of(gone.id);
    CHECK(after.state == device::State::Kicked);
    CHECK(after.description != "back again");
}

TEST_CASE("Devices - a departure is a tombstone of its own kind", "[core][devices]") {
    TempCore c;
    auto k = c->devices.rotate_device_keys();

    auto [self, registered] = c->devices.device_info(await);
    REQUIRE(registered);

    auto deliver = [&](const device::map& m) {
        TestHelper::receive_device_group_message(
                c->devices, TestHelper::encrypt_device_data(c->devices, m));
    };
    auto state_of = [&](const device::Id& id) {
        auto devs = c->devices.devices(true, true, true);
        auto found = devs.find(id);
        REQUIRE(found != devs.end());
        return found->second;
    };
    auto tombstone = [&](const device::Id& id, device::State state, auto when) {
        device::Info t{};
        t.id = id;
        t.state = state;
        t.kicked = when;
        return t;
    };

    device::Id id;
    random::fill(id);
    auto t0 = clock_now_s() - 3h;
    auto t1 = clock_now_s() - 2h;
    auto t2 = clock_now_s() - 1h;

    // It leaves.
    deliver({{self.id, self}, {id, tombstone(id, device::State::Left, t1)}});
    CHECK(state_of(id).state == device::State::Left);
    CHECK(state_of(id).kicked == t1);

    // And is written back as a departure, which is all its tombstone says.
    auto plaintext = TestHelper::decrypt_device_data(
            c->devices,
            TestHelper::encrypt_device_data(c->devices, c->devices.devices(true, true, true)));
    oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
    REQUIRE(btdc.skip_until("D"));
    auto devs = btdc.consume_dict_consumer();
    REQUIRE(devs.skip_until(std::string_view{reinterpret_cast<const char*>(id.data()), id.size()}));
    auto written = devs.consume_dict_consumer();
    CHECK(written.require<int64_t>("l") == t1.time_since_epoch().count());
    CHECK(written.is_finished());

    // A removal beats it, even one timestamped earlier: a device that left and was then removed
    // must read as removed everywhere, or it would never be told.
    deliver({{self.id, self}, {id, tombstone(id, device::State::Kicked, t0)}});
    CHECK(state_of(id).state == device::State::Kicked);
    CHECK(state_of(id).kicked == t0);

    // A later departure does not undo it.
    deliver({{self.id, self}, {id, tombstone(id, device::State::Left, t2)}});
    CHECK(state_of(id).state == device::State::Kicked);
    CHECK(state_of(id).kicked == t0);

    // Between removals the later wins, and an older one changes nothing.
    deliver({{self.id, self}, {id, tombstone(id, device::State::Kicked, t2)}});
    CHECK(state_of(id).kicked == t2);
    deliver({{self.id, self}, {id, tombstone(id, device::State::Kicked, t1)}});
    CHECK(state_of(id).kicked == t2);

    // A device that left cannot re-add itself any more than a removed one can.
    device::Id leaver;
    random::fill(leaver);
    deliver({{self.id, self}, {leaver, tombstone(leaver, device::State::Left, t1)}});
    device::Info returning{};
    returning.id = leaver;
    returning.state = device::State::Registered;
    returning.seqno = 5;
    returning.timestamp = clock_now_s();
    returning.description = "back again";
    returning.type = device::Type::Session_Android;
    returning.version = {1, 0, 0};
    returning.pk_x25519 = k.x25519_pub;
    returning.pk_mlkem768 = k.mlkem768_pub;
    deliver({{self.id, self}, {leaver, returning}});
    CHECK(state_of(leaver).state == device::State::Left);
    CHECK(state_of(leaver).description != "back again");
    CHECK(state_of(leaver).kicked > t1);
}

TEST_CASE("Devices - a single-recipient group is readable", "[core][devices]") {
    TempCore c;

    // The common case: an account with one device, which is what establishing a group produces.
    // With one recipient every other slot in the message is padding, so nothing else can stand in
    // for a real entry that was overwritten.
    auto [self, registered] = c->devices.device_info(await);
    REQUIRE(registered);

    auto enc = TestHelper::encrypt_device_data(c->devices, device::map{{self.id, self}});
    auto plain = TestHelper::decrypt_device_data(c->devices, enc);

    REQUIRE_FALSE(plain.empty());
    oxenc::bt_dict_consumer btdc{to_string_view(plain)};
    REQUIRE(btdc.skip_until("D"));
    auto devs = btdc.consume_dict_consumer();
    std::string_view self_key{reinterpret_cast<const char*>(self.id.data()), self.id.size()};
    CHECK(devs.skip_until(self_key));
}

namespace {

/// An account's existing device, and a second one on the same account asking to join it.
struct Linking {
    // What each side is told.  Declared first so they outlive the Cores that report to them.
    DeviceEventsRecorder events;
    DeviceEventsRecorder applicant_events;

    TempCore core{reporting_to(events)};  // generated, so it is in the group and can admit others
    std::array<std::byte, 32> seed = seed_of(core);
    TempCore applicant{
            core::predefined_seed{std::span<const std::byte, 32>{seed}},
            reporting_to(applicant_events)};

    static core::callbacks reporting_to(DeviceEventsRecorder& r) {
        core::callbacks cb;
        cb.devices = &r;
        return cb;
    }

    static std::array<std::byte, 32> seed_of(TempCore& c) {
        std::array<std::byte, 32> out;
        auto s = c->globals.account_seed();
        std::ranges::copy(std::as_bytes(s.seed()), out.begin());
        return out;
    }

    static device::Id id_of(TempCore& c) {
        auto hex = c->devices.device_id();
        device::Id id;
        oxenc::from_hex(hex.begin(), hex.end(), reinterpret_cast<unsigned char*>(id.data()));
        return id;
    }

    device::Id applicant_id() { return id_of(applicant); }

    // The applicant's request, as the existing device receives it.  Whole seconds, because that is
    // what the deadline is stored in, so a test can compare it exactly.
    auto
    ask(std::chrono::sys_seconds expiry = std::chrono::floor<std::chrono::seconds>(clock_now_s()) +
                                          10min,
        std::string hash = "L1") {
        auto req = TestHelper::build_link_request(*applicant, *core);
        TestHelper::deliver_device_message(*core, req.message, expiry, std::move(hash));
        return req;
    }

    // The existing device's group, as the applicant sees it once it has fetched a group message:
    // what it asks to join.  A completed fetch, so the applicant knows where it stands --
    // GroupsVisible -- before it asks.
    device::GroupId show_group() {
        TestHelper::deliver_device_message(
                *applicant,
                core->devices.build_device_group_message().message,
                std::chrono::floor<std::chrono::seconds>(clock_now_s()) + Devices::DEVICE_GROUP_TTL,
                "G0");
        auto group = TestHelper::group_id(*core);
        REQUIRE(group);
        return *group;
    }

    device::Info state_of_applicant() {
        auto devs = core->devices.devices(true, true, true);
        auto found = devs.find(applicant_id());
        REQUIRE(found != devs.end());
        return found->second;
    }

    // The applicant asks, is accepted here, reads the group message admitting it, and has its user
    // confirm the SAS, leaving a group of two.
    void admit() {
        ask();
        REQUIRE(core->devices.accept_request(events.added.at(0).id, await));
        TestHelper::deliver_device_message(
                *applicant,
                core->devices.build_device_group_message().message,
                std::chrono::floor<std::chrono::seconds>(clock_now_s()) + 10min,
                "G1");
        REQUIRE(applicant->devices.confirm_link(await));
        REQUIRE(applicant->devices.device_info(await).second);
    }
};

}  // namespace

TEST_CASE(
        "Devices - a link request is listed with its SAS and the swarm's deadline",
        "[core][devices][linking]") {
    Linking l;
    auto expiry = std::chrono::floor<std::chrono::seconds>(clock_now_s()) + 7min;
    auto sent = l.ask(expiry);

    auto incoming = l.core->devices.incoming_link_requests(await);
    REQUIRE(incoming.size() == 1);
    CHECK(incoming[0].sas == sent.sas);
    CHECK(incoming[0].expires == expiry);
    CHECK(incoming[0].status == device::LinkStatus::Pending);
    CHECK(oxenc::to_hex(incoming[0].device.id) == l.applicant->devices.device_id());

    // One id per request for the whole session, however many times it is read.
    CHECK(l.core->devices.incoming_link_requests(await)[0].id == incoming[0].id);
    CHECK(l.core->devices.link_requests(await)[0].id == incoming[0].id);
}

TEST_CASE("Devices - accepting a request admits the device, once", "[core][devices][linking]") {
    Linking l;
    l.ask();
    auto id = l.core->devices.incoming_link_requests(await).at(0).id;

    CHECK(l.core->devices.accept_request(id, await));
    CHECK(l.state_of_applicant().state == device::State::Registered);

    // Kept, not removed: it is the request most worth being able to look back at.
    CHECK(l.core->devices.incoming_link_requests(await).empty());
    auto all = l.core->devices.link_requests(await);
    REQUIRE(all.size() == 1);
    CHECK(all[0].status == device::LinkStatus::Accepted);

    // Carried by the next push as a transition to broadcast, which is how every other device hears
    // of it.  Asked of the message rather than of needs_push(), which a fresh account's first push
    // already makes true whether or not anything was accepted.
    auto push = l.core->devices.build_device_group_message();
    CHECK(std::ranges::any_of(
            push.broadcast, [&](const auto& b) { return b.first == l.applicant_id(); }));

    CHECK_FALSE(l.core->devices.accept_request(id, await));
}

TEST_CASE(
        "Devices - ignoring a request is local and leaves the device pending",
        "[core][devices][linking]") {
    Linking l;
    l.ask();
    auto id = l.core->devices.incoming_link_requests(await).at(0).id;

    CHECK(l.core->devices.ignore_request(id, await));
    CHECK(l.core->devices.incoming_link_requests(await).empty());
    CHECK(l.core->devices.link_requests(await).at(0).status == device::LinkStatus::Ignored);

    // Pending rather than removed or kicked, so the same request redelivered does not prompt again
    // but a real retry from the applicant still can.
    CHECK(l.state_of_applicant().state == device::State::Pending);

    CHECK_FALSE(l.core->devices.ignore_request(id, await));
    CHECK_FALSE(l.core->devices.accept_request(id, await));
}

TEST_CASE("Devices - a request past its deadline cannot be accepted", "[core][devices][linking]") {
    Linking l;
    auto expiry = std::chrono::floor<std::chrono::seconds>(clock_now_s()) - 1s;
    l.ask(expiry);

    CHECK(l.core->devices.incoming_link_requests(await).empty());

    auto all = l.core->devices.link_requests(await);
    REQUIRE(all.size() == 1);
    CHECK(all[0].status == device::LinkStatus::Pending);
    CHECK(all[0].expired(std::chrono::system_clock::now()));
    CHECK_FALSE(l.core->devices.accept_request(all[0].id, await));
}

TEST_CASE("Devices - a resent request replaces the one on screen", "[core][devices][linking]") {
    Linking l;
    auto first = l.ask();
    auto first_id = l.core->devices.incoming_link_requests(await).at(0).id;

    auto second = l.ask(std::chrono::floor<std::chrono::seconds>(clock_now_s()) + 10min, "L2");
    REQUIRE(second.sas != first.sas);

    // One live request, and it is the new one: a user comparing emoji must be shown the SAS of the
    // record that would actually be admitted.
    auto incoming = l.core->devices.incoming_link_requests(await);
    REQUIRE(incoming.size() == 1);
    CHECK(incoming[0].id != first_id);
    CHECK(incoming[0].sas == second.sas);

    auto all = l.core->devices.link_requests(await);
    REQUIRE(all.size() == 2);
    CHECK(all[1].status == device::LinkStatus::Superseded);

    CHECK_FALSE(l.core->devices.accept_request(first_id, await));
    CHECK(l.core->devices.accept_request(incoming[0].id, await));
}

TEST_CASE(
        "Devices - forgetting requests never takes one still waiting", "[core][devices][linking]") {
    Linking l;
    l.ask();
    auto id = l.core->devices.incoming_link_requests(await).at(0).id;

    std::vector<int> ids{id, id + 1000};  // the second was never handed out
    CHECK(l.core->devices.forget_link_requests(ids, await) == 0);
    CHECK(l.core->devices.link_requests(await).size() == 1);

    l.core->devices.ignore_request(id, await);
    CHECK(l.core->devices.forget_link_requests(ids, await) == 1);
    CHECK(l.core->devices.link_requests(await).empty());
}

TEST_CASE("Devices - a link request id is never handed out twice", "[core][devices][linking]") {
    Linking l;
    l.ask();
    auto first = l.core->devices.incoming_link_requests(await).at(0).id;
    l.core->devices.ignore_request(first, await);

    // Forgotten, which takes away the row holding the highest id: the one row whose id an insert
    // would otherwise take next.
    REQUIRE(l.core->devices.forget_link_requests(std::vector{first}, await) == 1);
    REQUIRE(l.core->devices.link_requests(await).empty());

    l.ask(std::chrono::floor<std::chrono::seconds>(clock_now_s()) + 10min, "L2");
    auto incoming = l.core->devices.incoming_link_requests(await);
    REQUIRE(incoming.size() == 1);
    CHECK(incoming[0].id != first);
    CHECK_THROWS_AS(l.core->devices.accept_request(first, await), std::invalid_argument);
}

TEST_CASE("Devices - an id this session never handed out is an error", "[core][devices][linking]") {
    Linking l;
    CHECK_THROWS_AS(l.core->devices.accept_request(12345, await), std::invalid_argument);
    CHECK_THROWS_AS(l.core->devices.ignore_request(12345, await), std::invalid_argument);
}

namespace {
auto in(std::chrono::minutes m) {
    return std::chrono::floor<std::chrono::seconds>(clock_now_s()) + m;
}

// For what happens with no call to wait on.  `done` runs on Core's loop, which is the thread that
// writes the recorders it reads.
template <typename F>
bool eventually(Core& core, F done) {
    auto give_up = std::chrono::steady_clock::now() + 5s;
    while (!core.call_get(done)) {
        if (std::chrono::steady_clock::now() > give_up)
            return false;
        std::this_thread::sleep_for(20ms);
    }
    return true;
}
}  // namespace

TEST_CASE(
        "Devices events - a request is announced once, by the fetch that brought it",
        "[core][devices][linking][events]") {
    Linking l;
    auto sent = l.ask();

    REQUIRE(l.events.added.size() == 1);
    CHECK(l.events.added[0].sas == sent.sas);

    // Neither reading it nor fetching again announces it a second time.
    l.core->devices.incoming_link_requests(await);
    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.added.size() == 1);

    // Where this device stands became known with the first fetch, and is not told again by later
    // ones that change nothing.
    CHECK(l.events.membership == std::vector{device::Membership::InGroup});
}

TEST_CASE(
        "Devices events - nothing is announced before the first fetch",
        "[core][devices][linking][events]") {
    Linking l;
    auto req = TestHelper::build_link_request(*l.applicant, *l.core);

    // Stored, as a request left over from before a restart would be, but the swarm not yet asked.
    TestHelper::deliver_device_message(*l.core, req.message, in(10min), "L1", /*is_final=*/false);

    // A local change reports what it can -- and a request is not something it can report yet.
    device::Info info{};
    info.description = "renamed";
    l.core->devices.update_info(info, await);
    CHECK(l.events.added.empty());

    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.added.size() == 1);
}

TEST_CASE(
        "Devices events - a request the application already read is not announced",
        "[core][devices][linking][events]") {
    Linking l;
    auto req = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(*l.core, req.message, in(10min), "L1", /*is_final=*/false);

    // Drawn from before the fetch: the application has it, so the fetch must not hand it over
    // twice.
    REQUIRE(l.core->devices.incoming_link_requests(await).size() == 1);
    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.added.empty());
}

TEST_CASE(
        "Devices events - a request read after it closed is not reported closed",
        "[core][devices][linking][events]") {
    Linking l;
    auto first = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(*l.core, first.message, in(10min), "L1", /*is_final=*/false);
    auto second = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(
            *l.core, second.message, in(10min), "L2", /*is_final=*/false);

    // The superseded one is there to be read, and reads as superseded.
    REQUIRE(l.core->devices.link_requests(await).size() == 2);
    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.ended.empty());
}

TEST_CASE(
        "Devices events - a resend closes the old prompt before opening the new one",
        "[core][devices][linking][events]") {
    Linking l;
    l.ask();
    auto first = l.events.added.at(0).id;

    auto second = l.ask(in(10min), "L2");

    REQUIRE(l.events.ended.size() == 1);
    CHECK(l.events.ended[0] == std::pair{first, device::LinkRequestEnd::Superseded});
    REQUIRE(l.events.added.size() == 2);
    CHECK(l.events.added[1].id != first);
    CHECK(l.events.added[1].sas == second.sas);

    std::vector<std::string> prompts;
    for (const auto& e : l.events.order)
        if (e == "added" || e == "ended")
            prompts.push_back(e);
    CHECK(prompts == std::vector<std::string>{"added", "ended", "added"});
}

TEST_CASE(
        "Devices events - acceptance by another device closes the prompt here",
        "[core][devices][linking][events]") {
    Linking l;
    l.ask();
    auto id = l.events.added.at(0).id;

    // Another device admitted it, and its group message says so.
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto admitted = l.state_of_applicant();
    admitted.state = device::State::Registered;
    auto group = TestHelper::encrypt_device_data(
            l.core->devices, {{self.id, self}, {admitted.id, admitted}});
    TestHelper::deliver_device_message(*l.core, group, in(10min), "G1");

    REQUIRE(l.events.ended.size() == 1);
    CHECK(l.events.ended[0] == std::pair{id, device::LinkRequestEnd::Accepted});
    REQUIRE(!l.events.replaced.empty());
    CHECK(l.events.replaced.back().at(l.applicant_id()).state == device::State::Registered);
}

TEST_CASE(
        "Devices events - another device joining or leaving the group is a notice",
        "[core][devices][events]") {
    Linking l;
    l.ask();
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto deliver = [&](const device::Info& applicant, std::string hash) {
        TestHelper::deliver_device_message(
                *l.core,
                TestHelper::encrypt_device_data(
                        l.core->devices, {{self.id, self}, {applicant.id, applicant}}),
                in(10min),
                std::move(hash));
    };

    // Admitted by another device.
    auto admitted = l.state_of_applicant();
    admitted.state = device::State::Registered;
    deliver(admitted, "G1");
    REQUIRE(l.events.members.size() == 1);
    CHECK(l.events.members[0].id == l.applicant_id());
    CHECK(l.events.members[0].state == device::State::Registered);

    // The notice, then the list to redraw.
    auto member = std::ranges::find(l.events.order, "member");
    REQUIRE(member != l.events.order.end());
    CHECK(std::ranges::find(member, l.events.order.end(), "replaced") != l.events.order.end());

    auto gone = admitted;
    gone.kicked = clock_now_s();
    SECTION("removed elsewhere") {
        gone.state = device::State::Kicked;
        deliver(gone, "G2");
        REQUIRE(l.events.members.size() == 2);
        CHECK(l.events.members[1].state == device::State::Kicked);
    }
    SECTION("left") {
        gone.state = device::State::Left;
        deliver(gone, "G2");
        REQUIRE(l.events.members.size() == 2);
        CHECK(l.events.members[1].state == device::State::Left);
    }
}

TEST_CASE(
        "Devices events - no notice for a change made here, or for a new group's members",
        "[core][devices][events]") {
    Linking l;

    // Accepted here, and the applicant admitted: neither side has news of the other.
    l.admit();
    CHECK(l.events.members.empty());
    CHECK(l.applicant_events.members.empty());

    // Removed here.
    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.members.empty());

    // A tombstone for a device this one never knew of says nothing about the group it knew.
    auto [self, registered] = l.core->devices.device_info(await);
    device::Info stranger{};
    random::fill(stranger.id);
    stranger.state = device::State::Kicked;
    stranger.kicked = clock_now_s();
    TestHelper::deliver_device_message(
            *l.core,
            TestHelper::encrypt_device_data(
                    l.core->devices, {{self.id, self}, {stranger.id, stranger}}),
            in(10min),
            "G9");
    CHECK(l.events.members.empty());
}

TEST_CASE(
        "Devices events - an unanswered request closes when its deadline passes",
        "[core][devices][linking][events]") {
    Linking l;
    l.ask(in(1min));
    auto id = l.events.added.at(0).id;

    ScopedClockOffset later{2min};
    TestHelper::finish_fetch(*l.core);

    REQUIRE(l.events.ended.size() == 1);
    CHECK(l.events.ended[0] == std::pair{id, device::LinkRequestEnd::Expired});
}

// Deadlines are stored in whole seconds, so these land somewhere between half a second and a second
// and a half out.
TEST_CASE(
        "Devices events - a deadline closes the prompt with no fetch to notice it",
        "[core][devices][linking][events]") {
    Linking l;
    auto req = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(*l.core, req.message, clock_now_ms() + 1500ms, "L1");
    auto id = l.events.added.at(0).id;

    REQUIRE(eventually(*l.core, [&] { return !l.events.ended.empty(); }));
    CHECK(l.events.ended[0] == std::pair{id, device::LinkRequestEnd::Expired});
}

TEST_CASE(
        "Devices events - a request read rather than announced still closes at its deadline",
        "[core][devices][linking][events]") {
    Linking l;
    auto req = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(
            *l.core, req.message, clock_now_ms() + 1500ms, "L1", /*is_final=*/false);
    auto id = l.core->devices.incoming_link_requests(await).at(0).id;

    REQUIRE(eventually(*l.core, [&] { return !l.events.ended.empty(); }));
    CHECK(l.events.ended[0] == std::pair{id, device::LinkRequestEnd::Expired});
}

TEST_CASE(
        "Devices events - ignoring here is not reported back", "[core][devices][linking][events]") {
    Linking l;
    l.ask();

    CHECK(l.core->devices.ignore_request(l.events.added.at(0).id, await));
    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.ended.empty());
}

TEST_CASE(
        "Devices events - accepting here reports the device list, not a closed request",
        "[core][devices][linking][events]") {
    Linking l;
    l.ask();

    // The list changed, which other views need to hear; the request closing is something only the
    // caller was waiting on, and it knows.
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.ended.empty());
    REQUIRE(l.events.replaced.size() == 1);
    CHECK(l.events.replaced[0].at(l.applicant_id()).state == device::State::Registered);
}

TEST_CASE(
        "Devices events - a link request alone does not change the device list",
        "[core][devices][linking][events]") {
    Linking l;
    l.ask();
    CHECK(l.events.replaced.empty());
}

TEST_CASE(
        "Devices events - a removal is reported once, not every time it is restated",
        "[core][devices][events]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);

    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto gone = l.applicant->devices.device_info(await).first;
    gone.state = device::State::Kicked;
    gone.kicked = std::chrono::floor<std::chrono::seconds>(clock_now_s()) - 1h;
    device::map group{{self.id, self}, {gone.id, gone}};

    TestHelper::deliver_device_message(
            *l.core, TestHelper::encrypt_device_data(l.core->devices, group), in(10min), "G1");
    REQUIRE(l.events.replaced.size() == 1);
    CHECK(l.events.replaced[0].at(gone.id).state == device::State::Kicked);

    // Every group message carries the group's recent tombstones.
    TestHelper::deliver_device_message(
            *l.core, TestHelper::encrypt_device_data(l.core->devices, group), in(10min), "G2");
    CHECK(l.events.replaced.size() == 1);
}

TEST_CASE(
        "Devices events - a device hears it was admitted, not that it asked",
        "[core][devices][linking][events]") {
    Linking l;
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE(l.applicant_events.membership == std::vector{device::Membership::NoGroup});
    l.applicant_events.membership.clear();

    // Its own request has it Requesting, which it knows: it is the one asking.
    l.ask();
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant_events.membership.empty());

    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    auto group = l.core->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.applicant, group, in(10min), "G1");

    // Approved, which it hears wherever its user is, but not in until they confirm the SAS.
    CHECK(l.applicant_events.membership == std::vector{device::Membership::Approved});
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant_events.membership ==
          std::vector{device::Membership::Approved, device::Membership::InGroup});
}

namespace {

using Asked = std::optional<Expected<Devices::OutgoingLinkRequest>>;

// Whether `r` is the fetch of the device namespace alone that asking to join begins with, rather
// than an ordinary poll.
bool is_device_fetch(const MockNetwork::SentRequest& r) {
    if (r.request.endpoint != "batch")
        return false;
    auto reqs = push_requests(r);
    return reqs.size() == 1 && reqs[0]["params"]["namespace"] == 21;
}

using Held = std::vector<std::pair<std::vector<std::byte>, std::string>>;

// Answers the fetch asking to join begins with, as a swarm holding `held` -- messages and their
// hashes -- beyond what the device already has; or fails it, as an unreachable swarm would.
size_t answer_fetch(TempCore& c, MockNetwork& net, const Held& held = {}, bool reached = true) {
    auto answered = answer_requests(
            net,
            is_device_fetch,
            [&](MockNetwork::SentRequest& r) {
                if (!reached)
                    return r.callback(false, true, 0, {}, std::nullopt);
                nlohmann::json messages = nlohmann::json::array();
                for (const auto& [data, hash] : held)
                    messages.push_back(
                            {{"data", oxenc::to_base64(to_string_view(data))},
                             {"hash", hash},
                             {"expiry", epoch_ms(clock_now_ms() + 10min)}});
                nlohmann::json result{
                        {"code", 200}, {"body", {{"messages", messages}, {"more", false}}}};
                r.callback(true, false, 200, {}, nlohmann::json{{"results", {result}}}.dump());
            },
            1);
    TestHelper::drain(*c);
    return answered;
}

// Asks for a link from `c` and runs the job, answering the fetch it begins with as a swarm holding
// nothing new, so that the upload has been sent by the time this returns.  What it answers lands in
// `into`, once the upload is answered.
void request_link(TempCore& c, const device::GroupId& group, Asked& into) {
    c->devices.request_link(
            group, [&into](Expected<Devices::OutgoingLinkRequest> r) { into = std::move(r); });
    TestHelper::drain(*c);
    if (auto* net = dynamic_cast<MockNetwork*>(c->network()))
        answer_fetch(c, *net);
}

// The applicant asks to join the existing device's group, having first seen it in the swarm.
void request_link(Linking& l, Asked& into) {
    request_link(l.applicant, l.show_group(), into);
}

bool same(const Devices::OutgoingLinkRequest& a, const Devices::OutgoingLinkRequest& b) {
    return a.sas == b.sas && a.expires == b.expires;
}

// The link request carried by the oldest upload not yet answered.  Read before answering it, since
// answering takes it off the list.
std::vector<std::byte> uploaded(MockNetwork& net) {
    auto sent = pushes(net);
    REQUIRE(!sent.empty());
    auto store = push_requests(*sent.front())[0]["params"];
    return to_vector<std::byte>(oxenc::from_base64(store["data"].get<std::string_view>()));
}

// Answers the oldest upload not yet answered as the swarm would: storing it, or refusing it.
void answer_upload(TempCore& c, MockNetwork& net, bool stored) {
    auto answered = answer_requests(
            net,
            "sequence",
            [stored](MockNetwork::SentRequest& r) {
                auto result = stored ? nlohmann::json{{"code", 200}, {"body", {{"hash", "L1"}}}}
                                     : nlohmann::json{{"code", 406}, {"body", "refused"}};
                r.callback(true, false, 200, {}, nlohmann::json{{"results", {result}}}.dump());
            },
            1);
    REQUIRE(answered == 1);
    TestHelper::drain(*c);
}

device::State own_state(TempCore& c) {
    return c->devices.device_info(await).first.state;
}

}  // namespace

TEST_CASE(
        "Devices - a requested link is uploaded, prompted for elsewhere, and its admission "
        "reported",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);

    auto sent = pushes(*net);
    REQUIRE(sent.size() == 1);
    auto store = push_requests(*sent[0])[0]["params"];
    CHECK(store["namespace"] == 21);
    CHECK(store["ttl"] == std::chrono::milliseconds{Devices::LINK_REQUEST_TTL}.count());
    auto message = uploaded(*net);

    // Not answered, nor there to be read, until the swarm has it: until then there is nothing
    // another device could accept.
    CHECK_FALSE(got);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    auto asked = **got;
    CHECK(asked.expires > clock_now_s() + 9min);
    CHECK(own_state(l.applicant) == device::State::Pending);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Requesting);

    // What the waiting screen is redrawn from is what it was first drawn from.
    auto waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    CHECK(same(*waiting, asked));

    // The other device prompts with what this one shows, and the user, seeing them match there,
    // approves it.
    TestHelper::deliver_device_message(*l.core, message, asked.expires, "L1");
    REQUIRE(l.events.added.size() == 1);
    CHECK(l.events.added[0].sas == asked.sas);
    REQUIRE(l.core->devices.accept_request(l.events.added[0].id, await));
    auto group = l.core->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.applicant, group, in(10min), "G1");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);
    waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    CHECK(same(*waiting, asked));

    // And then here.  Seeing the group, being approved -- not asking, which it did itself -- and
    // then being admitted.
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant_events.membership == std::vector{
                                                   device::Membership::GroupsVisible,
                                                   device::Membership::Approved,
                                                   device::Membership::InGroup});
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
}

TEST_CASE(
        "Devices - a link request the swarm refused is withdrawn, and reported only as a failure",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);
    answer_upload(l.applicant, *net, false);

    REQUIRE(got);
    REQUIRE_FALSE(got->has_value());
    CHECK(got->error().code == err::store_failed);
    CHECK(own_state(l.applicant) == device::State::Unregistered);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));

    // The caller has been told; that it is no longer waiting is not news.
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
}

TEST_CASE(
        "Devices - a refused upload does not withdraw the request that replaced it",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked first, second;
    request_link(l, first);
    request_link(l, second);

    answer_upload(l.applicant, *net, false);
    REQUIRE(first);
    CHECK_FALSE(first->has_value());
    CHECK(own_state(l.applicant) == device::State::Pending);

    answer_upload(l.applicant, *net, true);
    REQUIRE(second);
    REQUIRE(second->has_value());
    CHECK(own_state(l.applicant) == device::State::Pending);
    auto waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    CHECK(same(*waiting, **second));
}

TEST_CASE(
        "Devices - asking again while a request is out reopens it",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked first, second;
    request_link(l, first);
    auto message = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(first);
    REQUIRE(first->has_value());

    // The same emoji and deadline, at once, with nothing uploaded.
    auto uploads = pushes(*net).size();
    request_link(l, second);
    REQUIRE(second);
    REQUIRE(second->has_value());
    CHECK(same(**second, **first));
    CHECK(pushes(*net).size() == uploads);

    // Approved, too, by an approval the asking itself fetches: it is not let go.
    TestHelper::deliver_device_message(*l.core, message, (*first)->expires, "L1");
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    Asked third;
    l.applicant->devices.request_link(
            *TestHelper::group_id(*l.core),
            [&third](Expected<Devices::OutgoingLinkRequest> r) { third = std::move(r); });
    TestHelper::drain(*l.applicant);
    REQUIRE(answer_fetch(
                    l.applicant,
                    *net,
                    {{l.core->devices.build_device_group_message().message, "G1"}}) == 1);
    REQUIRE(third);
    REQUIRE(third->has_value());
    CHECK(same(**third, **first));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
}

TEST_CASE(
        "Devices - asking to join fetches the group first, and asks under the key it finds",
        "[core][devices][linking][request]") {
    Linking l;
    l.admit();
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G2");
    auto group = *TestHelper::group_id(*l.core);

    // A new device, which saw the group while the applicant was in it.
    TempCore asking{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::deliver_device_message(
            *asking, l.core->devices.build_device_group_message().message, in(10min), "G3");
    auto* net = attach_mock_network(*asking);

    // The applicant removed since, which moves the group to a key the applicant does not hold.
    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    auto since = l.core->devices.build_device_group_message().message;

    Asked got;
    asking->devices.request_link(
            group, [&got](Expected<Devices::OutgoingLinkRequest> r) { got = std::move(r); });
    TestHelper::drain(*asking);
    CHECK(pushes(*net).empty());
    auto prompts = l.events.added.size();

    SECTION("finding the group as it is now: asked under its current key, and prompted for") {
        REQUIRE(answer_fetch(asking, *net, {{since, "G4"}}) == 1);
        auto message = uploaded(*net);
        answer_upload(asking, *net, true);
        REQUIRE(got);
        REQUIRE(got->has_value());
        TestHelper::deliver_device_message(*l.core, message, (*got)->expires, "L2");
        CHECK(l.events.added.size() == prompts + 1);
    }

    SECTION("finding nothing newer: under the key it saw, which the removed device holds") {
        REQUIRE(answer_fetch(asking, *net) == 1);
        auto message = uploaded(*net);
        answer_upload(asking, *net, true);
        REQUIRE(got);
        REQUIRE(got->has_value());
        TestHelper::deliver_device_message(*l.core, message, (*got)->expires, "L2");
        CHECK(l.events.added.size() == prompts);
    }
}

TEST_CASE(
        "Devices - what the fetch before asking finds can stop the asking",
        "[core][devices][linking][request]") {
    Linking l;
    auto group = l.show_group();
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    l.applicant->devices.request_link(
            group, [&got](Expected<Devices::OutgoingLinkRequest> r) { got = std::move(r); });
    TestHelper::drain(*l.applicant);

    SECTION("the swarm out of reach") {
        while (!got && answer_fetch(l.applicant, *net, {}, false))
            ;
        REQUIRE(got);
        REQUIRE_FALSE(got->has_value());
        CHECK(got->error().code == err::network_unavailable);
    }

    SECTION("the group dissolved since") {
        REQUIRE(answer_fetch(
                        l.applicant,
                        *net,
                        {{TestHelper::build_dissolution(*l.core, {group}), "T1"}}) == 1);
        REQUIRE(got);
        REQUIRE_FALSE(got->has_value());
        CHECK(got->error().code == err::unknown_group);
    }

    CHECK(pushes(*net).empty());
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
    CHECK(own_state(l.applicant) == device::State::Unregistered);
}

TEST_CASE(
        "Devices - an unanswered link request lapses at its deadline",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());

    REQUIRE(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
    l.applicant_events.membership.clear();

    // Brought to within a second of the deadline, and the timer re-armed from there, so that it is
    // the timer that finds the request lapsed rather than anything this test does.
    ScopedClockOffset later{Devices::LINK_REQUEST_TTL - 1s};
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE(l.applicant_events.membership.empty());

    REQUIRE(eventually(*l.applicant, [&] { return !l.applicant_events.membership.empty(); }));
    CHECK(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
    CHECK(own_state(l.applicant) == device::State::Unregistered);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
}

namespace {
void restart_applicant(Linking& l) {
    l.applicant.core.reset();
    l.applicant.core = std::make_unique<core::Core>(
            l.applicant.path, Linking::reporting_to(l.applicant_events));
}
}  // namespace

TEST_CASE(
        "Devices - a link request left waiting at shutdown is still waiting after a restart",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());

    restart_applicant(l);

    CHECK(own_state(l.applicant) == device::State::Pending);
    auto waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    CHECK(same(*waiting, **got));

    // And it still lapses, with no fetch to notice: the restart re-arms its deadline.  Reported
    // once a fetch has made where it stands known again.
    ScopedClockOffset later{Devices::LINK_REQUEST_TTL - 1s};
    restart_applicant(l);
    l.applicant_events.membership.clear();
    REQUIRE(eventually(
            *l.applicant, [&] { return own_state(l.applicant) == device::State::Unregistered; }));
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
}

TEST_CASE(
        "Devices - a link request never confirmed stored is withdrawn at the next start",
        "[core][devices][linking][request]") {
    Linking l;
    attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);
    REQUIRE(own_state(l.applicant) == device::State::Pending);

    restart_applicant(l);
    l.applicant_events.membership.clear();

    CHECK(own_state(l.applicant) == device::State::Unregistered);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
}

TEST_CASE(
        "Devices - a link is not requested without a network, or by a device already in the group",
        "[core][devices][linking][request]") {
    Linking l;
    Asked got;

    SECTION("no network") {
        request_link(l, got);
        REQUIRE(got);
        REQUIRE_FALSE(got->has_value());
        CHECK(got->error().code == err::network_unavailable);
        CHECK(own_state(l.applicant) == device::State::Unregistered);
    }

    SECTION("already registered") {
        attach_mock_network(*l.core);
        request_link(l.core, *TestHelper::group_id(*l.core), got);
        REQUIRE(got);
        REQUIRE_FALSE(got->has_value());
        CHECK(got->error().code == err::already_registered);
        CHECK(own_state(l.core) == device::State::Registered);
    }
}

TEST_CASE(
        "Devices - a group's identifier is carried readably only for seed holders",
        "[core][devices][group-id]") {
    TempCore c;
    auto id = TestHelper::group_id(*c);
    REQUIRE(id);
    CHECK(std::chrono::abs(id->created() - clock_now()) <= 1min);

    auto m1 = c->devices.build_device_group_message().message;
    auto m2 = c->devices.build_device_group_message().message;
    CHECK(TestHelper::group_of(*c, m1) == id);
    CHECK(TestHelper::group_of(*c, m2) == id);

    // To anyone without the seed it is different in every message, so nothing links them.
    auto at = [](std::span<const std::byte> msg) {
        oxenc::bt_dict_consumer outer{msg};
        auto v = outer.require_span<std::byte>("@");
        return std::vector<std::byte>{v.begin(), v.end()};
    };
    CHECK(at(m1) != at(m2));
    CHECK(std::ranges::search(m1, id->value).empty());
}

TEST_CASE(
        "Devices - groups seen in the swarm are remembered, with the key to ask them on",
        "[core][devices][group-id]") {
    Linking l;
    auto group = TestHelper::group_id(*l.core);
    REQUIRE(group);
    auto key = [&] { return l.core->devices.active_account_keys().front().x25519_pub; };

    // A group the applicant cannot read is still a group it can see, and ask to join.
    auto first_key = key();
    auto first = l.core->devices.build_device_group_message().message;
    auto expiry = in(10min);
    TestHelper::deliver_device_message(*l.applicant, first, expiry, "G1");
    auto seen = TestHelper::seen_group(*l.applicant, *group);
    REQUIRE(seen);
    CHECK(seen->first == first_key);
    CHECK(seen->second == epoch_seconds(expiry));

    // The key follows the group's newest message, by when it was written rather than when it
    // arrived, whichever order they arrive in.
    l.core->devices.rotate_account_keys();
    auto second_key = key();
    REQUIRE(second_key != first_key);
    std::vector<std::byte> second;
    {
        ScopedClockOffset later{1h};
        second = l.core->devices.build_device_group_message().message;
        TestHelper::deliver_device_message(*l.applicant, second, in(10min), "G2");
    }
    CHECK(TestHelper::seen_group(*l.applicant, *group)->first == second_key);
    TestHelper::deliver_device_message(*l.applicant, first, expiry, "G1");
    CHECK(TestHelper::seen_group(*l.applicant, *group)->first == second_key);

    // Not from a message whose signature does not check out, newer though it is: anything else
    // could plant a key of its own for requests to this group to be encrypted to.
    {
        ScopedClockOffset later{2h};
        auto forged = l.core->devices.build_device_group_message().message;
        oxenc::bt_dict_consumer outer{forged};
        auto x_at = outer.require_span<std::byte>("X").data() - forged.data();
        forged[x_at] ^= std::byte{1};
        TestHelper::deliver_device_message(*l.applicant, forged, in(10min), "G3");
    }
    CHECK(TestHelper::seen_group(*l.applicant, *group)->first == second_key);
}

TEST_CASE(
        "Devices - a group message dated too far ahead of this device's clock is ignored",
        "[core][devices][group-id]") {
    Linking l;
    l.admit();
    TempCore outsider{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    auto group = *TestHelper::group_id(*l.core);

    // The applicant renames itself, and pushes from a clock running `ahead`.
    auto renamed = l.applicant->devices.device_info(await).first;
    auto push = [&](std::string description, std::chrono::minutes ahead, std::string hash) {
        renamed.description = description;
        l.applicant->devices.update_info(renamed, await);
        std::vector<std::byte> message;
        {
            ScopedClockOffset fast{ahead};
            message = l.applicant->devices.build_device_group_message().message;
        }
        TestHelper::deliver_device_message(*l.core, message, in(10min), hash);
        TestHelper::deliver_device_message(*outsider, message, in(10min), hash);
    };

    // Neither merged nor noted as the group's newest, which would hold back every honest message
    // for as long as it is ahead.
    push("from the future", Devices::GROUP_MESSAGE_MAX_AHEAD + 1min, "G2");
    CHECK(l.state_of_applicant().description != "from the future");
    CHECK_FALSE(TestHelper::seen_group(*outsider, group));

    // A clock merely running fast is another matter.
    push("a little fast", Devices::GROUP_MESSAGE_MAX_AHEAD - 1min, "G3");
    CHECK(l.state_of_applicant().description == "a little fast");
    CHECK(TestHelper::seen_group(*outsider, group));
}

TEST_CASE(
        "Devices - a group identifier says when its group was created",
        "[core][devices][group-id]") {
    device::GroupId id{};
    oxenc::write_host_as_little(uint32_t{29'600'000}, id.value.data());
    CHECK(id.created().time_since_epoch() == 29'600'000min);

    // The emoji come from a hash rather than the bytes, so groups created in the same minute -- the
    // same leading half -- still look different.
    auto other = id;
    other.value[7] = std::byte{1};
    CHECK(id.sas() != other.sas());
    CHECK(id.sas() == device::GroupId{id.value}.sas());
}

TEST_CASE(
        "Devices - an admitted device takes on its group's identifier",
        "[core][devices][group-id]") {
    Linking l;
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    l.admit();
    CHECK(TestHelper::group_id(*l.applicant) == TestHelper::group_id(*l.core));
}

TEST_CASE(
        "Devices - a readable message from another group is not merged",
        "[core][devices][group-id]") {
    Linking l;
    l.admit();
    auto ours = TestHelper::group_id(*l.core);
    REQUIRE(ours);

    device::Info info{};
    info.description = "changed";
    l.core->devices.update_info(info, await);
    auto other = *ours;
    other.value[7] ^= std::byte{0xff};
    TestHelper::set_group_id(*l.core, other);
    auto message = l.core->devices.build_device_group_message().message;

    TestHelper::deliver_device_message(*l.applicant, message, in(10min), "G2");
    auto [core_self, _] = l.core->devices.device_info(await);
    auto seen = l.applicant->devices.devices(true, false, false, core_self.id);
    REQUIRE(seen.size() == 1);
    CHECK(seen.begin()->second.description != "changed");
    CHECK(TestHelper::group_id(*l.applicant) == ours);
}

TEST_CASE(
        "Devices - a link request is readable only by the group it asks to join",
        "[core][devices][linking]") {
    Linking l;

    // A seed holder outside the group -- what a removed device is.  It must learn nothing from a
    // request: not the applicant's keys, not its SAS, not that there is one.
    DeviceEventsRecorder outsider_events;
    TempCore outsider{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(outsider_events)};

    auto req = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(*outsider, req.message, in(10min), "L1");
    CHECK(outsider_events.added.empty());
    CHECK(outsider->devices.link_requests(await).empty());

    // Nor does the key indicator say which group's key the request is for, to anyone without the
    // seed: the group's key is visible in its messages, and a bare prefix of it would match.
    oxenc::bt_dict_consumer outer{req.message};
    auto indicator = outer.require_span<std::byte, 2>("i");
    auto key = l.core->devices.active_account_keys().front().x25519_pub;
    CHECK_FALSE((indicator[0] == key[0] && indicator[1] == key[1]));

    TestHelper::deliver_device_message(*l.core, req.message, in(10min), "L1");
    REQUIRE(l.events.added.size() == 1);
    CHECK(l.events.added[0].sas == req.sas);
}

TEST_CASE(
        "Devices - a link request not signed by the account is not prompted for",
        "[core][devices][linking]") {
    Linking l;
    auto k = l.applicant->devices.active_device_keys().front();

    // A request anything could encrypt, since the group's link key is published.
    auto request = [&](std::optional<std::span<const std::byte, 64>> signer) {
        oxenc::bt_dict_producer out;
        out.append("I", l.applicant_id());
        {
            auto i = out.append_dict("i");
            i.append("#", 1);
            i.append("@", epoch_seconds(clock_now_s()));
            i.append("M", k.mlkem768_pub);
            i.append("X", k.x25519_pub);
        }
        if (signer)
            out.append_signature("~", [&](std::span<const std::byte> body) {
                return ed25519::sign(*signer, body);
            });
        auto s = std::move(out).str();
        return TestHelper::encrypt_link_request(*l.applicant, *l.core, to_span(s));
    };

    b32 other_pk;
    b64 other_sk;
    ed25519::keypair(other_pk, other_sk);

    TestHelper::deliver_device_message(*l.core, request(std::nullopt), in(10min), "L1");
    TestHelper::deliver_device_message(*l.core, request(other_sk), in(10min), "L2");
    CHECK(l.events.added.empty());

    // The same request, signed as the account: so it was the signature that was missing above.
    auto seed = l.applicant->globals.account_seed();
    TestHelper::deliver_device_message(*l.core, request(seed.ed25519_secret()), in(10min), "L3");
    CHECK(l.events.added.size() == 1);
}

TEST_CASE(
        "Devices - a link request survives the group rotating its key",
        "[core][devices][linking]") {
    Linking l;

    // Asked on the key the applicant last saw, which the group has since moved on from.
    auto req = TestHelper::build_link_request(*l.applicant, *l.core);
    l.core->devices.rotate_account_keys();

    TestHelper::deliver_device_message(*l.core, req.message, in(10min), "L1");
    REQUIRE(l.events.added.size() == 1);
    CHECK(l.events.added[0].sas == req.sas);
}

TEST_CASE(
        "Devices - membership is unknown until the first fetch says otherwise",
        "[core][devices][membership]") {
    DeviceEventsRecorder events;
    TempCore c{Linking::reporting_to(events)};

    // In a group by its own record, but that record may be stale: removed, or cut off, while away.
    auto before = c->devices.membership(await);
    CHECK(before.membership == device::Membership::Unknown);

    TestHelper::finish_fetch(*c);
    auto after = c->devices.membership(await);
    CHECK(after.membership == device::Membership::InGroup);
    CHECK(after.group == TestHelper::group_id(*c));
    CHECK(after.others.empty());
    CHECK(events.membership == std::vector{device::Membership::InGroup});
}

TEST_CASE(
        "Devices - a device outside any group sees whether there are groups to join",
        "[core][devices][membership]") {
    Linking l;
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::NoGroup);

    auto group = l.show_group();
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::GroupsVisible);
    CHECK_FALSE(state.group);
    REQUIRE(state.others.size() == 1);
    CHECK(state.others[0].id == group);
    CHECK(l.applicant_events.membership ==
          std::vector{device::Membership::NoGroup, device::Membership::GroupsVisible});
}

namespace {
// Counted directly: active_account_keys() mints one when there are none.
int account_key_count(TempCore& c) {
    return c->database().conn().prepared_get<int>("SELECT count(*) FROM device_account_keys");
}

// The code a call failed with, or empty if it did not.
template <typename F>
std::string failure_code(F&& f) {
    try {
        f();
    } catch (const session::error& e) {
        return std::string{e.err().code};
    }
    return {};
}
}  // namespace

TEST_CASE(
        "Devices - a second group beside ours is a fork, until the user keeps one",
        "[core][devices][membership][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    auto ours = *TestHelper::group_id(*l.core);
    auto* net = attach_mock_network(*l.core);

    // Another device on the account starts a group of its own.
    TestHelper::start_group(*l.applicant);
    auto second = *TestHelper::group_id(*l.applicant);
    auto written = std::chrono::floor<std::chrono::seconds>(clock_now_s());
    TestHelper::deliver_device_message(
            *l.core, l.applicant->devices.build_device_group_message().message, in(10min), "B1");

    auto state = l.core->devices.membership(await);
    CHECK(state.membership == device::Membership::Forked);
    CHECK(l.events.membership.back() == device::Membership::Forked);
    CHECK(state.group == ours);
    REQUIRE(state.others.size() == 1);
    CHECK(state.others[0].id == second);
    CHECK(std::chrono::abs(state.others[0].last_seen - written) <= 1s);

    // Nothing is wrong with its group, which goes on working while the user decides.
    CHECK(l.core->devices.needs_push().device_group);

    // Only another group in view can be dissolved, and only from here.
    CHECK_THROWS_AS(l.core->devices.dissolve_group(ours, await), std::invalid_argument);
    CHECK_FALSE(l.core->devices.dissolve_group(device::GroupId{}, await));

    // The user keeps this one.
    REQUIRE(l.core->devices.dissolve_group(second, await));
    state = l.core->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.others.empty());
    CHECK(l.core->devices.needs_push().device_group);
    // Its own doing, so not news to it.
    CHECK(l.events.membership.back() == device::Membership::Forked);

    // The other group's message deleted, and a tombstone naming it published in the same push --
    // the latest one, after this group's own.
    auto sent = pushes(*net);
    REQUIRE(!sent.empty());
    auto reqs = push_requests(*sent.back());
    REQUIRE(reqs.size() == 2);
    CHECK(reqs[0]["method"] == "store");
    CHECK(reqs[1]["method"] == "delete");
    CHECK(reqs[1]["params"]["messages"] == nlohmann::json::array({"B1"}));
    auto tombstone = to_vector<std::byte>(
            oxenc::from_base64(reqs[0]["params"]["data"].get<std::string_view>()));
    TestHelper::deliver_device_message(*l.applicant, tombstone, in(10min), "T1");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dissolved);

    // Nothing left to dissolve.
    CHECK_FALSE(l.core->devices.dissolve_group(second, await));
}

TEST_CASE(
        "Devices - a device whose group is gone beside another is dropped",
        "[core][devices][membership]") {
    Linking l;
    auto old_id = Linking::id_of(l.core);

    // Another group, whose message outlives everything we know of our own.
    TestHelper::start_group(*l.applicant);
    auto theirs = *TestHelper::group_id(*l.applicant);
    TestHelper::deliver_device_message(
            *l.core,
            l.applicant->devices.build_device_group_message().message,
            in(1min) + Devices::DEVICE_GROUP_TTL + 1h,
            "B1");
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::Forked);

    // Ours gone from the swarm, as far as we can tell; theirs not.  Whatever became of ours, the
    // account's group is now the other: nothing to push, and nothing for this device to dissolve.
    ScopedClockOffset later{Devices::DEVICE_GROUP_TTL + 1h};
    TestHelper::finish_fetch(*l.core);
    CHECK(l.core->devices.membership(await).membership == device::Membership::Dropped);
    CHECK(l.events.membership.back() == device::Membership::Dropped);
    CHECK_FALSE(l.core->devices.needs_push().device_group);
    CHECK_FALSE(l.core->devices.dissolve_group(theirs, await));

    // It comes back as a new device, like a removed one.
    auto* net = attach_mock_network(*l.core);
    Asked got;
    request_link(l.core, theirs, got);
    answer_upload(l.core, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    CHECK(Linking::id_of(l.core) != old_id);
    CHECK(l.core->devices.membership(await).membership == device::Membership::Requesting);
}

TEST_CASE(
        "Devices - a device whose group is dissolved leaves it behind, under a new id",
        "[core][devices][dissolve]") {
    Linking l;
    l.admit();
    auto group = *TestHelper::group_id(*l.core);
    auto old_id = l.applicant_id();
    auto leftover = l.core->devices.build_device_group_message().message;

    // Another of the account's devices, whose user chose to keep a group of its own.
    ScopedClockOffset later{1min};
    TempCore keeper{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::deliver_device_message(
            *l.applicant, TestHelper::build_dissolution(*keeper, {group}), in(10min), "T1");

    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dissolved);
    CHECK(l.applicant_events.membership.back() == device::Membership::Dissolved);
    CHECK(l.applicant_id() != old_id);
    CHECK(l.applicant->devices.devices(true, true, true).empty());
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(account_key_count(l.applicant) == 0);
    CHECK_FALSE(l.applicant->devices.needs_push().device_group);

    // What the group left behind is nothing to it now, nor something it could join.
    TestHelper::deliver_device_message(*l.applicant, leftover, in(10min), "G2");
    CHECK(l.applicant->devices.membership(await).others.empty());
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dissolved);

    // Until it starts or joins a group.
    l.applicant->devices.start_group(await);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
}

TEST_CASE("Devices - a dissolved group is no longer one to join", "[core][devices][dissolve]") {
    Linking l;
    auto theirs = l.show_group();
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_group(*other);
    auto second = *TestHelper::group_id(*other);
    TestHelper::deliver_device_message(
            *l.applicant, other->devices.build_device_group_message().message, in(10min), "B1");
    REQUIRE(l.applicant->devices.membership(await).others.size() == 2);

    // One tombstone, naming both.
    TestHelper::deliver_device_message(
            *l.applicant, TestHelper::build_dissolution(*other, {theirs, second}), in(10min), "T1");
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::NoGroup);
    CHECK(state.others.empty());
}

namespace {
// The message stored by a push, and what it deleted.
std::pair<std::vector<std::byte>, nlohmann::json> pushed(const MockNetwork::SentRequest& push) {
    auto reqs = push_requests(push);
    std::vector<std::byte> stored;
    nlohmann::json deleted = nlohmann::json::array();
    for (const auto& req : reqs) {
        if (req["method"] == "store")
            stored = to_vector<std::byte>(
                    oxenc::from_base64(req["params"]["data"].get<std::string_view>()));
        else if (req["method"] == "delete")
            deleted = req["params"]["messages"];
    }
    return {stored, deleted};
}

// The pushes that are not our own group's: tombstones and deletions.
std::vector<MockNetwork::SentRequest*> dissolutions(MockNetwork& net) {
    std::vector<MockNetwork::SentRequest*> out;
    for (auto* p : pushes(net)) {
        auto stored = pushed(*p).first;
        if (stored.empty() || oxenc::bt_dict_consumer{stored}.require<std::string_view>("") != "G")
            out.push_back(p);
    }
    return out;
}
}  // namespace

TEST_CASE(
        "Devices - a dissolved group seen again is dissolved again", "[core][devices][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    auto* net = attach_mock_network(*l.core);

    // A group of one device, beside ours, with a message of it ours never sees until later.
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_group(*other);
    auto theirs = *TestHelper::group_id(*other);
    auto leftover = other->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(
            *l.core, other->devices.build_device_group_message().message, in(10min), "B1");

    ScopedClockOffset later{1min};
    REQUIRE(l.core->devices.dissolve_group(theirs, await));
    REQUIRE(dissolutions(*net).size() == 1);
    auto [first_tombstone, first_deleted] = pushed(*dissolutions(*net)[0]);
    CHECK(first_deleted == nlohmann::json::array({"B1"}));

    // Something the dissolving device did not know to delete: deleted, and that is all.
    TestHelper::deliver_device_message(*l.core, leftover, in(10min), "B0");
    REQUIRE(dissolutions(*net).size() == 2);
    auto [none, leftover_deleted] = pushed(*dissolutions(*net)[1]);
    CHECK(none.empty());
    CHECK(leftover_deleted == nlohmann::json::array({"B0"}));

    // Its device back after the tombstone has gone, pushing again: told again, and that message
    // deleted too.
    later.advance(1min);
    auto back = other->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.core, back, in(10min), "B2");
    CHECK(l.core->devices.membership(await).membership == device::Membership::InGroup);
    REQUIRE(dissolutions(*net).size() == 3);
    auto [tombstone, deleted] = pushed(*dissolutions(*net)[2]);
    CHECK(deleted == nlohmann::json::array({"B2"}));
    TestHelper::deliver_device_message(*other, tombstone, in(10min), "T2");
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);

    // A device outside any group is in no position to decide which group is the account's: it
    // knows of the dissolution, but takes a group pushing since it as any other.
    TestHelper::deliver_device_message(*l.applicant, first_tombstone, in(10min), "T1");
    TestHelper::deliver_device_message(*l.applicant, leftover, in(10min), "B0");
    CHECK(l.applicant->devices.membership(await).others.empty());
    TestHelper::deliver_device_message(*l.applicant, back, in(10min), "B2");
    auto seen = l.applicant->devices.membership(await).others;
    REQUIRE(seen.size() == 1);
    CHECK(seen[0].id == theirs);
}

TEST_CASE(
        "Devices - a device back after its group lapsed dissolves again what it saw dissolved",
        "[core][devices][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    auto* net = attach_mock_network(*l.core);

    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_group(*other);
    auto theirs = *TestHelper::group_id(*other);
    TestHelper::deliver_device_message(
            *l.core, other->devices.build_device_group_message().message, in(10min), "B1");
    // Its own group's push, which would hold back every later one until answered.
    answer_upload(l.core, *net, true);
    REQUIRE(l.core->devices.dissolve_group(theirs, await));
    REQUIRE(dissolutions(*net).size() == 1);

    // Away for longer than its group's messages last, and back to find nothing of it: either an
    // empty swarm, or a third group, which leaves it dropped.
    bool dropped = GENERATE(false, true);
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_group(*third);
    if (dropped)
        TestHelper::deliver_device_message(
                *l.core,
                third->devices.build_device_group_message().message,
                in(1min) + Devices::DEVICE_GROUP_TTL + 1h,
                "C1");
    ScopedClockOffset later{Devices::DEVICE_GROUP_TTL + 1h};
    auto expected = dropped ? device::Membership::Dropped : device::Membership::InGroup;
    REQUIRE(l.core->devices.membership(await).membership == expected);

    // The dissolved group's device, back too and never told, in the first fetch since.  Telling it
    // again decides nothing, so even a dropped device does it; the third group it leaves alone.
    // Before anything else, too: the rotation all that time away has made due, and the push
    // carrying it, come after the fetch.
    auto before = pushes(*net).size();
    auto back = other->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.core, back, in(10min), "B2");
    auto sent = pushes(*net);
    REQUIRE(sent.size() > before);
    auto [tombstone, deleted] = pushed(*sent[before]);
    CHECK(oxenc::bt_dict_consumer{tombstone}.require<std::string_view>("") == "T");
    CHECK(deleted == nlohmann::json::array({"B2"}));
    TestHelper::deliver_device_message(*other, tombstone, in(10min), "T2");
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);
    TestHelper::deliver_device_message(*third, tombstone, in(10min), "T2");
    CHECK(third->devices.membership(await).membership == device::Membership::InGroup);

    // And then its own group again -- unless it is dropped, when the account's group is the third.
    CHECK(l.core->devices.membership(await).membership == expected);
    REQUIRE(sent.size() == before + (dropped ? 1 : 2));
    if (!dropped)
        CHECK(oxenc::bt_dict_consumer{pushed(*sent.back()).first}.require<std::string_view>("") ==
              "G");
}

TEST_CASE(
        "Devices - joining one of several groups dissolves the rest", "[core][devices][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);

    // Another group on the account, which the existing device sees too: forked.
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_group(*other);
    auto theirs = *TestHelper::group_id(*other);
    auto b1 = other->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.core, b1, in(10min), "B1");
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::Forked);

    // The new device sees both, and the user picks the existing device's.
    TestHelper::deliver_device_message(*l.applicant, b1, in(10min), "B1");
    auto ours = l.show_group();
    REQUIRE(l.applicant->devices.membership(await).others.size() == 2);
    auto* net = attach_mock_network(*l.applicant);
    l.admit();

    // Completing the join is the choice of that group over the other.
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.group == ours);
    CHECK(state.others.empty());
    auto sent = dissolutions(*net);
    REQUIRE(sent.size() == 1);
    auto [tombstone, deleted] = pushed(*sent[0]);
    CHECK(deleted == nlohmann::json::array({"B1"}));

    // Which the other group's device, and the existing device it forked, both hear of.
    TestHelper::deliver_device_message(*other, tombstone, in(10min), "T1");
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);
    TestHelper::deliver_device_message(*l.core, tombstone, in(10min), "T1");
    CHECK(l.core->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(l.core->devices.membership(await).others.empty());
    CHECK(theirs != ours);
}

TEST_CASE(
        "Devices - ignoring a request deletes it from the swarm only when asked to",
        "[core][devices][linking]") {
    Linking l;
    auto* net = attach_mock_network(*l.core);

    // The group's own pushes go the same way, so look for the deletion by what it names.
    auto deleted = [&](std::string_view hash) {
        for (auto* push : pushes(*net))
            for (const auto& req : push_requests(*push))
                if (req["method"] == "delete" &&
                    req["params"]["messages"] == nlohmann::json::array({hash}))
                    return true;
        return false;
    };

    l.ask(in(10min), "L1");
    REQUIRE(l.core->devices.ignore_request(l.events.added.at(0).id, await));
    TestHelper::drain(*l.core);
    CHECK_FALSE(deleted("L1"));

    // One the user does not recognise.
    l.ask(in(10min), "L2");
    REQUIRE(l.core->devices.ignore_request(l.events.added.at(1).id, true, await));
    TestHelper::drain(*l.core);
    CHECK(deleted("L2"));
}

TEST_CASE(
        "Devices - a device admitted only by an impostor's group does not join",
        "[core][devices][linking][confirm]") {
    Linking l;

    // A seed holder outside the real group -- a removed device, say -- publishes a group of its
    // own, and the applicant asks to join that one instead.
    DeviceEventsRecorder impostor_events;
    TempCore impostor{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(impostor_events)};
    TestHelper::start_group(*impostor);
    auto req = TestHelper::build_link_request(*l.applicant, *impostor);

    // The real group cannot read the request, so it never prompts, and the user never sees a SAS
    // to compare.
    TestHelper::deliver_device_message(*l.core, req.message, in(10min), "L1");
    CHECK(l.events.added.empty());

    // The impostor can, and admits it.
    TestHelper::deliver_device_message(*impostor, req.message, in(10min), "L1");
    REQUIRE(impostor_events.added.size() == 1);
    REQUIRE(impostor->devices.accept_request(impostor_events.added[0].id, await));
    TestHelper::deliver_device_message(
            *l.applicant, impostor->devices.build_device_group_message().message, in(10min), "G1");

    // Readable, but not enough: with no confirmation from its user, who has no device of theirs
    // showing emoji to compare, it does not join.
    CHECK(own_state(l.applicant) == device::State::Pending);
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(l.applicant_events.membership == std::vector{device::Membership::Approved});
}

TEST_CASE(
        "Devices - an admission held for confirmation survives its deadline and a restart",
        "[core][devices][linking][confirm]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);
    auto message = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());

    TestHelper::deliver_device_message(*l.core, message, (*got)->expires, "L1");
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    REQUIRE(own_state(l.applicant) == device::State::Pending);
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Approved);

    // The approval came in time, so the request no longer lapses.
    ScopedClockOffset later{Devices::LINK_REQUEST_TTL + 1min};
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);

    restart_applicant(l);
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);
    CHECK(l.applicant_events.membership.back() == device::Membership::Approved);

    // The fetch that brought the admission will not bring it again; it was kept.
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(own_state(l.applicant) == device::State::Registered);
    CHECK(TestHelper::group_id(*l.applicant) == TestHelper::group_id(*l.core));
}

TEST_CASE(
        "Devices - confirming before the approval is refused, and authorises nothing",
        "[core][devices][linking][confirm]") {
    Linking l;
    CHECK_FALSE(l.applicant->devices.confirm_link(await));

    l.ask();
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Requesting);
    CHECK_FALSE(l.applicant->devices.confirm_link(await));

    // The approval, when it comes, still waits for the user.
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    CHECK(own_state(l.applicant) == device::State::Pending);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);

    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(own_state(l.applicant) == device::State::Registered);
}

TEST_CASE(
        "Devices - an admission after the request lapsed here still waits for the user",
        "[core][devices][linking][confirm]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);
    auto message = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    TestHelper::deliver_device_message(*l.core, message, in(20min), "L1");
    l.applicant_events.membership.clear();

    // Lapsed here, by the timer, before the acceptance reached this device.
    ScopedClockOffset later{Devices::LINK_REQUEST_TTL + 1s};
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE(eventually(*l.applicant, [&] { return !l.applicant_events.membership.empty(); }));
    REQUIRE(l.applicant_events.membership.back() == device::Membership::GroupsVisible);

    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");

    // Not taken: any holder of the seed could have sent it.  Approved, and waiting on the user.
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);
    CHECK(l.applicant_events.membership.back() == device::Membership::Approved);
    auto shown = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(shown);
    CHECK(shown->sas == (**got).sas);

    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
}

TEST_CASE(
        "Devices - an admission on no request of this device's is not taken",
        "[core][devices][linking][confirm]") {
    Linking l;
    l.ask();
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));

    // As though it had never asked: what an impostor's group, admitting it unbidden, looks like.
    auto id = l.applicant_id();
    TestHelper::on_loop(*l.applicant, [&] {
        auto c = l.applicant->database().conn();
        c.prepared_exec("DELETE FROM device_own_requests");
        c.prepared_exec(
                "UPDATE devices SET state = ? WHERE unique_id = ?",
                static_cast<int>(device::State::Unregistered),
                id);
        return 0;
    });

    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::GroupsVisible);
    CHECK(own_state(l.applicant) == device::State::Unregistered);
    CHECK_FALSE(l.applicant->devices.confirm_link(await));
}

TEST_CASE(
        "Devices - an admission on a request since replaced is not taken",
        "[core][devices][linking][confirm]") {
    Linking l;
    l.ask();
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));

    // The user is looking at the newer one, whose emoji the accepting device never showed.
    TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::finish_fetch(*l.applicant);
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Requesting);
    CHECK_FALSE(l.applicant->devices.confirm_link(await));
    CHECK(own_state(l.applicant) == device::State::Pending);
}

TEST_CASE(
        "Devices - a second admission does not replace the one held",
        "[core][devices][linking][confirm]") {
    Linking l;
    l.ask();
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Approved);

    // Another, readable and admitting the same record, saying something else of the group.
    auto group = l.core->devices.devices(true, true, true);
    auto core_id = Linking::id_of(l.core);
    group.at(core_id).description = "Not what the user approved";
    TestHelper::deliver_device_message(
            *l.applicant, TestHelper::encrypt_device_data(l.core->devices, group), in(10min), "G2");

    REQUIRE(l.applicant->devices.confirm_link(await));
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(l.applicant->devices.devices().at(core_id).description != "Not what the user approved");
}

TEST_CASE(
        "Devices - a link request under a key a removed device holds is not read",
        "[core][devices][linking][removal]") {
    Linking l;
    l.admit();

    // The group's key, delivered to both devices: by the admission, and by the existing device's
    // push once the swarm confirms it.
    auto key = l.core->devices.active_account_keys().front().x25519_pub;
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G2");
    std::set<device::Id> both{Linking::id_of(l.core), l.applicant_id()};
    auto pushed_to = TestHelper::key_recipients(*l.core, key);
    CHECK(std::set(pushed_to.begin(), pushed_to.end()) == both);
    auto merged_to = TestHelper::key_recipients(*l.applicant, key);
    CHECK(std::set(merged_to.begin(), merged_to.end()) == both);

    // A new device asking under that key.
    TempCore asking{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    auto request = TestHelper::build_link_request(*asking, *l.core);
    REQUIRE(l.events.added.size() == 1);

    SECTION("rotated away from since: still read") {
        l.core->devices.rotate_account_keys();
        TestHelper::deliver_device_message(*l.core, request.message, in(10min), "L2");
        CHECK(l.events.added.size() == 2);
    }

    SECTION("held by a device removed since: not read") {
        REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
        TestHelper::deliver_device_message(*l.core, request.message, in(10min), "L2");
        CHECK(l.events.added.size() == 1);
    }
}

TEST_CASE(
        "Devices - starting a group with others in view dissolves them",
        "[core][devices][membership][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    auto theirs = l.show_group();
    REQUIRE(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
    auto held_before = l.applicant->devices.active_account_keys().front().x25519_pub;
    auto* net = attach_mock_network(*l.applicant);

    auto mine = l.applicant->devices.start_group(await);
    CHECK(mine != theirs);

    // With a key of its own, not whatever it held before.
    CHECK(account_key_count(l.applicant) == 1);
    CHECK(l.applicant->devices.active_account_keys().front().x25519_pub != held_before);

    // The only group now, and nothing to alert about: the choice was this device's own.
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.group == mine);
    CHECK(state.others.empty());
    CHECK(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});

    // The other group's message deleted, and a tombstone naming it published.
    auto sent = pushes(*net);
    REQUIRE(sent.size() == 1);
    auto reqs = push_requests(*sent[0]);
    REQUIRE(reqs.size() == 2);
    CHECK(reqs[0]["method"] == "store");
    CHECK(reqs[1]["method"] == "delete");
    CHECK(reqs[1]["params"]["messages"] == nlohmann::json::array({"G0"}));

    // Which the devices of that group learn of, after which the group kept is the one they see.
    auto tombstone = to_vector<std::byte>(
            oxenc::from_base64(reqs[0]["params"]["data"].get<std::string_view>()));
    TestHelper::deliver_device_message(*l.core, tombstone, in(10min), "T1");
    CHECK(l.core->devices.membership(await).membership == device::Membership::Dissolved);
    TestHelper::deliver_device_message(
            *l.core, l.applicant->devices.build_device_group_message().message, in(10min), "B1");
    state = l.core->devices.membership(await);
    REQUIRE(state.others.size() == 1);
    CHECK(state.others[0].id == mine);
}

TEST_CASE(
        "Devices - a group is started only when the user can have decided to",
        "[core][devices][membership]") {
    Linking l;

    // Before any fetch, nothing is known of what the swarm holds.
    CHECK(failure_code([&] { l.applicant->devices.start_group(await); }) ==
          err::membership_unknown);

    // Already in one.
    TestHelper::finish_fetch(*l.core);
    CHECK(failure_code([&] { l.core->devices.start_group(await); }) == err::already_registered);

    // Requesting: starting a group instead withdraws the request.
    l.show_group();
    TestHelper::build_link_request(*l.applicant, *l.core);
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Requesting);
    l.applicant->devices.start_group(await);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(own_state(l.applicant) == device::State::Registered);
}

TEST_CASE(
        "Devices - a device in a group does not ask to join another",
        "[core][devices][membership][linking]") {
    Linking l;
    l.admit();

    // Another group on the account, which the applicant sees: forked.
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_group(*third);
    auto other = *TestHelper::group_id(*third);
    TestHelper::deliver_device_message(
            *l.applicant, third->devices.build_device_group_message().message, in(10min), "Y1");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Forked);

    // An account has one group, so there is no switching: leaving comes first.
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l.applicant, other, got);
    REQUIRE(got);
    REQUIRE_FALSE(got->has_value());
    CHECK(got->error().code == err::already_registered);
    CHECK(pushes(*net).empty());
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
    CHECK(own_state(l.applicant) == device::State::Registered);

    // Its user choosing the other group: leave, then ask.
    REQUIRE(l.applicant->devices.leave_group(await));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::GroupsVisible);
    got.reset();
    request_link(l.applicant, other, got);
    CHECK(own_state(l.applicant) == device::State::Pending);
    answer_upload(l.applicant, *net, true);  // the departure from the group it left
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    CHECK(got->has_value());
}

TEST_CASE(
        "Devices - a device leaving its group tells it, and forgets it",
        "[core][devices][membership][leave]") {
    Linking l;
    l.admit();
    auto group = *TestHelper::group_id(*l.core);
    auto* net = attach_mock_network(*l.applicant);
    auto old_id = l.applicant_id();

    REQUIRE(l.applicant->devices.leave_group(await));

    // Under a new identity, with nothing of the group left, though the group itself is still
    // there to see.
    CHECK(l.applicant_id() != old_id);
    CHECK(l.applicant->devices.devices(true, true, true).empty());
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(account_key_count(l.applicant) == 0);
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::GroupsVisible);
    REQUIRE(state.others.size() == 1);
    CHECK(state.others[0].id == group);
    // Its own doing, so not news to it.
    CHECK(l.applicant_events.membership.back() == device::Membership::InGroup);

    // And the group hears of the departure, from a message it can read and the leaver will not
    // again, and moves to an account key the leaver does not hold: the one it was given, by the
    // push that admitted it.
    auto sent = pushes(*net);
    REQUIRE(sent.size() == 1);
    auto [farewell, deleted] = pushed(*sent[0]);
    REQUIRE_FALSE(farewell.empty());
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G1");
    auto key_before = l.core->devices.active_account_keys().front().x25519_pub;
    TestHelper::deliver_device_message(*l.core, farewell, in(10min), "G9");
    CHECK(l.core->devices.devices(true, true, true, old_id).at(old_id).state ==
          device::State::Left);
    ScopedClockOffset later{Devices::KEY_ROTATION_JITTER + 1s};
    TestHelper::finish_fetch(*l.core);
    CHECK(l.core->devices.active_account_keys().front().x25519_pub != key_before);

    // Nothing more to leave.
    CHECK_FALSE(l.applicant->devices.leave_group(await));
}

TEST_CASE(
        "Devices - a device that left a group can join it again, as a new device",
        "[core][devices][membership][leave]") {
    Linking l;
    l.admit();
    auto group = *TestHelper::group_id(*l.core);
    auto old_id = l.applicant_id();
    auto* net = attach_mock_network(*l.applicant);
    REQUIRE(l.applicant->devices.leave_group(await));
    TestHelper::deliver_device_message(*l.core, pushed(*pushes(*net)[0]).first, in(10min), "G9");
    REQUIRE(l.core->devices.devices(true, true, true, old_id).at(old_id).state ==
            device::State::Left);

    // The id it left under is spent there; the one it holds now has never been seen.
    answer_upload(l.applicant, *net, true);
    Asked got;
    request_link(l.applicant, group, got);
    auto request = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    auto prompts = l.events.added.size();
    TestHelper::deliver_device_message(*l.core, request, (*got)->expires, "L2");
    REQUIRE(l.events.added.size() == prompts + 1);
    CHECK_FALSE(l.events.added.back().replaces);
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G10");
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);

    // Both: the departure of the old id, and the new one in the group.
    auto held = l.core->devices.devices(true, true, true);
    CHECK(held.at(old_id).state == device::State::Left);
    CHECK(held.at(l.applicant_id()).state == device::State::Registered);
}

namespace {
int pending_pushes(TempCore& c) {
    return c->database().conn().prepared_get<int>("SELECT count(*) FROM device_pending_pushes");
}
}  // namespace

TEST_CASE(
        "Devices - a departure made without a network goes once there is one",
        "[core][devices][membership][leave]") {
    Linking l;
    l.admit();
    auto old_id = l.applicant_id();

    // Built, and kept, though nothing of the group is left to build it from again.
    REQUIRE(l.applicant->devices.leave_group(await));
    CHECK(pending_pushes(l.applicant) == 1);
    CHECK_FALSE(TestHelper::group_id(*l.applicant));

    SECTION("at the next fetch, and again until the swarm has it") {
        auto* net = attach_mock_network(*l.applicant);
        TestHelper::finish_fetch(*l.applicant);
        REQUIRE(pushes(*net).size() == 1);
        auto [farewell, deleted] = pushed(*pushes(*net)[0]);
        REQUIRE_FALSE(farewell.empty());

        answer_upload(l.applicant, *net, false);
        CHECK(pending_pushes(l.applicant) == 1);
        TestHelper::finish_fetch(*l.applicant);
        REQUIRE(pushes(*net).size() == 1);
        answer_upload(l.applicant, *net, true);
        CHECK(pending_pushes(l.applicant) == 0);

        // Nothing more to send.
        TestHelper::finish_fetch(*l.applicant);
        CHECK(pushes(*net).empty());

        TestHelper::deliver_device_message(*l.core, farewell, in(10min), "G9");
        CHECK(l.core->devices.devices(true, true, true, old_id).at(old_id).state ==
              device::State::Left);
    }

    SECTION("after a restart") {
        restart_applicant(l);
        auto* net = attach_mock_network(*l.applicant);
        TestHelper::finish_fetch(*l.applicant);
        REQUIRE(pushes(*net).size() == 1);
        auto [farewell, deleted] = pushed(*pushes(*net)[0]);
        TestHelper::deliver_device_message(*l.core, farewell, in(10min), "G9");
        CHECK(l.core->devices.devices(true, true, true, old_id).at(old_id).state ==
              device::State::Left);
    }

    SECTION("not once the group it was for has expired from the swarm") {
        ScopedClockOffset later{Devices::DEVICE_GROUP_TTL + 1min};
        auto* net = attach_mock_network(*l.applicant);
        TestHelper::finish_fetch(*l.applicant);
        CHECK(pushes(*net).empty());
        CHECK(pending_pushes(l.applicant) == 0);
    }
}

TEST_CASE(
        "Devices - a departure is stored in the same commit as the leaving",
        "[core][devices][membership][leave]") {
    Linking l;
    l.admit();
    auto old_id = l.applicant_id();
    auto group = *TestHelper::group_id(*l.applicant);
    auto sql = [&](const std::string& query) {
        TestHelper::on_loop(
                *l.applicant, [&] { return l.applicant->database().conn().prepared_exec(query); });
    };

    // Forgetting the group made to fail, after the departure is built, as an interruption there
    // would leave things.
    sql("CREATE TRIGGER interrupted BEFORE DELETE ON devices BEGIN SELECT RAISE(ABORT, 'x'); END");
    CHECK_THROWS(l.applicant->devices.leave_group(await));
    sql("DROP TRIGGER interrupted");

    // None of it, then: no departure waiting to go for a group still held.
    CHECK(pending_pushes(l.applicant) == 0);
    CHECK(TestHelper::group_id(*l.applicant) == group);
    CHECK(l.applicant_id() == old_id);
    CHECK(own_state(l.applicant) == device::State::Registered);

    // And all of it, done again.
    REQUIRE(l.applicant->devices.leave_group(await));
    CHECK(pending_pushes(l.applicant) == 1);
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(l.applicant_id() != old_id);
}

TEST_CASE(
        "Devices - a dissolution made without a network goes once there is one",
        "[core][devices][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_group(*other);
    auto theirs = *TestHelper::group_id(*other);
    TestHelper::deliver_device_message(
            *l.core, other->devices.build_device_group_message().message, in(10min), "B1");
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::Forked);
    // Nothing of its own owed, so that the push the fetch sends below is the dissolution's.
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G0");

    REQUIRE(l.core->devices.dissolve_group(theirs, await));
    CHECK(pending_pushes(l.core) == 1);

    auto* net = attach_mock_network(*l.core);
    TestHelper::finish_fetch(*l.core);
    REQUIRE(pushes(*net).size() == 1);
    auto [tombstone, deleted] = pushed(*pushes(*net)[0]);
    CHECK(deleted == nlohmann::json::array({"B1"}));
    answer_upload(l.core, *net, true);
    CHECK(pending_pushes(l.core) == 0);

    TestHelper::deliver_device_message(*other, tombstone, in(10min), "T1");
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);
}

TEST_CASE(
        "Devices - a device leaving a group of its own deletes it",
        "[core][devices][membership][leave]") {
    TempCore c;
    TestHelper::deliver_device_message(
            *c, c->devices.build_device_group_message().message, in(10min), "B1");
    auto* net = attach_mock_network(*c);

    REQUIRE(c->devices.leave_group(await));

    // Nobody was left in it, so it is deleted rather than told anything, and is no group to see.
    auto sent = pushes(*net);
    REQUIRE(sent.size() == 1);
    auto [stored, deleted] = pushed(*sent[0]);
    CHECK(stored.empty());
    CHECK(deleted == nlohmann::json::array({"B1"}));
    CHECK(c->devices.membership(await).others.empty());
}

TEST_CASE(
        "Devices - a device no longer in good standing leaves without a word",
        "[core][devices][membership][leave]") {
    Linking l;
    l.admit();

    SECTION("displaced") {
        // A copy of it admitted in its place, as in "a device whose place another has taken".
        TempCore copy{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
        TestHelper::set_device_id(*copy, l.applicant_id());
        ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
        TestHelper::deliver_device_message(
                *l.core, TestHelper::build_link_request(*copy, *l.core).message, in(10min), "L2");
        REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
        TestHelper::deliver_device_message(
                *l.applicant,
                l.core->devices.build_device_group_message().message,
                in(10min),
                "G2");
        REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Displaced);
    }
    SECTION("removed") {
        REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
        TestHelper::deliver_device_message(
                *l.applicant,
                l.core->devices.build_device_group_message().message,
                in(10min),
                "G2");
        REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Removed);
    }

    // A departure under its id would now apply to another device, or could not undo its removal.
    auto* net = attach_mock_network(*l.applicant);
    REQUIRE(l.applicant->devices.leave_group(await));
    CHECK(pushes(*net).empty());
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::GroupsVisible);
}

namespace {
// The record of device `id` that a group message carries, as `reader` -- one of its recipients --
// reads it.
device::Info record_in(Devices& reader, std::span<const std::byte> message, const device::Id& id) {
    auto plaintext = TestHelper::decrypt_device_data(reader, message);
    oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
    REQUIRE(btdc.skip_until("D"));
    auto devs = btdc.consume_dict_consumer();
    REQUIRE(devs.skip_until(std::string_view{reinterpret_cast<const char*>(id.data()), id.size()}));
    auto rec = devs.consume_dict_consumer();
    device::Info info{};
    info.seqno = rec.require<int64_t>("#");
    rec.skip_until("X");
    auto X = rec.consume_span<std::byte, 32>();
    std::ranges::copy(X, info.pk_x25519.begin());
    info.description = rec.maybe<std::string_view>("d").value_or(""sv);
    return info;
}
}  // namespace

TEST_CASE(
        "Devices - what a device says of itself goes with it from group to group",
        "[core][devices][membership]") {
    Linking l;
    device::Info described{};
    described.description = "Alice's tablet";
    described.type = device::Type::Session_Android;
    described.version = {1, 2, 3};
    l.applicant->devices.update_info(described, await);
    TestHelper::finish_fetch(*l.applicant);

    // A group of its own: the first record of it carries the description.
    l.applicant->devices.start_group(await);
    auto own = record_in(
            l.applicant->devices,
            l.applicant->devices.build_device_group_message().message,
            l.applicant_id());
    CHECK(own.description == "Alice's tablet");
    CHECK(own.seqno == 1);

    // The account's other group, which the user chooses: leave this one, then join that.
    l.show_group();
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Forked);
    REQUIRE(l.applicant->devices.leave_group(await));
    l.ask(in(10min), "L1");
    REQUIRE(!l.events.added.empty());
    CHECK(l.events.added.back().device.description == "Alice's tablet");
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    REQUIRE(l.applicant->devices.confirm_link(await));
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
    auto held = l.state_of_applicant();
    CHECK(held.description == "Alice's tablet");
    CHECK(held.type == device::Type::Session_Android);
    CHECK(held.version == std::array<int, 3>{1, 2, 3});
}

TEST_CASE(
        "Devices - a forged record of this device's own is overtaken by its next push",
        "[core][devices]") {
    Linking l;
    device::Info described{};
    described.description = "the real one";
    l.applicant->devices.update_info(described, await);
    l.admit();
    auto id = l.applicant_id();
    auto [core_self, _] = l.core->devices.device_info(await);
    auto mine = [&] { return l.applicant->devices.devices(true, false, false, id).at(id); };
    auto held = mine();

    // A seed holder who knows this device's keys writes a record for it at the seqno the group
    // holds, saying something else.  Whichever of two such records has the higher digest wins the
    // merge; the held one's is made the lowest there is, so that the forged one is the winner.
    TestHelper::on_loop(*l.applicant, [&] {
        return l.applicant->database().conn().prepared_exec(
                "UPDATE devices SET digest = zeroblob(8) WHERE unique_id = ?", id);
    });
    auto forged = held;
    forged.description = "forged";
    TestHelper::receive_device_group_message(
            l.applicant->devices,
            TestHelper::encrypt_device_data(
                    l.core->devices, {{core_self.id, core_self}, {id, forged}}));
    REQUIRE(mine().description == "forged");
    CHECK(mine().seqno == held.seqno);

    // Merged like anyone's, but nothing of it goes into what this device publishes: its next push
    // carries its own record, past the forged one.
    CHECK(l.applicant->devices.needs_push().device_group);
    auto push = l.applicant->devices.build_device_group_message();
    auto pushed = record_in(l.core->devices, push.message, id);
    CHECK(pushed.description == "the real one");
    CHECK(pushed.seqno == held.seqno + 1);
    CHECK(pushed.pk_x25519 == l.applicant->devices.active_device_keys().front().x25519_pub);

    // Which the group takes, and so does this device once the swarm has it.
    TestHelper::deliver_device_message(*l.core, push.message, in(10min), "G2");
    CHECK(l.state_of_applicant().description == "the real one");
    l.applicant->devices.mark_device_group_pushed(push, "G2");
    CHECK(mine().description == "the real one");
    CHECK(mine().seqno == held.seqno + 1);
    CHECK_FALSE(l.applicant->devices.needs_push().device_group);
}

TEST_CASE(
        "Devices - a removed device comes back under a new identity",
        "[core][devices][membership]") {
    Linking l;
    l.admit();
    auto group = *TestHelper::group_id(*l.core);
    auto old_id = l.applicant_id();
    REQUIRE(l.core->devices.remove_device(old_id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Removed);

    // Asking again is all it takes: the new identity comes with the asking.
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l.applicant, group, got);
    auto request = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    CHECK(l.applicant_id() != old_id);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Requesting);

    // Nothing of its old group left to carry into one it starts, or to mistake for the one it
    // joins -- its account keys included.
    auto held = l.applicant->devices.devices(true, true, true);
    REQUIRE(held.size() == 1);
    CHECK(held.begin()->first == l.applicant_id());
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(account_key_count(l.applicant) == 0);

    // And joins again like any device asking: the new id is not the one the group removed.
    TestHelper::deliver_device_message(*l.core, request, (*got)->expires, "L2");
    REQUIRE(l.events.added.size() == 2);
    REQUIRE(l.core->devices.accept_request(l.events.added[1].id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G3");
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
}

namespace {

// The applicant as it would be after losing track of having joined -- restored from a backup taken
// before, at `seqno`: not in a group as far as it knows, and holding keys the group never saw.
void lose_track(Linking& l, int64_t seqno) {
    auto id = l.applicant_id();
    TestHelper::on_loop(*l.applicant, [&] {
        l.applicant->database().conn().prepared_exec(
                "UPDATE devices SET state = ?, seqno = ? WHERE unique_id = ?",
                static_cast<int>(device::State::Unregistered),
                seqno,
                id);
        l.applicant->devices.rotate_device_keys();
        return 0;
    });
}

}  // namespace

TEST_CASE(
        "Devices - a device that lost track of joining asks to replace its record",
        "[core][devices][linking]") {
    Linking l;
    auto backup = l.applicant->devices.device_info(await).first.seqno;
    l.admit();

    // Details changed since joining, which the group holds and the backup does not: the request
    // comes from a device whose seqno is behind its record's.
    auto renamed = l.applicant->devices.device_info(await).first;
    renamed.description = "renamed";
    l.applicant->devices.update_info(renamed, await);
    TestHelper::deliver_device_message(
            *l.core, l.applicant->devices.build_device_group_message().message, in(10min), "G1b");
    auto before = l.state_of_applicant();
    REQUIRE(before.description == "renamed");
    auto keys_before = account_key_count(l.core);

    ScopedClockOffset later{1min};
    lose_track(l, backup);
    l.ask(in(10min), "L2");

    REQUIRE(l.events.added.size() == 2);
    auto asked = l.events.added[1];
    REQUIRE(asked.replaces);
    CHECK(asked.replaces->pk_x25519 == before.pk_x25519);
    CHECK(asked.device.pk_x25519 != before.pk_x25519);
    // Until someone accepts, the group goes on encrypting to the record it holds.
    CHECK(l.state_of_applicant().pk_x25519 == before.pk_x25519);

    REQUIRE(l.core->devices.accept_request(asked.id, await));
    auto after = l.state_of_applicant();
    CHECK(after.state == device::State::Registered);
    CHECK(after.pk_x25519 == asked.device.pk_x25519);
    CHECK(after.seqno > before.seqno);
    CHECK(account_key_count(l.core) == keys_before + 1);

    // And the device joins as any new device does: once its user has confirmed the SAS too.
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(l.applicant->devices.device_info(await).first.pk_x25519 == after.pk_x25519);
}

TEST_CASE(
        "Devices - the request that admitted a device does not ask to replace it",
        "[core][devices][linking]") {
    Linking l;
    auto first = l.ask();
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));

    // Still in the swarm, and fetched again by a device that missed it the first time round.
    TestHelper::deliver_device_message(*l.core, first.message, in(10min), "L1-again");
    CHECK(l.events.added.size() == 1);
    CHECK(l.core->devices.incoming_link_requests(await).empty());
}

TEST_CASE(
        "Devices - a removed device cannot ask to replace its record", "[core][devices][linking]") {
    Linking l;
    auto backup = l.applicant->devices.device_info(await).first.seqno;
    l.admit();
    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));

    ScopedClockOffset later{1min};
    lose_track(l, backup);
    l.ask(in(10min), "L2");
    CHECK(l.events.added.size() == 1);
    CHECK(l.core->devices.incoming_link_requests(await).empty());
}

TEST_CASE(
        "Devices - a replacement accepted elsewhere closes the prompt here",
        "[core][devices][linking]") {
    Linking l;
    auto backup = l.applicant->devices.device_info(await).first.seqno;
    l.admit();

    // A third device in the group, to see the request without answering it.
    DeviceEventsRecorder third_events;
    TempCore third{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(third_events)};
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_link_request(*third, *l.core).message, in(10min), "L3");
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    TestHelper::deliver_device_message(
            *third, l.core->devices.build_device_group_message().message, in(10min), "G2");
    REQUIRE(third->devices.confirm_link(await));
    REQUIRE(third->devices.membership(await).membership == device::Membership::InGroup);

    ScopedClockOffset later{1min};
    lose_track(l, backup);
    auto asked = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(*l.core, asked.message, in(10min), "L4");
    TestHelper::deliver_device_message(*third, asked.message, in(10min), "L4");
    REQUIRE(third_events.added.size() == 1);
    REQUIRE(third_events.added[0].replaces);

    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    TestHelper::deliver_device_message(
            *third, l.core->devices.build_device_group_message().message, in(10min), "G3");
    CHECK(third_events.ended ==
          std::vector{std::pair{third_events.added[0].id, device::LinkRequestEnd::Accepted}});
    CHECK(third->devices.incoming_link_requests(await).empty());
}

TEST_CASE(
        "Devices - a device whose place another has taken is told so",
        "[core][devices][membership]") {
    Linking l;
    l.admit();

    // A copy of the applicant, under its id but with keys of its own, admitted in its place.
    TempCore copy{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::set_device_id(*copy, l.applicant_id());
    ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_link_request(*copy, *l.core).message, in(10min), "L2");
    REQUIRE(l.events.added.back().replaces);
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));

    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Displaced);
    CHECK(l.applicant_events.membership.back() == device::Membership::Displaced);

    // It speaks for the group no longer: nothing pushed, nobody admitted or removed.
    CHECK_FALSE(l.applicant->devices.needs_push().device_group);
    CHECK_FALSE(l.applicant->devices.remove_device(Linking::id_of(l.core), await));

    // The way back is a removed device's: asking to join again, as a new device, which takes the
    // new identity as part of the asking.
    auto old_id = l.applicant_id();
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l.applicant, *TestHelper::group_id(*l.core), got);
    auto request = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    CHECK(l.applicant_id() != old_id);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Requesting);

    // Not under the id the copy now holds, so asking as a new device, not to replace it.
    auto prompts = l.events.added.size();
    TestHelper::deliver_device_message(*l.core, request, (*got)->expires, "L3");
    REQUIRE(l.events.added.size() == prompts + 1);
    CHECK_FALSE(l.events.added.back().replaces);
}

TEST_CASE(
        "Devices - a snapshot that has yet to hear of this device does not displace it",
        "[core][devices][membership]") {
    Linking l;
    // The group as it was before the applicant joined, which a member could still push for a moment
    // after: built before it fetched the admission.
    auto before = l.core->devices.build_device_group_message().message;

    // Admitted by a message held until the user confirms, which is when it is read -- but as of
    // when it was written.
    l.ask();
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    REQUIRE(l.applicant->devices.confirm_link(await));
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::InGroup);

    TestHelper::deliver_device_message(*l.applicant, before, in(10min), "G-stale");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);

    // Nor when it arrives long after: it is as old as it was written, which is not something a
    // storage server can change.
    ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
    TestHelper::deliver_device_message(*l.applicant, before, in(10min), "G-late");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);

    // Beyond the grace, though, a message leaving it out is one the group sent without it.
    auto [core_self, _] = l.core->devices.device_info(await);
    TestHelper::deliver_device_message(
            *l.applicant,
            TestHelper::encrypt_device_data(l.core->devices, {{core_self.id, core_self}}),
            in(10min),
            "G-without");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Displaced);

    // And reading the group again, at or past what displaced it, puts it back.
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
}

TEST_CASE(
        "Devices - a removed device starts a group under a new identity",
        "[core][devices][membership]") {
    Linking l;
    l.admit();
    auto old_id = l.applicant_id();
    auto theirs = *TestHelper::group_id(*l.core);
    REQUIRE(l.core->devices.remove_device(old_id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Removed);

    // Out of the group it was removed from first, and so, under the rule for starting a group
    // with others in view, dissolving it: nothing of that group comes along.
    auto mine = l.applicant->devices.start_group(await);
    CHECK(mine != theirs);
    CHECK(l.applicant_id() != old_id);
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.others.empty());
    auto devs = l.applicant->devices.devices(true, true, true);
    REQUIRE(devs.size() == 1);
    CHECK(devs.begin()->first == l.applicant_id());
}

TEST_CASE(
        "Devices - a removed device is told so, though it can read nothing else",
        "[core][devices][removal]") {
    Linking l;
    l.admit();
    auto key_before = l.core->devices.active_account_keys().front().x25519_pub;

    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    CHECK(l.state_of_applicant().state == device::State::Kicked);

    // The key it held is no longer the current one.
    CHECK(l.core->devices.active_account_keys().front().x25519_pub != key_before);

    // It is given no key to the message that removes it...
    auto group = l.core->devices.build_device_group_message().message;
    CHECK_THROWS_AS(
            TestHelper::decrypt_device_data(l.applicant->devices, group),
            device::decryption_failed);

    // ...but learns of the removal from the kicked list all the same.
    TestHelper::deliver_device_message(*l.applicant, group, in(10min), "G2");
    CHECK(own_state(l.applicant) == device::State::Kicked);
    REQUIRE(!l.applicant_events.membership.empty());
    CHECK(l.applicant_events.membership.back() == device::Membership::Removed);
}

TEST_CASE(
        "Devices - a member learning of a departure replaces the account key within the jitter",
        "[core][devices][removal][rotation]") {
    Linking l;
    l.admit();
    // The existing device's push, confirmed: what delivered the key to the applicant.
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G1");
    auto current = [&] { return l.core->devices.active_account_keys().front().x25519_pub; };
    auto before = current();
    auto scheduled = *l.core->devices.next_account_rotation();
    REQUIRE(scheduled > clock_now() + Devices::KEY_ROTATION_PERIOD - Devices::KEY_ROTATION_JITTER);

    // The farewell the applicant pushes on leaving: its own view of the group, itself departed.
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto leaver = l.state_of_applicant();
    leaver.state = device::State::Left;
    leaver.kicked = clock_now_s();
    auto farewell = TestHelper::encrypt_device_data(
            l.applicant->devices, {{self.id, self}, {leaver.id, leaver}});
    TestHelper::deliver_device_message(*l.core, farewell, in(10min), "G2");

    // Not at once, but soon: every member learning of it is due within the jitter, and whichever
    // rotates first stands the rest down.  The same moment however often it is asked.
    CHECK(current() == before);
    auto due = *l.core->devices.next_account_rotation();
    CHECK(due <= clock_now() + Devices::KEY_ROTATION_JITTER);
    CHECK(*l.core->devices.next_account_rotation() == due);

    // A key the departed device does not hold, and nothing early about the next.
    ScopedClockOffset later{Devices::KEY_ROTATION_JITTER + 1s};
    TestHelper::finish_fetch(*l.core);
    auto after = current();
    CHECK(after != before);
    for (const auto& k : l.applicant->devices.active_account_keys())
        CHECK(k.x25519_pub != after);
    CHECK(*l.core->devices.next_account_rotation() >
          clock_now() + Devices::KEY_ROTATION_PERIOD - Devices::KEY_ROTATION_JITTER);

    // Hearing of the same departure again -- restated later, as a device trying to return gets --
    // is not a second one.
    leaver.kicked = clock_now_s() + 1h;
    TestHelper::deliver_device_message(
            *l.core,
            TestHelper::encrypt_device_data(
                    l.applicant->devices, {{self.id, self}, {leaver.id, leaver}}),
            in(10min),
            "G3");
    CHECK(current() == after);
}

TEST_CASE(
        "Devices - a member learning of a removal brings both its rotations forward",
        "[core][devices][removal][rotation]") {
    Linking l;
    l.admit();
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G1");
    auto soon = [] { return clock_now() + Devices::KEY_ROTATION_JITTER; };
    REQUIRE(*l.core->devices.next_account_rotation() > soon());
    REQUIRE(*l.core->devices.next_device_rotation() > soon());

    // A removal made elsewhere, by a device that kept the key the removed device holds -- one that
    // never heard of the rotation the remover made, say.
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto removed = l.state_of_applicant();
    removed.state = device::State::Kicked;
    removed.kicked = clock_now_s();
    TestHelper::deliver_device_message(
            *l.core,
            TestHelper::encrypt_device_data(
                    l.applicant->devices, {{self.id, self}, {removed.id, removed}}),
            in(10min),
            "G2");

    // The account key, because the removed device holds it; our device keys, because it knows them.
    CHECK(*l.core->devices.next_account_rotation() <= soon());
    CHECK(*l.core->devices.next_device_rotation() <= soon());
}

namespace {

// The devices a group message says anything about, records and tombstones alike.
std::set<device::Id> carried_ids(Devices& d, std::span<const std::byte> message) {
    auto plaintext = TestHelper::decrypt_device_data(d, message);
    oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
    REQUIRE(btdc.skip_until("D"));
    auto devs = btdc.consume_dict_consumer();
    std::set<device::Id> ids;
    while (!devs.is_finished()) {
        auto key = devs.key();
        REQUIRE(key.size() == device::ID_SIZE);
        device::Id id;
        std::memcpy(id.data(), key.data(), id.size());
        ids.insert(id);
        devs.consume_dict_data();
    }
    return ids;
}

size_t kicked_slots(std::span<const std::byte> message) {
    oxenc::bt_dict_consumer outer{message};
    return outer.skip_until("k") ? outer.consume_span<std::byte>().size() / 16 : 0;
}

device::Info tombstone(device::State state, std::chrono::sys_seconds when) {
    device::Info t{};
    random::fill(t.id);
    t.state = state;
    t.kicked = when;
    return t;
}

}  // namespace

TEST_CASE(
        "Devices - a message carries only the most recent removal markers",
        "[core][devices][removal]") {
    TempCore c;
    auto [self, registered] = c->devices.device_info(await);
    REQUIRE(registered);
    device::map group{{self.id, self}};

    // Another device holding the account seed, to read the `kicked` list as a removed one would.
    TempCore removed{core::predefined_seed{std::span<const std::byte, 32>{Linking::seed_of(c)}}};

    // Removals and departures, the newest first.
    std::vector<device::Info> markers;
    for (int i = 0; i < 10; i++) {
        auto& m = markers.emplace_back(tombstone(
                i % 2 ? device::State::Left : device::State::Kicked,
                std::chrono::floor<std::chrono::seconds>(clock_now_s()) - (i + 1) * 1h));
        group.emplace(m.id, m);
    }

    // One bucket's worth for each bucket of live devices: 4 with only this one in the group, 8 with
    // a fifth device.  Departures count towards it, though only removals are in `kicked`.
    auto check = [&](size_t cap) {
        auto message = TestHelper::encrypt_device_data(c->devices, group);
        auto carried = carried_ids(c->devices, message);
        for (size_t i = 0; i < markers.size(); i++) {
            CHECK(carried.contains(markers[i].id) == (i < cap));
            if (markers[i].state == device::State::Kicked) {
                TestHelper::set_device_id(*removed, markers[i].id);
                CHECK(TestHelper::names_us_kicked(*removed, message) == (i < cap));
            }
        }
        CHECK(kicked_slots(message) == 4);
    };

    SECTION("one device") {
        check(4);
    }
    SECTION("five devices") {
        for (int i = 0; i < 4; i++) {
            auto k = c->devices.rotate_device_keys();
            device::Info other{};
            random::fill(other.id);
            other.seqno = 1;
            other.timestamp = clock_now_s();
            other.state = device::State::Registered;
            other.pk_x25519 = k.x25519_pub;
            other.pk_mlkem768 = k.mlkem768_pub;
            group.emplace(other.id, other);
        }
        check(8);
    }
}

TEST_CASE(
        "Devices - a message from our group we cannot read says what became of us by its removals",
        "[core][devices][membership][removal]") {
    Linking l;
    l.admit();
    auto now = std::chrono::floor<std::chrono::seconds>(clock_now_s());

    // A removal the applicant knows of, from a message it could read.
    auto known = tombstone(device::State::Kicked, now - 1h);
    auto group = l.core->devices.devices(true, true, true);
    group.emplace(known.id, known);
    TestHelper::deliver_device_message(
            *l.applicant, TestHelper::encrypt_device_data(l.core->devices, group), in(10min), "G1");
    REQUIRE(l.applicant->devices.devices(false, false, true).contains(known.id));

    // The group gone on without the applicant, carrying `removed` -- as any holder of the seed
    // could write it.
    auto core_self = l.core->devices.device_info(await).first;
    auto without = [&](std::vector<device::Info> removed) {
        device::map m{{core_self.id, core_self}};
        for (auto& r : removed)
            m.emplace(r.id, r);
        return TestHelper::encrypt_device_data(l.core->devices, m);
    };
    auto membership = [&] { return l.applicant->devices.membership(await).membership; };

    SECTION("naming it: removed, however soon after what it last read") {
        auto ours = tombstone(device::State::Kicked, now);
        ours.id = l.applicant_id();
        TestHelper::deliver_device_message(*l.applicant, without({known, ours}), in(10min), "G2");
        CHECK(membership() == device::Membership::Removed);
    }

    SECTION("with a removal it knew of and not its own: displaced") {
        ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
        TestHelper::deliver_device_message(*l.applicant, without({known}), in(10min), "G2");
        CHECK(membership() == device::Membership::Displaced);
    }

    SECTION("with no removal at all") {
        SECTION("having read the group lately: displaced") {
            ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
            TestHelper::deliver_device_message(*l.applicant, without({}), in(10min), "G2");
            CHECK(membership() == device::Membership::Displaced);
        }
        SECTION("not for longer than removals are carried: dropped") {
            ScopedClockOffset later{Devices::REMOVAL_MARKER_MAX_AGE + 1h};
            TestHelper::deliver_device_message(*l.applicant, without({}), in(10min), "G2");
            CHECK(membership() == device::Membership::Dropped);
        }
    }

    SECTION("with only removals it never heard of: dropped, which acts on nothing") {
        // Within the grace, a snapshot that may have yet to hear of it, and so nothing.
        auto unknown = tombstone(device::State::Kicked, now);
        TestHelper::deliver_device_message(*l.applicant, without({unknown}), in(10min), "G2");
        REQUIRE(membership() == device::Membership::InGroup);

        // A forger cannot make more of it than that: nothing pushed, nobody admitted or removed.
        ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
        TestHelper::deliver_device_message(*l.applicant, without({unknown}), in(10min), "G3");
        CHECK(membership() == device::Membership::Dropped);
        CHECK(l.applicant_events.membership.back() == device::Membership::Dropped);
        CHECK_FALSE(l.applicant->devices.needs_push().device_group);
        CHECK_FALSE(l.applicant->devices.remove_device(Linking::id_of(l.core), await));

        // A later one telling more says so.
        later.advance(1min);
        TestHelper::deliver_device_message(*l.applicant, without({known}), in(10min), "G4");
        CHECK(membership() == device::Membership::Displaced);

        // And reading the group again, at or past both, puts it back.
        TestHelper::deliver_device_message(
                *l.applicant,
                l.core->devices.build_device_group_message().message,
                in(10min),
                "G5");
        CHECK(membership() == device::Membership::InGroup);
    }
}

TEST_CASE("Devices - a removal announced by another group is ignored", "[core][devices][removal]") {
    Linking l;
    l.admit();

    // Another group on the account, whose message names the applicant's id as removed.
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_group(*other);
    auto other_self = other->devices.device_info(await).first;
    auto ours = tombstone(
            device::State::Kicked, std::chrono::floor<std::chrono::seconds>(clock_now_s()));
    ours.id = l.applicant_id();
    auto message = TestHelper::encrypt_device_data(
            other->devices, {{other_self.id, other_self}, {ours.id, ours}});
    REQUIRE(TestHelper::names_us_kicked(*l.applicant, message));

    ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
    TestHelper::deliver_device_message(*l.applicant, message, in(10min), "B1");
    CHECK(l.applicant->devices.device_info(await).first.state == device::State::Registered);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Forked);
}

TEST_CASE(
        "Devices - an old removal leaves the group's messages but not this device",
        "[core][devices][removal]") {
    TempCore c;
    auto k = c->devices.rotate_device_keys();
    auto [self, registered] = c->devices.device_info(await);
    REQUIRE(registered);

    auto removal = tombstone(device::State::Kicked, clock_now_s());
    TestHelper::receive_device_group_message(
            c->devices,
            TestHelper::encrypt_device_data(c->devices, {{self.id, self}, {removal.id, removal}}));
    REQUIRE(carried_ids(c->devices, c->devices.build_device_group_message().message)
                    .contains(removal.id));

    ScopedClockOffset later{Devices::REMOVAL_MARKER_MAX_AGE + 1h};
    auto message = c->devices.build_device_group_message().message;
    CHECK_FALSE(carried_ids(c->devices, message).contains(removal.id));
    CHECK(kicked_slots(message) == 0);

    // Still held here, and still what stops the device coming back.
    auto held = c->devices.devices(true, true, true, removal.id);
    REQUIRE(held.size() == 1);
    CHECK(held.begin()->second.state == device::State::Kicked);

    auto returning = removal;
    returning.state = device::State::Registered;
    returning.kicked.reset();
    returning.seqno = 5;
    returning.timestamp = clock_now_s();
    returning.pk_x25519 = k.x25519_pub;
    returning.pk_mlkem768 = k.mlkem768_pub;
    TestHelper::receive_device_group_message(
            c->devices,
            TestHelper::encrypt_device_data(
                    c->devices, {{self.id, self}, {returning.id, returning}}));
    CHECK(c->devices.devices(true, true, true, removal.id).begin()->second.state ==
          device::State::Kicked);

    // Restated as of now, so that the group's messages carry it again.
    CHECK(carried_ids(c->devices, c->devices.build_device_group_message().message)
                  .contains(removal.id));
}

TEST_CASE("Devices - a device that left is not told it was removed", "[core][devices][removal]") {
    Linking l;
    l.admit();

    // A group message carrying a departure for it, as the group it left would push.
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto left = l.state_of_applicant();
    left.state = device::State::Left;
    left.kicked = clock_now_s();
    auto group =
            TestHelper::encrypt_device_data(l.core->devices, {{self.id, self}, {left.id, left}});

    TestHelper::deliver_device_message(*l.applicant, group, in(10min), "G2");
    CHECK(own_state(l.applicant) == device::State::Registered);
}

TEST_CASE(
        "Devices - only a device in the group can be removed, and only by another",
        "[core][devices][removal]") {
    Linking l;
    device::Id unknown;
    random::fill(unknown);
    CHECK_FALSE(l.core->devices.remove_device(unknown, await));

    // Still only asking: that is ignore_request's to answer.
    l.ask();
    CHECK_FALSE(l.core->devices.remove_device(l.applicant_id(), await));
    CHECK(l.state_of_applicant().state == device::State::Pending);

    // A device outside the group has nobody to remove.
    auto [self, registered] = l.core->devices.device_info(await);
    CHECK_FALSE(l.applicant->devices.remove_device(self.id, await));

    CHECK_THROWS_AS(l.core->devices.remove_device(self.id, await), std::invalid_argument);
}

namespace {

// Each of the pair's pushes confirmed and read by the other, so that neither owes anything.
void settle(Linking& l) {
    auto mine = l.applicant->devices.build_device_group_message();
    l.applicant->devices.mark_device_group_pushed(mine, "S1");
    TestHelper::deliver_device_message(*l.core, mine.message, in(10min), "S1");
    auto theirs = l.core->devices.build_device_group_message();
    l.core->devices.mark_device_group_pushed(theirs, "S2");
    TestHelper::deliver_device_message(*l.applicant, theirs.message, in(10min), "S2");
    REQUIRE_FALSE(l.core->devices.needs_push().device_group);
    REQUIRE_FALSE(l.applicant->devices.needs_push().device_group);
}

bool carries_transition(const Devices::DeviceGroupPush& push, const device::Id& id) {
    return std::ranges::any_of(push.broadcast, [&](const auto& b) { return b.first == id; });
}

}  // namespace

TEST_CASE(
        "Devices - merging another device's change owes no push of our own",
        "[core][devices][push]") {
    Linking l;
    l.admit();
    settle(l);

    // The device that makes a change owes the push carrying it.
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_link_request(*third, *l.core).message, in(10min), "L2");
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    REQUIRE(l.core->devices.needs_push().device_group);

    // The message carrying it is in the swarm already, so the other member has nothing to relay.
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G3");
    REQUIRE(l.applicant->devices.devices().size() == 3);
    CHECK_FALSE(l.applicant->devices.needs_push().device_group);

    // Nor for a removal, nor the account key the removing device minted with it.
    REQUIRE(l.core->devices.remove_device(Linking::id_of(third), await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G4");
    REQUIRE(l.applicant->devices.devices().size() == 2);
    REQUIRE(l.applicant->devices.active_account_keys().front().x25519_pub ==
            l.core->devices.active_account_keys().front().x25519_pub);
    CHECK_FALSE(l.applicant->devices.needs_push().device_group);
}

TEST_CASE(
        "Devices - a removal restated while its push is in flight is still owed after it",
        "[core][devices][push]") {
    Linking l;
    l.admit();
    // The removed device's view of the group, which it can push again whenever it likes.
    auto revived = l.applicant->devices.build_device_group_message().message;

    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    auto push = l.core->devices.build_device_group_message();
    REQUIRE(carries_transition(push, l.applicant_id()));

    // Brought back while the push is in flight, and the removal restated.
    TestHelper::deliver_device_message(*l.core, revived, in(10min), "G2");
    l.core->devices.mark_device_group_pushed(push, "G3");
    CHECK(carries_transition(l.core->devices.build_device_group_message(), l.applicant_id()));
}

TEST_CASE(
        "Devices - an account key merged from another device is not ours to distribute",
        "[core][devices][push][rotation]") {
    Linking l;
    l.admit();
    settle(l);

    l.core->devices.rotate_account_keys();
    auto push = l.core->devices.build_device_group_message();
    l.core->devices.mark_device_group_pushed(push, "G3");
    TestHelper::deliver_device_message(*l.applicant, push.message, in(10min), "G3");
    REQUIRE(l.applicant->devices.active_account_keys().front().x25519_pub ==
            l.core->devices.active_account_keys().front().x25519_pub);
    CHECK_FALSE(l.applicant->devices.needs_push().device_group);
}

namespace {
auto account_key(TempCore& c) {
    return c->devices.active_account_keys().front().x25519_pub;
}
auto device_key(TempCore& c) {
    return c->devices.active_device_keys().front().x25519_pub;
}
}  // namespace

TEST_CASE(
        "Devices - a member rotates both its keys when due, after a fetch, in one push",
        "[core][devices][rotation]") {
    Linking l;
    auto* net = attach_mock_network(*l.core);
    TestHelper::finish_fetch(*l.core);
    answer_upload(l.core, *net, true);
    REQUIRE_FALSE(l.core->devices.needs_push().device_group);
    auto account = account_key(l.core);
    auto device = device_key(l.core);

    // Long away: both overdue, but nothing rotated until a fetch has brought what waited for it,
    // encrypted to the keys it had.
    ScopedClockOffset later{Devices::KEY_ROTATION_PERIOD + Devices::KEY_ROTATION_JITTER};
    REQUIRE(l.core->devices.account_rotation_due());
    REQUIRE(l.core->devices.device_rotation_due());
    CHECK(account_key(l.core) == account);
    CHECK(device_key(l.core) == device);

    auto before = pushes(*net).size();
    TestHelper::finish_fetch(*l.core);
    CHECK(account_key(l.core) != account);
    CHECK(device_key(l.core) != device);
    REQUIRE(pushes(*net).size() == before + 1);
    answer_upload(l.core, *net, true);
    CHECK_FALSE(l.core->devices.needs_push().device_group);

    // Once: the next fetch finds neither due.
    account = account_key(l.core);
    device = device_key(l.core);
    TestHelper::finish_fetch(*l.core);
    CHECK(account_key(l.core) == account);
    CHECK(device_key(l.core) == device);
    CHECK(pushes(*net).empty());
}

TEST_CASE(
        "Devices - a device outside a group keeps the keys its request names",
        "[core][devices][rotation][linking]") {
    Linking l;
    l.ask();
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Requesting);
    CHECK_FALSE(l.applicant->devices.next_device_rotation());
    CHECK_FALSE(l.applicant->devices.next_account_rotation());

    auto device = device_key(l.applicant);
    ScopedClockOffset later{Devices::KEY_ROTATION_PERIOD + Devices::KEY_ROTATION_JITTER};
    TestHelper::finish_fetch(*l.applicant);
    CHECK(device_key(l.applicant) == device);
}

TEST_CASE(
        "Devices - a device with a quiet swarm still rotates on time",
        "[core][devices][rotation]") {
    Linking l;
    auto* net = attach_mock_network(*l.core);
    TestHelper::finish_fetch(*l.core);
    answer_upload(l.core, *net, true);
    auto account = account_key(l.core);
    auto device = device_key(l.core);

    // To within a second of the earlier rotation, and the timer re-armed from there by a fetch, so
    // that it is the timer that notices rather than anything this test does.
    auto next = std::min(
            *l.core->devices.next_account_rotation(), *l.core->devices.next_device_rotation());
    ScopedClockOffset later{
            std::chrono::duration_cast<std::chrono::seconds>(next - clock_now()) - 1s};
    TestHelper::finish_fetch(*l.core);
    REQUIRE(account_key(l.core) == account);
    REQUIRE(device_key(l.core) == device);

    // It fetches the group, and rotates after that fetch, as after any other.
    REQUIRE(eventually(
            *l.core, [&] { return std::ranges::any_of(net->sent_requests, is_device_fetch); }));
    later.advance(2s);
    REQUIRE(answer_fetch(l.core, *net) == 1);
    CHECK((account_key(l.core) != account || device_key(l.core) != device));
}

TEST_CASE(
        "Devices - a key minted without hearing of a removal is replaced, at once by the remover",
        "[core][devices][removal][rotation]") {
    Linking l;
    l.admit();

    // A third member, which hears nothing of what follows until it has rotated.
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_link_request(*third, *l.core).message, in(10min), "L2");
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    auto joined = l.core->devices.build_device_group_message();
    l.core->devices.mark_device_group_pushed(joined, "G2");
    TestHelper::deliver_device_message(*third, joined.message, in(10min), "G2");
    REQUIRE(third->devices.confirm_link(await));
    REQUIRE(third->devices.membership(await).membership == device::Membership::InGroup);

    // The existing device removes the applicant, rotating as it does...
    ScopedClockOffset later{1min};
    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    auto removal = l.core->devices.build_device_group_message();
    l.core->devices.mark_device_group_pushed(removal, "G3");

    // ...while the third rotates on its own schedule, and its push delivers the newer key -- the
    // one every device will take as current -- to the removed device.
    later.advance(1min);
    third->devices.rotate_account_keys();
    auto concurrent = third->devices.build_device_group_message();
    third->devices.mark_device_group_pushed(concurrent, "G4");
    auto leaked = account_key(third);

    SECTION("the remover replaces it at once") {
        TestHelper::deliver_device_message(*l.core, concurrent.message, in(10min), "G4");
        CHECK(account_key(l.core) != leaked);
    }

    SECTION("any other member within the jitter, standing down when another gets there first") {
        TestHelper::deliver_device_message(*third, removal.message, in(10min), "G3");
        REQUIRE(account_key(third) == leaked);
        CHECK(*third->devices.next_account_rotation() <=
              clock_now() + Devices::KEY_ROTATION_JITTER);

        TestHelper::deliver_device_message(*l.core, concurrent.message, in(10min), "G4");
        TestHelper::deliver_device_message(
                *third, l.core->devices.build_device_group_message().message, in(10min), "G5");
        CHECK(account_key(third) == account_key(l.core));
        CHECK(*third->devices.next_account_rotation() >
              clock_now() + Devices::KEY_ROTATION_PERIOD - Devices::KEY_ROTATION_JITTER);
    }
}

TEST_CASE(
        "Devices - a device admitted to a group with an old departure does not rotate",
        "[core][devices][rotation][linking]") {
    Linking l;

    // A device that was in the group once, and left a month ago.
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto gone = tombstone(
            device::State::Left,
            std::chrono::floor<std::chrono::seconds>(clock_now_s()) - Devices::DEVICE_GROUP_TTL);
    TestHelper::deliver_device_message(
            *l.core,
            TestHelper::encrypt_device_data(l.core->devices, {{self.id, self}, {gone.id, gone}}),
            in(10min),
            "G0");
    REQUIRE(l.core->devices.devices(false, false, true).contains(gone.id));

    // Every departure in the group's history is new to a device joining it, and none of them
    // holds the key it is given.
    l.admit();
    CHECK(account_key(l.applicant) == account_key(l.core));
    CHECK(*l.applicant->devices.next_account_rotation() >
          clock_now() + Devices::KEY_ROTATION_PERIOD - Devices::KEY_ROTATION_JITTER);
}
