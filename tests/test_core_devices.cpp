#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/clock.hpp>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/core/error_codes.hpp>
#include <session/core/globals.hpp>
#include <session/xed25519.hpp>
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

    SECTION("device_id is 64-char hex") {
        auto id = c->devices.device_id();
        REQUIRE(id.size() == 64);
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
        // seqno == 0 is the sentinel meaning no row exists yet
        CHECK(info.seqno == 0);
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

    SECTION("update_info persists fields and sets seqno=1") {
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
    }

    SECTION("identical update does not bump seqno") {
        device::Info info{};
        info.type = device::Type::Session_Desktop;
        info.description = "desktop";
        info.version = {0, 1, 0};

        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 1);

        c->devices.update_info(info, await);  // identical — should not bump
        CHECK(c->devices.device_info(await).first.seqno == 1);
    }

    SECTION("changed description bumps seqno") {
        device::Info info{};
        info.description = "first";
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 1);

        info.description = "second";
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 2);
    }

    SECTION("changed type bumps seqno") {
        device::Info info{};
        info.type = device::Type::Session_Android;
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 1);

        info.type = device::Type::Session_Desktop;
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 2);
    }

    SECTION("changed version bumps seqno") {
        device::Info info{};
        info.version = {1, 0, 0};
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 1);

        info.version = {2, 0, 0};
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 2);
    }

    SECTION("extra fields round-trip and participate in comparison") {
        device::Info info{};
        info.extra["custom_key"] = std::string{"hello"};
        c->devices.update_info(info, await);

        auto [got, _] = c->devices.device_info(await);
        CHECK(got.seqno == 1);
        REQUIRE(got.extra.count("custom_key"));
        CHECK(std::get<std::string>(got.extra.at("custom_key")) == "hello");

        // Same extra — no bump
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 1);

        // Changed extra — bump
        info.extra["custom_key"] = std::string{"world"};
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 2);
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

    SECTION("update_info device appears in devices(include_unregistered=true)") {
        device::Info info{};
        info.description = "my device";
        c->devices.update_info(info, await);

        auto devs = c->devices.devices(false, false, true);
        CHECK(devs.size() == 1);
        CHECK(devs.begin()->second.description == "my device");
    }
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

    SECTION("after two rotations active_device_keys has three entries") {
        c->devices.active_device_keys();  // ensure initial key exists
        c->devices.rotate_device_keys();
        c->devices.rotate_device_keys();
        auto keys = c->devices.active_device_keys();
        CHECK(keys.size() == 3);
        CHECK_FALSE(keys[0].rotated.has_value());
        CHECK(keys[1].rotated.has_value());
        CHECK(keys[2].rotated.has_value());
    }
}

TEST_CASE("Devices - device group payload padding", "[core][devices]") {
    TempCore c;

    // Real keys, not random bytes: ML-KEM encapsulation is performed against each device's pubkey.
    // Rotating produces distinct valid keypairs, and all of them stay in this device's active key
    // set, so this Core can also decrypt whatever it encrypts below.
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
        for (size_t i = 0; i < 3; i++)
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
        device::map m;
        for (size_t i = 0; i < 4; i++)
            m.emplace(infos[i].id, infos[i]);
        auto four_registered = TestHelper::encrypt_device_data(c->devices, m).size();

        // A fifth entry, kicked rather than registered.
        auto kicked = infos[4];
        kicked.state = device::State::Kicked;
        kicked.kicked = clock_now_s();
        m.emplace(kicked.id, kicked);

        auto with_kicked = TestHelper::encrypt_device_data(c->devices, m);

        // Unchanged size: five entries, but still only four recipients, so the key and ciphertext
        // lists stay in the 4 bucket.  Were the kicked device handed a key they would cross into
        // the 8 bucket and this would grow -- which is what makes this an assertion about the
        // recipient set rather than about padding.
        CHECK(with_kicked.size() == four_registered);

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

TEST_CASE("Devices - build_link_request", "[core][devices]") {
    // Restored, not generated: asking to join a group only makes sense for a device that adopted
    // an existing account's seed.  A device that generated the account *is* the group.
    auto c = restored_core();

    SECTION("returns non-empty message and 21-entry SAS") {
        auto result = TestHelper::build_link_request(*c);
        CHECK_FALSE(result.message.empty());
        CHECK(result.sas.size() == 21);
        for (const auto& s : result.sas)
            CHECK_FALSE(s.empty());
    }

    SECTION("consecutive calls produce different messages") {
        auto r1 = TestHelper::build_link_request(*c);
        auto r2 = TestHelper::build_link_request(*c);
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
        std::optional<std::array<std::byte, 32>> first_id;
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
    auto state_of = [&](const std::array<std::byte, 32>& id) {
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
    auto state_of = [&](const std::array<std::byte, 32>& id) {
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
    auto state_of = [&](const std::array<std::byte, 32>& id) {
        auto devs = c->devices.devices(true, true, true);
        auto found = devs.find(id);
        REQUIRE(found != devs.end());
        return found->second;
    };
    auto tombstone = [&](const std::array<std::byte, 32>& id, device::State state, auto when) {
        device::Info t{};
        t.id = id;
        t.state = state;
        t.kicked = when;
        return t;
    };

    std::array<std::byte, 32> id;
    random::fill(id);
    auto t0 = clock_now_s() - 3h;
    auto t1 = clock_now_s() - 2h;
    auto t2 = clock_now_s() - 1h;

    // It leaves.
    deliver({{self.id, self}, {id, tombstone(id, device::State::Left, t1)}});
    CHECK(state_of(id).state == device::State::Left);
    CHECK(state_of(id).kicked == t1);

    // And is written back as a departure: the timestamp negated.
    auto plaintext = TestHelper::decrypt_device_data(
            c->devices,
            TestHelper::encrypt_device_data(c->devices, c->devices.devices(true, true, true)));
    oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
    REQUIRE(btdc.skip_until("D"));
    auto devs = btdc.consume_dict_consumer();
    REQUIRE(devs.skip_until(std::string_view{reinterpret_cast<const char*>(id.data()), id.size()}));
    CHECK(devs.consume_integer<int64_t>() == -t1.time_since_epoch().count());

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
    std::array<std::byte, 32> leaver;
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

    std::array<std::byte, 32> applicant_id() {
        auto hex = applicant->devices.device_id();
        std::array<std::byte, 32> id;
        oxenc::from_hex(hex.begin(), hex.end(), reinterpret_cast<unsigned char*>(id.data()));
        return id;
    }

    // The applicant's request, as the existing device receives it.  Whole seconds, because that is
    // what the deadline is stored in, so a test can compare it exactly.
    auto
    ask(std::chrono::sys_seconds expiry = std::chrono::floor<std::chrono::seconds>(clock_now_s()) +
                                          10min,
        std::string hash = "L1") {
        auto req = TestHelper::build_link_request(*applicant);
        TestHelper::deliver_device_message(*core, req.message, expiry, std::move(hash));
        return req;
    }

    device::Info state_of_applicant() {
        auto devs = core->devices.devices(true, true, true);
        auto found = devs.find(applicant_id());
        REQUIRE(found != devs.end());
        return found->second;
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
    CHECK(std::ranges::find(push.broadcast, l.applicant_id()) != push.broadcast.end());

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

    // Where this device stood at startup is the baseline, not news.
    CHECK(l.events.membership.empty());
}

TEST_CASE(
        "Devices events - nothing is announced before the first fetch",
        "[core][devices][linking][events]") {
    Linking l;
    auto req = TestHelper::build_link_request(*l.applicant);

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
    auto req = TestHelper::build_link_request(*l.applicant);
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
    auto first = TestHelper::build_link_request(*l.applicant);
    TestHelper::deliver_device_message(*l.core, first.message, in(10min), "L1", /*is_final=*/false);
    auto second = TestHelper::build_link_request(*l.applicant);
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

    CHECK(l.events.order == std::vector<std::string>{"added", "ended", "added"});
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
    auto req = TestHelper::build_link_request(*l.applicant);
    TestHelper::deliver_device_message(*l.core, req.message, clock_now_ms() + 1500ms, "L1");
    auto id = l.events.added.at(0).id;

    REQUIRE(eventually(*l.core, [&] { return !l.events.ended.empty(); }));
    CHECK(l.events.ended[0] == std::pair{id, device::LinkRequestEnd::Expired});
}

TEST_CASE(
        "Devices events - a request read rather than announced still closes at its deadline",
        "[core][devices][linking][events]") {
    Linking l;
    auto req = TestHelper::build_link_request(*l.applicant);
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

    // Every group message carries every tombstone.
    TestHelper::deliver_device_message(
            *l.core, TestHelper::encrypt_device_data(l.core->devices, group), in(10min), "G2");
    CHECK(l.events.replaced.size() == 1);
}

TEST_CASE(
        "Devices events - a device hears it was admitted, not that it asked",
        "[core][devices][linking][events]") {
    Linking l;
    l.ask();

    // Its own request moved it to Pending, which it knows: it is the one asking.
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant_events.membership.empty());

    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    auto group = l.core->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.applicant, group, in(10min), "G1");

    REQUIRE(l.applicant_events.membership.size() == 1);
    CHECK(l.applicant_events.membership[0] == device::State::Registered);
}

namespace {

using Asked = std::optional<Expected<Devices::OutgoingLinkRequest>>;

// Asks for a link from `c` and runs the job, so that the upload has been sent by the time this
// returns.  What it answers lands in `into`, once the upload is answered.
void request_link(TempCore& c, Asked& into) {
    c->devices.request_link(
            [&into](Expected<Devices::OutgoingLinkRequest> r) { into = std::move(r); });
    TestHelper::drain(*c);
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
    request_link(l.applicant, got);

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

    // What the waiting screen is redrawn from is what it was first drawn from.
    auto waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    CHECK(same(*waiting, asked));

    // The other device prompts with what this one shows.
    TestHelper::deliver_device_message(*l.core, message, asked.expires, "L1");
    REQUIRE(l.events.added.size() == 1);
    CHECK(l.events.added[0].sas == asked.sas);

    REQUIRE(l.core->devices.accept_request(l.events.added[0].id, await));
    auto group = l.core->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.applicant, group, in(10min), "G1");

    CHECK(l.applicant_events.membership == std::vector{device::State::Registered});
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
}

TEST_CASE(
        "Devices - a link request the swarm refused is withdrawn, and reported only as a failure",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l.applicant, got);
    answer_upload(l.applicant, *net, false);

    REQUIRE(got);
    REQUIRE_FALSE(got->has_value());
    CHECK(got->error().code == err::store_failed);
    CHECK(own_state(l.applicant) == device::State::Unregistered);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));

    // The caller has been told; the membership it never left is not news.
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant_events.membership.empty());
}

TEST_CASE(
        "Devices - a refused upload does not withdraw the request that replaced it",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked first, second;
    request_link(l.applicant, first);
    request_link(l.applicant, second);

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
        "Devices - a request being replaced is not shown while its replacement uploads",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked first, second;
    request_link(l.applicant, first);
    answer_upload(l.applicant, *net, true);
    REQUIRE(l.applicant->devices.outgoing_link_request(await));

    // Its SAS is about to be superseded, so it must not be what a redraw shows in the meantime.
    request_link(l.applicant, second);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));

    answer_upload(l.applicant, *net, true);
    auto waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    REQUIRE(second);
    REQUIRE(second->has_value());
    CHECK(same(*waiting, **second));
    CHECK(waiting->sas != (*first)->sas);
}

TEST_CASE(
        "Devices - an unanswered link request lapses at its deadline",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l.applicant, got);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());

    // Brought to within a second of the deadline, and the timer re-armed from there, so that it is
    // the timer that finds the request lapsed rather than anything this test does.
    ScopedClockOffset later{Devices::LINK_REQUEST_TTL - 1s};
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE(l.applicant_events.membership.empty());

    REQUIRE(eventually(*l.applicant, [&] { return !l.applicant_events.membership.empty(); }));
    CHECK(l.applicant_events.membership == std::vector{device::State::Unregistered});
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
    request_link(l.applicant, got);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());

    restart_applicant(l);

    CHECK(own_state(l.applicant) == device::State::Pending);
    auto waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    CHECK(same(*waiting, **got));

    // And it still lapses, with no fetch to notice: the restart re-arms its deadline.
    ScopedClockOffset later{Devices::LINK_REQUEST_TTL - 1s};
    restart_applicant(l);
    REQUIRE(eventually(*l.applicant, [&] { return !l.applicant_events.membership.empty(); }));
    CHECK(l.applicant_events.membership == std::vector{device::State::Unregistered});
}

TEST_CASE(
        "Devices - a link request never confirmed stored is withdrawn at the next start",
        "[core][devices][linking][request]") {
    Linking l;
    attach_mock_network(*l.applicant);
    Asked got;
    request_link(l.applicant, got);
    REQUIRE(own_state(l.applicant) == device::State::Pending);

    restart_applicant(l);

    CHECK(own_state(l.applicant) == device::State::Unregistered);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant_events.membership.empty());
}

TEST_CASE(
        "Devices - a link is not requested without a network, or by a device already in the group",
        "[core][devices][linking][request]") {
    Linking l;
    Asked got;

    SECTION("no network") {
        request_link(l.applicant, got);
        REQUIRE(got);
        REQUIRE_FALSE(got->has_value());
        CHECK(got->error().code == err::network_unavailable);
        CHECK(own_state(l.applicant) == device::State::Unregistered);
    }

    SECTION("already registered") {
        attach_mock_network(*l.core);
        request_link(l.core, got);
        REQUIRE(got);
        REQUIRE_FALSE(got->has_value());
        CHECK(got->error().code == err::already_registered);
        CHECK(own_state(l.core) == device::State::Registered);
    }
}
