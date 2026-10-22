#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <session/clock.hpp>
#include <session/config/namespaces.hpp>
#include <session/core.hpp>
#include <session/network/session_network.hpp>

#include "test_helper.hpp"
#include "utils.hpp"

using namespace session;
using namespace std::literals;

// Wraps a single bt-dict message payload as a mock AccountPubkeys retrieve response.
// prefetch_pfs_keys() sends a plain "retrieve" and expects {messages: [...]} at the top level.
static nlohmann::json make_pubkey_response(std::span<const std::byte> msg_data) {
    return retrieved_body(nlohmann::json::array({retrieved_message(msg_data, "pubkeys")}));
}

// Returns an AccountPubkeys response body with no messages.
static nlohmann::json make_empty_response() {
    return retrieved_body();
}

TEST_CASE("prefetch_pfs_keys throws without network", "[core][pfs]") {
    TempCore c;
    TempCore remote;
    auto session_id = remote->globals.session_id();
    b33 sid;
    std::ranges::copy(session_id, sid.begin());
    CHECK_THROWS_AS(c->prefetch_pfs_keys(sid), std::logic_error);
}

TEST_CASE("prefetch_pfs_keys fetches and caches remote account pubkeys", "[core][pfs]") {
    TempCore c;
    auto* mock_net = attach_mock_network(*c);

    // Build a "remote" account whose pubkeys we want to fetch.
    TempCore remote;
    auto remote_msg = remote->devices.build_account_pubkey_message();

    auto session_id_span = remote->globals.session_id();
    b33 sid;
    std::ranges::copy(session_id_span, sid.begin());

    SECTION("Fetches and stores pubkeys when cache is absent") {
        c->prefetch_pfs_keys(sid);

        REQUIRE(mock_net->sent_requests.size() == 1);
        CHECK(mock_net->sent_requests[0].request.endpoint == "retrieve");
        auto req = parse_json(*mock_net->sent_requests[0].request.body);
        CHECK(req["pubkey"] == oxenc::to_hex(sid));
        CHECK(req["namespace"] == static_cast<int16_t>(config::Namespace::AccountPubkeys));

        mock_net->sent_requests[0].callback(
                true, false, 200, {}, make_pubkey_response(remote_msg).dump());

        auto entry = TestHelper::pfs_cache_entry(*c, sid);
        REQUIRE(entry.has_value());
        REQUIRE(entry->fetched_at.has_value());
        // fetched_at should be close to now.
        auto age = clock_now_s() - from_epoch_s(*entry->fetched_at);
        CHECK(age >= 0s);
        CHECK(age < 5s);
        CHECK_FALSE(entry->nak_at.has_value());

        // The stored pubkeys must match those from the remote's active account key.
        auto [expected_x25519, expected_mlkem768] = TestHelper::active_account_pubkeys(*remote);
        REQUIRE(entry->pubkey_x25519.has_value());
        REQUIRE(entry->pubkey_mlkem768.has_value());
        CHECK(*entry->pubkey_x25519 == expected_x25519);
        CHECK(*entry->pubkey_mlkem768 == expected_mlkem768);
    }

    SECTION("Skips fetch when cache is fresh") {
        // First fetch: populates the cache.
        c->prefetch_pfs_keys(sid);
        REQUIRE(mock_net->sent_requests.size() == 1);
        mock_net->sent_requests[0].callback(
                true, false, 200, {}, make_pubkey_response(remote_msg).dump());
        REQUIRE(TestHelper::pfs_cache_entry(*c, sid).has_value());
        mock_net->sent_requests.clear();

        // Second fetch within PFS_KEY_FRESH_DURATION: must not send another request.
        c->prefetch_pfs_keys(sid);
        CHECK(mock_net->sent_requests.empty());
    }

    SECTION("Re-fetches when cache is stale (older than PFS_KEY_FRESH_DURATION)") {
        // First fetch.
        c->prefetch_pfs_keys(sid);
        REQUIRE(mock_net->sent_requests.size() == 1);
        mock_net->sent_requests[0].callback(
                true, false, 200, {}, make_pubkey_response(remote_msg).dump());
        mock_net->sent_requests.clear();

        // Advance clock past the fresh threshold.
        ScopedClockOffset advance_past_fresh{core::Core::PFS_KEY_FRESH_DURATION + 1s};
        c->prefetch_pfs_keys(sid);
        CHECK(mock_net->sent_requests.size() == 1);
    }
}

TEST_CASE("prefetch_pfs_keys NAK handling", "[core][pfs]") {
    TempCore c;
    auto* mock_net = attach_mock_network(*c);

    TempCore remote;
    auto session_id_span = remote->globals.session_id();
    b33 sid;
    std::ranges::copy(session_id_span, sid.begin());

    // Helper: fire the pending request with an empty-messages response (NAK condition).
    auto fire_nak = [&] {
        REQUIRE(mock_net->sent_requests.size() == 1);
        mock_net->sent_requests[0].callback(true, false, 200, {}, make_empty_response().dump());
        mock_net->sent_requests.clear();
    };

    SECTION("Records NAK when fetch succeeds but returns no keys") {
        c->prefetch_pfs_keys(sid);
        fire_nak();

        auto entry = TestHelper::pfs_cache_entry(*c, sid);
        REQUIRE(entry.has_value());
        CHECK_FALSE(entry->fetched_at.has_value());
        REQUIRE(entry->nak_at.has_value());
        auto nak_age = clock_now_s() - from_epoch_s(*entry->nak_at);
        CHECK(nak_age >= 0s);
        CHECK(nak_age < 5s);
        CHECK_FALSE(entry->pubkey_x25519.has_value());
        CHECK_FALSE(entry->pubkey_mlkem768.has_value());
    }

    SECTION("NAK suppresses re-fetch within PFS_KEY_NAK_DURATION") {
        c->prefetch_pfs_keys(sid);
        fire_nak();

        // Should not issue another request while the NAK is fresh.
        c->prefetch_pfs_keys(sid);
        CHECK(mock_net->sent_requests.empty());
    }

    SECTION("NAK allows re-fetch after PFS_KEY_NAK_DURATION expires") {
        c->prefetch_pfs_keys(sid);
        fire_nak();

        ScopedClockOffset advance_past_nak_expiry{core::Core::PFS_KEY_NAK_DURATION + 1s};
        c->prefetch_pfs_keys(sid);
        CHECK(mock_net->sent_requests.size() == 1);
    }

    SECTION("NAK does not overwrite an existing valid entry") {
        // Populate the cache with a valid entry.
        auto remote_msg = remote->devices.build_account_pubkey_message();
        c->prefetch_pfs_keys(sid);
        REQUIRE(mock_net->sent_requests.size() == 1);
        mock_net->sent_requests[0].callback(
                true, false, 200, {}, make_pubkey_response(remote_msg).dump());
        mock_net->sent_requests.clear();

        auto before = TestHelper::pfs_cache_entry(*c, sid);
        REQUIRE(before.has_value());
        REQUIRE(before->pubkey_x25519.has_value());

        // Advance clock to make the entry stale, then fire a re-fetch that returns nothing.
        ScopedClockOffset advance_past_fresh{core::Core::PFS_KEY_FRESH_DURATION + 1s};
        c->prefetch_pfs_keys(sid);
        fire_nak();

        // Valid pubkeys must still be present; nak_at is also set.
        auto after = TestHelper::pfs_cache_entry(*c, sid);
        REQUIRE(after.has_value());
        CHECK(after->pubkey_x25519 == before->pubkey_x25519);
        CHECK(after->pubkey_mlkem768 == before->pubkey_mlkem768);
        CHECK(after->fetched_at == before->fetched_at);
        REQUIRE(after->nak_at.has_value());
    }

    SECTION("Stale valid entry is not gated by a concurrent NAK") {
        // Populate the cache with a valid entry.
        auto remote_msg = remote->devices.build_account_pubkey_message();
        c->prefetch_pfs_keys(sid);
        REQUIRE(mock_net->sent_requests.size() == 1);
        mock_net->sent_requests[0].callback(
                true, false, 200, {}, make_pubkey_response(remote_msg).dump());
        mock_net->sent_requests.clear();

        // Make stale and fire a NAK.
        {
            ScopedClockOffset advance_past_fresh{core::Core::PFS_KEY_FRESH_DURATION + 1s};
            c->prefetch_pfs_keys(sid);
            fire_nak();

            // With a fresh NAK and stale valid entry, a new call should still re-fetch because
            // the NAK only gates the no-valid-keys path.
            c->prefetch_pfs_keys(sid);
            CHECK(mock_net->sent_requests.size() == 1);
        }
    }
}

TEST_CASE("prefetch_pfs_keys handles malformed responses gracefully", "[core][pfs]") {
    TempCore c;
    auto* mock_net = attach_mock_network(*c);

    TempCore remote;
    auto session_id_span = remote->globals.session_id();
    b33 sid;
    std::ranges::copy(session_id_span, sid.begin());

    SECTION("Garbage bt-dict data: NAK written, no valid pubkeys stored") {
        c->prefetch_pfs_keys(sid);
        REQUIRE(mock_net->sent_requests.size() == 1);

        auto bad_resp = make_pubkey_response(to_span<std::byte>("not a bt-dict"sv));

        mock_net->sent_requests[0].callback(true, false, 200, {}, bad_resp.dump());
        auto entry = TestHelper::pfs_cache_entry(*c, sid);
        REQUIRE(entry.has_value());
        CHECK(entry->nak_at.has_value());
        CHECK_FALSE(entry->pubkey_x25519.has_value());
    }

    SECTION("Bad signature: NAK written, no valid pubkeys stored") {
        c->prefetch_pfs_keys(sid);
        REQUIRE(mock_net->sent_requests.size() == 1);

        // A message signed with the wrong key (our own account instead of the remote's).
        auto wrong_msg = c->devices.build_account_pubkey_message();
        mock_net->sent_requests[0].callback(
                true, false, 200, {}, make_pubkey_response(wrong_msg).dump());
        auto entry = TestHelper::pfs_cache_entry(*c, sid);
        REQUIRE(entry.has_value());
        CHECK(entry->nak_at.has_value());
        CHECK_FALSE(entry->pubkey_x25519.has_value());
    }

    SECTION("Network failure: nothing written") {
        c->prefetch_pfs_keys(sid);
        REQUIRE(mock_net->sent_requests.size() == 1);

        mock_net->sent_requests[0].callback(false, false, 0, {}, std::nullopt);
        CHECK_FALSE(TestHelper::pfs_cache_entry(*c, sid).has_value());
    }
}

TEST_CASE("pfs_key_info reports the cache as it stands, and fetches nothing", "[core][pfs]") {
    TempCore c;
    auto* mock_net = attach_mock_network(*c);
    TempCore remote;
    b33 sid;
    std::ranges::copy(remote->globals.session_id(), sid.begin());
    auto [x25519, mlkem768] = TestHelper::active_account_pubkeys(*remote);

    auto none = c->pfs_key_info(sid);
    CHECK(none.state == core::PfsKeyState::none);
    CHECK_FALSE(none.x25519_pub);
    CHECK_FALSE(none.fetched_at);

    SECTION("a key, through its ages") {
        TestHelper::seed_pfs_cache(*c, sid, x25519, mlkem768);
        auto info = c->pfs_key_info(sid);
        CHECK(info.state == core::PfsKeyState::fresh);
        CHECK(info.x25519_pub == x25519);
        CHECK(info.mlkem768_pub == mlkem768);
        REQUIRE(info.fetched_at);
        CHECK_FALSE(info.nak_at);

        ScopedClockOffset later{core::Core::PFS_KEY_FRESH_DURATION + 1s};
        CHECK(c->pfs_key_info(sid).state == core::PfsKeyState::stale);
        later.advance(core::Core::PFS_KEY_EXPIRY_DURATION - core::Core::PFS_KEY_FRESH_DURATION);
        info = c->pfs_key_info(sid);
        CHECK(info.state == core::PfsKeyState::expired);
        // Still what this device last saw them publish.
        CHECK(info.x25519_pub == x25519);
    }

    SECTION("a NAK, until it lapses") {
        TestHelper::seed_pfs_nak(*c, sid);
        auto info = c->pfs_key_info(sid);
        CHECK(info.state == core::PfsKeyState::nak);
        CHECK(info.nak_at);
        CHECK_FALSE(info.x25519_pub);

        ScopedClockOffset later{core::Core::PFS_KEY_NAK_DURATION + 1s};
        info = c->pfs_key_info(sid);
        CHECK(info.state == core::PfsKeyState::none);
        CHECK(info.nak_at);
    }

    CHECK(mock_net->sent_requests.empty());
}

TEST_CASE("refetch_pfs_keys fetches whatever the cache says, once at a time", "[core][pfs]") {
    std::vector<core::PfsKeyFetch> fetched;
    core::callbacks cbs;
    cbs.pfs_keys_fetched = [&](std::span<const std::byte, 33>, core::PfsKeyFetch r) {
        fetched.push_back(r);
    };
    TempCore c{cbs};
    TempCore remote;
    b33 sid;
    std::ranges::copy(remote->globals.session_id(), sid.begin());
    auto remote_msg = remote->devices.build_account_pubkey_message();

    CHECK_THROWS_AS(c->refetch_pfs_keys(sid), std::logic_error);
    auto* mock_net = attach_mock_network(*c);

    SECTION("despite a fresh key") {
        auto [x25519, mlkem768] = TestHelper::active_account_pubkeys(*remote);
        TestHelper::seed_pfs_cache(*c, sid, x25519, mlkem768);
        c->refetch_pfs_keys(sid);
        CHECK(mock_net->sent_requests.size() == 1);
    }

    SECTION("despite a recent NAK") {
        TestHelper::seed_pfs_nak(*c, sid);
        c->refetch_pfs_keys(sid);
        CHECK(mock_net->sent_requests.size() == 1);
    }

    SECTION("joining one in flight, from either") {
        c->refetch_pfs_keys(sid);
        c->refetch_pfs_keys(sid);
        CHECK(c->prefetch_pfs_keys(sid) == core::PfsKeyStatus::fetching);
        REQUIRE(mock_net->sent_requests.size() == 1);

        // One answer, one report; and the next asks again.
        mock_net->sent_requests[0].callback(
                true, false, 200, {}, make_pubkey_response(remote_msg).dump());
        mock_net->sent_requests.clear();
        CHECK(fetched == std::vector{core::PfsKeyFetch::new_key});
        c->refetch_pfs_keys(sid);
        CHECK(mock_net->sent_requests.size() == 1);
    }
}
