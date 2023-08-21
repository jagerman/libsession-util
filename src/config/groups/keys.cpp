#include <sodium/core.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include <session/config/groups/info.hpp>
#include <session/config/groups/keys.hpp>
#include <session/config/groups/members.hpp>
#include <stdexcept>

#include "../internal.hpp"

namespace session::config::groups {

Keys::Keys(
        ustring_view user_ed25519_secretkey,
        ustring_view group_ed25519_pubkey,
        std::optional<ustring_view> group_ed25519_secretkey,
        std::optional<ustring_view> dumped) {

    if (sodium_init() == -1)
        throw std::runtime_error{"libsodium initialization failed!"};

    if (user_ed25519_secretkey.size() != 64)
        throw std::invalid_argument{"Invalid Keys construction: invalid user ed25519 secret key"};
    if (group_ed25519_pubkey.size() != 32)
        throw std::invalid_argument{"Invalid Keys construction: invalid group ed25519 public key"};
    if (group_ed25519_secretkey && group_ed25519_secretkey->size() != 64)
        throw std::invalid_argument{"Invalid Keys construction: invalid group ed25519 secret key"};

    init_sig_keys(group_ed25519_pubkey, group_ed25519_secretkey);

    user_ed25519_sk.load(user_ed25519_secretkey.data(), 64);
}

std::vector<ustring_view> Keys::group_keys() const {
    std::vector<ustring_view> ret;
    ret.reserve(keys_.size() + !pending_key_config_.empty());

    if (pending_key_config_.empty())
        ret.emplace_back(pending_key_.data(), 32);

    for (auto it = keys_.rbegin(); it != keys_.rend(); ++it)
        ret.emplace_back(it->key.data(), 32);

    return ret;
}

static std::array<unsigned char, 32> compute_xpk(const unsigned char* ed25519_pk) {
    std::array<unsigned char, 32> xpk;
    if (0 != crypto_sign_ed25519_pk_to_curve25519(xpk.data(), ed25519_pk))
        throw std::runtime_error{
                "An error occured while attempting to convert Ed25519 pubkey to X25519; "
                "is the pubkey valid?"};
    return xpk;
}

static constexpr auto seed_hash_key = "SessionGroupKeySeed"sv;
static const ustring_view enc_key_hash_key = to_unsigned_sv("SessionGroupKeyGen"sv);
static constexpr auto enc_key_admin_hash_key = "SessionGroupKeyAdminKey"sv;
static const ustring_view enc_key_member_hash_key = to_unsigned_sv("SessionGroupKeyMemberKey"sv);
static const ustring_view junk_seed_hash_key = to_unsigned_sv("SessionGroupJunkMembers"sv);

ustring_view Keys::rekey(Info& info, Members& members) {
    if (!_sign_sk || !_sign_pk)
        throw std::logic_error{
                "Unable to issue a new group encryption key without the main group keys"};

    // For members we calculate the outer encryption key as H(aB || A || B).  But because we only
    // have `B` (the session id) as an x25519 pubkey, we do this in x25519 space, which means we
    // have to use the x25519 conversion of a/A rather than the group's ed25519 pubkey.
    auto group_xpk = compute_xpk(_sign_pk->data());

    sodium_cleared<std::array<unsigned char, 32>> group_xsk;
    crypto_sign_ed25519_sk_to_curve25519(group_xsk.data(), _sign_sk.data());

    // We need quasi-randomness: full secure random would be great, except that different admins
    // encrypting for the same update would always create different keys, but we want it
    // deterministic so that that doesn't happen.
    //
    // So we use:
    //
    // H1(member0 || member1 || ... || memberN || generation || H2(group_secret_key))
    //
    // where:
    // - H1(.) = 56-byte BLAKE2b keyed hash with key "SessionGroupKeyGen"
    // - memberI is each members full session ID, expressed in hex (66 chars), in sorted order (note
    //   that this includes *all* members, not only non-admins).
    // - generation is the new generation value, expressed as a base 10 string (e.g. "123")
    // - H2(.) = 32-byte BLAKE2b keyed hash of the sodium group secret key seed (just the 32 byte,
    //           not the full 64 byte with the pubkey in the second half), key "SessionGroupKeySeed"
    //
    // And then from this 56-byte hash we use the first 32 bytes as the new group key and the last
    // 24 bytes as the encryption nonce.
    //
    // If we have to append junk member keys (for padding) them we reuse H1 with H(H1 || a) to
    // produce a sodium pseudo-RNG seed for deterministic junk value generation.
    //
    // To encrypt this we have one key encrypted for all admins, plus one encryption per non-admin
    // member.  For admins we encrypt using a 32-byte blake2b keyed hash of the group secret key
    // seed, just like H2, but with key "SessionGroupKeyAdminKey".

    std::array<unsigned char, 32> h2 = seed_hash(seed_hash_key);

    std::array<unsigned char, 56> h1;

    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(
            &st, enc_key_hash_key.data(), enc_key_hash_key.size(), h1.size());
    for (const auto& m : members)
        crypto_generichash_blake2b_update(
                &st, to_unsigned(m.session_id.data()), m.session_id.size());

    auto gen = keys_.empty() ? 0 : keys_.back().generation + 1;
    auto gen_str = std::to_string(gen);
    crypto_generichash_blake2b_update(&st, to_unsigned(gen_str.data()), gen_str.size());

    crypto_generichash_blake2b_update(&st, h2.data(), 32);

    crypto_generichash_blake2b_final(&st, h1.data(), h1.size());

    ustring_view enc_key{h1.data(), 32};
    ustring_view nonce{h1.data() + 32, 24};

    oxenc::bt_dict_producer d{};

    d.append("#", from_unsigned_sv(nonce));
    // d.append("+", 0); // Not supplemental, so leave off

    static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES == 32);
    static_assert(crypto_aead_xchacha20poly1305_ietf_ABYTES == 16);
    std::array<
            unsigned char,
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES>
            encrypted;
    std::string_view enc_sv{reinterpret_cast<const char*>(encrypted.data()), encrypted.size()};

    // Shared key for admins
    auto member_k = seed_hash(enc_key_admin_hash_key);
    static_assert(member_k.size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    crypto_aead_xchacha20poly1305_ietf_encrypt(
            encrypted.data(),
            nullptr,
            enc_key.data(),
            enc_key.size(),
            nullptr,
            0,
            nullptr,
            nonce.data(),
            member_k.data());

    d.append("G", gen);
    d.append("K", enc_sv);

    auto member_keys = d.append_list("k");

    int member_count = 0;
    for (const auto& m : members) {
        auto m_xpk = session_id_xpk(m.session_id);
        // Calculate the encryption key: H(aB || A || B)
        if (0 != crypto_scalarmult_curve25519(member_k.data(), group_xsk.data(), m_xpk.data()))
            continue;  // The scalarmult failed; maybe a bad session id?

        crypto_generichash_blake2b_init(
                &st,
                enc_key_member_hash_key.data(),
                enc_key_member_hash_key.size(),
                member_k.size());
        crypto_generichash_blake2b_update(&st, member_k.data(), member_k.size());
        crypto_generichash_blake2b_update(&st, group_xpk.data(), group_xpk.size());
        crypto_generichash_blake2b_update(&st, m_xpk.data(), m_xpk.size());
        crypto_generichash_blake2b_final(&st, member_k.data(), member_k.size());

        crypto_aead_xchacha20poly1305_ietf_encrypt(
                encrypted.data(),
                nullptr,
                enc_key.data(),
                enc_key.size(),
                nullptr,
                0,
                nullptr,
                nonce.data(),
                member_k.data());

        member_keys.append(enc_sv);
        member_count++;
    }

    // Pad it out with junk entries to the next MESSAGE_KEY_MULTIPLE
    if (member_count % MESSAGE_KEY_MULTIPLE) {
        int n_junk = MESSAGE_KEY_MULTIPLE - (member_count % MESSAGE_KEY_MULTIPLE);
        std::vector<unsigned char> junk_data;
        junk_data.resize(encrypted.size() * n_junk);

        std::array<unsigned char, randombytes_SEEDBYTES> rng_seed;
        crypto_generichash_blake2b_init(
                &st, junk_seed_hash_key.data(), junk_seed_hash_key.size(), rng_seed.size());
        crypto_generichash_blake2b_update(&st, h1.data(), h1.size());
        crypto_generichash_blake2b_update(&st, _sign_sk.data(), _sign_sk.size());
        crypto_generichash_blake2b_final(&st, rng_seed.data(), rng_seed.size());

        randombytes_buf_deterministic(junk_data.data(), junk_data.size(), rng_seed.data());
        std::string_view junk_view{
                reinterpret_cast<const char*>(junk_data.data()), junk_data.size()};
        while (!junk_view.empty()) {
            member_keys.append(junk_view.substr(0, encrypted.size()));
            junk_view.remove_prefix(encrypted.size());
        }
    }

    // Finally we sign the message at put it as the ~ key (which is 0x7f, and thus comes later than
    // any other ascii key).
    auto to_sign = to_unsigned_sv(d.view());
    // The view contains the trailing "e", but we don't sign it (we are going to append the
    // signature there instead):
    to_sign.remove_suffix(1);
    auto sig = signer_(to_sign);
    if (sig.size() != 64)
        throw std::logic_error{"Invalid signature: signing function did not return 64 bytes"};

    d.append("~", from_unsigned_sv(sig));

    // Load this key/config/gen into our pending variables
    pending_gen_ = gen;
    std::memcpy(pending_key_.data(), enc_key.data(), pending_key_.size());
    pending_key_config_.clear();
    auto conf = d.view();
    pending_key_config_.resize(conf.size());
    std::memcpy(pending_key_config_.data(), conf.data(), conf.size());

    auto new_key_list = group_keys();
    // We want to dirty the member/info lists so that they get re-encrypted and re-pushed with the
    // new key:
    members.replace_keys(new_key_list, /*dirty=*/true);
    info.replace_keys(new_key_list, /*dirty=*/true);

    return ustring_view{pending_key_config_.data(), pending_key_config_.size()};
}

std::optional<ustring_view> Keys::pending_config() const {
    if (pending_key_config_.empty())
        return std::nullopt;
    return ustring_view{pending_key_config_.data(), pending_key_config_.size()};
}

void Keys::load_key_message(
        ustring_view data, ustring_view msgid, int64_t timestamp_ms, Members& members, Info& info) {

    oxenc::bt_dict_consumer d{from_unsigned_sv(data)};

    if (!_sign_pk || !verifier_)
        throw std::logic_error{"Group pubkey is not set; unable to load config message"};

    auto group_xpk = compute_xpk(_sign_pk->data());

    if (!d.skip_until("#"))
        throw config_value_error{"Key message has no nonce"};
    auto nonce = to_unsigned_sv(d.consume_string_view());

    bool supplemental = false;
    if (d.skip_until("+")) {
        auto supp = d.consume_integer<int>();
        if (supp == 0 || supp == 1)
            supplemental = static_cast<bool>(supp);
        else
            throw config_value_error{
                    "Unexpected value " + std::to_string(supp) + " for '+' key (expected 0/1)"};
    }

    bool found_key = false;
    sodium_cleared<key_info> new_key{};
    new_key.timestamp = std::chrono::system_clock::from_time_t(timestamp_ms / 1000) +
                        1ms * (timestamp_ms % 1000);

    if (!d.skip_until("G"))
        throw config_value_error{"Key message missing required generation (G) field"};

    new_key.generation = d.consume_integer<int64_t>();
    if (new_key.generation < 0)
        throw config_value_error{"Key message contains invalid negative generation"};

    if (!supplemental) {
        if (!d.skip_until("K"))
            throw config_value_error{
                    "Non-supplemental key message is missing required admin key (K)"};

        auto admin_key = to_unsigned_sv(d.consume_string_view());
        if (admin_key.size() != 32 + crypto_aead_xchacha20poly1305_ietf_ABYTES)
            throw config_value_error{"Key message has invalid admin key length"};

        if (_sign_sk) {
            auto k = seed_hash(enc_key_admin_hash_key);

            if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                             new_key.key.data(),
                             nullptr,
                             nullptr,
                             admin_key.data(),
                             admin_key.size(),
                             nullptr,
                             0,
                             nonce.data(),
                             k.data()))
                throw config_value_error{"Failed to decrypt admin key from key message"};

            found_key = true;
        }
    }

    sodium_cleared<std::array<unsigned char, 32>> member_dec_key;
    if (!found_key) {
        sodium_cleared<std::array<unsigned char, 32>> member_xsk;
        crypto_sign_ed25519_sk_to_curve25519(member_xsk.data(), user_ed25519_sk.data());
        auto member_xpk = compute_xpk(user_ed25519_sk.data() + 32);

        // Calculate the encryption key: H(bA || A || B) [A = group, B = member]
        if (0 != crypto_scalarmult_curve25519(
                         member_dec_key.data(), member_xsk.data(), group_xpk.data()))
            throw std::runtime_error{
                    "Unable to compute member decryption key; invalid group or member keys?"};

        crypto_generichash_blake2b_state st;
        crypto_generichash_blake2b_init(
                &st,
                enc_key_member_hash_key.data(),
                enc_key_member_hash_key.size(),
                member_dec_key.size());
        crypto_generichash_blake2b_update(&st, member_dec_key.data(), member_dec_key.size());
        crypto_generichash_blake2b_update(&st, group_xpk.data(), group_xpk.size());
        crypto_generichash_blake2b_update(&st, member_xpk.data(), member_xpk.size());
        crypto_generichash_blake2b_final(&st, member_dec_key.data(), member_dec_key.size());
    }

    // Even if we're already found a key we still parse these, so that admins and all users have the
    // same error conditions for rejecting an invalid config message.
    if (!d.skip_until("k"))
        throw config_value_error{"Config is missing member keys list (k)"};
    auto key_list = d.consume_list_consumer();

    int member_key_count = 0;
    for (; !key_list.is_finished(); member_key_count++) {
        auto member_key = to_unsigned_sv(key_list.consume_string_view());
        if (member_key.size() != 32 + crypto_aead_xchacha20poly1305_ietf_ABYTES)
            throw config_value_error{
                    "Key message has invalid member key length at index " +
                    std::to_string(member_key_count)};

        if (found_key)
            continue;

        if (0 == crypto_aead_xchacha20poly1305_ietf_decrypt(
                         new_key.key.data(),
                         nullptr,
                         nullptr,
                         member_key.data(),
                         member_key.size(),
                         nullptr,
                         0,
                         nonce.data(),
                         member_dec_key.data())) {
            // Decryption success, we found our key!
            found_key = true;
        }
    }

    if (!supplemental && member_key_count % MESSAGE_KEY_MULTIPLE != 0)
        throw config_value_error{"Member key list has wrong size (missing junk key padding?)"};

    verify_config_sig(d, data, verifier_, false);

    if (found_key) {
        auto it = std::lower_bound(keys_.begin(), keys_.end(), new_key);
        if (it != keys_.end() && new_key == *it) {
            // We found a key we already had, so just ignore it.
            found_key = false;
        } else {
            keys_.insert(it, new_key);

            remove_expired();
        }
    }

    // If this is our pending config or this has a later generation than our pending config then
    // drop our pending status.
    if (!pending_key_config_.empty() &&
        (new_key.generation > pending_gen_ || new_key.key == pending_key_))
        pending_key_config_.clear();

    auto new_key_list = group_keys();
    members.replace_keys(new_key_list, /*dirty=*/false);
    info.replace_keys(new_key_list, /*dirty=*/false);
}

void Keys::remove_expired() {
    if (keys_.size() < 2)
        return;

    auto lapsed_end = keys_.begin();

    for (auto it = keys_.begin(); it != keys_.end();) {
        // Advance `it` if the next element is an alternate key (with a later timestamp) from the
        // same generation.  When we finish this loop, `it` is the last element of this generation
        // and `it2` is the first element of the next generation.
        auto it2 = std::next(it);
        while (it2 != keys_.end() && it2->generation == it->generation)
            it = it2++;
        if (it2 == keys_.end())
            break;

        // it2 points at the lowest-timestamp value of the next-largest generation: if there is
        // something more than 30 days newer than it2, then that tells us that `it`'s generation is
        // no longer needed since a newer generation passed it more than 30 days ago.  (We actually
        // use 60 days for paranoid safety, but the logic is the same).
        //
        // NB: We don't trust the local system clock here (and the `timestamp` values are
        // swarm-provided), because devices are notoriously imprecise, which means that since we
        // only invalidate keys when new keys come in, we can hold onto one obsolete generation
        // indefinitely (but this is a tiny overhead and not worth trying to build a
        // system-clock-is-broken workaround to avoid).
        if (it2->timestamp + KEY_EXPIRY < keys_.back().timestamp)
            lapsed_end = it2;
        else
            break;
        it = it2;
    }

    if (lapsed_end != keys_.begin())
        keys_.erase(keys_.begin(), lapsed_end);
}

bool Keys::needs_rekey() const {
    if (!_sign_sk || !_sign_pk || keys_.size() < 2)
        return false;

    // We rekey if the max generation value is being used across multiple keys (which indicates some
    // sort of rekey collision, somewhat analagous to merge configs in regular config messages).
    auto last_it = std::prev(keys_.end());
    auto second_it = std::prev(last_it);
    return last_it->generation == second_it->generation;
}

std::optional<ustring_view> Keys::pending_key() const {
    if (!pending_key_config_.empty())
        return ustring_view{pending_key_.data(), pending_key_.size()};
    return std::nullopt;
}

}  // namespace session::config::groups