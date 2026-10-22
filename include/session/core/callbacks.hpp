#pragma once
#include <functional>
#include <optional>
#include <session/config/namespaces.hpp>
#include <session/core/devices.hpp>
#include <session/core/swarm_message.hpp>
#include <session/util.hpp>
#include <span>
#include <string_view>
#include <vector>

namespace session::core {

class Core;

/// Return value of prefetch_pfs_keys() describing the current cache state at the time of the call.
enum class PfsKeyStatus {
    fresh,     ///< A fresh cached key exists; no fetch was initiated
    stale,     ///< A usable but stale key exists; a background re-fetch was initiated.
               ///< The pfs_keys_fetched callback will fire when the fetch completes.
    fetching,  ///< No usable key is cached; a background fetch was initiated.
               ///< The pfs_keys_fetched callback will fire when the fetch completes.
    nak,       ///< An unexpired NAK suppresses fetching; no usable key exists
};

/// Result passed to the pfs_keys_fetched callback when a background fetch completes.
/// Where a contact's cached PFS/PQ keys stand, as `Core::pfs_key_info` reports them without
/// fetching anything.
enum class PfsKeyState {
    none,     ///< Nothing cached: never fetched, or a NAK that has lapsed.
    nak,      ///< The last fetch found no keys, within PFS_KEY_NAK_DURATION.
    fresh,    ///< Keys fetched within PFS_KEY_FRESH_DURATION.
    stale,    ///< Keys fetched within PFS_KEY_EXPIRY_DURATION, but no longer fresh.
    expired,  ///< Keys fetched longer ago than PFS_KEY_EXPIRY_DURATION.
};

/// What `Core::pfs_key_info` reports of a contact's cached PFS/PQ keys.
///
/// `fetched_at` and `nak_at` are stamped by Core's clock (`session::clock_now`, which corrects for
/// the network's offset from this machine's), so compare them with that and never with
/// `std::chrono::system_clock`: the two can differ by however far off this machine's clock is.
struct PfsKeyInfo {
    PfsKeyState state;
    /// The keys last fetched, whatever their age: what this device last saw the contact publish.
    std::optional<std::array<std::byte, 32>> x25519_pub;
    std::optional<std::array<std::byte, 1184>> mlkem768_pub;
    /// When those keys were fetched.
    std::optional<std::chrono::sys_seconds> fetched_at;
    /// When a fetch last found no keys at all.
    std::optional<std::chrono::sys_seconds> nak_at;
};

enum class PfsKeyFetch {
    new_key,    ///< A key was retrieved and stored (new or changed from the previous cache entry)
    unchanged,  ///< Keys were retrieved but match what was already cached
    not_found,  ///< The fetch succeeded but the remote account pubkey namespace held no valid keys
    failed,     ///< The network request failed (swarm lookup or send_request)
};

/// Reason code passed to the message_decrypt_failed callback.
enum class MessageDecryptFailure {
    no_pfs_key,      ///< Version 2 message: no PFS account key matched the key indicator AND the
                     ///< non-PFS fallback decryption also failed; the message cannot be read.
    decrypt_failed,  ///< Decryption failed (either version); key was found but did not work
    bad_format,      ///< Message is structurally malformed (e.g. invalid bencode, truncated fields)
    unknown_version,  ///< Message starts with 0x00 but carries an unrecognised version byte;
                      ///< likely a future protocol version this build does not understand
};

/// A successfully decrypted one-to-one message from Namespace::Default.
struct ReceivedMessage {
    std::string hash;                  ///< Swarm-assigned message hash
    sys_ms timestamp;                  ///< Server-reported upload timestamp
    sys_ms expiry;                     ///< Server-reported expiry timestamp
    b33 sender_session_id;             ///< 0x05-prefixed sender session ID
    int version;                       ///< Protocol version: 1 or 2
    std::vector<std::byte> content;    ///< Decrypted protobuf-encoded payload
    std::optional<b64> pro_signature;  ///< Session Pro signature, if present
    bool pfs_encrypted = false;        ///< True iff decrypted via PFS+PQ (X-Wing) key derivation;
                                       ///< false for v1 messages and v2 non-PFS fallback messages.
};

/// Status of a send operation initiated by Core::send_dm().
enum class MessageSendStatus {
    awaiting_keys,   ///< Waiting for a PFS+PQ pubkey fetch to complete before encrypting.
    sending,         ///< Encryption complete; the store request has been dispatched.
    retrying,        ///< A previous send attempt failed; retrying.  (Not yet implemented:
                     ///< currently a failed send goes directly to network_error.  TODO:
                     ///< implement automatic retry with a maximum retry count.)
    success,         ///< The store request was accepted by a swarm node.
    network_error,   ///< The swarm lookup or store request failed (terminal).
    no_network,      ///< No network object is attached.
    encrypt_failed,  ///< Encryption failed (should not normally happen).
};

/// What a device linking interface answers to: the requests other devices send this account, and
/// the account's devices themselves.
///
/// One interface rather than a handler each because they only work as a set.  A prompt opened by
/// `link_request_added` has to be closed by `link_request_ended`, or it goes on showing the SAS of
/// a request that has been replaced -- the substitution the SAS exists to catch -- so leaving any
/// of these out has to be a compile error, not a quiet gap.
///
/// Everything here is reported once the fetch that caused it has been merged in full, so a handler
/// never sees a half-applied state.  State to draw from initially is read the ordinary way, through
/// `Devices::membership()`, `Devices::devices()` and `Devices::incoming_link_requests()`; these
/// report what changes after.
///
/// Called on Core's event loop, so a method must not block.  One that throws is logged, and the
/// others are still called; what it was told is not told again.
class DeviceEvents {
  public:
    virtual ~DeviceEvents() = default;

    /// Another device asked to join the account's device group.  The request whole, so a prompt
    /// can be drawn from it without reading anything back.
    ///
    /// Once per request per session, and not at all for one the application has already been handed
    /// by `incoming_link_requests()` -- so an application that reads nothing at startup is still
    /// told of every request waiting, and one that does is not told twice.  Held back until the
    /// first fetch from the swarm has been merged, since a request stored before shutting down may
    /// have been accepted elsewhere or expired since.  Never for this device's own request.
    virtual void link_request_added(device::LinkRequest request) = 0;

    /// A request announced by `link_request_added` can no longer be answered, and whatever prompt
    /// was drawn for it should close.  Not for a request this device accepted or ignored itself,
    /// whose prompt closed when the user acted on it, nor on hearing afterwards that another device
    /// accepted that same request too.
    virtual void link_request_ended(int reqid, device::LinkRequestEnd why) = 0;

    /// The account's devices changed: one joined, was removed, or changed how it describes itself.
    /// The whole set, since one group message can change several at once: every device that is or
    /// was in the group.  Not the ones asking to join, which arrive as link requests instead.
    virtual void devices_replaced(device::map devices) = 0;

    /// Another device joined the group, or stopped being in it: removed, or left of its own accord.
    /// Its record as it now stands -- `state` says which (Registered, Kicked or Left), and `kicked`
    /// when it went.  For a notice ("Alice's laptop was added"); `devices_replaced` follows for
    /// redrawing the list.  Not for a change this device made itself through `accept_request` or
    /// `remove_device`, nor for the members of a group this device has just been admitted to.
    virtual void device_membership_changed(device::Info device) = 0;

    /// Where this device stands, or the groups it can see, changed -- or became known with the
    /// first fetch of this run; see device::Membership for what each value means.  So the same
    /// value can arrive twice: a `Dissolved` device is told again when the group it can join
    /// appears in `MembershipState::others`.  `Removed`, `Displaced`, `Dissolved`,
    /// `Dropped` and `Forked` are the ones to alert on, and arrive as soon as the fetch that
    /// reveals them is merged.  `Approved` is the one to bring up the confirmation on, wherever
    /// the user is.  Not for the move to `Requesting` that `Devices::request_link` makes, nor back
    /// from it when that call reports failure: the caller knows.  Never `Unknown`.
    virtual void membership_changed(device::Membership membership) = 0;
};

/// Struct holding application callbacks to fire when libsession Core events happen to allow the
/// Core object to fire into the application front-end.
///
/// The signatures say what a handler may keep.  A parameter taken by rvalue reference was read for
/// this delivery and nothing else holds it, so a handler may move from it; one taken by `const&` or
/// as a span is borrowed and valid only for the duration of the call.  A handler may declare an
/// rvalue parameter as `T&&`, `const T&` or `T`, whichever suits it: only the last constructs
/// anything, and a handler that just reads pays nothing.
struct callbacks {

    /// Device group and link request events; see DeviceEvents.  Null for an application with no
    /// device linking of its own to show.  Must outlive the Core.
    DeviceEvents* devices = nullptr;

    /// Callback invoked when a background PFS key fetch initiated by prefetch_pfs_keys() completes.
    /// Not invoked for cache hits or NAK suppressions (i.e. only fires when prefetch_pfs_keys()
    /// returns stale or fetching).
    ///
    /// Parameters:
    /// - session_id -- 33-byte session ID (0x05 prefix + X25519 pubkey) of the remote user
    /// - result -- the outcome of the fetch: new_key, unchanged, not_found, or failed
    std::function<void(std::span<const std::byte, 33> session_id, PfsKeyFetch result)>
            pfs_keys_fetched;

    /// Callback invoked when a one-to-one message from Namespace::Default is successfully
    /// decrypted.  The message is passed as an rvalue reference: the callback may move from it
    /// (e.g. to take ownership of the content vector) or simply read it in place.
    ///
    /// Parameters:
    /// - msg -- the decrypted message data
    std::function<void(ReceivedMessage&& msg)> message_received;

    /// Callback invoked when a one-to-one message from Namespace::Default could not be decrypted
    /// or parsed.  The raw swarm message and a reason code are provided so the caller can decide
    /// how to handle it (e.g. log, queue for retry, surface to the user).
    ///
    /// When receive_messages() is called directly by the application, `msg` is a reference to one
    /// of the SwarmMessage elements passed in, which the caller can identify exactly by comparing
    /// pointers.  When triggered by internal polling, `msg` refers to an internally-owned object.
    ///
    /// Parameters:
    /// - msg    -- the raw swarm message that could not be decrypted
    /// - reason -- why decryption failed
    std::function<void(const SwarmMessage& msg, MessageDecryptFailure reason)>
            message_decrypt_failed;

    /// Callback fired as a send operation initiated by Core::send_dm() progresses.  This is
    /// typically invoked multiple times for a single message — once or more for intermediate
    /// states (awaiting_keys, sending, retrying) followed by a terminal state (success,
    /// network_error, no_network, or encrypt_failed).
    ///
    /// Parameters:
    /// - message_id -- the value returned by the originating send_dm() call
    /// - status -- the current state of the send
    /// - swarm_hash -- the hash the swarm assigned the stored message, on `success` and when the
    ///   storage server reported one.  Unset for every other status.
    std::function<void(
            int64_t message_id,
            MessageSendStatus status,
            std::optional<std::string_view> swarm_hash)>
            message_send_status;

    /// Callback fired when merging config messages from the swarm changed one or more of the
    /// account's configs, so that the layer holding a queryable copy of that state knows to go and
    /// reconcile it.
    ///
    /// Fires once per batch of merges rather than once per config, with every namespace that
    /// changed: one poll can carry all four, and reacting to each in turn would show the
    /// application a half-applied state.  It fires *after* the changed configs have been dumped,
    /// so what a handler reads is already on disk.
    ///
    /// Only merges are reported.  A config the application changed itself is not news to it, and
    /// Local never appears at all, since it merges nothing.
    ///
    /// This says *that* something changed, not what.  There is deliberately no diff: a config diff
    /// describes a transition between config states, while the reconciling layer's own currency is
    /// not a config state and is not tracked -- a merge can jump several updates at once, and a
    /// crash between merging and reconciling leaves it behind by an unrecorded amount.  Comparing
    /// against its own stored state is what makes reconciliation self-correcting, and a diff would
    /// silently skip anything those cases had left behind.
    ///
    /// Parameters:
    /// - changed -- the namespaces whose configs the merge altered.  Valid only for the duration of
    ///   the call.
    std::function<void(std::span<const config::Namespace> changed)> configs_changed;

    /// Callback fired when the account's key outbox (namespace -21) -- where contacts find the key
    /// they encrypt PFS/PQ messages to -- holds a key that is not one of this account's.
    ///
    /// Only a holder of the account's seed can publish there, so it means someone other than the
    /// account's own devices has the seed: tell the user, as for a forged Displaced alert, that the
    /// recovery phrase is in someone else's hands (see the device groups guide).  Whether PFS/PQ is
    /// enabled or not: a seed holder publishing a key need not have enabled it, and contacts
    /// encrypt to whatever they find.  Where it is enabled, this device publishes the account's own
    /// key over it straight away, if it is a member of its group in good standing.  Nothing is ever
    /// deleted from -21, and the seed holder can publish again.
    ///
    /// Not decided on sight: a key another device of the account has just rotated to is in -21 a
    /// moment before its group message reaches this device, so a key not yet known is checked again
    /// after a fetch of the device group, and reported only if it is still unknown then.  May fire
    /// more than once for the same key, if it is seen again.
    ///
    /// Only on a device that is a member of its group in good standing (`InGroup` or `Forked`): one
    /// outside it holds none of the group's keys to compare against.  A device that becomes a
    /// member fetches -21 again from the start, so a key published before then is still judged.
    std::function<void()> rogue_account_key;
};

}  // namespace session::core
