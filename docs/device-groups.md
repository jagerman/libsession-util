# Device groups: how an application uses them

This is the guide for an application that wants to support several devices on one Session account:
linking a new device, approving one, listing and removing devices, and handling the situations
that can go wrong. It describes *what to call and when*. The protocol behind it is in
`docs/protocol-v2.md`; the exact signatures and their full documentation are in
`include/session/core/devices.hpp`, `include/session/core/callbacks.hpp` and (for the emoji)
`include/session/core/link_sas.hpp`.

## The one rule: the application is dumb

libsession works out where the device stands, owns every piece of state, and makes every protocol
decision. The application **draws what it is told and passes the user's choices back as calls**.
It never infers anything from swarm contents, and never keeps state of its own about device groups:
not a SAS, not a deadline, not a request id across a restart. Anything a screen needs is re-read
from libsession each time the screen is drawn, and the events below say when to read again.

## Concepts

- **Device group.** The devices that share an account's encryption keys. A device outside the
  group cannot read what the group shares, so a device that has restored an account from its
  recovery phrase still has to *join* the group before it is a full member.
- **Group identifier.** Each group has a fixed identifier (`device::GroupId`), shown as the first
  **4** emoji of `sas()` beside `created()` (all 21 emoji are there for an extended view). It tells
  apart groups the user has to choose between, and how old an unfamiliar one is. It is not a
  security check. **Show it only when more than one group is in view.** With a single group there
  is nothing to choose between, and its emoji beside a link request's emoji only gives the user two
  sets to confuse.
- **Link request.** How a device asks to join a group. Both devices show the same **7** emoji (21
  for an extended view), and the user confirms on *both* that they match.
- **Showing emoji.** A SAS (`sas` on a request, `GroupId::sas()`) is a list of indices, 0-63, into
  Matrix's SAS emoji table. Look each up with `sas_emoji(i)` and show its `emoji` with its
  `description` under it -- Matrix's English name for it, or your own translation of that name,
  which you keep by the same index -- the first 7 in a row, or all 21 as 3 rows of 7 for the
  extended view. Never show the index itself. A few emoji look alike or render differently from
  one platform to another, which the names settle. Ask whether the two devices show "the same"
  emoji, not "identical" ones.
- **Words for the user.** "Device group" is the API's term, and the protocol's. What the user sees
  generally needs no "group" at all: "your devices", "link a device", "device list", "this device
  was removed". Where two groups have to be told apart, and only then, say what they are rather
  than naming the concept.
- **One group per account.** An account can still end up with two, usually because a device
  started a new group when it should have joined the existing one: a **fork**. libsession does not
  resolve it by itself. The user does, by keeping one group, which **dissolves** the other: its
  messages are deleted and its devices told, and they link again to the group that was kept.

## Wiring it up

Implement `core::DeviceEvents` (re-exported as `client::DeviceEvents`). It has five methods, all
pure virtual, so none can be left out by accident:

| Event | Meaning |
|---|---|
| `link_request_added(LinkRequest)` | Another device asks to join this device's group. Prompt the user. |
| `link_request_ended(reqid, why)` | That request can no longer be answered (accepted elsewhere, replaced, expired). Close its prompt. |
| `device_membership_changed(device::Info)` | Another device joined the group, or was removed, or left. Tell the user ("Alice's laptop was added"). |
| `devices_replaced(device::map)` | The group's device list changed. Redraw the device screen. |
| `membership_changed(Membership)` | Where this device stands, or the groups it can see, changed -- or became known. The same value can arrive again when only `others` changed. Re-read `membership()` and act on it. `Approved` is the cue to bring up the new device's confirmation, wherever the user is. |

One more belongs with these but is not a `DeviceEvents` method: `rogue_account_key`, a plain
function in the same `callbacks` struct, which fires when the account's published key has been
replaced by someone else (see "PFS/PQ").

Pass a pointer to your implementation as `callbacks::devices`: `client::callbacks` for a `Client`
application, `core::callbacks` for one using `Core` directly. It must outlive the `Client` (or
`Core`), and for a `Client` also any delivery its dispatcher still holds. A `Client` delivers these
through its dispatcher, onto your thread; `Core` calls them on its own event loop. Either way a
handler must not block and must not throw.

Everything else is on `devices`: `client.core.devices` for a `Client` application. Most calls have
a handler form, which takes a `result_function` and answers on the dispatcher or loop, and an
`await` form, which blocks the calling thread. Network operations (`request_link`) have only the
handler form. Two are neither: `devices()` and `device_id()` are plain synchronous calls, safe from
any thread, which read the database directly. Failures carry an `Error` whose `code` is one of
`core::err::*`. The other plain calls in `devices.hpp` -- building and marking pushes, rotating
and listing keys -- are Core's own machinery, and not for an application.

At startup, and whenever the user changes them, describe this device with `update_info`: its
`type` (e.g. `device::Type::Session_CLI`), a short `description`, and its `version`. That is what
other devices show for it. The description is capped at `device::DESCRIPTION_MAX` (64) bytes;
libsession cuts a longer one to fit, on a UTF-8 character boundary, so limit what the user can
type to the same, or show them what was kept. It is this device's own and kept across joining,
leaving and starting groups, so there is no need to set it again after any of those.
`device_info()` reads back what it publishes; the device list (`devices()`) shows what the group
holds for it, which catches up once a push carrying a change has reached the swarm.

## Startup: membership drives everything

Call `membership()` at startup. Until the first fetch from the swarm completes it answers
`Unknown`, because the swarm may have changed while the application was down. **Do not prompt from
`Unknown`.** Wait for `membership_changed`, which fires when the first fetch makes the state known,
and on every change after -- to the state, or to which groups are in `others` -- except one made
by your own call (asking to join, starting a group, dissolving one, leaving one). Re-read
`membership()` after making those calls.

`membership()` returns the state, this device's `group` (only while it is a member in good
standing: `InGroup` or `Forked`), and `others`: every group in the swarm this device could ask to
join, newest first, each with its id and when it was last active (`last_seen`: when its newest
message was written, by the clock of the device that wrote it). For a device `Removed`,
`Displaced` or `Dropped`, `others` includes the group it was in, while that group is still in the
swarm: asking again, under a new identity, is the way back into it. "Link this device again" in
the table below is `request_link(others.front().id)`, or a choice among them if there are several.

| Membership | What it means | What to offer |
|---|---|---|
| `InGroup` | A full member, and the only group in the swarm. | Normal operation: the device screen, approving requests. |
| `NoGroup` | Not in a group, and no group is in the swarm. | "No existing device group was found. Start a new one, or bring one of your other devices online to link this one?" Start → `start_device_group`. Otherwise wait: the state changes when a group appears. |
| `DeviceGroupVisible` | Not in a group; groups it cannot read are in the swarm. | "Link to your existing devices" (see "Joining"). Less prominently, "Start a new device group instead" → `start_device_group`, with a warning that it **dissolves** the existing group (see "Starting a group"). |
| `Requesting` | This device's link request is out, awaiting approval. | The waiting screen, without a confirm action (see "Joining"). |
| `Approved` | Another device approved the request; the user has to confirm the emoji. | The confirmation, brought up wherever the user is (see "Joining"). |
| `Removed` | Another device removed this one. | An alert: "This device was removed from your account's device group." Then the same choices as `DeviceGroupVisible`: link this device again, to the group it was removed from (in `others`), or start a group. Either call gives the device a new identity first; there is nothing else to do. Starting a group from here dissolves the group in view: the very group this device was removed from. |
| `Forked` | In its group, which is fine and goes on working, while another group is in the swarm: the account has forked. | A prominent prompt that does not go away by itself: keep this group, or use the other. See "Forks". |
| `Displaced` | Another device now holds this device's place in its group, under this device's identity -- or someone with the recovery phrase has made it look that way. | A critical alert (see "Forks and alerts"), shown so it cannot be missed; once dismissed it stays as a warning the user can reopen. It arrives with the first unreadable message written more than `DISPLACEMENT_GRACE` (5 minutes) after the last one this device could read. Offer to link this device again, to the group in `others` (the one it was displaced from), which gives it a new identity as part of asking. Starting a group from here dissolves the group in view. |
| `Dropped` | No longer in a device group: its group has gone from the swarm while another group is there, or has moved on to keys it doesn't hold without saying why. It was removed, replaced, or away too long, and cannot tell which. | "This device is no longer in your account's device group. It may have been removed or replaced, or been away too long." Offer "link this device again" as the default, to the group in `others` -- the one it was in, if that is still in the swarm, or else the one that took its place -- which gives it a new identity; "start a new group" less prominently, with the dissolve warning (see "Starting a group"): it dissolves the group in view. |
| `Dissolved` | The user, on another of their devices, kept a different group over this device's. This device has already forgotten its old group and taken a new identity. | "Your devices now use a different device group; link this device to it." Offer to join (see "Joining"), as from `DeviceGroupVisible`. |

`NoGroup` is deliberately the user's decision. It cannot be told apart from a group that expired
while all of the account's devices were offline for 30 days, and starting a group in that case
forks the account. An application that really does want to start a group automatically can call
`start_device_group` without asking, but that is its choice, not libsession's.

On a restored account, say at the "Start a new one" choice what it costs: **messages sent to the
account before this restore cannot be recovered on this device** unless one of the account's other
devices comes back online and links it. They were encrypted to keys that only those devices hold,
and the recovery phrase does not bring those keys back. If the user has no other device, that is
how it is; if they do, bringing it online and linking is the better choice.

There is no "link later" call. If the user dismisses the prompt, do nothing: the state is
unchanged, and the next start (or the device screen) offers the choice again.

### Creating and restoring accounts

- **New account:** `globals.create_account(SeedSize::Bits128)` (13 words) or `Bits256` (25
  words). A new account gets its group at once and becomes `InGroup` with the first fetch.
- **Restored account:** `globals.restore_account(seed)`. No group is created. The first fetch
  makes the state `DeviceGroupVisible` (join one) or `NoGroup`.

A new account has PFS/PQ enabled from the start; a restored one keeps whatever the account says,
which for an account made before PFS/PQ is off until the user turns it on (see "PFS/PQ").

## Joining a group (the new device)

1. **Choose.** In `DeviceGroupVisible`, take the group from `membership().others`. Usually there is
   exactly one: use it without asking, and without showing its emoji. If there are several, the
   account has forked: offer the most recently active (the first in `others`) by default, with the
   others listed by emoji, creation time and last activity. **Joining one dissolves the rest** once
   the link completes: their devices become `Dissolved` and have to link to the chosen group. Say
   so at the choice, with what is lost: messages that reached those groups' devices only,
   encrypted to keys the chosen group's devices do not hold, cannot be recovered afterwards unless
   another device still holds those keys.
2. **Ask.** `request_link(group, cb)`. It fetches the group from the swarm first, then uploads the
   request and answers once the swarm has stored it, with the SAS and the deadline (10 minutes).
   Errors: `err::unknown_group` (the fetch found the group gone), `err::network_unavailable` (no
   network, or the swarm could not be reached), `err::store_failed` (worth retrying),
   `err::already_registered` (this device is in a group; there is no moving straight to another).
   Show progress meanwhile: the fetch and the upload take a round trip each. From `Removed`,
   `Displaced` or `Dropped` the call first gives the device a new identity, forgetting the group it
   is no longer in: the request then comes from a new device. The device is now `Requesting`; that
   move is not reported, since the caller made it.
3. **`Requesting`: show the waiting screen**, drawn from `outgoing_link_request()` every time it is
   opened: the 7 emoji (21 extended), "Awaiting approval from one of your existing devices", and a
   countdown to `expires`. **No confirm action**: there is nothing to confirm yet, and
   `confirm_link` answers false. Tell the user to open Session on one of their existing devices,
   where a matching prompt will appear.
4. **`Approved`: ask the user to confirm.** `membership_changed(Approved)` means another device has
   approved the request. Register for it and bring up the confirmation wherever the user is: the
   same emoji, "Approved on your other device. Do these match?", and a **"These match"** action;
   no countdown, since the request no longer lapses. When the user says they match, call
   `confirm_link`.
5. **Done** when `membership_changed(InGroup)` arrives, which happens inside the `confirm_link`
   call.

The request is a background thing, and the waiting screen only a view of it. There is no cancel:
the request lives in the swarm for its 10 minutes, across restarts, whatever the screen does.
Closing the screen changes nothing, and tapping "Link" again while `Requesting` reopens the same
request: `request_link` for the same group answers with it, same emoji and same deadline, and
uploads nothing (on the decision screen, "join" then means "show my request"). If the deadline
passes unapproved, `membership_changed` reports the device back in `DeviceGroupVisible`/`NoGroup`;
offer to try again, which makes a new request with a new SAS. Starting a group instead withdraws
the request.

An approval can arrive after the deadline has passed here: the other device approved in time, but
this one fetched the message late. It is `Approved` all the same, and `outgoing_link_request()`
returns the request past its `expires`; show it as in step 4.

**Why the confirmation on the new device matters.** Anyone who holds the account's recovery phrase
(a removed device, a stolen backup) can publish a fake group. A device that asks *that* group to
let it in would be admitted by the impostor, and from the new device alone that looks exactly like
success. The real group can't even read such a request, so no prompt ever appears on the user's
real devices. Confirming on the new device is what catches this: **the user should only press
"These match" after seeing the same emoji on one of their own existing devices.** Never confirm
automatically.

## Approving a request (an existing device)

1. On `link_request_added`, prompt the user with the requesting device's description, type,
   version, when it asked, and the 7 emoji (21 extended). Consider holding the prompt until the
   user has stopped typing for a few seconds, so that a keystroke can't answer it by accident.
   Re-read `incoming_link_requests()` when drawing the prompt rather than trusting a copy held from
   earlier: a request can be replaced or answered in between.
   If `replaces` is set, the request comes from a device already in the group, under the same
   identity: usually one that lost track of having joined, such as one restored from a backup.
   Say so plainly, and show `replaces` (its current description and when it last updated) beside
   the request: "This will replace *Alice's laptop* in your device group." The emoji check matters
   as much as for a new device, since someone holding the recovery phrase could ask under that
   identity too.
2. Offer three answers:
   - **Approve:** `accept_request(id)`. Only if the user confirms the emoji match what the new
     device shows.
   - **Ignore:** `ignore_request(id)`. Local only; another of the user's devices may still approve
     it, which is the normal case when the user is approving elsewhere. The requesting device is
     not told: it goes on waiting until its deadline (10 minutes) unless some device approves it.
     So word the button as "not now" or "decide on another device" rather than "decline", which
     it is not.
   - **"I don't recognise this":** `ignore_request(id, true)`. Also deletes it from the swarm, so
     devices that haven't fetched it yet never see it. A device that already has it can still
     approve it until it expires, so word this as "stop other devices seeing it", not "block it".
3. Close the prompt on `link_request_ended`, whatever the reason; the reason is there if you want
   to say something like "approved on another device". It does not fire for this device's own
   accept or ignore: close the prompt when that call returns.

`accept_request` answers false if the request can no longer be accepted (approved elsewhere,
replaced, expired, the device removed, or this device has left the group meanwhile). That is not an
error: close the prompt. Accepting a replacement also gives the group a new account key; there is
nothing for the application to do about that.

Ignoring is not final. A request this device ignored can still be accepted with `accept_request`
until its deadline, which is how an Ignore pressed by mistake is put right -- with or without the
swarm deletion, since this device keeps its own record of the request. `link_requests()` lists it,
with `status` `Ignored` and its `expires`, so a devices screen can offer "approve" for an ignored
request that is still live without prompting for it again.

Request ids are counters for this run only. Never persist or display them.

## The device list

`devices(true, false, true)` gives every device that is or was in the group, by id. It is a plain
synchronous call, safe from any thread, so a list can be drawn from it directly. `state` says
which:

- `Registered`: in the group. Show its description, type, version and `timestamp` (when it last
  updated its information).
- `Kicked`: removed, at `kicked`. `Left`: left of its own accord, at `kicked`.
- `Pending` devices are only asking to join, and appear as link requests rather than in the list.

A device that was removed before this one joined appears as a bare tombstone with nothing to show
for it (an empty description). Leave those out of the list.

Draw **this** device's own entry from `device_info()`, never from its row in `devices()`.
`devices()` mirrors what the group holds in the swarm, so this device's row there lags until a push
carrying its latest description has been confirmed; on a new account it is a blank record until
the first push lands, and stays blank for as long as that push keeps failing. `device_info()` is
what this device publishes, and is right at once.

A `Dissolved` device's list is empty by design: it has forgotten the group it was in. Show it as
"not in a device group", not as "no devices yet".

Redraw on `devices_replaced`. `device_membership_changed` comes first, once for each other device
that joined or stopped being in the group, with its record as it now stands; use it for a notice
rather than for the list. It does not fire for this device's own `accept_request` or
`remove_device`, nor for the devices of a group this device has just joined.

**Show an addition prominently**, as a notice the user will see rather than a line in a list: "A
new device was added to your account: *Alice's laptop*". It is the one event the user must not
miss. Anyone holding the account's recovery phrase -- a removed device included -- can add a device
of their own, and the design answers that, as it answers everything a holder of the phrase can do,
by telling the user rather than by preventing it: the user sees it, and the user decides. Offer,
with the notice, what to do about a device they don't recognise: remove it (`remove_device`); and if
the recovery phrase itself may be in someone else's hands, start afresh from a device they trust --
`leave_group`, then `start_device_group`, which dissolves the old group (see "Starting a group") --
and treat the recovery phrase as compromised.

To remove a device, call `remove_device(id)` behind a confirmation that makes its permanence clear:
**a removed device can never rejoin under the same identity**. It can only come back as a new
device, under a new identity (which asking to join gives it), approved again like any other.
`remove_device` answers false if the device is no longer in the group (or this one isn't), which is
not an error. This device cannot remove itself.

## Forks and alerts

### Forks

`membership_changed(Forked)`: this device is in its group, whose messages are in the swarm, and
another group's are there too. An account can have only one, so the user has to choose. Nothing
is wrong with this device's group, which goes on working meanwhile, and the user may settle the
fork here or on another of their devices; nothing has been decided yet, and nothing lost.

Two groups are in view, so show both by emoji and creation time, this device's included, with when
each was last active: this device's own is active now, and the other's is `others[i].last_seen`.
That is what tells the user's other devices, in use ("an hour ago"), from a stale leftover, such as
a device that started a group of its own by mistake months ago ("two months ago"). Offer:

- **Keep this group:** `dissolve_group(other)`. Its messages are deleted from the swarm and a
  tombstone tells its devices, which become `Dissolved` and can link again to this group. Before
  the user confirms, say plainly what is lost: **messages that reached the other group's devices
  only, encrypted to keys no device of this group holds, cannot be recovered afterwards** unless
  another device still holds those keys.
- **Use the other group:** `leave_group()`, then join the other group as a new device does (see
  "Joining"), with the emoji confirmation. Completing that join dissolves this group, so its other
  devices become `Dissolved` and link to the other group in turn; the same warning about what is
  lost applies, the other way round.

`dissolve_group` answers false if the group is no longer in view, or this device is no longer
`Forked`; re-read `membership()` and redraw.

### Other alerts

- **Displaced** (`membership_changed(Displaced)`). Critical. Bring it up so it cannot be missed
  (a full screen is fine, perhaps with a second confirmation to dismiss), and once dismissed keep
  it as a warning somewhere in the UI that the user can reopen at any time. The device is not
  read-only meanwhile: it can still send. The group has
  moved on to keys this device doesn't hold, under this device's own identity -- or a message from
  the group says so, and anyone with the recovery phrase can write one. An unreadable message
  counts only if it was written more than `Devices::DISPLACEMENT_GRACE` (5 minutes) after the
  newest message this device could read: a member may push a snapshot built before it fetched a
  new device's admission, which would otherwise look like displacement for no reason but timing.
  So the alert arrives with the first unreadable message past that window, not the first
  unreadable message. So there are three ways
  here: the user restored this device elsewhere and approved the copy as a replacement; someone
  with a copy of this device's data has taken its place; or someone with the recovery phrase has
  made the group's devices believe they were displaced. Say so: "Another device has taken this
  device's place in your device group. If you didn't restore it on another device, someone may
  have a copy of this device's data, or your recovery phrase." The device stops acting for the
  group by itself. The way back is joining again as a new device (`request_link` to the group in
  `others`, which takes the new identity itself); the user should also remove the old identity from
  one of their other devices if they don't recognise what now holds it. If several of their
  devices show this at once, no restore explains it: the recovery phrase is in someone else's
  hands, and the user should start afresh from a device they trust (`start_device_group`, which
  dissolves the group in view) and treat the phrase as compromised.
- **Removed** (`membership_changed(Removed)`). Tell the user. If they want the device back, offer
  to link it again, to the group it was removed from (in `others`), or to start a group; the call
  gives it a new identity, and it then joins like any new device. Messages and the account's
  configs are kept.
- **Dissolved** (`membership_changed(Dissolved)`). The user chose, on another device, to keep a
  different group, and this device's group is gone. Nothing is needed before joining again: the
  device already has a new identity, and its messages and the account's configs are kept. Offer to
  link it to the group that was kept, an ordinary join with the emoji confirmation.
- **Dropped** (`membership_changed(Dropped)`). Either this device's group has gone from the swarm
  while another group is there, or the group has moved on to keys this device doesn't hold without
  saying why. Either way the device cannot tell what happened: it may have been removed or
  replaced while away, been away too long, or had its group dissolved. It stops acting for the
  group by itself. Tell the user it is no longer in the account's device group, and offer to link
  it again (`request_link` to the group in `others`, which gives it a new identity first);
  starting a group instead is possible but dissolves any group in view, so offer it less
  prominently and with the warning from "Starting a group".

## Starting a group

`start_device_group()` creates a group with this device as its only member. It is valid from any
state outside a group. A device `Requesting` or `Approved` drops its request; one `Removed`,
`Displaced` or `Dropped` takes a new identity first, and the group it was in is then one in view
like any other. It fails with `err::membership_unknown` before the first fetch, and
`err::already_registered` from a group.

From `DeviceGroupVisible` (or anywhere else with groups in `others`), starting a group **dissolves
every group in view**: an account has only one, and the user is choosing the new group over them.
Their devices become `Dissolved` and have to link to the new group. Make that the warning on the
"Start a new device group instead" choice, and say what is lost: **messages that reached the
existing devices only, encrypted to keys this device does not hold, cannot be recovered afterwards**
unless another device still holds those keys. This device is not alerted about anything: the choice
was its user's.

## Leaving a group

`leave_group()` takes this device out of its group and forgets the group, leaving it `NoGroup` or
`DeviceGroupVisible`. Call it:

- **On logout, or when the user clears the app's data**, before wiping anything. The group is told
  the device has gone, so it stops listing it and encrypting to it; otherwise it stays in every
  other device's list until someone removes it by hand. The departure is attempted at once, and
  retried after each fetch while the app is still running (and after a restart) until the swarm
  has it; it is not reported on. On logout or clearing data the app then wipes the database, and
  the departure with it, so it gets whatever that first attempt achieved: call `leave_group` while
  the network is still up, and give it a moment before wiping if you can.
- **From `Forked`, when the user chooses the other group** (see "Forks"): leave, then join. A
  device that was its group's only member dissolves the group as it leaves, so the other group's
  devices stop showing a fork without anyone there having to choose.

A device that was removed, displaced, dropped or dissolved just forgets the group; it has nothing it
may tell it. Leaving gives the device a new identity, as joining the group again would need anyway:
it can ask to join any group afterwards, the one it left included. `leave_group` answers false if
there is no group to leave. A device cannot ask to join a group while it is in one
(`err::already_registered`): leaving comes first.

## PFS/PQ

Contacts send PFS/PQ messages to an account only once it publishes a key for them to encrypt to,
and it publishes one only once every device of it is declared able to read them. A new account has
that from the start. One restored from its recovery phrase may have older devices, and the user
turns it on by hand.

**When to offer it.** Only while `membership()` is `InGroup`, and only while `core.pfs_enabled()`
is false. Put "Enable PFS/PQ" beside the device list, as the step after the user has linked every
device they use: the list they are looking at is the list they are confirming is complete. Do not
offer it from any other state, nor before the user has had the chance to link their devices.

**What to tell them first**, and have them confirm:

> Once enabled, PFS/PQ cannot be disabled. Clients that are not in your device group, including
> legacy Session clients, will not be able to receive messages from contacts who use the new
> PFS/PQ encryption to send to you.

It helps to say what it does not touch: it applies to one-to-one messages only (groups and
communities have their own encryption); messages already received stay readable; and contacts
switch gradually, as they next fetch the account's key, rather than all at once.

**Then call `core.enable_pfs()`.** It records the setting in the account's profile, which reaches
the other devices as any setting does, and publishes the account's key straight away. There is no
call to turn it off, and no setting to offer for it: a contact that has fetched the key goes on
using it whatever the account later publishes, so off would not mean off. `pfs_enabled()` says
whether it is on, whichever device turned it on.

### A key that is not the account's

`rogue_account_key` fires when the account's published key -- the one contacts encrypt to -- is
one that none of the account's devices made. Only someone holding the recovery phrase can publish
one, so treat it as the forged Displaced alert is treated (see "Other alerts"): critical, brought up
so it cannot be missed, and kept as a warning the user can reopen once dismissed. Say plainly that
**someone else has the recovery phrase**: "Someone has published a key for your account that none
of your devices made. Only someone with your recovery phrase can do this." What to do about it is
the same: start afresh from a device they trust and treat the phrase as compromised.

libsession has already done what it can: where PFS/PQ is enabled, the account's own key goes back
over the rogue one at once. It deletes nothing, since whoever has the phrase can publish again.

It fires whether or not PFS/PQ is enabled -- a seed holder can publish a key either way, and
contacts encrypt to whatever they find -- and may fire again for the same key. It is never raised
for a key another of the user's devices has just rotated to: that is checked against the device
group before anything is reported.

Only a device that is in its group (`InGroup` or `Forked`) can raise it. One outside the group --
restored and not yet linked, asking to join, or removed, displaced, dropped or dissolved -- holds
none of the group's keys to compare against, so it never reports. It does not miss a key published
in the meantime, though: on joining, a device reads the account's published key again from the
start, and judges it then. One case need not be an attack: a `Forked` account whose other
group publishes its own key. That is still a device holding the phrase outside this group, but it
may well be the user's own; settle the fork (see "Forks") and the alert has its explanation.

## Do not

- Prompt from `Membership::Unknown`.
- Keep a SAS, deadline or request id yourself, or show a SAS from anywhere but a fresh read.
- Confirm a link (`confirm_link`) or approve a request (`accept_request`) without the user
  comparing the emoji on both devices.
- Start a group for a restored account without the user choosing to, unless that is a deliberate
  policy of your application -- and never with groups in view, which it would dissolve.
- Dissolve a group (`dissolve_group`) without the user choosing to.
- Rotate keys yourself (`rotate_account_keys`, `rotate_device_keys`): Core rotates both on its own
  schedule, after a fetch, and fetches by itself when a rotation falls due.
- Hardcode the numeric values of `device::State` or `device::Membership`.
- Block or throw in a `DeviceEvents` handler.
