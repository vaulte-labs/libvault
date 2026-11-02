# Vaulty design

Vaulty keeps passwords, cards, env vars, 2FA codes, passkeys, SSH keys and notes
in a local encrypted vault whose keys are bound to the device's secure hardware.
People and agents use the secrets through any interface over libvault. Agents use them; they do
not get to read them.

Claims below are tagged **tested** (run on a real machine), **documented** (primary
source) or **assumed**. An assumed claim is a bug until it is one of the other two.

## Threats

| Attacker | Outcome |
|---|---|
| Has a copy of the vault (cloud breach, stolen backup, any peer) | Nothing. There is no password to guess: keys are 256 random bits, wrapped with a P-256 + ML-KEM-1024 hybrid so a future quantum computer does not help. |
| Has the stolen, locked device | Needs Touch ID or the login password to use the enclave keys. Other devices revoke it and rotate keys. |
| Agent running as the user, without a grant | Can read the encrypted files and, while unlocked, item names. Cannot use or read a secret without a touch (**tested**), unless it takes a live session token from another process's environment, which then gives it that session and no more. It can ask for a touch with a misleading reason, because a source build's enclave blob is readable by any same-user process. Signed releases close this by keeping blobs in the keychain under the team's access group. |
| Agent running as the user, with a grant | Can *use* the granted space: proxied requests, fills, logins. Cannot read plaintext through any `vlt` path without a fresh touch. |
| Agent that drives a browser and deliberately reads a filled field | Can read it (**assumed**, follows from the DOM). This is why agent browsers log in through a separate browser and receive only session cookies. |
| A server you allowed that deliberately transforms what it receives | It can return an encoded secret the proxy does not recognize. Scrubbing catches echoes, not intent, so the real boundary is which hosts you allow. |
| Root, or a kernel compromise, while unlocked | Out of scope. It can read the broker's memory. |
| Malicious update of `vlt` itself | Out of scope for the format. Releases are signed; source builds trust their builder. |

An unsigned CLI cannot keep a Secure Enclave key in the keychain (`-34018`, **tested**),
but a wrapped key blob in a file works, including ML-KEM-1024 (**tested**). The blob is a
handle, not a secret: any same-user process can use an ungated blob (**tested**). So every
key that protects secrets is created gated, and the same design holds for source builds
and signed releases.

Environment variables handed to a child are visible to same-user processes (**tested**
with `ps eww` on macOS, **documented** for Linux `/proc/pid/environ`). So API keys default
to the proxy, and real env vars need a fresh touch per run.

## Keys

```
recovery key (256 bits, offline)      device enclave keys (gated, per device)
            \                                   /
             wrap                          hybrid wrap
               \                             /
                  epoch key (random, rotated on revoke)
                               |
                  space key (random, one per space)
                               |
                     item (XChaCha20-Poly1305)
```

- **Hybrid wrap.** Any device can wrap to any other from public keys alone, in software.
  The recipient needs its enclave. `wrap_key = HKDF-SHA-256(ecdh ‖ mlkem, transcript)`.
- **Recovery key.** 24 words shown once at setup. Can also approve a roster change, so a lost
  second device never means a locked vault.
- **Space keys** are independent, so reading one space says nothing about another.
- **No password anywhere** on hardware backends. Where no secure hardware exists, the
  software backend wraps device keys with Argon2id and says so. Nothing there stands in for a touch,
  so every approval takes the passphrase, even while the vault is open, and the broker keeps none.

Touch ID uses `.userPresence`, not `.biometryCurrentSet`: re-enrolling a finger must not
destroy access. Rejected: keychain-bound keys only, because source builds could not use them.

## Records

The vault is a directory of append-only logs, one per device. A device writes only its own
log, so any dumb transport (peer, folder, USB, iCloud Drive) can copy them without write
conflicts.

```
$LV_HOME/
  log/<device-id>.lvl     synced, ciphertext and public keys only
  local/                  never synced: enclave blobs, sync identity, backup and peer lists
  run/lv.sock             broker socket, inside a 0700 directory
```

Every entry carries the device id, a sequence number, the hash of the previous entry, a
hybrid logical clock and an Ed25519 device signature. The hash chain plus the copies held elsewhere
make truncation, tampering and rollback detectable, which is the useful part of a blockchain:
you are the only authority, so there is nothing to mine. The current state of an item is the
latest write by clock; ties break on device id. Deletes are tombstones. A clock more than a day
ahead of this device is refused.

Every entry is signed when it is written, and replay checks only the last signature in each chain.
An entry's previous hash covers the whole entry before it, signature included, so that one signature
covers everything behind it. A tip that fails sends that log back to a check per entry, which finds
exactly where it goes wrong. Roster changes are always checked for themselves.

Item plaintext is JSON padded to 256-byte buckets. A seal binds the vault, space, item, key
generation and part (listing or secret) as associated data, so records cannot be swapped. Logs
expose only random ids, sizes in buckets and timing.

A seal is `nonce ‖ commitment ‖ ciphertext ‖ tag`. The subkey and the commitment come from the key,
nonce and binding, because XChaCha20-Poly1305 alone commits to nothing: a ciphertext can be solved
to open under two keys, so two devices would read different secrets from one entry (**tested** with
a real forgery).

**Roster.** The genesis entry fixes the vault id and the recovery public key. Adding a device
needs signatures from two enrolled devices once two exist, or the recovery key. Removing one
rotates the epoch key and every space key. Nothing is re-encrypted: the old ciphertext stays in the
log whatever happens, so a removed device can read it either way, and a value written again would
look newer than an edit it never saw. What a rotation protects is what comes next.

Roster changes form their own hash chain: each names the change it follows, and its approvals sign
that position, the device writing it, and all of what changes: a whole public key, or a removal's
entry count and the hash of the last entry it keeps. Approvals are hybrid, ECDSA with ML-DSA-87.

Replay sorts entries by a clock their writer sets, so order alone proves nothing, and it runs in
two passes. The first finds every history the logs can support and settles the roster. The second
replays every entry against that roster, so a removal applies from the start whatever anything is
dated, and a removed device's log that differs from what its removal kept, or is too short to show
it, does not count at all.

What the reader knows comes first. A person's words go to a history where they are current, so
current words are never turned away, and a device stays in the history it is in, since it could not
open otherwise. Neither says anything to anyone else: they decide what this reader sees.

Then a fork goes to the branch signed by more of those who could sign at the fork, counting
everything on the branch, not only its first step. A stolen device can win any position it once held
alone, and only the removal that came later tells the two apart. Devices added after the fork have
no say, or a device could invent its own majority.

Where the count is even, signatures have run out: someone holds as much authority as the owner, a
stolen device and leaked words say, or two honest devices raced, and nothing in the logs can tell
which. What follows only picks a default for a reader with nothing else to go on: those a rival
branch retired count for less, then someone leaving beats anything else, then more signers on the
first step, then the words, then the clock. Someone leaving comes first because an addition lost can
be made again, and a removal lost leaves a device holding what comes next. A new machine does not take
the default: recovery lists the devices in each history and its person chooses, because a stolen
device that was once alone can write a rival nothing but a date separates, and it sets the date.

A device never gives up a roster change it wrote, approved or was enrolled by, unless that was not a
departure and a departure replaced it on an even count. What it was merely told, it gives up only to
a branch with strictly more behind it, because retired words reaching a device that had not heard of
their retirement must not cut it off from the real vault. Nothing but a departure moves it off a
departure, whatever the count. Otherwise an even count leaves it where it is, and it says so. Its
person settles that with the words of the side they choose, which stays settled on that device. A
change that loses is skipped and reported, while the rest of that device's log still counts. A
removal, its new epoch and the wraps land as one entry. If that removal lost, what it made is set
apart: it goes to the words and to nobody else, because this history may still hold the device it
was made to keep out.

**Generations.** Epochs and space versions are identified by number and author, so two devices
rotating offline make two generations that coexist instead of overwriting each other. A device
holding both reads both. A generation follows from the first, one step at a time, only its author
writes it, and each commits to its key, so a device cannot give different readers different keys.

Each epoch also names the roster change it was made after. Anything made before the last departure,
of a device or of the words, is exposed: whoever left could have been given it, whatever the wraps
say. So is anything by a device no longer here. Nothing new goes under an exposed key. `repair` works
out from the logs what is missing and writes it, and every write asks first, so a crash partway or a
space made by a device that had not heard is put right before it matters: a fresh epoch if no clean
one is held, then a new version for each space with none. Each is its own entry, so no batch can
overflow, however many spaces a device made.

A rotation links every generation it holds, so whoever holds the new key reaches what was written
under a generation raced with it. `repair` also wraps the newest clean generations, and any
generation nothing else reaches, to everyone who should hold them. Only a wrap this device wrote
counts as done, because a device can write one that opens nothing and the words cannot say so until
they are all that is left.

A removal keeps what the remover had seen, so a device that heard more can have built on something
that stops counting. Any device writes such an item again, worked out from the logs, reaching at the
next unlock for any key that was cut too, so it survives losing the device that wrote it. A removal
also settles which history of a removed device counts: a copy that replays whole and holds what it
kept replaces one that does not, the one case a log changes other than by growing, because the device
could have signed two. What was replaced stays beside the log, since something may be built on it. A
log is only ever taken up to what its removal kept, and never past what a folder could hold.

All of this exists because a device's writes can depend on keys in another device's log. Giving each
device keys of its own would remove that dependency, and most of this with it. That is a redesign,
and it is not done.

**Sharing the recovery key.** Its signing keys derive from the words. Its wrap keys are random, with
the private half sealed under the words in the log, so any device can wrap a new epoch to recovery
without ever holding the words.

## Broker

Every interface is a thin client of `lvd`, a per-user broker that holds keys and never returns
plaintext except through `reveal`. It disables core dumps and refuses debuggers (a same-user `lldb`
attach fails, **tested**). On Linux it is not dumpable, so its own user cannot read its environment
or memory through `/proc` (**tested**).

Keys stay out of swap. Locking all of a broker's memory does not work: an ordinary user may lock
8 MiB on Linux by default and a broker uses about 16 MiB, so `mlockall` failed and locked nothing
(**tested**, as an ordinary user on Debian 12). So every vault key lives in chunks of its own, 64 KiB
and 2048 keys at a time, each locked as it is made, and a key is made, derived or unwrapped straight
into one, and erased there as it is let go (**tested** on macOS, and on Linux as an ordinary user,
where a broker with its vault open now has 64 KiB locked). What a key opens, such as a value
on its way to a program, is in ordinary memory for as long as it is in use. So are device keys
inside aws-lc for the moment they are open, and this device's log signing key while the vault is,
which can sign entries and read nothing. macOS also encrypts its swap (**assumed**).

An agent cannot be told from a person by its process tree, since agents usually run inside your
terminal, so there is one mechanism: a scoped token. Rejected: 1Password-style per-terminal
authorization, which hands a terminal's access to any agent started in it.

- **Lock.** Keys are dropped on timeout and screen lock, by the clock on the wall, so sleep counts.
  A lock always wins: a touch already under way comes to nothing, and a fill never opens the vault.
- **Grant.** One touch gives one agent one space for a bounded time. The agent gets a token.
- **Use.** `vlt run` starts the child with placeholders and a loopback proxy. The proxy swaps
  the placeholder for the secret only on requests to that secret's allowed hosts, and only in a
  credential header: `Authorization`, `Cookie`, or a name holding `key`, `token` or `secret`.
- **Reveal.** `vlt reveal`, and `vlt run --env` for tools that need the real variable, need a
  fresh touch every time, naming the values. They go to the caller that asked, and `Client` scrubs
  the child's output, which is a courtesy to a person: a hostile caller would not.
- **Audit.** Each use is a log entry, so once it has synced a compromised device cannot erase it.

## Fill

| Target | Path |
|---|---|
| Chrome and Chromium | MV3 extension and native messaging host. Origin must match the item. |
| Safari | The same extension in a Safari App Extension, plus system AutoFill. |
| Native Mac apps | Accessibility set-value, then synthetic keys. Both are **assumed** until tested. |
| Agent browsers | `vlt login`: a broker-owned browser over `--remote-debugging-pipe` signs in, and only cookies are copied out. That browser has no listening port (**tested**), must pass a signature check on macOS, and inherits nothing from the broker's environment. The page's address comes from the browser before each field, and each value goes by reference to the field that was checked, from an isolated world no page script can reach, so a frame that holds focus sees nothing (**tested**). A lock, or the end of a grant, stops a sign-in between steps. Only cookies for the saved site are handed over, and none holding the password. `vlt signup` works in the agent's own browser instead, since the agent fills the form: it puts a password made for that sign-up into the password fields of the tab the browser says is on the site, by reference, and a passkey request there is answered from the page's own world with a key the broker makes and keeps, so that browser gets the public half or a signature and never a private key (**tested**). |

## Sync

Nothing needs a server of ours. A relay, which Vaulte hosts as its paid service, carries devices
that share no network, and it holds nothing.

- **Find.** Beacons on the local network, or a known address. macOS Local Network privacy can stop
  a third-party binary receiving multicast (**inferred**: Apple's Python hears beacons that no
  Rust socket setup does), and iOS needs an entitlement for it. So the Apple apps find devices with
  Bonjour and hand addresses to `Client::add_peer`, and every path works without discovery.
- **Pair.** Devices connect over Noise XX and both show three words. Three words is about 33 bits,
  which an attacker could otherwise beat offline by trying keys until they match, so each side
  commits to a random value before seeing the other's, as Bluetooth numeric comparison does. That
  leaves one guess in 2^33 per attempt, with a person watching. The new device then gets a wrap.
- **Background.** Paired devices announce a fresh nonce and one tag per peer, from what the two
  sync keys agree, padded so the count does not show. They exchange log tails over
  `Noise_XXpsk0_25519_ChaChaPoly_SHA256`, keyed from the vault, so a stranger gets nothing from the
  handshake. Only ciphertext moves, so sync runs while locked. When the logs on a device grow, by a
  write there or by taking one in, it syncs with every device it can reach at once, so a change
  travels on through devices that did not make it (**tested**, on one machine: 2 to 4 ms through a
  relay, 22 to 26 ms over two relays and a device between). A burst, such as an agent's audited
  uses, goes at most once a second, all together. Otherwise devices sync on a beat. With one
  device, nothing listens, until a removal leaves one behind: the port stays open until the broker
  restarts, and it opens to nobody who does not hold a vault key.
- **Relay.** A phone on mobile data and a Mac on a wired network share no network, and neither can
  be called, but both can call out. A device given `relay:host:port` waits there under one tag per
  peer, which only that pair can compute and which changes every ten minutes, padded like a
  beacon. A peer it has not heard from in 30 seconds, or has news for, dials it by that tag, and
  the relay joins the two connections and copies bytes. What crosses is the same Noise channel, so
  the relay sees addresses, timing and sizes, and nothing else. Addresses are tried first, and a
  device one of them reached is not called again. The relay server is Vaulte's and not part of
  libvault.
- **Paying for the relay.** The relay Vaulte hosts lets in only a connection showing a pass for the
  month. An account is sixteen random digits, with an email only if its person gives one, and
  Stripe, not Vaulte, knows who paid. Each month the account service makes an RSA key, which a
  long-lived Ed25519 root key vouches for. A device fetches that key, checks the root vouched for
  it, blinds a fresh message and has an account that has paid get it signed (RFC 9474,
  RSABSSA-SHA384-PSS, randomized), then unblinds it, so the pass it shows cannot be linked to the
  account, by the relay or by the account service. The relay checks it with aws-lc as an ordinary
  RSA-PSS signature, and takes last month's for two days. The account service is a Cloudflare
  Worker, `accounts`, with each month's private key sealed under a secret. Its signer and the Rust
  that blinds were run against each other (**tested**), and two devices synced through a relay
  checking passes the production service issued (**tested**).
- **Share.** Not built. [Sharing](#sharing) says what a build must guarantee.
- **Backup peers.** A folder (iCloud Drive, USB) holds logs and cannot read them.
- **Merging.** A log only ever grows. Anything shorter or different is refused, so the copies on
  disk double as the high-water marks that stop a rollback, with nothing else to track. A signed
  copy of this device's own log that holds more proves this device was rolled back, and it takes
  that copy back. If it has written since, the others will refuse it, so it says so and stops.

Honest limit: with one device and no backup peer, losing that device loses the vault, even
with the recovery key, because a key without ciphertext opens nothing. `Client::status` gives one
answer in `last_copy`, counting only backups it can reach.

Optional and off by default: a recovery key in iCloud Keychain (end-to-end encrypted,
**documented**), which then trusts the Apple account and device passcode.

## Threat model

Each threat below has a status: **fixed**, with the test that failed before the fix, **held**, with the test that shows an attack does not work, **accepted**, with the reason, or **not built**. A test named here is an attack run against the real code. `scripts/state_space.sh` walks every sequence of roster changes and attacks through the real replay, `scripts/fuzz.sh` runs a target for every parser that takes outside bytes, and `scripts/mutants.sh` breaks the security code on purpose to check a test notices.

### Log and replay

Attacker: a malicious or stolen enrolled device, a removed device, a retired key, anyone who can write to a backup folder.

| Threat | Status |
|---|---|
| A removed device dates entries to before its removal, so they replay while it still counts | **Fixed.** Removal applies from the start of replay. `a_removed_device_cannot_backdate_an_entry_to_before_its_removal` |
| A removed device writes a shorter history, which no cutoff looks at, and its value reaches every device | **Fixed.** A log that cannot show what its removal kept does not count. `a_removed_device_cannot_rewrite_its_history_by_making_it_shorter`, `what_a_removed_device_planted_before_a_device_heard_stops_counting_once_it_has`. What a device did with it before hearing of the removal stands: **accepted**, it had no way to know |
| A second removal moves the cutoff, keeping what the first refused. Enrolling a removed device moves the roster and changes nothing | **Fixed**, found by the state-space walk. A removed device comes back with new keys. `a_removal_is_final`, `a_removed_device_cannot_be_enrolled_again_with_the_same_keys` |
| A removal cuts off a roster change that already counted | **Fixed.** `a_removal_cannot_cut_off_a_roster_change_that_already_counted` |
| A removal pins a count, so a different history of the same length passes | **Fixed.** It also names the last entry it keeps. `a_different_history_inside_a_removal_s_cutoff_does_not_count` |
| A removed device keeps reading what is written next, through a generation only some devices could open | **Fixed.** Nothing new goes under a key made before the last departure, or by a device no longer here. `a_removed_device_reads_nothing_through_a_version_the_remover_could_not_open`. It reads what it read before: rotation cannot un-read that |
| A space made by a device that had not heard of a removal stays on the retired key | **Fixed.** `a_space_created_during_a_removal_is_rekeyed_before_anything_new_goes_in_it` |
| A crash after a removal leaves new secrets going under old keys | **Fixed.** The removal, its epoch and its wraps are one entry, and every write finishes the rest first. `a_removal_and_the_keys_that_replace_what_it_ended_land_as_one`, `a_rotation_that_stopped_partway_is_finished_before_a_write_goes_under_an_old_key` |
| A device makes enough spaces that no batch can hold their keys, so it cannot be removed and the words cannot be replaced | **Fixed.** `nothing_about_how_many_spaces_a_device_made_goes_in_the_batch_that_removes_it`. `a_device_with_enough_spaces_to_fill_a_batch_can_still_be_removed` runs it at 48,000 spaces, by hand, because it takes a minute |
| A rotation by a device that had not heard of a departure wraps new keys to whoever left | **Fixed.** It names the roster change it was made after, so it counts as exposed. `a_rotation_wrapped_to_retired_words_is_rotated_again` |
| Whoever writes a recovery rotation, or a first entry, keeps the approved signing keys and swaps in their own wrap keys, so every later epoch is wrapped to them, even after they are removed | **Fixed.** Approvals cover the whole public key. `an_approved_recovery_key_cannot_have_its_wrap_keys_swapped`, `a_first_entry_cannot_have_its_wrap_keys_swapped` |
| Someone names a recovery key they do not hold, or the words alone replace themselves | **Fixed.** A new key signs for itself, and a device must approve. `a_recovery_key_cannot_be_named_without_its_own_signature`, `the_words_alone_cannot_replace_themselves` |
| A device copies an honest roster entry into its own log, approvals included, to take that position | **Fixed.** Every approval names its writer. `an_approval_cannot_be_copied_into_another_device_s_log` |
| A stolen or retired key dates itself early at a position it once held, so a fresh copy brings back a removed device, drops the honest ones, and stops the current words working | **Fixed.** A fork goes to the branch more of those at the fork signed, so what came later counts. `a_removed_first_device_cannot_undo_its_removal_on_a_fresh_copy`, `recovery_with_the_right_words_leaves_a_removed_device_out`, `retired_words_cannot_turn_the_current_ones_away`, `the_recovery_key_outranks_a_lone_device_whatever_the_clocks_say`, `a_rotation_of_the_recovery_key_beats_retired_words_at_the_same_position`, `two_devices_outrank_retired_words_at_the_same_position` |
| A stolen device and retired words turn the owner's current words away from a copy | **Fixed.** Words go to a history where they are current, whatever else is in the copy. `a_stolen_device_and_retired_words_do_not_turn_the_owner_s_words_away`, `an_unnoticed_device_and_retired_words_do_not_turn_the_current_words_away`, `a_stolen_device_that_also_holds_the_old_words_still_loses_to_the_owner_s_words`. Retired words open a rival they planted themselves, which holds nothing they could not already read: **accepted** |
| A stolen device that was once alone wins a fresh copy on a date it set | **Fixed.** Nothing picks: recovery shows each history and refuses to finish until the person chooses. A thief can name its devices after the person's, so each history also shows the newest items the words open in it, and what the person wrote after the split is only in theirs. Each history shown can be chosen. `p3_a_person_can_tell_a_stolen_device_s_history_from_their_own`, `p4_every_history_shown_can_be_chosen`, `a_removed_first_device_does_not_take_a_fresh_recovery_by_retiring_itself`, `an_enrolled_first_device_does_not_take_a_fresh_recovery_on_a_date`, `a_removed_first_device_cannot_win_a_fresh_copy_by_its_date_when_two_devices_removed_it` |
| A removal loses a race to an ordinary change, and the keys it made reach the device it removed | **Fixed.** On an even count someone leaving wins, wherever it comes on its branch, on every device, including one that signed what lost, and a device that heard of a removal keeps it. `p9_on_an_even_count_someone_leaving_beats_anything_else_wherever_it_comes_on_the_branch`, `a_removal_does_not_lose_to_an_honest_add_on_the_date_alone`, `what_a_writes_after_removing_r_stays_out_of_r_s_reach_through_a_race`, `a_person_with_the_words_can_keep_a_removal_that_raced`, `a_removal_dated_first_is_heard_on_the_device_that_raced_it`, `an_approval_got_from_a_device_does_not_keep_the_asker_in_it_past_a_removal`, `a_removal_is_not_lost_with_nothing_said_when_more_signers_stand_behind_a_race`. Where more of the vault signed the race, the removal does not count on a device that did not hear of it first: **accepted**, more of the vault said so, it is reported, and what the removal made is set apart, so the person removes it again |
| A device takes a rival with no more behind it than what it heard, and hands it what comes next | **Fixed.** Only strictly more signers at the fork moves a device off what it was told. `a_device_that_heard_of_a_removal_does_not_give_it_up_to_a_rival_with_no_more_behind_it`, `two_removed_devices_cannot_take_over_a_device_that_heard` |
| A rival with as much behind it reaches a device first, with nothing but itself on its side | **Accepted** until a person settles it. Someone holding a device and leaked words has exactly the authority the owner has, so no signature can say which is real, and that device treats the rival as the vault. It reports the conflict when the real one arrives, and the owner's words bring it back for good. `a_person_s_words_bring_back_a_device_a_rival_reached_first_and_it_stays_back`. A fresh copy with the same words on both sides, a device stolen from a vault of one whose rival removes it too, is the same case: the person is told there are two histories |
| A device stolen while it was the only one, with its touch available, replaces the words, so the owner's stop opening the backup | **Fixed.** `Recovery::open` says the words were replaced, and `Recovery::open_as_it_stood` opens the vault up to that point. `words_a_stolen_lone_device_replaced_still_open_the_vault_as_it_stood`. Whoever holds retired words gets the same, and that is what they could already read: **accepted**. A device that heard of the change refuses what comes of it |
| An approval nobody checked counts toward a fork | **Fixed.** Only checked signatures count, and the device being removed gets no say. `an_approval_nobody_checked_is_not_counted` |
| A device jumps to generation `u32::MAX`, where no rotation can be newest again, or claims or overwrites a generation | **Fixed.** A generation follows from the first, one step at a time, by its author. `a_device_cannot_skip_ahead_to_the_last_generation`, `a_space_version_cannot_be_written_over_or_claimed_for_another_device` |
| A device wraps a different key under a generation to each reader, or a junk generation hides a real rotation | **Fixed.** Each generation commits to its key. `a_generation_opens_only_with_the_key_it_committed_to`, `a_wrap_of_the_wrong_key_for_a_generation_changes_nothing`, `a_new_generation_with_a_link_that_leads_nowhere_costs_nothing`, `a_rotation_is_seen_whatever_higher_generation_sits_above_it` |
| A device writes a rotation whose wrap to the words opens nothing, silently voiding recovery for everything after | **Fixed.** Every device writes its own wrap. `a_device_cannot_void_recovery_with_a_wrap_that_opens_nothing`. Words cannot be tried until they are needed, so one honest device has to run after it: until then it is **accepted**, and removal ends it |
| A rotation reverts an edit it never saw | **Fixed.** Nothing is re-encrypted. `a_rotation_does_not_revert_an_edit_it_never_saw`, `a_rotation_never_writes_an_older_value_over_a_newer_one` |
| Something written under a generation raced with another is stranded | **Fixed.** `a_device_added_after_a_race_reads_what_either_side_wrote`, `a_person_settles_a_roster_conflict_with_the_winning_words`, `the_words_settle_a_conflict_between_devices_with_no_folder` |
| A link that opens nothing is believed, cutting old data off from new devices and new words | **Fixed.** A link counts once it opens and gives the key its target committed to. `a_link_that_opens_nothing_cuts_nothing_off` |
| A key a removal cut, still in memory, passes for clean | **Fixed.** Clean is a list of what this vault has on record. `a_cut_key_held_in_memory_does_not_count_as_clean` |
| One junk entry stops every list, every unlock, and the removal of the device that wrote it | **Fixed.** Readers take the newest thing that opens. `junk_from_an_enrolled_device_leaves_every_read_working`, `junk_cannot_stop_a_device_unlocking`, `the_device_that_wrote_junk_can_still_be_removed`, `a_space_with_a_junk_first_version_does_not_send_repair_and_rescue_round_for_ever` |
| A device renames another, or hides behind a name to escape removal, by leaving none or by copying a lost device's | **Fixed.** The device that added another names it once, and only it can rename itself. A shared name shows an id, and an id always works. `a_device_cannot_rename_another`, `p2_a_stolen_adder_cannot_point_a_removal_at_an_honest_device`, `a_device_hiding_behind_a_junk_name_can_still_be_removed`, `a_device_copying_a_lost_device_s_name_can_still_be_told_apart_and_removed`, `a_name_cannot_pose_as_another_device_s_id`, `removing_by_a_name_two_devices_share_never_picks_this_one_and_never_guesses` |
| An entry dated far ahead beats every honest edit and drags every clock with it | **Fixed** past a day ahead. Such an entry waits, with what follows it, and what came before is taken, or a removed device could cost others what its removal kept. `a_log_dated_far_ahead_of_this_device_waits_and_is_reported`, `p11_a_far_dated_tail_past_a_cut_does_not_cost_a_device_what_the_removal_kept`. Up to a day ahead is **accepted**: honest clocks disagree, the older value stays in history, and removal ends it |
| Two recipients of one wrap read different secrets from one ciphertext, which needs a non-committing cipher | **Fixed.** Every seal commits to its key, nonce and binding. `a_ciphertext_crafted_to_open_under_two_keys_opens_under_one` is a real forgery, solved against the cipher |
| A listing from another device carries terminal escapes | **Fixed.** `a_listing_from_another_device_cannot_carry_terminal_escapes` |
| A log from another vault, or a chain spliced from a fork | **Held.** `a_log_is_rooted_in_its_own_vault`, `a_validly_signed_entry_from_a_forked_history_is_rejected` |
| Two spellings of one log, or two logs for a device in an archive, replay as a fork nothing else sees | **Fixed.** `a_log_file_has_one_name`, `an_archive_holds_one_log_per_device` |
| Anything written to a backup folder reaches outside it: a link at the temp path, a link for the folder, a pipe or `/dev/zero` for a log | **Fixed.** `a_link_planted_in_a_folder_cannot_redirect_a_write`, `a_link_in_place_of_the_log_folder_is_refused`, `a_pipe_or_a_link_in_a_folder_cannot_hang_or_flood_the_broker` |
| A folder or peer offers an older log | **Held** on any device that holds a newer one. `a_folder_offering_an_older_log_is_refused_and_reported` |
| A stray tail, a copied first entry, a file from another vault or a bad copy stops recovery, or a new machine trusts a copy without being told what is wrong with it | **Fixed.** `a_stray_tail_on_a_log_does_not_stop_recovery_or_come_with_it`, `a_copy_of_a_first_entry_under_another_name_does_not_stop_recovery`, `a_file_from_another_vault_does_not_stop_recovery`, `a_plain_file_named_like_a_vault_folder_does_not_stop_recovery`, `what_a_copy_has_wrong_is_shown_before_it_is_trusted`. Whoever can write to a folder can also empty it, which costs that backup and no device: **accepted**, that is why a backup is not the only copy |
| A pile of junk files uses up the limit on new devices, keeping a real one from ever being heard | **Fixed.** A device approved by someone still here goes first. `a_pile_of_junk_files_does_not_keep_a_recovered_device_out_of_a_folder`, `files_a_removed_first_device_signed_do_not_keep_a_real_device_out_of_a_folder` |
| One flipped bit in a copy of a log makes a good peer look like a contradiction for good | **Fixed.** What replay trusted of the copy is what counts, and a good copy puts the rest right, this device's own log included. `one_flipped_bit_in_a_copy_of_a_peer_s_log_heals_from_that_peer`, `one_flipped_bit_in_a_device_s_own_log_heals_from_a_peer` |
| A new machine with a slow clock leaves out recent entries without saying so | **Fixed.** It says how many. `a_new_machine_is_told_when_a_copy_holds_more_than_it_took` |
| A folder holds so much that reading it exhausts memory, or one bad file costs the rest of it | **Fixed.** Sizes are added up before anything is read, a file past what a log can be is passed over, and a stray tail says nothing about what is in front of it. `a_folder_holding_more_than_a_vault_could_is_turned_down_unread`, `one_oversized_file_does_not_cost_a_good_folder`, `a_stray_byte_in_a_folder_does_not_stop_a_log_being_backed_up` |
| A crash or a failed write leaves this device's own log unable to continue, or a torn tail hides real damage | **Fixed.** `a_failed_write_leaves_the_file_where_it_was_or_stops_all_further_writes`, `a_torn_tail_is_kept_beside_the_log_before_it_is_cut`, `an_unreadable_entry_with_more_behind_it_is_damage_not_a_torn_tail` |
| An entry from a newer version looks like tampering | **Fixed.** `an_entry_from_a_newer_version_is_named_as_that_not_as_tampering`, `a_future_version_is_reported_rather_than_treated_as_damage` |
| A same-user process rolls back this device's own log, or a person restores it from a disk backup, which brings back a deleted secret, drops audit events, and can reinstate a removed device | **Fixed where a copy exists.** A signed copy that holds more proves it, and the device takes its log back. `a_device_rolled_back_on_disk_hears_it_from_a_copy_of_its_own_log`, `a_device_restored_from_an_old_copy_takes_its_own_log_back`, `a_tail_this_device_never_signed_cannot_claim_it_was_rolled_back`. With no copy anywhere it is **accepted**: nothing on this machine can tell, and such a process could read the same files anyway |
| A device restored from an old copy writes before it syncs, so nothing it writes ever leaves it | **Fixed.** It says so and stops. `a_device_that_forked_itself_stops_rather_than_writing_what_nobody_will_take`. What it wrote in between stays on it until it is exported: **accepted**, nothing can join two histories signed by one key |
| A same-user process swaps the whole vault folder | **Accepted.** It can destroy, and cannot forge. It can put a vault of its own in place, which a person would see as different items, and which its peers would refuse |
| Two devices remove each other, each with the words, so each removal is fully approved | **Accepted.** They part ways: each refuses the other's head, keeps working, and reports it. `two_devices_that_remove_each_other_part_ways_and_both_say_so`. Nothing can pick a winner, because both changes are equally valid. It needs the words used twice while the devices are apart, and a person then wipes one and joins it again |
| A device shows different histories to different peers | **Fixed once it is removed.** Each peer refuses what contradicts its copy and reports it, and the removal says which history counts, so a copy holding that replaces the other, once all of it replays, in whichever order they arrive. What was replaced stays beside the log, for what was built on it. `a_removal_settles_which_of_a_device_s_two_histories_counts`, `a_fork_is_taken_even_when_the_kept_log_arrives_after_the_removal`, `a_removal_keeps_the_key_to_what_b_built_on_the_history_it_refused`. Until then nothing can say: **accepted** |
| A key id used again after a removal cut the first, stopping a device in the replay recovery reads, so current words fail or a device bricks itself | **Fixed.** What counts now is read first, and each view is held to its own record. `a_space_rescued_under_its_old_id_does_not_stop_the_device_in_the_replay_recovery_reads`, `new_words_recover_a_vault_after_a_rescue`, `the_same_words_recover_what_was_written_after_a_later_rotation`, `a_generation_re_issued_after_a_cut_does_not_stop_the_device_either`, `one_junk_orphan_does_not_cost_a_device_its_newest_keys`, `removing_the_junk_writer_does_not_brick_the_device_doing_it`, `one_bad_device_alone_cannot_brick_an_honest_one` |
| Anyone who can write to a folder forges a removed device's log around the one real entry its removal names, to replace a device's copy | **Fixed.** One hash proves nothing, so the whole of it has to replay. `a_forged_copy_of_a_removed_device_s_log_is_neither_taken_nor_spread`, `a_forged_copy_of_a_removed_first_device_s_log_breaks_nothing` |
| A removed device goes on writing, so the only copy left runs past its removal, and a device behind on it is left with nothing | **Fixed.** A log is taken up to what its removal kept, and the rest is reported. `a_device_behind_on_a_removed_log_takes_what_its_removal_kept_from_a_copy_that_holds_more`, `a_device_behind_on_a_removed_first_device_is_not_left_with_an_empty_vault` |
| A removal cuts entries the remover had not seen, and a device that built on them loses that work, with no attacker needed | **Fixed** for what any device still in the vault wrote: any of them writes it again, edits included, reaching for any key that was cut too, through a link or the words. `a_device_gets_back_what_it_built_on_a_tail_a_removal_cut`, `removing_a_lost_device_leaves_what_another_device_put_in_its_space`, `an_edit_on_a_cut_key_comes_back`, `what_was_written_under_a_cut_generation_comes_back_too`, `what_a_later_device_wrote_under_a_key_it_reached_by_a_link_comes_back`, `what_a_lost_device_built_on_a_cut_tail_comes_back_through_the_words`, `what_a_device_wrote_before_its_removal_is_not_lost_with_it`. What a removed device wrote past its cut stays cut, because nothing can tell that from what it writes after being stolen. A peer that already held it can still get it out: an export includes it, marked as cut. `what_a_lost_device_wrote_and_a_peer_holds_is_not_lost_to_a_removal_that_had_not_seen_it`. A value put right before a newer edit is heard counts as newer: **accepted**, the edit stays in history, and it needs a device hiding a tail from the remover |
| A device removed while it was offline cannot reach what it wrote | **Fixed.** An export from it holds everything in its logs. `a_device_removed_while_offline_can_still_take_out_what_it_wrote`, `an_export_from_a_removed_device_holds_what_it_wrote_under_a_generation_it_made_after_the_cut` |
| A device enrolled in a race loses, by a stronger branch or two restores at once, and merges itself out of the vault | **Fixed.** A device keeps the history it is in. `p8_a_removed_device_can_still_open_and_take_out_what_it_wrote`, `a_paired_device_never_merges_itself_out_of_the_vault`, `a_planted_file_does_not_merge_a_paired_device_out_of_the_vault`. The one left out keeps working and is told, and the others refuse its log. `a_device_left_out_of_a_race_keeps_its_work_and_says_so`. It cannot rejoin as it is: **accepted**, its person exports, recovers again and imports |
| A new machine recovers from a folder that was rolled back | **Accepted.** It holds no high-water mark, so it trusts the copy it is given, and if that goes back past a removal, the removed device is back on that machine, with nothing to show it, until it hears from a live device. Words that were rotated away do not open a newer copy. Live devices refuse what it then writes, and report the conflict |
| Retired words reach a device that missed their retirement, enrolling a device of their own | **Fixed** for what matters: the real vault has more behind it, so when it arrives it wins, and the planted device is out. `a_device_that_missed_a_rotation_still_takes_the_real_vault_after_retired_words_reach_it`. Until then the device cannot tell, and wraps its keys to what it was shown, as it would for anyone: **accepted**, those words could already read that |
| Someone stops a device hearing from the others, so it never learns of a removal | **Accepted.** Nothing in a log can prevent it. `status` shows when each device was last heard from, so it can be seen. `status_says_when_each_device_was_last_heard_from` |
| A small log makes every replay slow for good | **Fixed.** Replay no longer goes quadratic in the versions of one item, or in a chain of roster changes. `versions_of_an_item_stay_in_clock_order_whatever_order_they_arrive`, and by hand `how_replay_grows_with_a_chain_of_roster_changes` and `one_long_chain` |
| A log grows past what a folder keeps, so a backup drops it, the roster with it, and the owner's words fail | **Fixed.** A log that long is refused when offered, while the device that wrote it can still be removed. `a_log_grown_past_what_a_folder_reads_does_not_turn_the_owner_s_words_away`, by hand, since it writes more than 1 GiB |
| An enrolled device writes huge entries, or a merge holds the broker while it replays a large log | **Accepted.** Replay costs what a log weighs, more where signed side branches are wide, which takes two keys, and an enrolled device holds every key anyway. Removal stops it growing, not what it already wrote: entries it kept stay in every log. Past 1 GiB in all, a new device cannot pair and has to recover from a copy |
| Junk wrapped to a device costs a key agreement per wrap at every unlock | **Fixed** once its writer is removed: what a removed device wrote is tried last and only so far, unless something is lost and needs it. `junk_a_removed_device_left_does_not_push_out_the_wrap_b_needs`, `a_removed_device_cannot_lift_the_limit_on_what_it_left_with_one_orphan`. While it is enrolled it is **accepted**, and removal ends it |
| A device locks another at will, ending every grant and run, and interrupting its own removal | **Fixed** down to once a day per device. A new generation alone is no reason to lock, except that honest devices racing each other need one. `a_device_can_lock_another_with_a_new_generation_once_and_no_more` |
| An enrolled device writes an audit event that blames a caller it invented | **Accepted.** The log proves which device wrote the event, and the name inside is that device's word. An enrolled device can read everything anyway |
| A quantum computer forges log signatures, which are Ed25519 alone, or reads the Noise transport, which is X25519 | **Accepted.** A forger could write a device's ordinary entries, and removal ends it. A roster change also needs hybrid approvals, so it could not change who is in the vault. The transport carries only what is already hybrid-wrapped |
| Someone without a device's key damages a log so that replay trusts more than checking every signature would | **Fixed.** A good signature on a chain's last entry covers all of it, and anything else gets a check per entry. `without_the_key_no_damage_tells_vouching_from_checking_every_signature` |
| A device's key holder leaves a bad signature behind a good one | **Accepted.** Replay does not notice, and it gains nothing: the good signature after it covers that entry, so its author signed it anyway. `a_key_holder_gains_nothing_from_a_bad_signature_behind_a_good_one` |
| A list shows a row the log no longer agrees with | **Fixed.** Rows are stamped with the state and keys they were read with, and every replay and applied entry makes a new state, so a mismatch discards them. `rows_stay_true_through_every_kind_of_change` |
| A hostile device plants an address for every device to call, or a website learns which accounts a device holds | **Fixed.** A site's icon is saved once by the device adding the login and synced as an encrypted item, so other devices make no request at all. Nothing uses a third-party icon service, and no device ever fetches an address it did not add. `another_device_gets_the_icon_without_asking_the_site` |
| An enrolled device or a website writes an icon built to exploit an image decoder | **Fixed.** No platform decoder sees an icon. The broker reads only the fixed PNG header. `Client` decodes in safe Rust, whose PNG parser and inflate forbid unsafe code, and interfaces get plain pixels, which take no parsing to draw. A website's image is redrawn at a small size before it is saved, so nothing else it carried reaches the vault. What cannot be decoded is no icon. `nothing_hostile_gets_past_being_no_icon` |
| Item names, usernames and sites stay in the broker's memory while the vault is unlocked | **Accepted.** They sit beside keys that open them and everything else, so reading that memory already gets more. They are wiped when the vault locks. `locking_takes_the_rows_with_it` |

### Peer sync

Attacker: anyone on the local network, or an enrolled device gone bad.

| Threat | Status |
|---|---|
| A machine in the middle of pairing, in any order of moves, including forwarding one side's values to the other | **Held** at one guess in 2^33 per attempt. `no_order_of_moves_beats_one_guess` plays every schedule through the real commitment and word functions, cut to six bits, and `without_the_commitment_the_same_attacker_always_wins` shows it would see a break. It assumes SHA-256 binds and Noise separates sessions |
| A man in the middle retries on the joining device, reading its value and hanging up until the words match | **Fixed.** Once a commitment has arrived, a failure ends the join, visibly. `a_man_in_the_middle_who_hangs_up_after_a_commitment_ends_the_join`, `a_join_gives_up_on_time_however_many_strangers_keep_connecting` |
| A person approves a pairing without comparing | **Partly fixed.** The words are in the touch itself, so an agent starting a pairing cannot get a bare approval. `adding_a_device_shows_the_words_at_the_moment_of_the_touch`. Comparing them stays the person's job |
| An enrolled key that is not the one the words vouched for, or a vault from a device not in it | **Fixed.** `what_is_enrolled_must_be_the_key_on_this_connection`, `a_vault_must_come_from_a_device_in_it`. A new device finds itself in what it is sent, whatever else is in there: `a_new_device_finds_itself_in_what_it_was_sent_whatever_else_is_in_there` |
| A stranger ends a join by connecting first | **Fixed.** `a_stranger_connecting_first_does_not_end_a_join`. A stranger who sends a commitment and hangs up does end it, and that is deliberate, because retrying would hand a man in the middle more guesses: **accepted**, and a stranger answering every beacon can hold up a join the same way on a hostile network, so use an address |
| Following a device by its beacons, or counting the devices in a vault | **Fixed.** Each has a fresh nonce and one tag per peer, from what the two sync keys agree, padded so the count does not show. `nothing_in_a_beacon_repeats_so_it_cannot_be_followed`, `a_peer_recognizes_a_beacon_and_nobody_else_does`, `a_beacon_does_not_say_how_many_devices_a_vault_has`. An address and a port are the network's to show: **accepted** |
| A recorded beacon sent again, to point a device somewhere | **Fixed.** A tag covers the port and the time, and lasts about twenty minutes at most. An address stays known only once a real device answers there. `a_beacon_cannot_be_pointed_at_another_port_or_kept_for_long` |
| A stranger reads a device's static key from the handshake | **Fixed.** The handshake is keyed from the vault. `a_stranger_gets_nothing_from_a_device_s_handshake`. Anyone holding a copy of the logs has that key, and the static key is in those logs: **accepted** |
| A stranger holds threads with a slow handshake, floods connections, drips a message, or claims a huge one | **Fixed.** `a_handshake_sent_a_byte_at_a_time_is_cut_off`, `a_flood_of_connections_is_turned_away_at_the_door`, `a_session_ends_when_its_time_is_up`, `empty_frames_cannot_keep_a_message_open`, `a_message_past_its_limit_is_refused_before_it_is_read`. A stranger who keeps reconnecting can hold all sixteen slots for as long as it stays on the network, which stops sync and second approvals, and the words still work: **accepted** |
| A device holds up its own removal by dripping bytes, or balloons memory by repeating a log in a message | **Fixed.** A removal does not ask that device, and everything before it is over in seconds. A log sent twice is refused. `a_log_sent_twice_is_refused_before_it_costs_anything` |
| Addresses a person gave never sync in the background, so a removal reaches nobody where multicast is missing | **Fixed.** They are tried on every beat. `an_address_a_person_gave_keeps_devices_current_with_no_beacons` |
| A stranger who goes silent holds a join past its time | **Fixed.** `a_stranger_who_goes_silent_does_not_hold_a_join_past_its_time`. A handshake can still run ten seconds over |
| A session opened before a removal goes on after it | **Accepted.** It ends within twenty minutes, and what it receives is the tail of logs it cannot open |
| A replayed beacon makes a device dial whoever sent it | **Accepted.** A dial trusts nothing, so this costs time on the network and no more |
| An enrolled device holds a sync open, and with it the next one | **Fixed** to five minutes at most, and nothing is sent once a session is over. `nothing_goes_out_once_the_session_is_over`. Within that, **accepted**: such a device is one to remove, and a removal waits on it for ten seconds at most |
| A beacon's port links a device across networks for as long as the broker runs | **Accepted.** The tags change each time. Moving the port would cost more in lost addresses than it hides |
| A low-order key at pairing, or the Noise key also used for discovery | **Accepted.** No attack found. A low-order key weakens only the channel of the device that chose it, past the words, and discovery refuses such a key and hashes under its own label |
| A hostile device gets an honest one blamed for a contradiction | **Fixed** in what is said: it says a copy contradicts, not that the device offered it |
| A vault past 64 MiB can neither pair nor sync | **Fixed.** `logs_past_the_old_limit_still_sync` |
| Two histories of one length pass as the same log, so a fork is never seen | **Fixed.** Lengths are compared with a hash, and a fork is sent whole. `two_histories_of_the_same_length_are_not_mistaken_for_one` |
| Logs for invented devices, kept and relayed, or costing a replay each | **Fixed.** Nobody's log is kept unless its device was approved, on a new machine too, and a sync takes a limited number of new ones. `a_log_from_a_device_nobody_approved_is_refused_and_not_kept`, `logs_from_invented_devices_cost_one_sync_a_limited_amount`, `p5b_recovery_keeps_no_log_from_a_device_nobody_approved_and_a_file_cannot_then_stop_a_folder` |
| One file in a folder that no replay takes stops every merge with that folder | **Fixed.** It is refused on its own. `p5_a_file_in_a_folder_does_not_stop_every_sync_with_it` |
| A refused change stops being reported once anything else arrives | **Fixed** until a restart, after which the next copy of that log reports it again. `p6_a_refused_removal_stays_on_the_list_of_problems` |
| A device that settled against its own removal removes again, and stops its own log for good | **Fixed.** A new generation is numbered above every one on record. `p1_a_device_that_settled_against_its_removal_can_remove_again`, `p1b_after_that_a_still_writes_and_its_earlier_work_still_reaches_the_others` |
| What a lost removal made is handed to a device added later, or a device added later cannot read what only such a generation reaches | **Fixed.** It gets what lies behind instead. `p10_what_a_lost_removal_made_goes_to_nobody_else`, `a_device_with_no_keys_yet_reads_the_oldest_items_when_only_a_set_apart_generation_reaches_them` |
| An edit that won a tie on the clock, under a key a removal cut, gives way to the edit it beat | **Fixed.** `an_edit_that_won_at_the_same_moment_under_a_cut_key_is_given_back` |
| Reading anything from a peer before knowing who it is | **Held.** Only the handshake comes first, and the roster check precedes the first message. `a_stranger_on_the_port_gets_nothing_and_breaks_nothing` |
| Someone who reads a server's files, or its memory, takes its keys | **Accepted.** They hold what the server was given, its chosen spaces or the whole vault, and removing the server from another device rotates the keys. That is why a server is opt-in at join and named in the device list |
| Whoever takes a server reads past the spaces it was given | **Fixed.** It is wrapped no epoch key, only versions of its own spaces, and a wrap of another space to it, or to anything but a server holding that space, is passed over. `a_server_holding_chosen_spaces_opens_them_alone`, `a_server_keeps_its_spaces_through_a_rotation_and_is_given_nothing_else`, `a_space_s_key_is_given_only_to_a_server_holding_that_space` |
| A server, or whoever holds its key file, signs a roster change, as the second device or at a fork | **Fixed.** Replay never counts it. `a_server_s_signature_never_counts_toward_a_roster_change`, `a_change_a_server_signed_as_the_second_device_counts_on_no_copy`, `a_server_s_signature_does_not_win_a_fork`, `a_server_cannot_remove_a_device_on_its_own_say`, `a_server_has_no_say_in_what_needs_two_devices` |
| A server, or whoever holds it, approves something with nobody there | **Fixed.** Its keys open the vault and do nothing else: every approval on a server refuses, its own and any another device asks for. `a_server_opens_its_keys_by_itself_and_approves_nothing`, `nothing_on_a_server_stands_in_for_a_person`, `a_server_opens_its_vault_by_itself_and_its_agent_gets_a_grant_from_another_device` |
| A same-user process reads `sync.key`, which is in the clear so sync can run while locked | **Accepted.** It can impersonate this device to peers, which gets it ciphertext it can already read, and lets it ask for approvals, which name the truth and need a person |
| A device asks another to approve a removal under a false name, or to keep too much or too little of the log, reuses an old request, or wears a person down with prompts | **Fixed.** The name and count come from this device's own roster, and prompts come one at a time with a pause after a refusal. `a_prompt_names_the_device_this_vault_says_it_is`, `a_removal_must_keep_exactly_what_this_device_holds`, `a_request_from_before_a_roster_change_is_out_of_date`, `prompts_for_other_devices_come_one_at_a_time`, `a_refusal_holds_off_the_next_prompt` |
| The device being removed ends the search for a second approval by answering first | **Fixed.** `only_another_enrolled_device_can_give_a_second_approval` |
| A request from another device opens a locked vault | **Fixed.** `a_request_from_another_device_cannot_open_a_locked_vault` |
| A device asks another to approve adding a device, under a name it chose | **Accepted.** Nothing on the second device can check the name. The person has to have started it |
| A record holding another device's keys is approved, so that device stops finding itself | **Fixed.** `a_record_with_another_device_s_keys_is_not_enrolled` |
| A record nothing can be wrapped to is approved, so every rotation stops | **Fixed.** `a_device_record_with_a_key_nobody_can_wrap_to_does_not_stop_every_rotation` |
| The connection drops at the last step of pairing, leaving a device enrolled that never got the vault | **Accepted.** It holds nothing, and it can be removed: by a second device, or the words if it is the only other one |

| The relay reads or changes what it carries | **Held.** It carries the same Noise channel as an address, keyed from the vault, so it can drop or delay and nothing more. `devices_that_share_no_network_stay_current_through_a_relay`, `a_person_can_approve_on_a_device_that_is_only_reachable_through_a_relay` |
| The relay, or anyone watching it, learns which devices make up a vault, or follows one from period to period | **Fixed** for tags: only the pair can compute one, they change every ten minutes, and padding hides the count. `only_a_peer_knows_where_a_device_waits_at_a_relay`. The address of a device's waiting connection, and its timing, are the network's to show: **accepted** |
| Someone answers a dial meant for another device | **Fixed.** Only the connection told of a dial gets its random id. `only_the_waiting_device_can_take_a_dial`. Someone who computes a device's tag, which takes one of the pair's sync keys, can wait under it in its place: that stops sync through the relay, and the handshake still fails for them: **accepted** |
| An agent's reason talks a person into a grant | **Fixed** as far as words can be. The device that asks, the agent, the space and how long come first, from the vault, and the reason after them, quoted as the agent's, with quotes and control characters taken out and cut at 160 characters, so it can add to the facts but never replace or push them out. `an_agent_s_reason_comes_after_the_facts_as_its_own_words_and_cannot_push_them_out`, `an_agent_s_grant_is_approved_on_another_device_which_shows_the_facts_then_its_reason`. A person who approves without reading is not: **accepted** |
| A device asking for a grant names a space other than the one it means | **Fixed** where the answering device can read its spaces: it refuses a name that does not match the id it signs. `a_device_that_can_read_its_spaces_refuses_a_grant_that_names_one_wrongly`. A locked device shows the asker's word for the space and itself: **accepted**, because the asker holds the vault and could use that space anyway. The approval signs the whole request and who asked. `a_grant_reads_back_as_sent_and_its_approval_covers_every_word` |
| A prompt answered on another device stays up, and a late touch there seems to do something, or it holds that device's next prompt off as a refusal | **Fixed.** `the_first_device_to_approve_wins_and_the_others_are_called_off` |
| The relay, or the account service, ties a device's traffic to the account that paid | **Fixed.** A pass is signed blind, and nothing in it names the account. `a_paid_account_s_devices_meet_at_a_relay_that_asks_for_passes`. The account service could give one person a key of their own, to tell their passes apart: a device checks the root vouched for the key, not that everyone has it: **accepted**, it is Vaulte's own service |
| A relay lets in someone who has not paid, or a pass from another key, month or message | **Fixed.** `an_account_that_has_not_paid_gets_nothing_through`, `a_relay_that_asks_for_passes_lets_in_only_this_month_s`, `a_pass_is_good_only_as_it_was_signed`, `a_pass_from_a_key_the_root_vouched_for_this_month_is_good` |
| A pass is handed around | **Fixed** to 32 connections a pass at once, for a month at most. `one_pass_holds_only_so_many_connections` |
| Someone guesses account numbers | **Accepted.** Sixteen digits is about 53 bits, and the account service takes 20 requests a minute from an address. Cloudflare's limiter is loose by design: a burst of 150 had 13 refused (**tested**), so it slows a guesser rather than stops one |
| Someone who cancels keeps using the relay | **Accepted.** Until their month ends, which they paid for |
| A stranger floods the relay | **Accepted** for a relay that asks for no pass. It stops new connections past 4,096, which stops sync through it, and addresses and folders still work. One that asks for passes turns a stranger away after its first message |

Discovery runs in tests over loopback as well as multicast, so everything past the socket is exercised on any machine. `the_network_path_itself` says plainly if the multicast socket itself was not.

### Sharing

**Not built.** Flow 17 is a design. An interface must not offer it until a build meets all of this. Three things in the existing design rule out the obvious build:

- Roster membership is all or nothing: every device gets every epoch key, so a recipient cannot be enrolled.
- A log holds every space's random ids, sizes and timing, so handing someone logs shows them the shape of the rest of the vault.
- Any two devices can change the roster, so a recipient with two devices could otherwise add and remove people.

A shared space is therefore **its own vault**, with its own first entry, roster, logs and epochs, and a person's vault holds only a reference to it. Sync, rollback, audit and rotation then come with it, and nothing about a personal vault's replay changes. Rejected: per-space wraps in one log, which leak that shape and put an access list into every replay rule.

| What a build must guarantee | Why |
|---|---|
| Owners alone change a shared roster, by a rule replay enforces, and the recovery key stays the owner's | The two-device rule assumes one person |
| A recipient's id is checked out of band, by the three words nearby, and remotely by a fingerprint of at least 128 bits compared by a person | A pasted id is whatever the paste says |
| Every share is signed by the sender's hybrid keys over a digest with its own domain, naming sender, recipient, vault, item and version | Anyone can encrypt to a public key, so a wrap alone says nothing about who sent it |
| Sharing is the person's alone, a touch naming the recipient and what is shared, each time. It never works through a session, and it is audited | It hands plaintext to someone else, like `reveal` |
| A shared item arrives labelled as shared and never merges into a personal space | A sharer could otherwise plant a login for `github.com` to shadow the real one |
| Hosts and sites on an arriving item take effect only after the recipient approves them with a touch | A sharer chooses where a secret may go |
| What arrives is checked as any outside input, with `item::validate` | A name can spoof a terminal, and a variable name can change how a program runs |
| Pasted ciphertext names nothing in the clear, sizes included to a bucket, and expires | It is safe to paste only if it says nothing |

**Revocation.** Stopping sharing a space removes the recipient and rotates its keys, so they read nothing written afterwards. It is the same machinery as removing a device, with the same cutoff.

**What a former recipient keeps.** Everything they could read: every value and every older version, for ever. Rotation cannot un-read it, so stopping lists what they saw, as `remove_device` does, and those secrets have to be changed where they are used. A shared single item is a copy, so it has no revocation at all, and the interface must say so before the touch.

### Servers, and approvals from anywhere

**Mostly built.** A person gives a server, such as a VPS running agents, what it needs, and approves
anything more from whichever device is at hand, without opening a shell on it. What an approval
releases to a server beyond a grant is not built.

- **What a server holds.** The person chooses when adding it: the whole vault, or only the spaces
  they name (`vlt device add --spaces Agents`). A server is the easiest device to break into, so
  losing one that holds chosen spaces costs those spaces and nothing else. It joins through its own
  roster entry, which its approvers sign naming what it holds, so nothing can widen it later. It is
  wrapped no epoch key. A device with one wraps it every version of each of its spaces, with the
  space's name sealed under that version's key, and wraps it each new version as rotations make
  them, so it reads what was written under any of them and writes under the newest clean one. It
  waits for that wrap after a rotation, writing nothing under a key that is no longer clean. An item
  can stand in more than one space as a copy under each space's key, so a space for agents holds
  only what agents use. Rejected: a vault of its own per space, the [sharing](#sharing) shape, which
  would have every device hold several vaults. A server is the person's own machine, so it holds
  every log, and the shape of the rest of the vault, ids, sizes and timing, reaches it: **accepted**.
  A device that holds an epoch key can wrap it a key that is not the space's, and the server would
  write what nobody else opens: **accepted**, as such a device holds every key anyway.
- **No say.** A server has no say in the roster, whatever it holds, because its keys sit in a file.
  Replay never counts it: not toward the two devices a change needs, not as an approval, and not as
  a signer where history forks. A laptop and a server are one person's device, so the laptop acts
  alone as it would by itself.
- **Unattended.** A server has no touch and nobody to type a passphrase. Its device key sits in a
  file only the service user can read, so whoever holds that machine holds what it was given, and
  removing it from another device rotates every key. Built as a kind of device: `vlt init --join --server`
  keeps its keys sealed under a random secret stored beside them, so its vault opens by itself,
  after a restart too, and never locks on its own, which would only end its agents' grants. The
  one thing its keys do unasked is open the vault. Every approval refuses, its own and any another
  device asks it for, so a server never counts as a person, and what it needs comes from a device
  that has one. One holding chosen spaces keeps no audit of its own, which needs an epoch key.
- **Asking.** An agent asks for something outside what the server holds, with a reason in its own
  words. The ask goes to every device at once, through the relay where needed, and the first person
  to approve answers it; the others are told and clear their prompt. Built for a grant (`vlt grant
  --why`): the asking device prompts too, the first approval that verifies counts, a refusal there
  ends it, and a refusal anywhere else takes out only that device. The asker hangs up on the rest,
  each sees it within a tenth of a second and its prompt goes away, Touch ID included (**tested** by
  hand, `a_prompt_goes_away_when_the_person_answered_elsewhere`), and that does not count as a
  refusal. Second approvals for adding and removing devices and plaintext exports ask the same way. The prompt states the facts
  from the vault first, which server, which agent, which item, which site and for how long, and the
  agent's reason after them as a quote, because an agent can be talked into lying. An approval
  signs that exact ask, and what it releases goes to the server sealed to its key, for that one use.
- **Waking a phone.** iOS lets an app listen only while it is open, and only the app's developer can
  wake it, through Apple's push service. So the relay sends a push holding ciphertext alone, which
  the phone opens on the device with a notification key that needs no touch. Apple and the relay
  see a device token, a time and a size. A Mac, Linux or Windows device keeps its relay connection
  open and needs no push.
- **Managing a device from another.** A server has no screen, so its settings, the spaces it holds
  and its grants are changed from another device over the same channel, each change approved there.

### Agent retrieval

Attacker: a hostile agent holding a session, or running as this user with none, a hostile page, or a server it can reach. The promise is that an agent can use a secret but never read it.

| Threat | Status |
|---|---|
| A proxied secret comes back in a response header, a `Location`, a cookie, a trailer or the status line | **Fixed.** `a_secret_reflected_in_response_headers_is_hidden`, `a_secret_reflected_in_a_trailer_is_hidden`, `a_secret_reflected_in_the_status_line_is_hidden` |
| It comes back in hex, percent, HTML or JSON escaping, or base64 at any offset | **Fixed.** `a_secret_reflected_in_a_common_encoding_is_hidden` |
| A secret whose end begins it again slips past the scrubber at the end of a chunk | **Fixed**, found by the fuzzer. `a_secret_whose_end_starts_it_again_is_hidden_wherever_a_chunk_ends`, `a_secret_that_ends_with_its_first_byte_is_hidden_at_the_end_of_a_chunk` |
| A compressed reply, or an upgraded connection, goes past the scrubber unread | **Fixed.** Refused, with or without a secret in the request. `a_reply_the_scrubber_cannot_read_never_reaches_the_program`, `a_connection_upgraded_after_carrying_a_secret_is_refused`, `nothing_can_be_upgraded_past_the_scrubber_even_with_no_secret_in_the_request` |
| A reflection is read in slices, too small for the scrubber to see a secret | **Fixed.** `Range` is never passed on, so a value stored by an earlier request does not come back in pieces either. `a_range_request_cannot_read_a_reflection_in_pieces`, `a_range_is_never_passed_on_because_a_kept_secret_could_come_back_in_slices` |
| A program puts a placeholder wherever an allowed server keeps or returns a value, such as a URL or an ordinary header, and reads it back outside the proxy | **Fixed.** A secret goes only in a credential header. `a_placeholder_in_a_url_stays_a_placeholder`, `a_placeholder_in_an_ordinary_header_stays_a_placeholder`, `a_placeholder_in_a_header_made_for_a_key_is_filled_in`. A server that stores a credential header and returns it transformed is the next row |
| A `Host` header, a routing header or a full URL sends the secret to another site on the same server or CDN | **Fixed.** `a_host_header_cannot_send_a_secret_to_another_site_on_the_same_server`, `a_routing_header_cannot_send_a_request_somewhere_else`, `an_absolute_request_line_cannot_send_a_secret_to_another_site` |
| A server you allowed stores a secret and returns it transformed, or sends it on | **Accepted.** Scrubbing catches echoes, not intent, so the real boundary is which hosts you allow |
| A placeholder sent to another host, another port, or as plain HTTP | **Held.** `a_placeholder_for_another_host_stays_a_placeholder`. Only port 443 is intercepted, and `HTTP_PROXY` is unset |
| A program keeps using a secret after its grant ends or the vault locks | **Fixed.** The proxy stops and erases its secrets. `locking_ends_a_running_program_s_access`, `revoking_a_grant_ends_a_running_program_s_access`, `an_expired_grant_ends_a_running_program_s_access` |
| A grant or a lock timer stops counting while the machine sleeps | **Fixed.** `Instant` stops on Apple platforms (**documented** in the Rust source). `a_grant_ends_by_the_clock_on_the_wall`, `a_vault_locks_by_the_clock_however_long_the_machine_slept` |
| A lock is undone by a touch already under way, a late fill, or a prompt that was waiting | **Fixed.** A lock always wins. `a_lock_during_a_touch_wins`, `a_lock_during_a_fill_touch_wins`, `a_lock_during_an_unlock_prompt_wins`, `a_fill_never_opens_a_locked_vault` |
| A variable stored free of charge changes what runs in a program that holds real values, such as `LD_PRELOAD` or `NODE_OPTIONS` | **Fixed.** `a_variable_that_changes_how_programs_run_cannot_be_stored` |
| A touch hides what it approves: a count instead of names, no destination, a long host pushed out of the prompt, or a host that only looks like another | **Fixed.** `a_touch_for_real_values_names_them`, `a_touch_says_where_things_go`, `two_long_names_that_differ_at_the_end_look_different`, `a_long_host_cannot_push_its_real_owner_out_of_a_prompt`, `a_host_cannot_look_like_another_in_a_prompt` |
| A touch for real values goes to something other than the program it names | **Accepted** until callers can be signed. The command is the caller's word, and values go back to the caller, where `Client` scrubs the output and a hostile caller would not. So the prompt names the values, and a touch means giving them to whatever asked |
| One environment variable picks the program that is typed the password | **Fixed.** There is no such setting, and a broker takes nothing from whoever started it. `a_browser_named_in_the_environment_is_never_given_a_password`, `a_broker_takes_nothing_from_the_environment_of_whoever_started_it` |
| Chrome itself is replaced with a program that collects passwords | **Fixed** on macOS, where this user can write to `/Applications`. `a_program_pretending_to_be_a_browser_is_not_trusted`. Any app signed through Apple at that path passes, and the check runs before launch and looks at the bundle, not every library in it: **accepted**, because that is a signed, revocable identity, and a process that can change those files already runs as this user. Linux checks only that the file exists |
| A page lies about its address, by replacing what the origin check calls | **Fixed**, shown leaking a password to a real Chrome. The address comes from the browser, and fields are found from a world no page script can reach. `a_page_cannot_talk_its_way_past_the_origin_check` |
| A frame from another site takes focus on a saved login page, and receives what is typed | **Fixed**, shown leaking a password to a real Chrome. A value goes by reference to the field that was checked, and is never typed. `a_frame_from_another_site_that_takes_focus_gets_nothing` |
| A sign-in goes on after a lock or the end of a grant | **Fixed.** Each step asks, and so does the hand-over. `a_lock_stops_a_sign_in_that_has_started`, `ending_a_grant_stops_a_sign_in_that_has_started` |
| A sign-in hands over other sites' cookies, or a cookie holding the password | **Fixed.** `a_cookie_holding_the_password_is_not_handed_over` |
| A page moves in the moment between the origin check and typing | **Held** for the timings tried, against a page that does catch typing. `a_page_that_moves_as_its_field_is_focused_gets_nothing_typed_at_its_destination`, `a_page_that_moves_just_after_settling_gets_nothing_typed_at_its_destination`, `the_page_those_attacks_aim_for_catches_what_is_typed`. The window is one call to the browser, and a page that moves takes the isolated world with it. It is a race, so this shows it is hard, not that it is impossible, and only a page on the saved site can start it |
| A site's subdomain receives its login | **Accepted.** Sign-ins move between subdomains, and every manager allows this. A tenant under a saved host can receive it, so save the narrowest host |
| A login saved on a suffix many sites share, such as `github.io` or `co.uk`, fills on all of them | **Fixed.** Only a host the public suffix list says is one site's own matches what lies under it, the list passkeys need anyway. `a_suffix_many_sites_share_matches_none_of_them` |
| A login saved for plain HTTP on this machine goes to whatever holds that port | **Accepted.** It is for development, and a session could already reach anything on this machine |
| A session asks to fill, or learns what exists from the refusal | **Fixed.** `a_refused_fill_says_nothing_about_what_exists_and_raises_no_prompt` |
| Anything but a login or a card is filled | **Fixed.** `only_logins_and_cards_can_be_filled` |
| A caller claims the origin of a fill | **Accepted** for now. The broker cannot verify its caller, so every fill takes a touch naming the page. Signed releases can check the caller |
| A session stops the broker, ending every grant, or locks everyone out | **Fixed.** `a_session_cannot_stop_the_broker`, `a_session_cannot_lock_everyone_out`, `a_dead_token_cannot_stop_the_broker` |
| An agent's browser address redirects the session elsewhere, or floods the broker | **Fixed.** `a_debugger_address_must_be_the_one_that_was_asked`, `an_endless_reply_from_a_debugger_address_is_cut_off` |
| A sign-in that fails partway leaves no record, with a password typed | **Fixed.** `a_refused_password_is_tried_once` |
| A password goes out for a session with nowhere to go | **Fixed.** The destination is checked before anything else. `a_session_with_nowhere_to_go_stops_before_the_password_goes_out` |
| A refused sign-in is reported as a success | **Fixed** when the site gave no cookies. `a_site_that_gives_no_session_was_not_signed_in_to`. A refusal that sets a cookie still reads as a success: **accepted**, because no general test tells them apart, nothing secret moves because of it, and the caller's first request shows it |
| A caller hangs up during a sign-in, and it goes on | **Accepted.** A person approved it, and a lock or the end of a grant still stops it |
| A page fills the broker's memory through the debugging pipe | **Fixed.** `a_message_past_the_limit_ends_the_conversation` |
| A caller's URL means one thing to a browser and another to the prompt | **Fixed** for backslashes. `a_backslash_ends_the_host_as_it_does_in_a_browser`. Other oddities match nothing, and a caller could name any page anyway |
| A saved two-factor seed gives wrong codes, so a sign-in fails or a setting is lost | **Fixed.** `a_setting_counts_however_it_is_capitalised`, `what_would_give_wrong_codes_is_refused` |
| A same-user process reads a session's cookies from the browser profile during a login | **Accepted.** Cookies only, in a private folder, for as long as the login takes, and a killed broker's profile goes at its next start. Such a process could use the session token anyway |
| A software vault stays open to anyone once it has been opened, because nothing stands in for a touch | **Fixed.** Every approval takes the passphrase, and the broker keeps none. `every_approval_on_a_software_vault_takes_the_passphrase_even_when_it_is_open`, `a_locked_software_vault_opens_for_nobody_without_its_passphrase`, `a_broker_never_holds_a_passphrase_it_was_not_just_handed`, `a_wrong_passphrase_changes_nothing_and_does_not_get_stuck` |
| Another local user reaches the socket | **Held.** The folder and socket are private, tightened at start, and the broker checks the peer's user id. `loose_permissions_on_the_run_folder_are_tightened_when_the_broker_starts`, `the_other_end_of_a_local_socket_is_known`. No test runs as a second user |
| A same-user process reads `LV_SESSION` or a placeholder from another process's environment | **Accepted** until callers can be signed. It then holds that session: it can use the space, and still cannot read a value without a touch. A token is not tied to a process, because anything tied to one would sit in the same environment |
| An agent with no token adds items, or drops its token to act as this user | **Accepted.** It can add, and anything that touches a value still needs a touch. Adding is how people use this too |
| A same-user process replaces `lvd`, injects a library into it, or sits on its socket and collects what a person types | **Accepted on source builds**, which trust their builder. **Not built** for releases, which need the hardened runtime, library validation, and `Client` checking the signature of what is on the socket |
| An agent keeps the vault from idling out by making requests | **Accepted.** The hard limit and the screen lock still hold. `use_does_not_put_off_the_hard_limit` |
| A test switch survives into a release | **Fixed.** A release build with `test-hooks` or `fuzz` does not compile |

### Not verified

On real hardware, none of this has been run since these format changes, because each needs a person's touch: creating a vault, unlocking, recovery and joining on the Secure Enclave, a touch prompt holding the three words, a junk wrap reaching the enclave, the message on a locked Mac, and a broker started with an empty environment. On Linux, the whole suite and `scripts/check.sh` pass on Debian 12 with kernel 6.12, as an ordinary user, the socket's user check included. Crash safety is tested with failed writes and torn files, not with real power loss. No auditor outside this project has reviewed any of it.

## Language and API

Rust core with Swift apps. Zig was the first choice and was dropped once the bar became "best in
class": it is pre-1.0 with no firm date, it has no TLS server in std (the proxy would need a
hand-written one), and safe Rust rules out use-after-free in code that parses untrusted network,
browser and peer data. Bitwarden and 1Password also build on Rust cores. All-Swift was rejected
as weak on Linux and Windows.

The product is Vaulty. libvault is its core, and everything else is an interface over it: `vlt`, the
desktop and mobile apps, browser extensions, the C ABI and the SDKs. An interface parses input and
draws output. If a second interface would need it, it belongs in the library, so rules cannot drift
between them. Each interface is its own repository under `sayvaulty`, created when it first exists,
and pins a version of libvault.

- `libvault`: vault, policy, broker, proxy, fill, sync, import and setup steps, plus `Client`, the
  typed API every interface calls, and every flow test. `Client` is the only way to reach a secret,
  so no interface can skip an approval. `unsafe` is denied outside `sys.rs` and the enclave bridge.
- `lvd`: the broker as a process, a one-line binary over `libvault::broker::run`.
- `vlt`: the CLI, which parses arguments and prints.
- aws-lc supplies the public-key algorithms and is the one crypto stack rustls also uses.
  XChaCha20-Poly1305 comes from RustCrypto, so random nonces are safe across devices.
- The macOS enclave needs CryptoKit for ML-KEM and ML-DSA, so `enclave/Enclave.swift` is linked
  in with a C ABI. macOS 26 or later is required for the enclave backend.

**Tested:** aws-lc wraps a key in software, the Secure Enclave opens it, and aws-lc verifies the
enclave's ECDSA and ML-DSA-87 signatures, all from one touch.

`scripts/check.sh` holds the rules that used to be advice. Run it before committing.

Neither this code nor its dependencies' current versions have had an audit commissioned for this
project. "Most secure" stays a goal until an outside auditor agrees.
