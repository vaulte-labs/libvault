# libvault flows

Every path a person or agent takes through `vlt` and the app. A flow is finished only when an
end-to-end test drives the real binary through its success path and each listed failure.

Rules that hold in every flow:

- **Nothing happens by accident.** Cancel, timeout or a crash leaves the vault as it was.
- **Secrets never travel in arguments.** They would land in shell history and `ps`. Values come
  from a hidden prompt or stdin.
- **Every change can be undone** with `vlt undo` or `vlt history`, except wiping and rotation.
- **A touch names what it approves.** The system prompt states the action and the target.
- **Errors say what happened and what to do next**, and never contain a secret.
- **Agents get `--json` everywhere** and stable exit codes:
  `0` ok, `1` error, `2` usage, `3` locked, `4` denied, `5` not found, `6` needs a person.
  An error under `--json` is `{"error", "code", "next"}`, and its code is one of `error`,
  `usage`, `locked`, `needs_passphrase` (exit `3`: ask for the passphrase and try again),
  `denied`, `not_found`, `needs_person`, `needs_host` (exit `1`) and `outdated` (exit `1`: the
  running broker is older than the program, and was not replaced).

## 1. Onboarding

`vlt init`, or opening the app for the first time.

| Step | What happens |
|---|---|
| 1 | Finds secure hardware. Reports it in one line. |
| 2 | Creates enclave keys. No touch is needed to generate them. |
| 3 | Shows the 24-word recovery key once. |
| 4 | Asks for three of the words, chosen at random, proving it was written down. |
| 5 | Touch to create the vault. All files are written atomically here, and not before. |
| 6 | Creates the `Personal` space. States what is not yet protected: "Losing this Mac loses this vault. Add a device or a backup." |

| Failure | Result |
|---|---|
| No terminal | Exit `6`. Setup needs a person. |
| A vault already exists | Stops and changes nothing. There is no overwrite path. |
| Wrong confirmation word | Ask again. The key is not reshown unless requested. |
| Touch cancelled, or killed at any step | Nothing was written. Run it again. |
| No secure hardware | Says so, and offers a passphrase-protected software vault, marked weaker in `vlt status`. |

## 2. Unlock and lock

| Step | What happens |
|---|---|
| 1 | The first command needing keys prompts one touch. One touch covers all enclave keys (tested). |
| 2 | The broker holds keys until the vault has gone unused for as long as this device's person chose, the screen locks if they chose that too, or `vlt lock`. Time asleep counts. Quitting an app does not lock. Restarting always does, because the keys are only ever in memory. |

Each device chooses for itself, because a phone and a desktop want different things and a stolen
device's choice must not reach the others: stay unlocked 5 minutes, 10 minutes, 1 hour (the
default), 2 hours or never, and lock with the screen (on by default). Changing it takes a touch,
and no agent can.

| Failure | Result |
|---|---|
| Touch cancelled | Exit `4`: "Cancelled. Nothing changed." |
| No person around, agent waiting | Exit `3` after the prompt times out. |
| Fingerprint re-enrolled | Still works; `.userPresence` is not tied to enrolled fingers. |
| Broker crashes | Keys are gone with it. Next command restarts it and prompts again. |
| Locked while a touch is waiting | The touch comes to nothing. A lock always wins. |
| Mac is locked when the enclave is asked | "This Mac is locked. Unlock it and try again." |
| Software vault | Every approval asks for the passphrase, even while the vault is open. A wrong one changes nothing. |

## 3. Add, edit, delete

`vlt add login github.com`, `vlt add card`, `vlt add env OPENAI_API_KEY`, `vlt add note`, `vlt add ssh`,
`vlt add wifi Home`, `vlt add profile Personal`.

- Values come from a hidden prompt or stdin. There are no value flags.
- `vlt add env` in a linked folder targets that space. Otherwise `--space`.
- Known keys get allowed hosts automatically (`OPENAI_API_KEY` to `api.openai.com`).
- A login's sites come from `--url`, which replaces the site a dotted name suggests.
- `--generate` saves a password for a login and 32 random bytes in hex for an env var, never
  printed. `vlt generate` prints one and saves nothing: `--length`, `--no-symbols`, `--bytes 32|64`.
- `vlt add login x --totp` asks for the two-factor setup key. `vlt code x` prints the current code,
  after a touch every time. The setup key never leaves the broker after that: a reveal gives the
  password alone, an edit that sends no key keeps it, and removing it is its own request. Only a
  plaintext export, with its second approval, carries it out.

| Failure | Result |
|---|---|
| The name exists | Stops, and says `vlt edit` changes it. An edit keeps the old version in history, keeps anything it was not given, a login's setup key included, and never changes an item's kind. |
| Empty stdin | Error. Nothing saved. |
| Agent overwrites an existing item | Needs a touch; a grant allows creating, never replacing. |
| Deleted by mistake | `vlt undo`, or `vlt history <name>` then restore. Restoring takes a touch, is a new write, and loses nothing. |
| A variable that changes how programs run (`LD_PRELOAD`, `NODE_OPTIONS`) | Refused. It would run inside anything given real values. |
| A variable name no shell takes (`my-key`, `1ABC`), or one starting `LV_` | Refused, saying which rule it breaks. `LV_` names configure Vaulte. |
| A login site that is not a web address (`javascript:`), or a setup key that makes no codes | Refused before any touch, on add, edit and import alike. An import names the row. |
| A card number that fails its checksum, or a profile detail no form takes | Refused before any touch is asked for, on add, edit and import alike. |

Spaces are named once: a name differing only by case or surrounding spaces is the same name.
`vlt space rename` keeps a space's items and grants, after a touch. `vlt space rm` removes only an
empty space, after a touch, saying what one still holds; making a space with its name again brings
it back with the history of what was deleted from it. Personal, where everything goes when no
space is named, keeps its name and stays.

One item can be in more than one space, such as a login a person also gives their agents through
an Agents space. Showing it in another space takes a touch naming both, because it widens who can
read it, and no agent can. Each space holds its own copy, sealed under that space's key, so a
device or agent holding only Agents opens that copy and nothing else. Every edit, rename and
restore writes all the copies in one entry, so they share a clock and a winner, and one undo
takes them all back. Removing it from one space leaves the others, and later changes no longer
reach that space; what it already showed has been seen, so a password should be changed. A device
must hold every space an item is in to change it.

| Failure | Result |
|---|---|
| The name is taken in the other space | Refused, and so is a rename that would clash in any space it is in. |
| An agent's session asks which other spaces hold it | Told none. |

## 4. Import

`vlt import passwords.csv` for Apple Passwords, `vlt import .env`, `vlt scan` to find `.env` files.

| Step | What happens |
|---|---|
| 1 | Parses in memory and writes nothing. |
| 2 | Previews counts only: "143 logins, 12 with 2FA, 3 already here, 2 unreadable rows (41, 97)." |
| 3 | Asks which space, then confirm. Touch. |
| 4 | Writes one batch, so `vlt undo` removes the entire import. |
| 5 | Reminds that the source is still plaintext, and offers to delete it. Default is no. |

| Failure | Result |
|---|---|
| Malformed row | Reported by row number, never by content. The rest can still import. |
| Identical existing item | Skipped and counted. |
| Same name, different value | Kept as a new item with a suffix. Nothing is overwritten. |
| Unknown format | Names the columns found. Writes nothing. |
| Non-UTF-8 or a BOM | BOM is handled. Non-UTF-8 is rejected with the row number. |
| `.env` quoting | Handles `export`, quotes, escapes, comments and multi-line values. |

`vlt scan [dir]` lists `.env` files with counts, never values, and imports the ones you pick. Each
folder is linked to a space. The plaintext file stays until you choose to delete it.

## 5. Export

No lock-in: the format is open and an export always works.

| Command | Needs | Result |
|---|---|---|
| `vlt export` | One touch | Encrypted archive, opened with the recovery key. |
| `vlt export --plaintext` | Touch, plus a second device if you have one | CSV or JSON, mode `0600`, audited. Anything a removal cut comes too, marked as cut. |

| Failure | Result |
|---|---|
| Plaintext requested to stdout (`-`) | Refused; a path is required. |
| Target exists | Refused. |
| Second device unavailable | Recovery key can stand in. |

## 6. Add a device

Enrolled device: `vlt device add`. New device: `vlt init --join`, or `vlt init --join --server` for
a machine nobody sits at, run once over SSH: it opens its vault by itself from then on and
approves nothing, so everything it needs is approved on another device. `vlt device add --spaces
Agents` gives a server only those spaces, and the touch names them. A server has no say in adding
or removing devices, so a laptop and a server need only the laptop.

| Step | What happens |
|---|---|
| 1 | New device creates its enclave keys and listens. |
| 2 | Existing device finds it on the network. Off-network, it connects to the address the new device shows, so that port must be open to it: the relay does not carry a pairing. |
| 3 | Both show the same three words. |
| 4 | Person compares and confirms on both, with a touch on each. |
| 5 | With two or more enrolled devices, another device must also approve. |
| 6 | Existing device writes the roster entry and hybrid wrap, then sends logs. |
| 7 | New device verifies the chain and reports "143 items synced." |

| Failure | Result |
|---|---|
| Words differ | Both abort and discard: "Someone may be interfering with this connection." |
| Connection lost once the words are decided | The join ends and says so. A silent retry would hand an attacker another guess. |
| Another device's stale beacon on the network | Skipped. Listening continues. |
| Devices have not synced yet | They sync first, so the change follows the newest roster. |
| No match within 2 minutes | Both exit. Nothing changed. |
| Second approval unavailable | Waits, or the recovery key stands in. |
| Connection lost mid-transfer | Device stays enrolled. Logs resume on next contact. |
| Device name already used | Suffix added. |

Any number of devices can join. Each holds a full encrypted copy, relays what it has for the others,
and needs only one other device to approve a sensitive change.

## 7. Remove a device

`vlt device rm "Old Mac"`, used for a replaced or stolen device.

| Step | What happens |
|---|---|
| 1 | Touch, plus a second device or the recovery key. |
| 2 | Rotates the epoch key and every space key. |
| 3 | Lists secrets that device could already read, for real-world rotation. |

| Failure | Result |
|---|---|
| Removing the only device | Refused. Use `vlt wipe`. |
| Two devices share the name | The list shows each with an id, and either that or the id says which. Never this device. |
| Removed device comes online | Peers reject its new entries. It keeps only old ciphertext. |
| Two devices make a roster change at once | The one more of the vault signed counts, and on an even count someone leaving wins. The other is refused and reported, and a device added that way has to be paired again. Neither loses any other entry. |
| Two devices remove each other, each with the words | They part ways. Each keeps working on its own and reports it. Wipe one and join it again. |

## 8. Allow an agent

An agent cannot be told apart from a person by its process tree, since agents usually run inside
your terminal. So there is one mechanism: a scoped token. Without one, each use needs a touch.

`eval "$(vlt grant --space a --agent claude --for 4h --why "deploying the API")"`.

| Step | What happens |
|---|---|
| 1 | This device and every other one ask at once: `"claude" wants to use Project A for 4 hours. It says: “deploying the API”`. Another device names the device asking first. The first approval counts, and the other prompts go away. |
| 2 | On a touch, `vlt` prints `export LV_SESSION=...`. Children inherit it. |
| 3 | Every use with the token is audited under that name. |

| Failure | Result |
|---|---|
| Denied or timed out | Exit `4` or `3`. The agent never blocks forever. |
| Agent name contains control characters or is too long | Sanitized before display, so it cannot fake the prompt. |
| Reason with control characters, or too long | Refused, or cut after the facts. |
| Refused on one device | Only that device is out. Another can still approve. |
| Expired, screen locked, or revoked | Exit `4`, and the agent must ask again. |
| Token used outside its space | Exit `4`. Audited. |

A grant lasts at most 24 hours; a longer or empty one is refused, never shortened. `vlt grant`
prints which space it gives and for how long on stderr, so stdout stays one line for `eval`.

`vlt grant ls` and `vlt grant rm` manage grants. The app lists them too. Item names are listed to
anyone running as you while the vault is unlocked; values never are.

## 9. Use a secret

`vlt run -- bun dev`. With no `LV_SESSION`, a touch approves this one run, and the prompt names the
command and space.

| Case | Result |
|---|---|
| Secret has allowed hosts | Child gets a placeholder. The proxy swaps it only for those hosts, and only in a credential header. |
| Placeholder in a URL or an ordinary header | Passed through unchanged. A server could keep it where nothing scrubs it. |
| Secret has no allowed hosts | Exit `1`, naming it and the fix: `vlt allow NAME host`. |
| A host allowed for anything but an env var | Refused: the proxy only ever sends env vars. |
| Tool needs the real value | `vlt run --env NAME -- cmd`: touch per run, even with a grant, output scrubbed. |
| Placeholder sent to another host | Passed through unchanged. Nothing leaks. |
| Response echoes the secret | Scrubbed before it reaches the child, in the usual encodings too. |
| Compressed reply, or a connection upgrade | Refused, because the scrubber cannot read it. |
| Vault locks, or the grant ends, during a run | The proxy stops and erases its secrets. |
| Folder has no linked space | Exit `1` with `vlt link SPACE`. |
| Tool ignores the proxy CA (Go on macOS, native apps) | TLS fails closed. Use `--env`. |

## 10. Reveal

`vlt reveal NAME`: a touch every time, naming the item. Never cached by a grant.

- `--copy` puts it on the clipboard marked concealed, and clears it after 30 seconds.
- Output scrubbing cannot stop a person pasting, and that is fine: this is the person's path.

## 11. Fill in a browser

| Step | What happens |
|---|---|
| 1 | Focus a field. Logins saved for this site, or a domain above it, appear by name, and cards and profiles on any form. |
| 2 | Pick one. A touch names the item and the site. |
| 3 | Filled. A saved two-factor secret stays in the vault: only the current code is sent. |

On a Mac, the system's Password AutoFill fills Safari and other apps the same way. So it can
suggest logins in its own menu, the app gives it each login's sites and username, never a password
and never for a session, and picking one takes the same touch. The AutoFill extension runs sandboxed and can
reach neither the vault's folder nor start a broker, so it connects through the app group's
container, where the broker for the vault in its usual place also listens, with the same checks.

The vault's own Mac app and its AutoFill extension need no touch of their own once the vault is
open: they reveal, fill, show codes, edit and delete on the touch that unlocked it. The broker
checks that the caller is signed as one of them, by the same team as the broker and unchanged,
using the kernel's token for its process, which a process cannot borrow by connecting and then
becoming something else. Anything else that asks, such as `vlt`, the browser's native host or an
agent, takes a touch every time, because any program the person runs could be speaking for them.
Adding a device, exporting, backups, the recovery key, agent access, imports, allowed hosts and
when the vault locks always take a touch.

| Failure | Result |
|---|---|
| Phishing lookalike origin | No match is offered, and a direct request is refused. |
| HTTP page with an HTTPS item | No match. Plain HTTP works only on this machine, for cards and profiles too. |
| A profile's details in a list | Never there. A list shows its name alone, so agents with a grant see nothing of the person. |
| Card in a cross-origin payment frame | The touch names the page it is going to. |
| Vault locked | Field shows locked, and a fill is refused. A fill never opens the vault: unlock first. |
| Native host missing | The extension says how to connect it. |
| A session asks to fill | Refused. Sessions use `vlt login`. |

Passkeys are kept like logins, so they reach every device in their space. A key that syncs cannot
be bound to one device's Secure Enclave, which is the trade every synced passkey makes. The
browser asks for one with the origin it reports, never the page's word for it: the library makes
a P-256 key for the site after a touch naming the site and the account, keeps the private half in
the broker, and hands back the public key and the bytes the site checks. Signing in takes a touch
naming the passkey and the site, even for the vault's own app, because a passkey tells the site
its user was just verified. Which passkeys fit a page is answered without a touch.

| Failure | Result |
|---|---|
| A page asks for a passkey for another site, or for a suffix many sites share such as `co.uk` | Refused before anyone is asked. A passkey belongs to its site and the sites under it. |
| A passkey is offered to another site | Never listed there, and a request to sign with it is refused. |
| The site already has a passkey for this person here | Refused, so none is made twice. |
| An interface hands in a passkey's private key | Refused. Keys are made in the broker. |
| A reveal | Shows the site, account and credential, never the private key. |
| A session asks to list them | Refused. It names the one it signs in with. |
| A session makes or signs with one | A touch every time, naming the agent, as in flow 12. |

## 12. Sign up and sign in for an agent

An agent makes accounts the way a person would, in the browser it drives, and the vault keeps what
proves them. The agent fills in the form and submits it. Vaulte only puts in the secret.

`vlt signup github.com --into http://127.0.0.1:9222`, with the sign-up form open there.

| Step | What happens |
|---|---|
| 1 | Session checked. Saving something new needs no touch, as in flow 3. |
| 2 | Finds the agent's tab on that site, asking the browser for its address, not the page. |
| 3 | Makes a password and puts it in the form's password field and its confirmation, each by reference. |
| 4 | Saves the login with the site and the username the form holds, under the agent's name in the audit. |
| 5 | The agent submits the form. |

The password never passes through the agent's output or its model. Whatever drives the browser
could still read the page, which is why this only ever hands over a password made for this
sign-up, never one the vault held. Signing in later is `vlt login`, which shows it nothing.

`vlt signup github.com --passkey --into ...` waits while the agent uses the page's passkey button.
The broker answers the page itself, as the extension does: the site asks, a touch names the agent,
the account and the site, and the key is made in the broker like any other passkey. The browser
gets the public half, never the private key. `vlt login NAME --into ...` with a passkey works the
same way, signing the site's challenge after a touch naming the passkey and the site.

| Failure | Result |
|---|---|
| No tab on that site | Exit `5`. Nothing saved. |
| No password field on the page | Exit `1`. Nothing saved. |
| The page moves to another site | Refused before anything is put in. |
| The login cannot be saved | The fields are emptied again, so nothing unsaved is submitted. |
| Passkey refused, or the vault locks or the grant ends | Nothing saved. A page that asked hears no. |
| Nothing on the page asks for a passkey within 2 minutes | Exit `6`, and the page is left as it was. |
| The site asks for a passkey this is not | Refused before anyone is asked. |
| A passkey sign-in into a session file | Refused. A passkey signs in only in the agent's own browser. |

`vlt login NAME --into http://127.0.0.1:9222`, or `--state session.json` for a Playwright file.

| Step | What happens |
|---|---|
| 1 | Session checked, or a touch. The broker starts its own browser with no debugging port. |
| 2 | Puts in the username, password and any saved code, asking the browser for the page's address before each. Each goes to that field and no other. |
| 3 | Copies only the cookies into the agent's browser. Closes and erases its profile. |

| Failure | Result |
|---|---|
| CAPTCHA, or a page it cannot follow | Exit `6`. A person has to sign in. Never solved. |
| Code needed and none saved | Exit `6`. |
| Password or code refused | Exit `1`. Never retried, which could lock the account. |
| Sign-in moves to another site | Refused before anything is typed there. |
| Vault locks, or the grant ends, partway | The sign-in stops, and no session is handed over. |
| Browser fails its signature check | Refused. It gets no password. |
| Agent's browser is not on this machine | Refused. A session never leaves this machine. |
| Session bound to device or browser | Falls back to fill-in-place with a touch, and says the agent could read it. Not built yet. |

## 13. Sync

Runs in the background once a second device or a backup exists. Nothing listens before that.

| Case | Result |
|---|---|
| Both devices edited one item | Latest wins, and the other stays in `vlt history`. |
| Device clocks disagree | Hybrid clock keeps order correct. |
| Offline for months | Catches up on next contact. |
| Peer offers an older log | Refused, and reported. |
| Tampered entry | Peer's log refused whole. Reported. Local data is unaffected. |
| Log from another vault | Refused and reported. |
| Log dated more than a day ahead | Refused and reported. |
| This device was rolled back | Once a signed copy elsewhere holds more of its log, it says so and takes that back. |
| This device was rolled back and has written since | It says so and stops writing, because the others will refuse it. Export, then recover. |
| A device was left out of a race | It keeps working and is told. Export, recover again and import. |
| A removal cut what this device built on | It writes its own items again at the next unlock. Nothing to do. |
| Roster conflict | Keeps working on its own log and reports it. `vlt conflict resolve` with the words of the side you choose settles it, and it stays settled. |
| Sync while locked | Works. Only ciphertext moves. |

`vlt status` shows last contact with every device and backup.

## 14. Backup

`vlt backup add <folder>`, for example iCloud Drive or a USB drive. Writes logs after each change.
`vlt backup verify` reads the folder back and checks the chain and the recovery key wrap.

| Failure | Result |
|---|---|
| Folder gone or full | Status shows it. Work continues. |
| One folder used by several vaults | Each keeps its own subfolder. |
| iCloud has evicted files | Downloads them before verifying. |

## 15. Recover

`vlt recover` on a new machine.

| Step | What happens |
|---|---|
| 1 | Point at a backup folder or an exported archive. |
| 2 | Enter the 24 words. |
| 3 | Verifies, and if the copy holds rival histories, the person chooses theirs. Shows anything wrong with the copy and asks before going on, then enrolls this device using the recovery authority. |
| 4 | Lists old devices and offers to remove them, which rotates keys. |

| Failure | Result |
|---|---|
| Typo | Checksum catches it and names the likely word. No lockout. |
| Key for a different vault | "This key does not open this vault." |
| Words that have been replaced | They open the vault as it stood until then. It says so, and goes on only if the person says yes. |
| The copy holds rival histories no signature separates | Shows the devices and the newest items in each, and the person chooses the one holding what they wrote. Nothing goes on until they do. |
| No copy | "A recovery key needs a copy of the vault." |

## 16. Replace the recovery key

`vlt recovery rotate`: touch, plus the current key when there are two or more devices. Shows a new
key with the same confirmation as onboarding, which must pass before anything changes. Every key
is then rotated, so the old words open nothing new. They can still open the old ciphertext they
were wrapped for, which is why a leaked key means changing the secrets it could reach.

## 17. Share

Not built. `DESIGN.md` says what a build must guarantee, and no interface offers this until then.

| Case | Flow |
|---|---|
| Person is nearby | Same three-word handshake, for a shared space that is a vault of its own. |
| Person is remote | `vlt share NAME --to <their id>` prints ciphertext safe to paste anywhere. |
| Stop sharing a space | Removes them and rotates its keys. Lists what they already saw. |

## 18. Push to a vendor

`vlt push cloudflare --script api`: shows a diff of names, never values, and asks. `--yes` for
agents with a grant. Partial failures report per secret and can be retried.

## 19. Leave

`vlt wipe` removes this device's keys and data. Requires typing the device name. If this is the
last copy anywhere, it says so first.

## 20. Upgrade

Old logs always stay readable. On an old binary, a device's log stops at the first entry from a
newer version, the reason says so, and everything else keeps working. Format changes are new entry
kinds, so old entries are never rewritten.

## 21. Devices on different networks

For the relay Vaulte hosts: `vlt relay subscribe` on one device starts the one subscription, $33 a
year before VAT, which covers everything. It prints the account number, which is the account, and where to pay, and points the device at the
relay. `vlt relay account NUMBER` on each other device. `vlt relay` says until when it is paid. For a
relay someone runs themselves: `vlt device connect relay:HOST:PORT` on each device.

| Step | What happens |
|---|---|
| 1 | Each device waits at the relay under tags only its peers can compute. |
| 2 | A device whose logs grow calls the others at once, so a change also travels on through a device that did not make it. Otherwise a device is called only when it may lack something, or after 15 minutes unheard, so idle devices cost the relay nothing. A failed call is tried again after 10 seconds, then twice as long each time, and a device coming back to the relay calls everyone. They sync as on a local network. `a_change_reaches_a_device_through_a_relay_moments_after_it_is_made`, `a_change_travels_on_through_a_device_that_did_not_make_it` |
| 3 | Approvals reach a device the same way. |

| Failure | Result |
|---|---|
| A relay name that does not resolve | Refused. Nothing saved. |
| Not paid, or a payment lapsed | The relay turns the device away. Addresses and folders still work. Within a minute of paying, the devices are in. |
| The account service cannot be reached | Last month's pass works for the first two days of a month, then the relay turns the device away. |
| Relay goes away | Addresses and folders still work. Devices wait there again when it is back. |
| A device is also reachable at an address | The address is used, and the relay is not asked. |

## 22. An agent on a server asks

Built for grants, from a server joined with `--server`: flow 8 with `--why`, approved on whichever
device the person has, while nobody touches the server after it joins.

| Case | Flow |
|---|---|
| It needs a grant | Every device shows which device asks, for which agent, space and how long, then the agent's reason. The first approval wins and the other prompts go away. |
| Nobody approves within a minute | Exit `3` or `4`. Nothing is granted. |
| A grant lasts | The agent uses the space with nobody asked, while the person's devices are off, until the grant ends. |
| It asks for a space the server does not hold | Not found. The server cannot see that space exists. |
| The server is lost | Remove it from any device. Every key rotates, and it held only its spaces. |
