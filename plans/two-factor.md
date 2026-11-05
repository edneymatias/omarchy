# Plan: Two-factor sudo — password plus something you have

Revision 1.

## Problem

Every authentication option Omarchy ships today *replaces* the password instead of adding to it:

- `omarchy-setup-security-fido2` inserts `auth sufficient pam_u2f.so` at line 1 of `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`. A touch on the key skips the password.
- `omarchy-setup-security-fingerprint` does the same with `pam_fprintd.so` (behind the clamshell gate).
- Third-party add-ons follow the same shape: glance-linux's `glancectl setup-pam --sudo` puts `auth sufficient pam_glance.so allow_setuid` at the top of `/etc/pam.d/sudo`; omarchy-yubikey makes the key an alternative to the password, with an explicit fallback.

All of these are conveniences. None of them answers "nobody gets root on this machine without my password **and** something physically mine", and because each one claims line 1 with `sufficient`, they cannot be composed into that answer: any of them, once installed, bypasses whatever comes after it.

The ask: one command that owns a password-plus-second-factor stack for `sudo` and polkit, uses hardware the user already has (a phone; optionally a FIDO2 key or the TPM-backed omapasskey), detects the setups that would silently defeat it, and cannot lock the user out.

## Threat model

- **Defends against**: someone who learned the account password (shoulder-surfing, reuse, a leaked password file) but does not hold the second factor; a program running as the user that captured the password from a terminal and tries to replay it through `sudo` without the user present.
- **Does not defend against**: a program running as the user that waits for the user's own successful `sudo` and rides the timestamp cache (`timestamp_timeout`), or that injects into the user's terminal at that moment. 2FA raises the bar for escalation; it does not make a compromised session safe. Root or kernel compromise is out of scope.
- **Not a bypass-proof boundary on its own**: anything that grants root without PAM keeps working — `omarchy-sudo-passwordless` (a `NOPASSWD` sudoers file on a timer), sudoless Docker (`docker` group membership), and the narrow `%wheel NOPASSWD` rules Omarchy ships in `etc/sudoers.d/` for DNS, theme and timezone switching. Setup reports the first two; the narrow rules are intentional and stay.
- **Scope boundary (v1)**: `sudo` and `polkit-1`. Not the lock screen, not the login manager, not `sshd`, not `su`. The lock screen only re-admits a user to a session they already own, and a mistake there locks them out of the desktop; it is a v2 candidate once the sudo stack has proven itself.

## Factors

The stack is: **password, then one second factor**. Second factors are tried in a fixed order, fastest first, and the first success ends the stack.

| Factor | Module | Hardware | Notes |
|---|---|---|---|
| FIDO2 key | `pam_u2f.so` | YubiKey or any FIDO2 key; omapasskey's virtual key | Optional. Skipped instantly when no enrolled key is present. |
| Fingerprint | `pam_fprintd.so` | built-in reader | Optional, only offered when `omarchy-hw-fingerprint` succeeds. Reuses the clamshell gate. |
| TOTP code | `pam_google_authenticator.so` | phone with any authenticator app | Always enrolled. The factor of last resort, works offline. |

Deliberately not factors in v1:

- **Face (glance-linux, Howdy, and similar)**: these daemons run as the user and the PAM module trusts a socket in the user's runtime directory. glance-linux's own `SECURITY.md` states that any process running as the user can replace the daemon with one that always answers yes. That is precisely the attacker a second factor exists to stop. Face stays a lock-screen convenience.
- **Phone passkey over the hybrid transport** (`spikes/phone-auth/`): verified working with Samsung Pass and Google Password Manager on Android, but every use needs a QR scan (no Android passkey provider offered state-assisted linking to a non-Chrome client), it depends on Google's tunnel server, and it needs a PAM conversation that can render a QR. Revisit if linking becomes available.
- **SMS / push**: need a third-party service. Out of scope.

### omapasskey as the FIDO2 factor

omapasskey presents itself as a USB HID FIDO2 key backed by the TPM, so `pam_u2f` should see it like any other key. Two things must be confirmed on real hardware before the setup offers it by name:

1. `fido2-token -L` lists the virtual device and `pamu2fcfg` can enroll it (omapasskey's README lists libfido2 tools as untested).
2. omapasskey enforces `alwaysUv`, so the enrollment must use `pamu2fcfg -N` and the PAM line must carry `pinverification=1`. A FIDO2 key that is also enrolled is then asked for its PIN too; that is consistent, not a regression.

The setup does not special-case omapasskey otherwise: it enrolls "a FIDO2 key", whichever one answers.

## PAM layout

One file owns the policy, and the stacks that use it get a single line.

`/etc/pam.d/omarchy-2fa` (written by setup, removed by teardown):

```
#%PAM-1.0
# Managed by omarchy-setup-security-2fa. Second factor only: the password has
# already been checked by system-auth in the calling stack.
auth  [success=done default=ignore]  pam_u2f.so  authfile=/etc/omarchy/2fa/u2f_keys origin=pam://omarchy-2fa appid=pam://omarchy-2fa cue pinverification=1
auth  [success=1 default=ignore]     pam_exec.so quiet /usr/bin/omarchy-hw-laptop-closed
auth  [success=done default=ignore]  pam_fprintd.so
auth  required                       pam_google_authenticator.so secret=/etc/omarchy/2fa/totp/${USER} user=root no_increment_hotp
```

Lines for factors the user did not enroll are not written. The TOTP line is always last and always `required`, so the stack can only succeed through a factor.

`pam_u2f`'s `nouserok` must never appear here: it makes the module return *success* for a user with no registered key, and with `success=done` that would end the stack before TOTP. Without it, an unregistered user or an absent key is a non-success that `default=ignore` passes over. The test suite asserts the option is absent.

`/etc/pam.d/sudo` and `/etc/pam.d/polkit-1` gain one line, immediately **after** their existing password line (`auth include system-auth` on stock Arch):

```
auth  substack  omarchy-2fa
```

Why this shape:

- **`substack`, not `include`.** `done` inside an included file ends the *whole* calling stack; inside a substack it ends only the substack, so the calling file's `account` and `session` phases still run.
- **After the password, never before.** The password check stays in `system-auth`, where `pam_faillock` already counts failures (`deny=10 unlock_time=120` via `install/config/increase-lockout-limit.sh`). A failed password still prompts for the factor, so the prompt sequence leaks nothing about which part was wrong; the overall result is a failure either way, because `required` failures recorded before a `done` still fail the stack.
- **Own credential paths.** `/etc/omarchy/2fa/` (root-owned, 0755) keeps this command's FIDO2 registrations apart from `/etc/fido2/fido2`, the file `omarchy-setup-security-fido2` and `omarchy-remove-security-fido2` own. Neither command can delete the other's enrollment.
- **Root-only TOTP secrets.** `pam_google_authenticator`'s default is `~/.google_authenticator`, a file the user can read, which means any program running as the user can read the seed and mint codes. Secrets live in `/etc/omarchy/2fa/totp/<user>` (root:root, 0600), and the module reads them as root (`user=root`). The secret file also carries the module's rate limit (`RATE_LIMIT 3 30`) and the scratch codes, so TOTP guessing does not depend on `faillock`, which only counts password failures.
- **Teardown is exact.** Removing the `substack` line and the file restores the stacks to what they were; nothing else in them was touched.

Multiple users: enrollment is per user. Whether wheel users who never enrolled are let through or refused is a decision recorded per machine (see open questions); v1 defaults to refusing, and setup lists every wheel user so the person running it sees who would be affected.

## Conflict detection

Before touching anything, setup inspects the effective `sudo` and `polkit-1` stacks (following `include`/`substack`), and refuses to continue while any of these hold, naming the command that removes each one:

| Found | Why it defeats 2FA | Remedy shown |
|---|---|---|
| `pam_u2f.so` as `sufficient` (Omarchy FIDO2 setup, omarchy-yubikey) | a key touch skips the password and the factor | `omarchy-remove-security-fido2`, then enroll the key here instead |
| `pam_fprintd.so` as `sufficient` | a finger skips both | `omarchy-remove-security-fingerprint`, then enroll it here instead |
| `pam_glance.so` / `pam_howdy.so` in sudo or polkit | a face skips both | `glancectl setup-pam --remove`, or that tool's equivalent; their lock-screen wiring can stay |
| any other `sufficient` auth module above the password line | unknown bypass | stop and show the line; no automatic fix |

And warns (does not refuse) on:

- an active `omarchy-sudo-passwordless` grant: `NOPASSWD` never reaches PAM, so 2FA is bypassed until it expires;
- membership in the `docker` group (sudoless Docker): root-equivalent without sudo;
- the clock not being synchronized (`timedatectl show -p NTPSynchronized`): TOTP depends on it.

The fingerprint and FIDO2 *lock-screen* stacks (`omarchy-lock-fingerprint`, `omarchy-lock-fido2`) are not conflicts: v1 does not touch the lock screen.

## Setup: `omarchy-setup-security-2fa`

A gum wizard in the mold of `omarchy-setup-security-fido2` and `omarchy-setup-security-sshd`, launched from _Setup > Security > Two-Factor_ through `omarchy-launch-floating-terminal-with-presentation`. `# omarchy:requires-sudo=true`. Run as the desktop user; it uses `sudo` for each privileged step.

1. **Preflight.** Conflict detection (above). Clock sync check. List wheel users and their enrollment state.
2. **Lifeline.** Start a root shell as a coprocess (`sudo bash`) before any PAM edit and keep it until the final test passes. If anything after this point fails, the rollback runs through the lifeline, which does not need to authenticate again. Same idea omarchy-yubikey asks users to do by hand ("keep a `sudo -s` open"), done for them.
3. **Packages.** `omarchy-pkg-add libpam-google-authenticator qrencode`, plus `pam-u2f libfido2` if a FIDO2 key will be enrolled. All are in Arch `extra`.
4. **TOTP enrollment (always).** Generate the secret straight into the root-owned path (`google-authenticator --time-based --disallow-reuse --force --rate-limit=3 --rate-time=30 --window-size=3 --issuer=Omarchy --label="$USER@$(hostname)" --secret=/etc/omarchy/2fa/totp/$USER`, run through the lifeline; the explicit label keeps the app entry from reading `root@…`). Show the QR in the terminal for the phone's authenticator app, then the scratch codes, with a typed confirmation that they were saved off this machine. Then **ask for a current code and verify it** against the new secret before going further; a wrong clock or a mis-scanned QR stops here, before PAM changes.
5. **Optional factors.** Offer FIDO2 (`pamu2fcfg -N -o pam://omarchy-2fa -i pam://omarchy-2fa`, one or more keys, appended per the pam_u2f mapping format) and fingerprint (only when a reader is detected; enrollment through `fprintd-enroll` as the fingerprint setup does).
6. **Write and wire.** Write `/etc/pam.d/omarchy-2fa`, back up `sudo` and `polkit-1` (creating `/etc/pam.d/polkit-1` from the packaged default when only `/usr/lib/pam.d/polkit-1` exists, as the existing setups do), insert the `substack` line.
7. **Test.** `sudo -k`, then `sudo true` in the user's terminal: password, then the factor. On failure, roll back through the lifeline and say what failed. On success, release the lifeline and point at the polkit test (a benign `pkexec true`).

Every step is idempotent. Re-running setup with an existing enrollment offers: add a factor, re-enroll TOTP (new secret, new scratch codes), or remove a factor. `--status` prints the stack, the enrolled factors per user, and active bypasses (passwordless sudo, docker group) without changing anything.

## Teardown: `omarchy-remove-security-2fa`

Remove the `substack` line from `sudo` and `polkit-1`, delete `/etc/pam.d/omarchy-2fa`, delete `/etc/omarchy/2fa/`, test that `sudo -k && sudo true` asks for the password alone. Packages stay installed (other tools may use them); the summary says so and names them. It reminds the user to delete the "Omarchy" entry from their authenticator app and, for FIDO2 keys, that nothing was stored on the key beyond a non-resident credential.

## Recovery

- **Lost phone**: a scratch code works once in place of a TOTP code; `omarchy-setup-security-2fa` then re-enrolls a new phone.
- **Lost phone and scratch codes**: any enrolled FIDO2 key or fingerprint still works as the factor. This is the argument for enrolling a second factor at all.
- **Everything lost**: boot the Omarchy ISO, unlock the disk, chroot, and remove the `substack` line from `/etc/pam.d/sudo`. The manual page documents this procedure in full; it is the same procedure that recovers any broken PAM stack.

## Polkit and the shell

`shell/plugins/polkit/PolkitAgent.qml` already handles multi-prompt PAM conversations: it re-renders on every `isResponseRequired`, shows `inputPrompt`, and switches `echoMode` with `responseVisible`, so "Password:" followed by "Verification code:" should work without code changes. Two things to verify in the running UI per `agents/skills/visual-verification.md`: the second prompt's label is readable and not mistaken for a retry of the password, and the FIDO2 "touch your key" cue (from `cue`) surfaces as an info message rather than an empty field. `PolkitModel.fingerprintConfiguredFromPamConfig` scans only `/etc/pam.d/polkit-1` directly and will not see `pam_fprintd` inside the substack; with fingerprint as a second factor the dialog should show the field first anyway, so this is acceptable for v1, but the model gains a note.

## Menu and router

- `setup.security.2fa` — _Two-Factor_, action `omarchy-launch-floating-terminal-with-presentation omarchy-setup-security-2fa`.
- `remove.security.2fa` — _Two-Factor_, `when` guard `[[ -f /etc/pam.d/omarchy-2fa ]]`.
- No new command group: both commands live under the existing `setup-` / `remove-` prefixes. No `aliases`.

## Rollout

- Fully opt-in. No packages, files or PAM changes until the wizard runs. No migration.
- Docs: a new `manual/` page "Two-factor sudo" (what it protects and what it does not, setup, recovery including the ISO procedure, interaction with fingerprint/FIDO2/face/passwordless sudo/sudoless Docker), and a cross-link from the existing fingerprint and FIDO2 pages explaining "replace the password" versus "add to the password".
- Tests:
  - `test/shell.d/security-2fa-test.sh`, following `security-fido2-test.sh`: retargeted copies of the commands with stubbed `sudo`, asserting the exact PAM text written, idempotent re-runs, conflict detection against fixture stacks (Omarchy FIDO2, fingerprint, glance, omarchy-yubikey, unknown `sufficient`), backup and exact teardown, root-only modes on the secret, and that rollback runs when the final test fails.
  - `test/cli` picks up the command metadata.
  - Acceptance (disposable VM, `agents/skills/acceptance-tests.md`): enroll TOTP with a known secret, compute codes with `oathtool`, drive `sudo` with expect: password + right code succeeds, right password + wrong code fails, wrong password + right code fails, scratch code works once, teardown restores password-only sudo. Polkit through `pkexec true` with the same matrix.
  - Visual verification of the polkit dialog's two-prompt flow.

## Open questions

1. **Unenrolled wheel users**: refuse (safe, can lock out a second admin who never enrolled) or let through with `nullok` (convenient, silently weaker)? Leaning refuse, with setup listing who is affected and requiring confirmation.
2. **Lock screen in v2**: the Omarchy lock uses separate PAM services per method (`omarchy-lock-password`, `omarchy-lock-fingerprint`, `omarchy-lock-fido2`). Adding a factor there means a two-step lock UI, and coexisting with glance-linux's lock wiring. Worth it, or is the lock screen fine as a convenience boundary?
3. **Order of second factors**: FIDO2 before fingerprint before TOTP assumes keys are usually plugged in. A user whose key is usually absent waits on nothing (pam_u2f skips with no key present), but one whose key is present and ignored waits for its timeout. Make the order configurable, or keep it fixed and simple?
4. **Upstream**: this replaces nothing and adds two commands, but it changes Omarchy's security story from "pick a convenience" to "pick a convenience or a policy". Open an issue upstream with this plan before implementation, so the maintainers can decide whether two-factor belongs in Omarchy or in a separate plugin.
5. **omapasskey**: if it works with `pam_u2f` (to be confirmed), should setup detect it and offer it by name, or keep treating it as "a FIDO2 key"?
