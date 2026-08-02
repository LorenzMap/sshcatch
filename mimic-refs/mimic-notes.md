# `--mimic` notes and reasoning

**All this is specific for the pinned asyncssh version and might change on updates of the library!**
**So check carefully if updates are intended**

To make `sshcatch` blend in during engagements, I added a `--mimic` flag that
disguises it as either an OpenSSH 8.4p1 (`debian`) or a Dropbear 2024.86 (`dropbear`)
server. Everything a client or a sufficiently sophisticated observer sees **before**
authentication (version banner, KEXINIT/HASSH, offered host keys and auth methods) is
matched byte-exact against a capture of the real server. After authentication we are
obviously not a normal SSH server and don't pretend to be.

Getting asyncssh to behave this way required some changes to the library's
internals. This file explains the reasoning behind each modification and
monkey-patched method (`apply_mimic_patches()`).

To keep my changes focused, I organized them around "phases" of the SSH protocol:

1. Before Encryption
   - Starting from the TCP handshake up to the `SSH_MSG_NEWKEYS` message that switches on encryption
   - Everything here is plaintext, so it's visible to any external observer
   - The SSH version banners live in this phase
   - HASSH is derived from the plaintext KEXINIT
2. Encrypted Pre-Auth
   - From the `SSH_MSG_NEWKEYS` message up to successful authentication
   - Any client or scanner that connects to the server can access the information of this phase
3. Encrypted Post-Auth 
   - Begins after successful authentication
   - Only clients with valid credentials or keys can reach this phase 

The `--mimic` implementation allows the following for each phase:

1. Before Encryption
   - **Byte-exact mimic** of the reference OpenSSH 8.4p1 and Dropbear 2024.86
   - including identical SSH version banner and HASSH
2. Encrypted Pre-Auth
   - **Byte-exact mimic** of the reference OpenSSH 8.4p1 and Dropbear 2024.86
   - including identical server-sig-algs and userauth methods
3. Encrypted Post-Auth 
   - Obviously **completely different** from OpenSSH 8.4p1 and Dropbear 2024.86
   - The allowed/denied operations are an easy tell
   - Additionally asyncssh sends a vendor-id at some points
   - Past authentication, we're plainly not a regular SSH server, so there's no longer any point in hiding it


## Why those two versions (and not OpenSSH 8.9+)

Simple. Those are two versions I got working and they are enough for what I wanted to 
achieve. I started with the version-banner presets from previous `asyncssh` versions
(`ubuntu`, `debian`, `windows`, `macos`, `dropbear`) and tried to get a clean connection
reference. Got one for `ubuntu`, `debian`, `dropbear` using docker. Afterwards I tried to
match them exactly, which dropped `ubuntu` along the way because the one I chose ships
OpenSSH 8.9p1, whose `sntrup761` kex and `publickey-hostbound` `asyncssh` does not
support by default. There are definitely some more SSH servers we could mimic, but I think
that's too much for this (not so simple anymore) tool.

Both of these already appear in OpenSSH 8.9, so we're limited to the 8.4p1 era:

- `sntrup761x25519-sha512@openssh.com` post-quantum kex that `asyncssh` only offers with an optional PQ backend
- `publickey-hostbound@openssh.com` advertised by 8.9+ servers before auth that `asyncssh` has no handler for


## Capture comparisons

To compare what is transferred between server and client `ssh -vvv` traces can be used (see my `capture.py` helper script).
My reference files and comparisons can be found in `/mimic-refs/`.

<details>
<summary><b>--mimic none</b></summary>

- Plain asyncssh ([`sshcatch_mimic_none.txt`](https://github.com/LorenzMap/sshcatch/blob/main/mimic-refs/sshcatch_mimic_none.txt)) against the debian reference ([`debian11.txt`](https://github.com/LorenzMap/sshcatch/blob/main/mimic-refs/debian11.txt))
- this is everything `--mimic` has to fix
- [Full File Comparison](https://htmlpreview.github.io/?https://github.com/LorenzMap/sshcatch/blob/main/mimic-refs/none_diff.html)

```diff
@@ -8,4 +8,4 @@
 debug1: Local version string SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18
-debug1: Remote protocol version 2.0, remote software version OpenSSH_8.4p1 Debian-5+deb11u7
-debug1: compat_banner: match: OpenSSH_8.4p1 Debian-5+deb11u7 pat OpenSSH* compat 0x04000000
+debug1: Remote protocol version 2.0, remote software version AsyncSSH_2.24.0
+debug1: compat_banner: no match: AsyncSSH_2.24.0
 debug2: fd 3 setting O_NONBLOCK
@@ -32,8 +32,8 @@
 debug2: peer server KEXINIT proposal
-debug2: KEX algorithms: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,kex-strict-s-v00@openssh.com
-debug2: host key algorithms: rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519
-debug2: ciphers ctos: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
-debug2: ciphers stoc: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
-debug2: MACs ctos: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
-debug2: MACs stoc: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
+debug2: KEX algorithms: mlkem768x25519-sha256,mlkem768nistp256-sha256,mlkem1024nistp384-sha384,curve25519-sha256,curve25519-sha256@libssh.org,curve448-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,ecdh-sha2-HOST.10,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group15-sha512,diffie-hellman-group16-sha512,diffie-hellman-group17-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256@ssh.com,diffie-hellman-group14-sha1,rsa2048-sha256,ext-info-s,kex-strict-s-v00@openssh.com
+debug2: host key algorithms: ssh-ed25519,rsa-sha2-256,rsa-sha2-512,ssh-rsa-sha224@ssh.com,ssh-rsa-sha256@ssh.com,ssh-rsa-sha384@ssh.com,ssh-rsa-sha512@ssh.com,ssh-rsa,ecdsa-sha2-nistp256
+debug2: ciphers ctos: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
+debug2: ciphers stoc: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
+debug2: MACs ctos: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha256-2@ssh.com,hmac-sha224@ssh.com,hmac-sha256@ssh.com,hmac-sha384@ssh.com,hmac-sha512@ssh.com
+debug2: MACs stoc: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha256-2@ssh.com,hmac-sha224@ssh.com,hmac-sha256@ssh.com,hmac-sha384@ssh.com,hmac-sha512@ssh.com
 debug2: compression ctos: none,zlib@openssh.com
@@ -53,3 +53,3 @@
 debug1: SSH2_MSG_KEX_ECDH_REPLY received
-debug1: Server host key: ssh-ed25519 SHA256:sHLhcZjLnR+X1O4EnomZlKpGhl7Mkr9zqRBCrOC9bJo
+debug1: Server host key: ssh-ed25519 SHA256:VM/3Yeimfn9muMrF+oEaYqYLdYpruChIdT5tCVziqj4
 debug3: put_host_port: [HOST]:PORT
@@ -63,2 +63,4 @@
 debug1: SSH2_MSG_NEWKEYS sent
+debug1: Sending SSH2_MSG_EXT_INFO
+debug3: send packet: type 7
 debug1: expecting SSH2_MSG_NEWKEYS
@@ -72,4 +74,6 @@
 debug1: SSH2_MSG_EXT_INFO received
+debug3: kex_input_ext_info: extension global-requests-ok
+debug1: kex_ext_info_client_parse: global-requests-ok (unrecognised)
 debug3: kex_input_ext_info: extension server-sig-algs
-debug1: kex_ext_info_client_parse: server-sig-algs=<ssh-ed25519,sk-ssh-ed25519@openssh.com,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com>
+debug1: kex_ext_info_client_parse: server-sig-algs=<rsa-sha2-256,rsa-sha2-512,ssh-rsa-sha224@ssh.com,ssh-rsa-sha256@ssh.com,ssh-rsa-sha384@ssh.com,ssh-rsa-sha512@ssh.com,ssh-rsa,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519,ssh-ed448,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,ecdsa-sha2-HOST.10,ssh-dss,rsa-sha2-256,rsa-sha2-512,ssh-rsa-sha224@ssh.com,ssh-rsa-sha256@ssh.com,ssh-rsa-sha384@ssh.com,ssh-rsa-sha512@ssh.com,ssh-rsa,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519,ssh-ed448,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,ecdsa-sha2-HOST.10>
 debug3: receive packet: type 6
@@ -78,7 +82,9 @@
 debug3: send packet: type 50
+debug3: receive packet: type 2
+debug3: Received SSH2_MSG_IGNORE
 debug3: receive packet: type 51
-debug1: Authentications that can continue: publickey,password
-debug3: start over, passed a different list publickey,password
+debug1: Authentications that can continue: publickey,keyboard-interactive,password
+debug3: start over, passed a different list publickey,keyboard-interactive,password
 debug3: preferred
 debug1: No more authentication methods to try.
-user@HOST: Permission denied (publickey,password).
+user@HOST: Permission denied (publickey,keyboard-interactive,password).
```

</details>

<details>
<summary><b>--mimic debian</b></summary>

- `--mimic debian` ([`sshcatch_mimic_debian.txt`](https://github.com/LorenzMap/sshcatch/blob/main/mimic-refs/sshcatch_mimic_debian.txt)) against the debian reference ([`debian11.txt`](https://github.com/LorenzMap/sshcatch/blob/main/mimic-refs/debian11.txt))
- only the host key fingerprint differs
- [Full File Comparison](https://htmlpreview.github.io/?https://github.com/LorenzMap/sshcatch/blob/main/mimic-refs/debian_diff.html)

```diff
@@ -52,5 +52,5 @@
 debug3: receive packet: type 31
 debug1: SSH2_MSG_KEX_ECDH_REPLY received
-debug1: Server host key: ssh-ed25519 SHA256:sHLhcZjLnR+X1O4EnomZlKpGhl7Mkr9zqRBCrOC9bJo
+debug1: Server host key: ssh-ed25519 SHA256:VM/3Yeimfn9muMrF+oEaYqYLdYpruChIdT5tCVziqj4
 debug3: put_host_port: [HOST]:PORT
 debug3: put_host_port: [HOST]:PORT
```

</details>

<details>
<summary><b>--mimic dropbear</b></summary>

- `--mimic dropbear` ([`sshcatch_mimic_dropbear.txt`](https://github.com/LorenzMap/sshcatch/blob/main/mimic-refs/sshcatch_mimic_dropbear.txt)) against the dropbear reference ([`dropbear.txt`](https://github.com/LorenzMap/sshcatch/blob/main/mimic-refs/dropbear.txt))
- only the host key fingerprint differs
- [Full File Comparison](https://htmlpreview.github.io/?https://github.com/LorenzMap/sshcatch/blob/main/mimic-refs/dropbear_diff.html)

```diff
@@ -52,5 +52,5 @@
 debug3: receive packet: type 31
 debug1: SSH2_MSG_KEX_ECDH_REPLY received
-debug1: Server host key: ssh-ed25519 SHA256:nYM5duP3hOtrHbZBz6ga5rkftM/pH7rWZVThlK3U8zc
+debug1: Server host key: ssh-ed25519 SHA256:VM/3Yeimfn9muMrF+oEaYqYLdYpruChIdT5tCVziqj4
 debug3: put_host_port: [HOST]:PORT
 debug3: put_host_port: [HOST]:PORT
```

</details>


## What exactly is changed from the default asyncssh

Dividing the "phases" of the SSH protocol further:

```
    | 1. TCP connect
    | 2. Version banner    SSH-2.0-...                                ── CLEARTEXT
 1. | 3. KEXINIT (both)    kex/cipher/mac/comp + host-key-algorithms  ── CLEARTEXT
    | 4. KEX_ECDH_REPLY    the host key itself                        ── CLEARTEXT
      5. NEWKEYS  ───────────── encryption on ─────────────
 2. | 6. EXT_INFO          server-sig-algs                            ── ENCRYPTED
    | 7. userauth          methods + credentials                      ── ENCRYPTED

 3. | 8. channels          data                                       ── ENCRYPTED
```

#### 2. Version banner (CLEARTEXT) 

- **Default:** `SSH-2.0-AsyncSSH_<ver>` is an instant giveaway
- **Fix:** `MIMIC_PRESETS` sets `server_version` to the exact banner
- **Result:** exact version banners for `OpenSSH_8.4p1 Debian-5+deb11u7` / `dropbear_2024.86`


#### 3. KEXINIT (CLEARTEXT)

##### 3a. kex / cipher / mac / compression (HASSH)

- **Default:** asyncssh's own algorithm set with a distinctive HASSH
- **Fix:** `DEBIAN_ALGS` / `DROPBEAR_ALGS` pin all four lists in the right order for the mimicked server
- **Result:** Good initial step towards byte-exact ciphers/MACs/compression match (3b. and 3c. required)

##### 3b. `ext-info-s` marker

- **Default:** asyncssh always appends `ext-info-s` to the server kex list which neither 
  of the two originals does
- **Fix:** patch `_get_extra_kex_algs` to filter `ext-info-s` out
- **Result:** No `ext-info-s` appended
- Client stops emitting its own EXT_INFO due to that (like with the originals)
- This does not disable `server-sig-algs`, which is gated on the client's `ext-info-c` (not our `ext-info-s`)

##### 3c. Dropbear `kexguess2@matt.ucc.asn.au`

- **Default:** real `dropbear` advertises kex-guess marker and asyncssh can't do that by default
- **Fix:** patch `_get_extra_kex_algs` to add it for the `dropbear` preset
- **Result:** Send `…group14-sha1,kexguess2@matt.ucc.asn.au,kex-strict-s-v00@openssh.com` like `dropbear`
- asyncssh seems to handle `kexguess2` quite well, it's not a directly supported or tested feature however
- Only dropbear clients guess at all, OpenSSH never sets the flag

##### 3d. host-key number

- **Default:** all three generated host-keys are offered in whatever order they come, while
  `debian` offers exactly three and `dropbear` only an ed25519 one
- **Fix:** `select_host_keys()` picks the types the mimicked server has and puts them in order
- **Result:** Number, type and order of offered host-keys match the originals

##### 3e. host-key-algorithms field

- **Default:** asyncssh advertises RSA key as proprietary `ssh-rsa-*@ssh.com` variants and
  in a different order than the originals
- **Fix:** patch `SSHServerConnection.__init__` to pin the advertised list to
     the OpenSSH form `rsa-sha2-512,rsa-sha2-256,ssh-rsa` (+ecdsa/ed25519)
- **Result:** identical RSA list to `debian`
- `dropbear` advertises `ssh-ed25519` only like the real one, so no RSA needed
- the patch keeps only algorithms `sshcatch` actually holds a key for, so we never
  advertise something we can't sign with


#### 4. KEX_ECDH_REPLY (CLEARTEXT)

- Host key fingerprint is unique to each server so it will always differ


#### 5. NEWKEYS

- Encryption turns on here

#### 6. EXT_INFO (ENCRYPTED)

##### 6a. `server-sig-algs`

- **Default:** current asyncssh emits this list duplicated (a library bug)
- **Fix:** passing an explicit `signature_algs` bypasses this bug
- **Result:** matches the originals

##### 6b. `global-requests-ok`

- **Default:** asyncssh adds this extension to EXT_INFO while none of the originals do
- **Fix:** patch `_send_ext_info` to remove it before sending
- **Result:** `global-requests-ok` not sent like the originals

##### 6c. `publickey-hostbound@openssh.com`

- Would be advertised by 8.9+ servers but asyncssh has no handler for it
- both chosen originals predate it, so there is nothing to advertise and nothing to fake

##### 6d. `SSH_MSG_IGNORE` chaff

- **Default:** asyncssh injects an `SSH_MSG_IGNORE` before each real packet
  as traffic-analysis padding (OpenSSH-9.5 and later behavior) that our originals don't insert
- **Fix:** patch `send_packet` to drop all outbound `MSG_IGNORE`
- **Result:** `SSH_MSG_IGNORE` not sent
- Safe because current asyncssh sends it *only* as this chaff at this location


#### 7. userauth (ENCRYPTED)

- **Default:** asyncssh returns by default `publickey,keyboard-interactive,password` and the 
  originals only `publickey,password`
- **Fix:** `kbdint_auth_supported()` returns `False` while a preset is active
- **Result:** only `publickey,password` returned when we want to mimic
