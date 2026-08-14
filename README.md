# sshcatch

[![PyPI](https://img.shields.io/pypi/v/sshcatch)](https://pypi.org/project/sshcatch/)
[![Python](https://img.shields.io/pypi/pyversions/sshcatch)](https://pypi.org/project/sshcatch/)
[![License](https://img.shields.io/pypi/l/sshcatch)](https://github.com/LorenzMap/sshcatch/blob/main/LICENSE)

A quick-deploy SSH server for tunneling (local/remote/dynamic) and simple SCP /
SFTP transfers - it **never opens a shell**.

By default all features are disabled: connections are logged and closed. Turn on
only what you need with the flags described below. Handy on an engagement when
you want a controlled SSH endpoint (a tunnel relay or a file drop) without 
setting up a full `sshd`.

Built on [asyncssh](https://github.com/ronf/asyncssh).

This is a pentesting tool. Only point it at systems and networks you are authorized 
to test.

## Why this tool exists

- During engagements and CTFs I love to use 'simple' tools on my host that just work
  - http-server -> `python3 -m http.server`
  - smb-server -> `impacket-smbserver`
  - ssh-server -> ??? (now `sshcatch`)

- `sshd` can be used, but:
  - configuring it through `sshd_configs` is a pain
  - multiple use-cases require different configs (tunnel direction? sftp direction? different ports?) 
  - logins are controlled by the OS so a user must be created (and secured)
  - ForceCommands need to be set up to restrict the shell

- My solution: `sshcatch`
  - Simply configure through clear flags and arguments on the commandline
    - restrictive defaults, every feature must be enabled consciously
  - Never allow shells (or commands)
  - Forward/Reverse tunnels can be individually activated 
  - SCP/SFTP file uploads and downloads can be individually activated
    - restrictive upload handling to prevent overwriting
    - symlinks denied

## Install

With `pipx` (recommended, installs into an isolated environment and puts
`sshcatch` on your `PATH`):

```
pipx install sshcatch
```

With `pip`:

```
pip install sshcatch
```

From source:

```
git clone https://github.com/LorenzMap/sshcatch
cd sshcatch
pipx install .          # or: pip install .
```

Needs Python 3.10+. Three host keys (ed25519, RSA, ECDSA) are auto-generated
into a single file in the working directory on first run (or point `--host-key`
at your own file).

## How it works

Without any flags sshcatch is in **log-only** mode: It accepts the
connection, records the client version, username, offered passwords and public
keys, then closes. Nothing else is enabled until you ask for it.

Adjust the amount of logging using `-vv` and `-q`. Or put everything into a 
logfile using `-o`.

#### Tunnels

Because no shell is ever created, tunnel clients **must** pass `-N` (e.g.
`ssh -NL ...`) or they get disconnected instantly.

Turning tunneling on with `--open-auth` means **anyone** who connects can pivot
through your host!

Only plain **TCP** forwards are ever available. UNIX-domain-socket forwards
(`ssh -L /sock:...` / `-R /sock:...`) and TUN/TAP tunnels (`ssh -w`) are always
denied, even with `--forward` / `--reverse` set.

#### SCP / SFTP

**Symlinks** are handled very restrictively: On upload they create a placeholder file
that contains the original target. On download they are outright denied. 

The host key, `authorized_keys`, logfile and the sshcatch script itself are **protected** 
and hidden when they live inside the SCP directory.

Uploads **never overwrite** an existing file. The new file gets a numeric suffix 
(`loot.tar` -> `loot_1.tar`). Non-existent parent folders are created.

Renames, deletes and directory removal are denied.

## Word of Warning

Only using `--version-banner` obviously isn't enough deception against a sufficiently
sophisticated observer because some of the data transferred in cleartext on the wire
during connection establishment is a clear tell. Use `--mimic` if that's something you
want to try and dodge in an engagement. Check out
[`mimic-refs/mimic-notes.md`](https://github.com/LorenzMap/sshcatch/blob/main/mimic-refs/mimic-notes.md)
for details about `--mimic`.

Also: `sshcatch` is **NOT** designed to be a **honeypot**. Advanced deception, long-term logging 
and everything else a real honeypot needs are deliberately out of scope. There are other
projects that can be used: [Cowrie](https://github.com/cowrie/cowrie),
[cyanide-framework](https://github.com/tanhiowyatt/cyanide-framework) and probably a lot more!


## Examples

Let one user pull/put files from the current directory via SCP/SFTP:

```
# Server
sshcatch -u user:pass --scp-download --scp-upload

# Client
scp user@host:secret.txt .
scp -r loot/ user@host:pete/pc/
sftp user@host
```

Let anyone tunnel through the server (local and dynamic forwards): **Be careful with this one!**

```
# Server
sshcatch --open-auth --forward

# Client
ssh -NL 8080:internal:80 user@host      # local forward
ssh -ND 1080 user@host                  # dynamic (SOCKS)
```

Using single-mode to return something to the first successful authentication
by closing the server afterwards, while printing timestamped logs to the console
and saving them into a file:

```
# Server
sshcatch -1 -u arthur:42 --version-banner 'heart_of_gold' \
         --pre-auth-banner "What is the answer to life the universe and everything" \
         --post-auth-banner "flag{So_Long_and_Thanks_for_All_the_Fish}" \
         -o sshcatch.log -t
```


My favorite one: Reverse tunnel and SCP uploads for the keys in
`./authorized_keys` on port 2222:

```
# Server
sshcatch --reverse --authorized-keys ./authorized_keys --scp-upload -p 2222

# Client
ssh -NR 9000:localhost:22 user@host -p 2222     # reverse tunnel
scp -P 2222 loot.tar user@host:.                # upload
```


## Options

`sshcatch -h` prints a short summary with just the flags you need to get going.
The full reference below is `sshcatch --help`:

```
usage: sshcatch [-h] [--help] [-p PORT] [-b BIND] [-1] [--mimic PRESET]
                [--host-key FILE] [--version] [-u USER:PASS] [--open-auth]
                [--authorized-keys FILE] [--forward] [--reverse]
                [--scp-upload] [--scp-download] [--scp-dir DIR]
                [--version-banner STRING] [--pre-auth-banner STRING]
                [--post-auth-banner STRING] [-q | -v] [-o FILE] [-t] [--plain]

sshcatch - a quick-deploy SSH server for tunneling (local/remote/dynamic)
and simple SCP/SFTP transfers (NEVER opens a shell!)
By default all features are disabled. Use flags to enable features.

options:
  -h                    show a short help message and exit
  --help                show the full help and exit
  -p PORT, --port PORT  listen port (default: 22)
  -b BIND, --bind BIND  bind address (default: all IPv4/v6 interfaces)
  -1, --single          close the listener after first successful auth (and
                        exit when that connection ends)
  --mimic PRESET        pose as another SSH server - presets (case-
                        insensitive): debian, dropbear, none - match the
                        preset's pre-auth (banner, KEXINIT, server-sig-algs,
                        ...) exactly - banner can be overridden by --version-
                        banner - check Github repository for details
  --host-key FILE       server host key file, may hold several keys - auto-
                        generated if missing - uses ./sshcatch_host_key by
                        default
  --version             show program's version number and exit

authentication:
  -u USER:PASS, --user USER:PASS
                        allowed user:password (repeatable)
  --open-auth           accept any credentials (open mode)
  --authorized-keys FILE
                        authorized_keys file for key auth (username
                        independent)

tunneling:
  --forward             enable forward tunnels (client: ssh -NL / -ND)
  --reverse             enable reverse tunnels (client: ssh -NR)

SCP / SFTP file transfer:
  --scp-upload          enable file upload (SCP/SFTP write) - files get suffix
                        instead of overwriting
  --scp-download        enable file download (SCP/SFTP read) - symlinks are
                        denied
  --scp-dir DIR         directory for SCP/SFTP (default: cwd) - sensitive
                        sshcatch files (host-key, authorized_keys, logfile)
                        are protected

banners:
  --version-banner STRING
                        manually set 'SSH-2.0-STRING' version banner
  --pre-auth-banner STRING
                        banner shown to every client before login
  --post-auth-banner STRING
                        banner shown only to clients that authenticate
                        successfully

logging:
  -q, --quiet           print nothing on console
  -v, --verbose         print additional information to the console
                        (repeatable)
  -o FILE, --output FILE
                        append the log to FILE (plain with timestamps)
  -t, --timestamps      prefix console lines with a timestamp
  --plain               disable ANSI colors on the console

examples: (also check README on Github)
  sshcatch                                   Log-only (capture creds)
  sshcatch -u user:pass --scp-download       Allow one user to download via SCP/SFTP
  sshcatch --open-auth --forward             Allow ANYONE! to tunnel through this SSH server
  # My favorite one
  #   Allows reverse tunnels and uploads via SCP for the keys in ./authorized_keys
  sshcatch --reverse --authorized-keys ./authorized_keys --scp-upload -p 2222
```

## Testing

- the test suite lives in `tests/` (pytest)
- run it from a virtualenv with the dev
dependencies installed (`pytest`, `coverage`, `asyncssh`) 
- the interop tests also need the OpenSSH client tools and `sshpass` on `PATH`
- run via `python -m pytest` or `tests/test.sh`
- for get the coverage of the tests run `tests/test.sh cov`

## License

MIT
