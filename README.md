# sshcatch

A quick-deploy SSH server for tunneling (local/remote/dynamic) and simple SCP
transfers - it NEVER opens a shell.

By default all features are disabled: connections are logged and closed. 
Turn on what you need with the flags described below. Handy on an engagement
when you want a controlled SSH endpoint without using a full `sshd`.

Built on [asyncssh](https://github.com/ronf/asyncssh).

## Install

```
pip install sshcatch
```

Or from source:

```
git clone https://github.com/LorenzMap/sshcatch
cd sshcatch
pip install .
```

Needs Python 3.10+. A host key is auto-generated in the working directory on
first run (or point `--host-key` at your own).

## Usage

Because no shell is created on the server **always** use the `-N` flag on 
your tunnel connections or you get disconnected instantly! 

The SCP directory does intentionally **NOT** support subdirectories! 

Log-only - just capture creds and full public keys:

```
# Server
sshcatch -K

# Client
ssh user@host
```

Let one user pull files via SCP/SFTP:

```
# Server
sshcatch -u user:pass --scp-download

# Client
scp user@host:secret.txt .
```

Let anyone tunnel through the server (local and dynamic forwards):

```
# Server
sshcatch --open-auth --forward

# Client
ssh -NL 8080:internal:80 user@host      # local forward
ssh -ND 1080 user@host                  # dynamic (SOCKS)
```

My favorite one - reverse tunnel and SCP uploads for the keys in
`./authorized-keys`, while posing as a ubuntu SSH server on port 2222:

```
# Server
sshcatch --reverse --authorized-keys ./authorized-keys --scp-upload --version-banner ubuntu -p 2222

# Client
ssh -NR 9000:localhost:22 user@host -p 2222     # reverse tunnel
scp -P 2222 loot.tar user@host:.                # upload
```

## Options

```
usage: sshcatch [-h] [--version] [-p PORT] [-b BIND] [--host-key FILE]
                [-u USER:PASS] [--open-auth] [--authorized-keys FILE] [-K]
                [--forward] [--reverse] [--scp-upload] [--scp-download]
                [--scp-dir DIR] [--version-banner STRING]
                [--pre-auth-banner STRING] [--post-auth-banner STRING]
                [-o FILE] [-t] [--plain]

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p PORT, --port PORT  listen port (default: 22)
  -b BIND, --bind BIND  bind address (default: all IPv4/v6 interfaces)
  --host-key FILE       server host key file (default: auto-generate)

authentication:
  -u USER:PASS, --user USER:PASS
                        allowed user:password (repeatable)
  --open-auth           accept any credentials (open mode)
  --authorized-keys FILE
                        authorized_keys file for key auth (username
                        independent)
  -K, --full-keys       log the full offered public key, not just its
                        fingerprint

tunneling:
  --forward             enable forward tunnels (client: ssh -NL / -ND)
  --reverse             enable reverse tunnels (client: ssh -NR)

SCP / file transfer:
  --scp-upload          enable file upload (SCP/SFTP write) - subdirectories
                        are disabled - files get suffix instead of overwriting
  --scp-download        enable file download (SCP/SFTP read) - subdirectories
                        are disabled
  --scp-dir DIR         directory for SCP/SFTP (default: cwd) - subdirectories
                        are disabled - host-key (and optional authorized_keys
                        and logfile) are protected

banners:
  --version-banner STRING
                        sent as 'SSH-2.0-STRING' version banner - presets
                        (case-insensitive): ubuntu, debian, dropbear, windows,
                        macos
  --pre-auth-banner STRING
                        banner shown to every client before login
  --post-auth-banner STRING
                        banner shown only to clients that authenticate
                        successfully

logging:
  -o FILE, --output FILE
                        append the log to FILE (plain with timestamps)
  -t, --timestamps      prefix console lines with a timestamp
  --plain               disable ANSI colors on the console
```

## A word of warning

- This is a pentesting tool. Only point it at systems and networks you are
authorized to test. 

- `--open-auth --forward` means ANYONE can tunnel through
your host - know what you're exposing before you run it.

## License

MIT
