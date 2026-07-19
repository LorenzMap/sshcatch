# sshcatch

A quick-deploy SSH server for tunneling (local/remote/dynamic) and simple SCP /
SFTP transfers - it **never opens a shell**.

By default all features are disabled: connections are logged and closed. Turn on
only what you need with the flags described below. Handy on an engagement when
you want a controlled SSH endpoint (a tunnel relay or a file drop) without 
setting up a full `sshd`.

Built on [asyncssh](https://github.com/ronf/asyncssh).

This is a pentesting tool. Only point it at systems and networks you are authorized 
to test.

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

Needs Python 3.10+. A host key is auto-generated in the working directory on
first run (or point `--host-key` at your own).

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

#### SCP / SFTP

**Symlinks** are handled very restrictively: On upload they create a placeholder file
that contains the original target. On download they are outright denied. 

The host key, `authorized_keys`, logfile and the sshcatch script itself are **protected** 
and hidden when they live inside the SCP directory.

Uploads **never overwrite** an existing file. The new file gets a numeric suffix 
(`loot.tar` -> `loot_1.tar`). Non-existent parent folders are created.

Renames and Remove operations are denied.

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
sshcatch -1 -u arthur:42 --version-banner debian \
         --pre-auth-banner "What is the answer to life the universe and everything" \
         --post-auth-banner "flag{So_Long_and_Thanks_for_All_the_Fish}" \
         -o sshcatch.log -t
```


My favorite one: Reverse tunnel and SCP uploads for the keys in
`./authorized-keys` while posing as an Ubuntu SSH server on port 2222:

```
# Server
sshcatch --reverse --authorized-keys ./authorized-keys --scp-upload --version-banner ubuntu -p 2222

# Client
ssh -NR 9000:localhost:22 user@host -p 2222     # reverse tunnel
scp -P 2222 loot.tar user@host:.                # upload
```


## Options

```
usage: sshcatch [-h] [--version] [-p PORT] [-b BIND] [--host-key FILE] [-1]
                [-u USER:PASS] [--open-auth] [--authorized-keys FILE]
                [--forward] [--reverse] [--scp-upload] [--scp-download]
                [--scp-dir DIR] [--version-banner STRING]
                [--pre-auth-banner STRING] [--post-auth-banner STRING]
                [-q | -v] [-o FILE] [-t] [--plain]

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p PORT, --port PORT  listen port (default: 22)
  -b BIND, --bind BIND  bind address (default: all IPv4/v6 interfaces)
  --host-key FILE       server host key file (default: auto-generate)
  -1, --single          close the listener after first successful
                        authentication (and exit when that connection ends)

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
                        instead of overwriting - symlinks become placeholder
                        files
  --scp-download        enable file download (SCP/SFTP read) - symlinks are
                        denied
  --scp-dir DIR         directory for SCP/SFTP (default: cwd) - sensitive
                        files (host-key, authorized_keys, logfile) are
                        protected

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
  -q, --quiet           print nothing on console
  -v, --verbose         print additional information to the console
                        (repeatable)
  -o FILE, --output FILE
                        append the log to FILE (plain with timestamps)
  -t, --timestamps      prefix console lines with a timestamp
  --plain               disable ANSI colors on the console
```

## License

MIT
