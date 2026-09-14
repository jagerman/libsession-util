# session-echo-bot

A Session account that runs a command for people you trust.

It keeps its account, contacts and message history in a SQLite database, so it comes back as the
same Session ID on every run.  Once it is polling, a DM from a session ID in its whitelist runs the
configured command, and whatever it prints (stdout and stderr together) is sent back as the reply,
quoting the message that asked.  A DM from anyone else is answered with "Unauthorized." and runs
nothing.

`command` is a command line, and the bare argument `ARGS` in it is where the message's own
arguments go — the only thing a message contributes:

| `command` | a message of `one two` runs |
|---|---|
| `/bin/echo ARGS` | `/bin/echo one two` |
| `/bin/echo hello ARGS` | `/bin/echo hello one two` |
| `/bin/echo` | `/bin/echo` — the message is only a trigger |

With no `ARGS` the message is not read at all, so an empty one is a perfectly good request and gets
an answer rather than being ignored.

Not part of the default build; ask for it by name:

    cmake --build build --target session-echo-bot

    cp examples/echo-bot/echo-bot.conf.example echo-bot.conf
    $EDITOR echo-bot.conf          # set `command` and at least one `authorized` session ID
    ./build/examples/echo-bot/session-echo-bot echo-bot.conf

It prints its own Session ID at startup; that is what you message it at.  `--run MESSAGE` runs a
message through the configured command and prints the reply it would have sent, without touching
the database or the network, which is the quick way to check a `command` setting.

A reply whose send fails is retried by the bot itself, on a doubling backoff (`retry_attempts`,
`retry_delay`): libsession reports the failure through `message_updated` and offers `retry_send()`,
but never retries a message on its own — `MessageSendStatus::retrying` is declared and not yet
implemented — so the policy belongs to the client. Only while the bot runs, though: a reply still
unsent when it exits is left alone on the next start.

`authorized = ALL` in place of a session ID lets anyone who messages the bot run the command.

No shell is involved: the message body is split into arguments (with shell-style quoting, so
`"two words"` is one argument) and passed to the binary directly, so shell syntax in a message is
just text.  The trust boundary is the whitelist and the binary: an authorized sender can run the
configured binary with *any* arguments, so `command = /bin/sh` hands them a shell, and a binary
that takes a filename as an argument hands them every file the bot can read.  Point it at
something that only does what you want done — and note that with `ALL`, "an authorized sender" is
anyone who learns the bot's Session ID.
