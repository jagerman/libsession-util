/// A minimal Session client that runs a command for authorized senders.
///
/// It keeps its account and message history in a SQLite database (so the same Session ID comes
/// back on every run), polls its swarm for direct messages, and for each one from a session ID in
/// its whitelist runs a configured command, replying with whatever it printed.  Anything from
/// anyone else gets "Unauthorized." and nothing is run.
///
/// What the message contributes is the `ARGS` argument of the configured command, which its own
/// arguments replace: `/bin/echo ARGS` echoes the message, `/bin/echo hello ARGS` echoes it after
/// "hello", and `/bin/echo` ignores it and answers the same thing every time.
///
///     session-echo-bot echo-bot.conf
///
/// See echo-bot.conf.example for the configuration file.

#include <fcntl.h>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fmt/std.h>
#include <oxenc/hex.h>
#include <poll.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <oxen/log.hpp>
#include <session/client.hpp>
#include <session/network/network_opt.hpp>
#include <session/network/session_network.hpp>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

using namespace std::literals;
namespace fs = std::filesystem;
namespace opt = session::network::opt;

using session::client::await;
using session::client::Client;
using session::client::ConversationId;
using session::client::Message;
using session::client::SendState;

auto cat = oxen::log::Cat("echo-bot");

/// Ceiling on the doubling backoff between send retries: past this the bot is waiting out an
/// outage rather than a glitch, and retrying more often achieves nothing.
constexpr std::chrono::seconds MAX_RETRY_DELAY = 10min;

/// The argument in a configured command that stands for the arguments the message asked with.
/// Recognised only as an argument of its own, so a command that wants to pass a literal `ARGS`
/// cannot -- which is the price of it needing no punctuation to be recognisable.
constexpr auto ARGS_SLUG = "ARGS"sv;

// -- Configuration --------------------------------------------------------------------------

struct Config {
    fs::path database = "echo-bot.db";
    fs::path cache_dir;  // Defaults to "<database>.cache"
    /// The command to run, already split into arguments.  A bare `ARGS` argument among them is
    /// where the message's own arguments go; with none, the message is only the trigger and the
    /// command runs with exactly what is configured here.
    std::vector<std::string> command;
    bool uses_args = false;  ///< Whether `command` contains the ARGS slug.
    std::unordered_set<std::string> authorized;
    bool testnet = false;
    opt::router router = opt::router::onion_requests();
    std::chrono::seconds timeout = 30s;
    std::chrono::seconds poll_interval = 20s;
    int retry_attempts = 5;
    std::chrono::seconds retry_delay = 10s;
    size_t max_output = 2000;
    std::string log_level = "*=error,echo-bot=info";
};

std::string_view trim(std::string_view s) {
    constexpr auto ws = " \t\r\n"sv;
    auto b = s.find_first_not_of(ws);
    if (b == std::string_view::npos)
        return {};
    return s.substr(b, s.find_last_not_of(ws) + 1 - b);
}

/// Parses a value that must be one of a fixed set of words, given as {word, value} pairs.
template <typename T>
T parse_enum(
        std::string_view key,
        std::string_view value,
        std::initializer_list<std::pair<std::string_view, T>> options) {
    for (const auto& [word, v] : options)
        if (value == word)
            return v;
    std::string words;
    for (const auto& [word, v] : options)
        fmt::format_to(std::back_inserter(words), "{}{}", words.empty() ? "" : ", ", word);
    throw std::runtime_error{
            fmt::format("invalid {} '{}'; expected one of: {}", key, value, words)};
}

int64_t parse_number(std::string_view key, std::string_view value) {
    int64_t n;
    auto [p, ec] = std::from_chars(value.data(), value.data() + value.size(), n);
    if (ec != std::errc{} || p != value.data() + value.size() || n < 0)
        throw std::runtime_error{fmt::format("invalid {} '{}': expected a number", key, value)};
    return n;
}

/// Splits a command line into arguments the way a shell would: on whitespace, with single quotes
/// taken literally, and double quotes and backslashes allowing whitespace and quotes to be passed
/// through.  Without this neither a configured command nor a message could pass an argument
/// containing a space.
///
/// Used for both, which is what makes `command` and a message body quote alike.
std::vector<std::string> split_args(std::string_view body) {
    std::vector<std::string> args;
    std::string current;
    bool have_current = false;
    for (size_t i = 0; i < body.size(); i++) {
        char c = body[i];
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (have_current) {
                args.push_back(std::move(current));
                current.clear();
                have_current = false;
            }
            continue;
        }
        have_current = true;
        if (c == '\'') {
            auto end = body.find('\'', i + 1);
            if (end == std::string_view::npos)
                end = body.size();
            current += body.substr(i + 1, end - i - 1);
            i = end;
        } else if (c == '"') {
            for (i++; i < body.size() && body[i] != '"'; i++) {
                if (body[i] == '\\' && i + 1 < body.size() &&
                    (body[i + 1] == '"' || body[i + 1] == '\\'))
                    i++;
                current += body[i];
            }
        } else if (c == '\\' && i + 1 < body.size()) {
            current += body[++i];
        } else {
            current += c;
        }
    }
    if (have_current)
        args.push_back(std::move(current));
    return args;
}

Config parse_config(const fs::path& path) {
    std::ifstream in{path};
    if (!in.is_open())
        throw std::runtime_error{fmt::format("Unable to open config file {}", path)};

    Config cfg;
    std::string line;
    for (int lineno = 1; std::getline(in, line); lineno++) {
        auto l = trim(line);
        if (l.empty() || l.front() == '#')
            continue;

        auto eq = l.find('=');
        if (eq == std::string_view::npos)
            throw std::runtime_error{fmt::format("{}:{}: expected 'key = value'", path, lineno)};
        auto key = trim(l.substr(0, eq));
        auto value = trim(l.substr(eq + 1));

        try {
            if (key == "database")
                cfg.database = value;
            else if (key == "cache_dir")
                cfg.cache_dir = value;
            else if (key == "command")
                cfg.command = split_args(value);
            else if (key == "authorized") {
                if (value.size() != 66 || !value.starts_with("05") || !oxenc::is_hex(value))
                    throw std::runtime_error{fmt::format(
                            "invalid authorized session ID '{}': expected 66 hex digits "
                            "beginning with 05",
                            value)};
                cfg.authorized.emplace(value);
            } else if (key == "network")
                cfg.testnet = parse_enum<bool>(key, value, {{"mainnet", false}, {"testnet", true}});
            else if (key == "router")
                cfg.router = parse_enum<opt::router>(
                        key,
                        value,
                        {{"onionreq", opt::router::onion_requests()},
#ifdef ENABLE_NETWORKING_SROUTER
                         {"srouter", opt::router::session_router()},
#endif
                         {"direct", opt::router::direct()}});
            else if (key == "timeout")
                cfg.timeout = std::chrono::seconds{parse_number(key, value)};
            else if (key == "poll_interval")
                cfg.poll_interval = std::chrono::seconds{parse_number(key, value)};
            else if (key == "retry_attempts")
                cfg.retry_attempts = static_cast<int>(parse_number(key, value));
            else if (key == "retry_delay")
                cfg.retry_delay = std::chrono::seconds{parse_number(key, value)};
            else if (key == "max_output")
                cfg.max_output = static_cast<size_t>(parse_number(key, value));
            else if (key == "log_level")
                cfg.log_level = value;
            else
                throw std::runtime_error{fmt::format("unknown setting '{}'", key)};
        } catch (const std::exception& e) {
            throw std::runtime_error{fmt::format("{}:{}: {}", path, lineno, e.what())};
        }
    }

    if (cfg.command.empty())
        throw std::runtime_error{fmt::format("{}: no `command` configured", path)};
    cfg.uses_args = std::ranges::find(cfg.command, ARGS_SLUG) != cfg.command.end();
    // Only for a path: a bare name is resolved against $PATH by execvp, which we are not going to
    // reimplement here just to complain a little earlier.
    const auto& binary = cfg.command.front();
    if (binary.find('/') != std::string::npos && access(binary.c_str(), X_OK) != 0)
        throw std::runtime_error{fmt::format(
                "{}: command {} is not executable: {}", path, binary, std::strerror(errno))};
    if (cfg.poll_interval < 1s)
        throw std::runtime_error{fmt::format("{}: poll_interval must be at least 1s", path)};
    if (cfg.cache_dir.empty())
        cfg.cache_dir = cfg.database.string() + ".cache";

    return cfg;
}

// -- Running the command --------------------------------------------------------------------

/// The command's arguments for one message: what `command` was configured with, with the ARGS slug
/// replaced in place by the arguments the message asked with.  With no slug the message's
/// arguments are not passed at all and the command runs with exactly what was configured, which is
/// how a bot whose command takes no input is written.
std::vector<std::string> build_argv(
        const std::vector<std::string>& command, std::string_view body) {
    std::vector<std::string> argv;
    argv.reserve(command.size());
    for (const auto& arg : command) {
        if (arg != ARGS_SLUG) {
            argv.push_back(arg);
            continue;
        }
        auto args = split_args(body);
        argv.insert(argv.end(), std::move_iterator{args.begin()}, std::move_iterator{args.end()});
    }
    return argv;
}

struct CommandResult {
    std::string output;
    int exit_status = -1;  // Negative: killed by signal -exit_status
    bool timed_out = false;
    bool truncated = false;
};

/// Closes every descriptor above stderr, from the child of a fork and so with only
/// async-signal-safe calls.  The command is not ours and has no business holding the bot's swarm
/// sockets or database open, whether or not each of them remembered O_CLOEXEC.
void close_inherited_fds() {
#if defined(__linux__) && defined(SYS_close_range)
    // Kernel 5.9+; falls through to the loop below with ENOSYS on anything older.
    if (syscall(SYS_close_range, STDERR_FILENO + 1, ~0U, 0) == 0)
        return;
#endif
    auto max_fd = sysconf(_SC_OPEN_MAX);
    for (int fd = STDERR_FILENO + 1; fd < static_cast<int>(max_fd); fd++)
        close(fd);
}

/// Runs `command args...`, with its stdout and stderr captured together and its stdin at
/// /dev/null.  No shell is involved: the arguments go to the binary as given, so nothing in a
/// message body can be interpreted as shell syntax.
CommandResult run_command(
        const std::vector<std::string>& args, std::chrono::seconds timeout, size_t max_output) {

    const auto& command = args.front();
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& a : args)
        argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);

    int pipefd[2];
    if (pipe(pipefd) == -1)
        throw std::runtime_error{fmt::format("pipe() failed: {}", std::strerror(errno))};

    auto pid = fork();
    if (pid == -1) {
        auto err = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        throw std::runtime_error{fmt::format("fork() failed: {}", std::strerror(err))};
    }

    if (pid == 0) {
        // Child.  Everything here has to be async-signal-safe, because the rest of the process
        // has threads (the network and event loops) that did not survive the fork.
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, nullptr);

        // Its own session, for two reasons: the timeout below can then kill whatever the command
        // spawned rather than only the command, and the command is detached from our controlling
        // terminal, so it cannot read from it or push input back into it.
        setsid();

        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close_inherited_fds();  // Takes both pipe fds with it, now that they are duplicated.
        execvp(command.c_str(), argv.data());
        _exit(127);
    }

    close(pipefd[1]);

    CommandResult result;
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (true) {
        int wait_ms = -1;
        if (timeout > 0s) {
            auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now());
            wait_ms = static_cast<int>(std::max(int64_t{0}, left.count()));
        }
        pollfd pfd{.fd = pipefd[0], .events = POLLIN, .revents = 0};
        int p = poll(&pfd, 1, wait_ms);
        if (p == 0) {
            result.timed_out = true;
            // The whole process group, so that a command that spawned children does not leave them
            // running after we stop waiting for it; `pid` is the group's id because the child made
            // itself a session leader.  The second kill is for the case where that failed and the
            // group does not exist.
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            break;
        }
        if (p < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        char buf[4096];
        auto n = read(pipefd[0], buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        // Keep draining past the limit rather than stopping: a command that filled the pipe and
        // is blocked on writing more would never exit if we stopped reading here.
        if (result.output.size() < max_output) {
            auto take = std::min(max_output - result.output.size(), static_cast<size_t>(n));
            result.output.append(buf, take);
            if (take < static_cast<size_t>(n))
                result.truncated = true;
        } else
            result.truncated = true;
    }
    close(pipefd[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) == -1 && errno == EINTR) {
    }
    result.exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);

    return result;
}

/// The reply to send for a command that ran: what it printed, plus whatever the sender cannot see
/// from the output alone (that it failed, was killed, or had more to say than we will send).
std::string format_reply(const CommandResult& r, std::chrono::seconds timeout) {
    auto body = r.output;
    while (!body.empty() && (body.back() == '\n' || body.back() == '\r'))
        body.pop_back();

    std::vector<std::string> notes;
    if (r.truncated)
        notes.push_back("output truncated");
    if (r.timed_out)
        notes.push_back(fmt::format("killed after {}s", timeout.count()));
    else if (r.exit_status < 0)
        notes.push_back(fmt::format("killed by signal {}", -r.exit_status));
    else if (r.exit_status != 0)
        notes.push_back(fmt::format("exit status {}", r.exit_status));
    else if (body.empty())
        notes.push_back("no output");

    if (notes.empty())
        return body;
    return fmt::format("{}{}[{}]", body, body.empty() ? "" : "\n", fmt::join(notes, "; "));
}

// -- The bot --------------------------------------------------------------------------------

class EchoBot {
  public:
    explicit EchoBot(Config config) : _config{std::move(config)} {
        _client = std::make_unique<Client>(
                _config.database,
                session::client::callbacks{
                        .message_added =
                                [this](ConversationId&& id, Message&& msg) {
                                    _on_message(std::move(id), std::move(msg));
                                },
                        .message_updated =
                                [this](ConversationId&& id, Message&& msg) {
                                    _on_send_state(std::move(id), std::move(msg));
                                },
                });

        fmt::print("Session ID: {}\n", _client->core.globals.session_id_hex());
        fmt::print(
                "Database:   {}\nCommand:    {}{}\nAuthorized: {} session ID(s)\n",
                _config.database,
                fmt::join(_config.command, " "),
                _config.uses_args ? "" : "  (message arguments not passed: no ARGS)",
                _config.authorized.size());
        std::fflush(stdout);

        _worker = std::thread{[this] { _run_jobs(); }};

        _client->core.set_poll_interval(_config.poll_interval);
        _client->core.make_network(
                _config.testnet ? opt::netid::testnet() : opt::netid::mainnet(),
                _config.router,
                opt::cache_directory{_config.cache_dir});
    }

    ~EchoBot() {
        {
            std::lock_guard lock{_mutex};
            _stopping = true;
            if (!_jobs.empty())
                oxen::log::warning(cat, "Dropping {} queued message(s)", _jobs.size());
        }
        _cv.notify_all();
        if (_worker.joinable())
            _worker.join();
    }

  private:
    struct Job {
        ConversationId conversation;
        int64_t reply_to;  ///< The message being answered, which the reply quotes.
        std::string body;
        bool authorized;
    };

    struct Retry {
        int64_t message_id;
        std::string conversation;  // For the log line only; the message knows where it belongs.
        int attempt;
    };

    /// Runs on Core's event loop, so it only decides what to do and hands it to the worker:
    /// running a command and waiting for the reply to be sent would stop Core polling, sending and
    /// decrypting for as long as the command takes.
    void _on_message(ConversationId&& id, Message&& msg) {
        if (msg.outgoing || id.type() != ConversationId::Type::dm)
            return;

        auto sender = oxenc::to_hex(msg.sender);
        bool authorized = _config.authorized.count(sender) > 0;
        // An empty message asks for nothing -- unless the body is not what is being asked with, in
        // which case any message at all is the whole request.
        if (authorized && _config.uses_args && trim(msg.body).empty()) {
            oxen::log::info(cat, "Ignoring empty message from {}", sender);
            return;
        }

        oxen::log::info(
                cat,
                "{} message from {}: {}",
                authorized ? "Authorized" : "Unauthorized",
                sender,
                msg.body);

        {
            std::lock_guard lock{_mutex};
            if (_stopping)
                return;
            _jobs.push_back(Job{std::move(id), msg.id, std::move(msg.body), authorized});
        }
        _cv.notify_one();
    }

    /// A send reaching a terminal state, also on Core's event loop.
    ///
    /// Nothing below this reports a failed send back to us a second time, and nothing retries one
    /// on our behalf: the library's `MessageSendStatus::retrying` is declared but not implemented,
    /// so a store that failed leaves the message in `failed` and stays there.  This is the only
    /// notice we get that a reply did not arrive -- `send_message()` returned long before, having
    /// only stored and dispatched it -- so it is where the retrying has to start.
    void _on_send_state(ConversationId&& id, Message&& msg) {
        if (!msg.outgoing)
            return;

        std::lock_guard lock{_mutex};
        if (_stopping)
            return;

        if (msg.send_state != SendState::failed && msg.send_state != SendState::interrupted) {
            // Anything else is either progress or success, and either way the message is no longer
            // owed a retry: drop what we were counting for it.
            if (msg.send_state == SendState::sent)
                _attempts.erase(msg.id);
            return;
        }

        // A message has two sends -- the recipient's copy and the one for our own swarm -- and
        // this fires for both, so a failure already waiting out its backoff must not be scheduled
        // a second time by the other one changing state.
        if (std::ranges::any_of(
                    _retries, [&](const auto& r) { return r.second.message_id == msg.id; }))
            return;

        auto attempt = ++_attempts[msg.id];
        if (attempt > _config.retry_attempts) {
            oxen::log::warning(
                    cat,
                    "Giving up on the reply to {} after {} attempt(s)",
                    id.to_string(),
                    attempt - 1);
            _attempts.erase(msg.id);
            return;
        }

        // Doubling, because what makes a send fail is usually not over by the time the first retry
        // would go out, and a bot with nobody watching it should not spend an outage retrying at
        // full speed.
        auto delay = std::min(_config.retry_delay * (1 << (attempt - 1)), MAX_RETRY_DELAY);
        oxen::log::info(
                cat,
                "Reply to {} failed to send; retrying in {} (attempt {} of {})",
                id.to_string(),
                delay,
                attempt,
                _config.retry_attempts);

        _retries.emplace(
                std::chrono::steady_clock::now() + delay, Retry{msg.id, id.to_string(), attempt});
        _cv.notify_one();
    }

    /// Re-dispatches one message whose backoff has elapsed.  `retry_send` answers false for a
    /// message that is no longer retryable -- it succeeded in the meantime, or it is
    /// `unsendable` -- which is an answer rather than a failure, and ends the attempts either way.
    void _retry(const Retry& r) {
        try {
            if (!_client->retry_send(r.message_id, await)) {
                std::lock_guard lock{_mutex};
                _attempts.erase(r.message_id);
            }
        } catch (const std::exception& e) {
            oxen::log::error(cat, "Retrying the reply to {} threw: {}", r.conversation, e.what());
        }
    }

    void _run_jobs() {
        while (true) {
            std::optional<Job> job;
            std::vector<Retry> due;
            {
                std::unique_lock lock{_mutex};
                if (_retries.empty())
                    _cv.wait(lock, [this] {
                        return _stopping || !_jobs.empty() || !_retries.empty();
                    });
                else
                    _cv.wait_until(lock, _retries.begin()->first, [this] {
                        return _stopping || !_jobs.empty();
                    });
                if (_stopping)
                    return;

                auto now = std::chrono::steady_clock::now();
                for (auto it = _retries.begin(); it != _retries.end() && it->first <= now;
                     it = _retries.erase(it))
                    due.push_back(std::move(it->second));

                if (!_jobs.empty()) {
                    job = std::move(_jobs.front());
                    _jobs.pop_front();
                }
            }

            for (const auto& r : due)
                _retry(r);

            if (!job)
                continue;

            std::string reply;
            if (!job->authorized)
                reply = "Unauthorized.";
            else {
                try {
                    reply = format_reply(
                            run_command(
                                    build_argv(_config.command, job->body),
                                    _config.timeout,
                                    _config.max_output),
                            _config.timeout);
                } catch (const std::exception& e) {
                    oxen::log::error(
                            cat, "Failed to run {}: {}", _config.command.front(), e.what());
                    reply = fmt::format("[failed to run command: {}]", e.what());
                }
            }

            // Sent as a reply to what was asked, so that a client shows the output under the
            // command that produced it: a bot that answers several messages at once is otherwise
            // a column of results with nothing saying which is which.
            try {
                _client->send_message(
                        job->conversation, {.body = reply, .reply_to = job->reply_to}, await);
            } catch (const std::invalid_argument& e) {
                // The quoted message is gone -- the conversation was cleared while the command
                // ran, say.  Losing the quote is better than losing the answer.
                oxen::log::warning(
                        cat,
                        "Replying without a quote to {}: {}",
                        job->conversation.to_string(),
                        e.what());
                try {
                    _client->send_message(job->conversation, {.body = reply}, await);
                } catch (const std::exception& e2) {
                    oxen::log::error(
                            cat,
                            "Failed to reply to {}: {}",
                            job->conversation.to_string(),
                            e2.what());
                }
            } catch (const std::exception& e) {
                oxen::log::error(
                        cat, "Failed to reply to {}: {}", job->conversation.to_string(), e.what());
            }
        }
    }

    Config _config;
    std::unique_ptr<Client> _client;

    std::mutex _mutex;
    std::condition_variable _cv;
    std::deque<Job> _jobs;
    /// Sends waiting to be retried, earliest first, and how many attempts each message has had.
    /// The count outlives the schedule entry: a retry that fails is reported to `_on_send_state`
    /// again, and what stops it going round forever is finding its own count there.
    std::multimap<std::chrono::steady_clock::time_point, Retry> _retries;
    std::unordered_map<int64_t, int> _attempts;
    bool _stopping = false;
    std::thread _worker;
};

void setup_logging(const std::string& level) {
    oxen::log::add_sink(oxen::log::Type::Print, "stderr");
    oxen::log::apply_categories(level);
}

}  // namespace

int main(int argc, char* argv[]) {
    std::vector<std::string_view> args{argv + 1, argv + argc};
    // The message is optional: a command with no ARGS slug does not read one, and typing an empty
    // string to say so is ceremony.
    bool dry_run = (args.size() == 2 || args.size() == 3) && args[1] == "--run";
    auto dry_run_body = args.size() == 3 ? args[2] : ""sv;
    if (!(args.size() == 1 || dry_run) || args[0] == "-h" || args[0] == "--help") {
        fmt::print(
                stderr,
                "Usage: {0} CONFIG-FILE\n"
                "       {0} CONFIG-FILE --run [MESSAGE]\n\n"
                "The second form runs MESSAGE through the configured command and prints the "
                "reply it would send, touching neither the database nor the network.\n\n"
                "See echo-bot.conf.example.\n",
                argv[0]);
        return args.size() == 1 ? 0 : 1;
    }

    // Blocked here, before any of the library's threads exist, so that they inherit the block and
    // the signal is delivered to the sigwait below rather than killing us mid-message.
    sigset_t quit_signals;
    sigemptyset(&quit_signals);
    sigaddset(&quit_signals, SIGINT);
    sigaddset(&quit_signals, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &quit_signals, nullptr);

    try {
        auto config = parse_config(args[0]);
        setup_logging(config.log_level);

        if (dry_run) {
            fmt::print(
                    "{}\n",
                    format_reply(
                            run_command(
                                    build_argv(config.command, dry_run_body),
                                    config.timeout,
                                    config.max_output),
                            config.timeout));
            return 0;
        }

        EchoBot bot{std::move(config)};

        int sig = 0;
        while (sigwait(&quit_signals, &sig) == -1 && errno == EINTR) {
        }
        fmt::print("\nCaught signal {}, shutting down\n", sig);
    } catch (const std::exception& e) {
        fmt::print(stderr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}
