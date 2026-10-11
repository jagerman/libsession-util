#pragma once

#include <string_view>

namespace client_test {

/// src/client/schema/full_schema.sql as it stood before client migration 006_ids_never_reused,
/// comments stripped: what a database created then was built from.
inline constexpr std::string_view client_schema_before_006 = R"sql(
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    session_id BLOB NOT NULL UNIQUE,
    name TEXT,
    profile_pic_url TEXT,
    profile_pic_key BLOB,
    profile_updated INTEGER NOT NULL DEFAULT 0,
    pro_flags INTEGER NOT NULL DEFAULT 0,
    pro_revocation_tag BLOB,
    pro_expiry INTEGER
) STRICT;

CREATE TABLE contacts (
    account INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    nickname TEXT,
    approved INTEGER NOT NULL DEFAULT 0,
    approved_me INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    group_id BLOB NOT NULL UNIQUE
) STRICT;

CREATE TABLE communities (
    id INTEGER PRIMARY KEY,
    base_url TEXT NOT NULL,
    room TEXT NOT NULL,
    UNIQUE (base_url, room)
) STRICT;

CREATE TABLE conversations (
    id INTEGER PRIMARY KEY,
    dm INTEGER UNIQUE REFERENCES accounts(id),
    closed_group INTEGER UNIQUE REFERENCES groups(id),
    community INTEGER UNIQUE REFERENCES communities(id),
    created INTEGER NOT NULL,
    last_activity INTEGER NOT NULL,
    last_read INTEGER NOT NULL DEFAULT 0,
    count INTEGER NOT NULL DEFAULT 0,
    unread_count INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 0,
    marked_unread INTEGER NOT NULL DEFAULT 0,
    notifications INTEGER NOT NULL DEFAULT 0,
    mute_until INTEGER NOT NULL DEFAULT 0,
    exp_mode INTEGER NOT NULL DEFAULT 0,
    exp_timer INTEGER NOT NULL DEFAULT 0,
    auto_download INTEGER,
    CHECK ((dm IS NOT NULL) + (closed_group IS NOT NULL) + (community IS NOT NULL) = 1)
) STRICT;

CREATE INDEX conversations_order ON conversations(priority DESC, last_activity DESC);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    conversation INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    msgid INTEGER,
    swarm_hash TEXT UNIQUE,
    sender INTEGER NOT NULL REFERENCES accounts(id),
    outgoing INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    body TEXT NOT NULL,
    send_state INTEGER,
    sync_send_state INTEGER,
    deleted INTEGER,
    gallery INTEGER NOT NULL DEFAULT 0,
    reply_author INTEGER REFERENCES accounts(id),
    reply_timestamp INTEGER,
    reply_msgid INTEGER
) STRICT;

CREATE UNIQUE INDEX messages_msgid ON messages(conversation, timestamp, msgid);

CREATE INDEX messages_history ON messages(conversation, timestamp DESC, id DESC);
CREATE INDEX messages_unread ON messages(conversation, timestamp) WHERE outgoing = 0;

CREATE INDEX messages_wire_key ON messages(conversation, sender, timestamp);

CREATE INDEX messages_reply_target ON messages(conversation, reply_author, reply_timestamp)
    WHERE reply_timestamp IS NOT NULL;

CREATE TRIGGER messages_insert AFTER INSERT ON messages
BEGIN
    UPDATE conversations SET count = count + 1 WHERE id = NEW.conversation;
END;

CREATE TRIGGER messages_delete AFTER DELETE ON messages
BEGIN
    UPDATE conversations SET count = count - 1 WHERE id = OLD.conversation;
END;

CREATE TRIGGER messages_move AFTER UPDATE OF conversation ON messages
WHEN OLD.conversation != NEW.conversation
BEGIN
    UPDATE conversations SET count = count - 1 WHERE id = OLD.conversation;
    UPDATE conversations SET count = count + 1 WHERE id = NEW.conversation;
END;

CREATE TABLE attachment_cache (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    last_used INTEGER NOT NULL
) STRICT;

CREATE INDEX attachment_cache_lru ON attachment_cache(last_used);

CREATE TABLE message_raw_content (
    message INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    content BLOB NOT NULL
) STRICT;

CREATE TABLE message_attachments (
    message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    idx INTEGER NOT NULL,
    path TEXT,
    content_type TEXT,
    filename TEXT,
    flags INTEGER NOT NULL DEFAULT 0,
    width INTEGER,
    height INTEGER,
    url TEXT,
    key BLOB,
    size INTEGER,
    digest BLOB,
    saved_at INTEGER,
    unavailable INTEGER,
    cached INTEGER REFERENCES attachment_cache(id) ON DELETE SET NULL,
    thumbhash BLOB,
    PRIMARY KEY (message, idx)
) STRICT;

CREATE INDEX message_attachments_url ON message_attachments(url) WHERE url IS NOT NULL;

CREATE INDEX message_attachments_cached ON message_attachments(cached) WHERE cached IS NOT NULL;
)sql";

}  // namespace client_test
