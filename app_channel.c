// app_channel.c — a channel session, both ends in one handler.
//
// The host holds the log. A member holds an epoch and the two positions it has
// read between, asks, and prints what comes back into the terminal grid through
// the ANSI parser. The host answers and never speaks first; THE HOST KEEPS
// NOTHING PER MEMBER, so a dropped stream costs only the asking again and a
// thousand members cost a thousand times nothing.
//
// A POSITION IS STORED BYTES FROM THE START OF THE CHANNEL'S LOG. Stored rather
// than rendered, because a rendered length moves when a contact is renamed --
// line_render puts the name in and author_name reads it from the HOST's
// contacts -- and nothing would tell a member holding a position that it had.
// The host finds a position by walking BACK from the newest entry, which is
// short both for a member catching up and for one stepping back a screen at a
// time. Nothing in the filesystem records a log's length, so the host keeps one
// per channel it hosts: primed by a walk, then maintained on append.
//
// DEDUP IS THE LOG, NOT A TABLE. A request carrying text is appended only if the
// log holds no line by this author at or after the position the member sent. One
// request is outstanding at a time, so a member cannot have sent a second line:
// a repeat at the same position is a retransmission whose reply was lost, and it
// is answered without being stored again.
//
// Both directions send one chunk: struct chunk_hdr (20 bytes) then text. A
// request carries `from` -- give me what follows this, or CURSOR_TAIL for the
// last chunk. A reply fills `from` and `to` with the span it carries: ask `to`
// to go forward, ask below `from` to go back. Nothing marks the direction,
// because the chunk names its host and that settles it -- a channel of ours is
// somebody asking, anyone else's is our host answering. CURSOR_NOTICE in `from`
// answers a command, shown once and never held. A reply whose epoch differs
// means the numbering changed and everything held is void. Chunks ride
// PORT_CHANNEL, and one fits a stream segment, so it arrives whole and there is
// nothing to gather and no per-peer state to keep.
//
// The member keeps the bytes on its screen in a ring. The screen either FOLLOWS
// the newest text or is PARKED where the reader scrolled it, with text still
// arriving behind it. Scrolling off the top of the ring asks the host for the
// CURSOR_STEP of log before what is held. One request is outstanding at a time.
// A chunk unanswered for channel_silence_ms is reported and nothing more --
// stream.c owns retransmission, and tearing the link down here restarted the
// stream underneath it, which is what once made a lost reply cost a duplicate.
//
// A channel we host is read without a network: the same answer is composed
// locally.
//
// Portable C, core 0.

#include "hal.h"
#include <string.h>
#include <stdio.h>
#include "config.h"
#include "kernel.h"
#include "stream.h"
#include "peer_data.h"
#include "channel_log.h"
#include "contacts.h"
#include "netif.h"
#include "view.h"
#include "filesystem.h"

#define CHUNK_MAX            1024
#define CURSOR_TAIL          0xFFFFFFFFu   // ask: the last chunk, wherever it is
#define CURSOR_NOTICE        0xFFFFFFFEu   // reply: a command's answer, shown once
#define CURSOR_STEP          1024          // how far back one scroll off the top reaches
#define CHANNEL_LINE_MAX     (8 + MAX_NAME + 4 + CHANNEL_TEXT_MAX)   // "HH:MM name: text\r\n"
#define CHANNEL_WINDOW_LINES 64

// ---- structs -----------------------------------------------------------------

// `room` sits second so every 32-bit field is 4-byte aligned.
#pragma pack(push, 1)
struct chunk_hdr {
	uint16_t length;    // be: bytes of text after this header
	uint16_t room;      // be: which channel on that host, 1..65535
	uint32_t host_id;   // be: whose channel
	uint32_t epoch;     // be: the numbering both positions are counted in
	uint32_t from;      // be: asking, give me what follows this; reply, where this starts
	uint32_t to;        // be: reply only, where this ends -- ask this to go on
};
#pragma pack(pop)

#define CHUNK_HDR ((int)sizeof(struct chunk_hdr))
_Static_assert(sizeof(struct chunk_hdr) == 20, "the chunk header is 20 bytes");
#define CHANNEL_TEXT_ROOM (CHUNK_MAX - CHUNK_HDR)


// The display seam: the device renders through the terminal grid, a headless
// host does nothing.
void channel_display_reset(void);
void channel_display_clear(void);
void channel_display_text(const char *text, int len);
void channel_display_pump(void);
const char *channel_display_key(int key);
bool channel_display_has_text(void);
bool channel_display_move(int dir);
int  channel_display_capacity(void);

static void retitle(void);
static bool ring_at_newest(void);
static void take_reply(uint32_t epoch, uint32_t from, uint32_t to,
                       const char *text, int text_len);

uint32_t channel_silence_ms = 10000;
uint32_t channel_poll_ms    = 10000;

static stream_handle channel_stream;

// What the member is looking at. Survives backgrounding.
static uint32_t view_host;
static uint16_t view_channel;
static uint32_t held_epoch;                // what the host last told us
static uint32_t held_from;                 // start of the log text we hold
static uint32_t held_to;                   // its end: ask this to go forward
static uint32_t asked_from;                // the position this request asked for
static bool     asked_back;                // ...and it was a reach into history
static bool     view_on_top;
static bool     view_waiting;
static bool     view_have_lines;
static uint16_t pending_channel;           // for the next APP_FOREGROUND; see channel_open

// The outbox: one chunk.
static uint8_t  out_chunk[CHUNK_MAX];
static int      out_len;
static bool     out_pending;
static uint32_t out_next_ms;
static uint32_t out_asked_ms;
static bool     drain_more;                // the last reply carried text: ask again

// THE BYTES ON THE SCREEN, AND NOTHING MORE. The screen reads forward from
// screen_top for one screenful, so the ring only has to hold that much and a
// little to grow into.
//
// Text runs from `oldest` forward to `next`, and BOTH ENDS MOVE: newer text
// appends at `next`, older text prepends below `oldest`. One pointer is not
// enough -- until the ring fills they are far apart, and writing older text
// below `next` would land it on top of the newest.
//
// screen_top sits between the two. Appending into a full ring drops from the
// oldest end, but never past screen_top: that is the one byte the screen is
// reading from.
//
// The screen is in one of two states. FOLLOWING, it sits at the end and rides
// the text as it appends. PARKED -- the user scrolled up -- it stays exactly
// where it is while text keeps arriving behind it, off the bottom of the
// screen, until scrolling back down to the end starts it following again.
struct ring {
	int     next;                 // one past the newest byte
	int     oldest;               // the oldest byte held
	int     screen_top;           // where the screen starts reading
	bool    following;            // the screen rides the newest text
	uint8_t *buffer;              // ring_bytes of it, allocated on the first append
};

static struct ring scrollback;
static int ring_bytes;


// ---- the chunk ---------------------------------------------------------------

// Returns the chunk's total length, or 0 if it will not fit.
static int chunk_put(uint8_t *buf, int cap, uint16_t room, uint32_t host_id,
                     uint32_t epoch, uint32_t from, uint32_t to,
                     const char *text, int text_len) {
	if (text_len < 0)
		text_len = 0;
	if (cap < CHUNK_HDR || text_len > cap - CHUNK_HDR || text_len > 0xFFFF)
		return 0;
	struct chunk_hdr h;
	memset(&h, 0, sizeof h);
	h.length  = be16((uint16_t)text_len);
	h.room    = be16(room);
	h.host_id = be32(host_id);
	h.epoch   = be32(epoch);
	h.from    = be32(from);
	h.to      = be32(to);
	memcpy(buf, &h, sizeof h);
	if (text_len > 0)
		memcpy(buf + CHUNK_HDR, text, (size_t)text_len);
	return CHUNK_HDR + text_len;
}

// ---- where a position is, on the host ----------------------------------------

// A POSITION IS STORED BYTES FROM THE START OF THE CHANNEL'S LOG. Stored, not
// rendered: line_render puts the author's name in, author_name reads that from
// OUR contacts, and renaming a contact would silently move every position after
// that person's first line with no epoch change to signal it.
//
// Nothing in the filesystem records a log's length (struct log_index holds only
// the newest entry's offset), so it is kept here: one walk to prime, then by
// hand on every append. Per channel we HOST -- never per member.
#define CHANNEL_LEN_SLOTS 8

struct chan_len {
	uint32_t host;
	uint16_t id;
	uint32_t total;
	bool     used;
};

static struct chan_len chan_lens[CHANNEL_LEN_SLOTS];

// Stored size of one line, from the entry's cleartext header -- no payload is
// decrypted, which is what makes priming a whole log affordable.
static uint32_t line_stored_len(uint32_t host, uint16_t id, uint32_t entry) {
	struct file_entry_info info;
	if (!file_entry_stat(thread_file(host, id), entry, &info))
		return 0;
	return (uint32_t)info.length;
}

static struct chan_len *chan_len_slot(uint32_t host, uint16_t id) {
	struct chan_len *free_slot = NULL;
	for (int i = 0; i < CHANNEL_LEN_SLOTS; i++) {
		if (chan_lens[i].used && chan_lens[i].host == host && chan_lens[i].id == id)
			return &chan_lens[i];
		if (!chan_lens[i].used && !free_slot)
			free_slot = &chan_lens[i];
	}
	if (!free_slot)
		free_slot = &chan_lens[0];      // evicting only costs the next asker a walk
	free_slot->used  = true;
	free_slot->host  = host;
	free_slot->id    = id;
	free_slot->total = 0;
	for (uint32_t e = channel_newest(host, id); e != FILE_NONE;
	     e = channel_older(host, id, e))
		free_slot->total += line_stored_len(host, id, e);
	return free_slot;
}

static uint32_t chan_total(uint32_t host, uint16_t id) {
	return chan_len_slot(host, id)->total;
}

static void chan_total_add(uint32_t host, uint16_t id, uint32_t n) {
	chan_len_slot(host, id)->total += n;
}

// The oldest entry at or after `pos`, found by walking BACK from the newest --
// the distance from the end is what is short, both for a member catching up and
// for one stepping back a screen at a time. *out_pos is where that entry starts.
static uint32_t entry_at_pos(uint32_t host, uint16_t id, uint32_t pos,
                             uint32_t *out_pos) {
	uint32_t total = chan_total(host, id);
	if (pos > total)
		pos = total;
	uint32_t entry = channel_newest(host, id);
	uint32_t start = total;
	uint32_t found = FILE_NONE;
	while (entry != FILE_NONE) {
		uint32_t len = line_stored_len(host, id, entry);
		if (start < len)
			break;
		start -= len;
		if (start < pos)
			break;
		found    = entry;
		*out_pos = start;
		entry    = channel_older(host, id, entry);
	}
	if (found == FILE_NONE)
		*out_pos = total;
	return found;
}

// ---- the host half -----------------------------------------------------------

// The host names authors, so members see the host's names.
static void author_name(uint32_t author, char *out, int max) {
	if (author == channel_my_partkey()) {
		snprintf(out, (size_t)max, "%s", "Host");
		return;
	}
	struct contact_record contact;
	if (contact_get(&contact, author) && contact.name[0]) {
		snprintf(out, (size_t)max, "%s", contact.name);
		return;
	}
	snprintf(out, (size_t)max, "%08x", (unsigned)author);
}

static void stamp_hhmm(uint32_t stamp, char *out, int max) {
	unsigned mins = (unsigned)((stamp / 60) % 60);
	unsigned hrs  = (unsigned)((stamp / 3600) % 24);
	snprintf(out, (size_t)max, "%02u:%02u", hrs, mins);
}

// THE STAMP AND THE NAME ONLY START A TURN. Consecutive lines by one author are
// one thing said -- a whole answer arrives as many lines -- and repeating the
// header on each costs more of a small screen than it tells the reader. `said`
// carries the author across the calls; NULL asks for the header every time,
// which is what a measuring pass wants: it can only over-estimate.
// Returns the line's length, or -1.
static int line_render(uint32_t host, uint16_t id, uint32_t entry,
                       uint32_t *said, char *out, int cap) {
	uint32_t author = 0, stamp = 0;
	char text[CHANNEL_TEXT_MAX + 1];
	if (channel_line_read(host, id, entry, &author, &stamp,
	                      text, (int)sizeof text) < 0)
		return -1;
	int n;
	if (said && *said == author) {
		n = snprintf(out, (size_t)cap, "%s\r\n", text);
	} else {
		char who[MAX_NAME];
		char when[8];
		author_name(author, who, (int)sizeof who);
		stamp_hhmm(stamp, when, (int)sizeof when);
		n = snprintf(out, (size_t)cap, "%s %s: %s\r\n", when, who, text);
	}
	if (n < 0 || n >= cap)
		return -1;
	if (said)
		*said = author;
	return n;
}

// Collect ids backward from `from` (its newest is included), newest first.
static int collect_back(uint32_t host, uint16_t id, uint32_t from, int cap,
                        uint32_t *ids, int max_lines) {
	static char scratch[CHANNEL_LINE_MAX];
	int lines = 0;
	int bytes = 0;
	uint32_t entry = from;
	while (entry != FILE_NONE && lines < max_lines) {
		int n = line_render(host, id, entry, NULL, scratch, (int)sizeof scratch);
		if (n < 0)
			break;
		if (bytes + n > cap)
			break;
		ids[lines++] = entry;
		bytes += n;
		entry = channel_older(host, id, entry);
	}
	return lines;
}

// Render ids that were collected newest first, oldest first into `out`.
static int render_ids(uint32_t host, uint16_t id, const uint32_t *ids, int lines,
                      char *out, int cap, uint32_t *newest, uint32_t *oldest) {
	int used = 0;
	uint32_t said = 0;
	for (int i = lines - 1; i >= 0; i--) {
		int n = line_render(host, id, ids[i], &said, out + used, cap - used);
		if (n < 0)
			break;
		used += n;
	}
	if (lines > 0) {
		*newest = ids[0];
		*oldest = ids[lines - 1];
	}
	return used;
}

// A window of rendered text, and the two positions it spans. CURSOR_TAIL asks
// for the last chunk -- what a member holding nothing wants, and what one whose
// epoch went stale is given. Any other position means "start here".
static int render_window(uint32_t host, uint16_t id, uint32_t want,
                         char *out, int cap, uint32_t *from, uint32_t *to) {
	uint32_t ids[CHANNEL_WINDOW_LINES];
	uint32_t total = chan_total(host, id);
	*from = total;
	*to   = total;

	if (want == CURSOR_TAIL) {
		int lines = collect_back(host, id, channel_newest(host, id), cap,
		                         ids, CHANNEL_WINDOW_LINES);
		if (lines <= 0)
			return 0;
		uint32_t back = 0;
		for (int i = 0; i < lines; i++)
			back += line_stored_len(host, id, ids[i]);
		*from = total - back;
		uint32_t newest = FILE_NONE;
		uint32_t oldest = FILE_NONE;
		return render_ids(host, id, ids, lines, out, cap, &newest, &oldest);
	}

	uint32_t start = total;
	uint32_t entry = entry_at_pos(host, id, want, &start);
	*from = start;
	*to   = start;
	int used  = 0;
	int lines = 0;
	uint32_t said = 0;
	while (entry != FILE_NONE && lines < CHANNEL_WINDOW_LINES) {
		int n = line_render(host, id, entry, &said, out + used, cap - used);
		if (n < 0)
			break;
		*to  += line_stored_len(host, id, entry);
		used += n;
		lines++;
		entry = channel_newer(host, id, entry);
	}
	return used;
}

// Has a line by this author landed at or after `pos`? If one has, the request in
// hand is a retransmission whose reply was lost: one request is outstanding at a
// time, so the member cannot have sent a second line. A member holding nothing
// has lost its view anyway, so its text is taken.
static bool author_wrote_since(uint32_t host, uint16_t id, uint32_t pos,
                               uint32_t author) {
	if (pos == CURSOR_TAIL)
		return false;
	static char scratch[CHANNEL_TEXT_MAX + 1];
	uint32_t start = 0;
	uint32_t entry = entry_at_pos(host, id, pos, &start);
	while (entry != FILE_NONE) {
		uint32_t who = 0;
		uint32_t stamp = 0;
		if (channel_line_read(host, id, entry, &who, &stamp,
		                      scratch, (int)sizeof scratch) >= 0 && who == author)
			return true;
		entry = channel_newer(host, id, entry);
	}
	return false;
}

static bool parse_partkey(const char *s, int len, uint32_t *out) {
	if (len < 8)
		return false;
	uint32_t v = 0;
	for (int i = 0; i < 8; i++) {
		char c = s[i];
		uint32_t d;
		if (c >= '0' && c <= '9')
			d = (uint32_t)(c - '0');
		else if (c >= 'a' && c <= 'f')
			d = (uint32_t)(c - 'a') + 10u;
		else if (c >= 'A' && c <= 'F')
			d = (uint32_t)(c - 'A') + 10u;
		else
			return false;
		v = (v << 4) | d;
	}
	*out = v;
	return true;
}

static bool word_is(const char *text, int len, const char *word) {
	int n = (int)strlen(word);
	if (len < n)
		return false;
	if (memcmp(text, word, (size_t)n) != 0)
		return false;
	return len == n || text[n] == ' ';
}

// /list is anyone's; /add, /remove and /clear are the host's, and `local`
// (typed on this device) is what says the host is asking. Writes the answer
// and returns its length.
static int channel_command(uint32_t host, uint16_t id, const char *text, int len,
                           bool local, char *out, int cap) {
	const char *body = text + 1;
	int         blen = len - 1;

	if (word_is(body, blen, "list")) {
		int used = snprintf(out, (size_t)cap, "members of this channel:\r\n");
		int n = channel_member_count(host, id);
		for (int i = 0; i < n; i++) {
			uint32_t uid = 0;
			if (!channel_member_at(host, id, i, &uid))
				break;
			struct contact_record c;
			const char *name = "";
			if (contact_get(&c, uid))
				name = c.name;
			int w = snprintf(out + used, (size_t)(cap - used), "  %08x  %s\r\n",
			                 (unsigned)uid, name);
			if (w < 0 || used + w >= cap)
				break;
			used += w;
		}
		if (n == 0)
			used += snprintf(out + used, (size_t)(cap - used), "  nobody yet\r\n");
		return used;
	}

	if (!local)
		return snprintf(out, (size_t)cap, "only the host may do that\r\n");

	if (word_is(body, blen, "add") || word_is(body, blen, "remove")) {
		bool adding = (body[0] == 'a');
		int at = 3;
		if (!adding)
			at = 6;
		while (at < blen && body[at] == ' ')
			at++;
		const char *verb = "remove";
		const char *said = "out";
		if (adding) {
			verb = "add";
			said = "in";
		}
		uint32_t uid = 0;
		if (!parse_partkey(body + at, blen - at, &uid))
			return snprintf(out, (size_t)cap, "usage: /%s <8 hex digits>\r\n", verb);
		bool ok;
		if (adding)
			ok = channel_admit(host, id, uid);
		else
			ok = channel_expel(host, id, uid);
		if (!ok)
			return snprintf(out, (size_t)cap, "could not change %08x\r\n", (unsigned)uid);
		return snprintf(out, (size_t)cap, "%08x is %s\r\n", (unsigned)uid, said);
	}

	if (word_is(body, blen, "clear")) {
		if (!channel_reset(host, id))
			return snprintf(out, (size_t)cap, "could not clear it\r\n");
		return snprintf(out, (size_t)cap, "cleared\r\n");
	}

	return snprintf(out, (size_t)cap, "no such command\r\n");
}

// What a request means: a command answers with its output, anything else
// appends its text and answers with what follows `from`, an already gated entry
// id. Both a peer's request and our own reading go through here. `*out_id` is
// what the reply carries: the last line sent, or NOTICE for a command.
static int channel_answer(uint32_t host, uint16_t id, uint32_t author,
                          uint32_t want, const char *text, int text_len,
                          bool local, char *out, int cap,
                          uint32_t *out_from, uint32_t *out_to) {
	*out_from = CURSOR_NOTICE;
	*out_to   = CURSOR_NOTICE;

	if (text_len >= 1 && text[0] == '/')
		return channel_command(host, id, text, text_len, local, out, cap);

	if (text_len > 0) {
		if (author_wrote_since(host, id, want, author)) {
			hal_debug(LOG_EVERYTHING, "channel: %08x said it again — already stored\n",
			          (unsigned)author);
		} else if (channel_append(host, id, author, text, text_len) == FILE_NONE) {
			hal_debug(LOG_WARNING, "channel: %08x line not stored\n", (unsigned)author);
		} else {
			chan_total_add(host, id, (uint32_t)(sizeof(struct channel_line) + text_len));
			hal_debug(LOG_EVERYTHING, "channel: %08x wrote %d bytes\n",
			          (unsigned)author, text_len);
		}
	}
	return render_window(host, id, want, out, cap, out_from, out_to);
}

// One request off a stream. The first chunk is the open, so this is where a
// peer is refused: dropped without an answer, like a malformed one.
static void serve_request(uint32_t peer, uint16_t room, uint32_t epoch_in,
                          uint32_t want_in, const char *text, int text_len) {
	if (room == 0) {
		hal_debug(LOG_WARNING, "channel: %08x asked for room %u\n",
		          (unsigned)peer, (unsigned)room);
		return;
	}
	// Not channel_my_partkey: a group chat is filed under us and a per-user log
	// under the member who asked, and only the app owning this id knows which.
	uint32_t host = channel_log_owner(room, peer);
	uint16_t id   = room;
	struct channel_record probe;
	if (!channel_get(host, id, &probe))
		return;
	if (!allow_into_channel(id, peer)) {
		hal_debug(LOG_WARNING, "channel: %08x not admitted to room %u\n",
		          (unsigned)peer, (unsigned)room);
		return;
	}

	// A member counting in another numbering holds nothing we can use, so its
	// position is dropped and it is answered from the tail.
	uint32_t epoch = channel_epoch(host, id);
	uint32_t want  = CURSOR_TAIL;
	if (epoch_in == epoch)
		want = want_in;

	static uint8_t reply[CHUNK_MAX];
	uint32_t from = CURSOR_NOTICE;
	uint32_t to   = CURSOR_NOTICE;
	int used = channel_answer(host, id, peer, want, text, text_len, false,
	                          (char *)reply + CHUNK_HDR, CHANNEL_TEXT_ROOM,
	                          &from, &to);
	int total = chunk_put(reply, CHUNK_MAX, room, host, epoch, from, to, NULL, 0);
	if (total == 0)
		return;
	struct chunk_hdr *h = (struct chunk_hdr *)reply;
	h->length = be16((uint16_t)used);
	if (stream_write(channel_stream, peer, reply, CHUNK_HDR + used) <= 0)
		hal_debug(LOG_WARNING, "channel: reply to %08x did not go\n", (unsigned)peer);
	else
		hal_debug(LOG_EVERYTHING, "channel: served %d bytes to %08x, %u..%u\n",
		          used, (unsigned)peer, (unsigned)from, (unsigned)to);
}

// ---- the member half ---------------------------------------------------------

static void serve_self(const char *text, int len) {
	// Reading our own channel: we are the member asking.
	uint32_t host = channel_log_owner(view_channel, channel_my_partkey());
	static char body[CHANNEL_TEXT_ROOM];
	uint32_t epoch = channel_epoch(host, view_channel);
	uint32_t from  = CURSOR_NOTICE;
	uint32_t to    = CURSOR_NOTICE;
	int used = channel_answer(host, view_channel, host, asked_from, text, len,
	                          true, body, (int)sizeof body, &from, &to);
	take_reply(epoch, from, to, body, used);
}

// Queue a request. Empty text is a pure fetch. Asking does not move the screen:
// whether the answer lands under it or scrolls it is the ring's state, not the
// request's, so reading back through history survives a poll arriving.
static void queue_request(const char *text, int len) {
	if (view_host == channel_my_partkey()) {
		serve_self(text, len);
		return;
	}
	int n = chunk_put((uint8_t *)out_chunk, CHUNK_MAX, view_channel, view_host,
	                  held_epoch, asked_from, 0, text, len);
	if (n == 0)
		return;
	out_len      = n;
	out_pending  = true;
	out_next_ms  = 0;
	out_asked_ms = now_ms();
	view_waiting = true;
	retitle();
}

// Ask for what follows what we hold. held_to is CURSOR_TAIL until the first
// reply lands, which is exactly the request for the last chunk.
static void ask_forward(const char *text, int len) {
	asked_from = held_to;
	asked_back = false;
	queue_request(text, len);
}

// Ask for the CURSOR_STEP of log before the oldest we hold, stopping at its
// start. Never carries text: a line is always said at the live end.
static void ask_backward(void) {
	if (held_from == CURSOR_TAIL || held_from == 0)
		return;                       // nothing older to ask for
	uint32_t want = 0;
	if (held_from > CURSOR_STEP)
		want = held_from - CURSOR_STEP;
	asked_from = want;
	asked_back = true;
	queue_request(NULL, 0);
}

static void outbox_pump(void) {
	uint32_t now = now_ms();
	// A reply that carried text may have more behind it, so the next ask does
	// not wait for the poll: an answer of several chunks would otherwise arrive
	// one chunk per channel_poll_ms. An empty reply says the host is drained.
	if (drain_more && !view_waiting && !out_pending) {
		drain_more = false;
		ask_forward(NULL, 0);
	}
	// Nothing else starts a request once a reply has landed. Deliberately not
	// gated on the screen being at the newest: a parked reader still has to
	// collect what arrives behind them.
	if (!view_waiting && !out_pending &&
	    view_host != channel_my_partkey() &&
	    (int32_t)(now - out_asked_ms) >= (int32_t)channel_poll_ms)
		ask_forward(NULL, 0);
	// Silence is reported, not acted on: stream.c owns retransmission and
	// relinking, and tearing the link down here only restarted the stream
	// underneath it, which is what made a lost reply cost a duplicate line.
	if (view_waiting && (int32_t)(now - out_asked_ms) >= (int32_t)channel_silence_ms) {
		hal_debug(LOG_WARNING, "channel: %08x silent for %us\n",
		          (unsigned)view_host, (unsigned)(channel_silence_ms / 1000));
		out_asked_ms = now;
	}
	if (!out_pending && view_waiting && out_len > 0 &&
	    !stream_exists(channel_stream, view_host)) {   // the stream was reaped under us
		out_pending = true;
		out_next_ms = now;
	}
	if (!out_pending)
		return;
	if ((int32_t)(now - out_next_ms) < 0)
		return;
	if (stream_write(channel_stream, view_host, out_chunk, out_len) <= 0) {
		out_next_ms = now + 500;        // refused: in flight, or the link is coming up
		return;
	}
	out_pending = false;
}

// ---- the window ------------------------------------------------------------

static int ring_wrap(int at) {
	if (at >= ring_bytes)
		return at - ring_bytes;
	if (at < 0)
		return at + ring_bytes;
	return at;
}

// The buffer outlives every reset: a reset empties the ring, it does not give
// the memory back.
static bool ring_ready(void) {
	if (scrollback.buffer)
		return true;
	scrollback.buffer = kernel_alloc((size_t)kernel_cfg->channel_ring_bytes);
	if (!scrollback.buffer)
		return false;
	ring_bytes = kernel_cfg->channel_ring_bytes;
	return true;
}

static void ring_reset(void) {
	uint8_t *keep = scrollback.buffer;
	memset(&scrollback, 0, sizeof scrollback);
	scrollback.buffer = keep;
	if (keep)
		memset(keep, 0, (size_t)ring_bytes);
	scrollback.following = true;      // an empty screen is already at the end
}

// One byte forward at the seam, eating the oldest. False when the seam has
// reached the cursor: full, as far as the reader is concerned.
// One byte onto the newest end. A full ring drops from the oldest end to make
// room, which is what scrolls the screen -- but never the byte the screen is
// reading from, and that is the only thing that can refuse an append.
static bool ring_append(char c) {
	if (!ring_ready())
		return false;
	int at = ring_wrap(scrollback.next + 1);
	if (at == scrollback.oldest) {
		if (scrollback.oldest == scrollback.screen_top)
			return false;
		scrollback.oldest = ring_wrap(scrollback.oldest + 1);
	}
	scrollback.buffer[scrollback.next] = (uint8_t)c;
	scrollback.next = at;
	return true;
}

// One byte onto the oldest end, fed from the end of the text so what arrives
// first ends up oldest. A full ring refuses: the newest is worth more than more
// history, and the caller sees where it stopped.
static bool ring_prepend(char c) {
	if (!ring_ready())
		return false;
	int at = ring_wrap(scrollback.oldest - 1);
	if (at == scrollback.next)
		return false;
	scrollback.buffer[at] = (uint8_t)c;
	scrollback.oldest = at;
	return true;
}

static int ring_oldest(void) {
	return scrollback.oldest;
}

// How far `to` sits ahead of `from` around the ring.
static int ring_span(int from, int to) {
	return ring_wrap(to - from);
}

// Put the screen on the newest text: the last screenful ending at the seam.
static void ring_follow(void) {
	int held = ring_span(ring_oldest(), scrollback.next);
	int room = channel_display_capacity();
	if (held > room)
		held = room;
	scrollback.screen_top = ring_wrap(scrollback.next - held);
}

// Is everything up to the newest byte already on the screen?
static bool ring_at_newest(void) {
	return ring_span(scrollback.screen_top, scrollback.next) <=
	       channel_display_capacity();
}

// Paint the screenful ending at the cursor. The run can straddle the buffer's
// end, and channel_display_text feeds a parser, so two calls concatenate.
static void ring_render(void) {
	int from = scrollback.screen_top;
	int held = ring_span(from, scrollback.next);
	int room = channel_display_capacity();
	if (held > room)
		held = room;
	channel_display_clear();
	if (held <= 0)
		return;
	int first = held;
	if (from + first > ring_bytes)
		first = ring_bytes - from;
	channel_display_text((const char *)scrollback.buffer + from, first);
	if (held > first)
		channel_display_text((const char *)scrollback.buffer, held - first);
}

// The end of the line before `at`, or the oldest byte held. Lines end in CRLF,
// so the pair at `at` belongs to the line being left behind.
static int ring_line_back(int at) {
	int oldest = ring_oldest();
	int room   = ring_span(oldest, at);
	if (room <= 0)
		return oldest;
	int i = ring_wrap(at - 1);
	room--;
	if (room > 0 && scrollback.buffer[i] == '\n') {
		i = ring_wrap(i - 1);
		room--;
	}
	if (room > 0 && scrollback.buffer[i] == '\r') {
		i = ring_wrap(i - 1);
		room--;
	}
	while (room > 0 && scrollback.buffer[ring_wrap(i - 1)] != '\n') {
		i = ring_wrap(i - 1);
		room--;
	}
	return i;
}

static int ring_line_forward(int at) {
	int room = ring_span(at, scrollback.next);
	int i = at;
	while (room > 0 && scrollback.buffer[i] != '\n') {
		i = ring_wrap(i + 1);
		room--;
	}
	if (room > 0)
		i = ring_wrap(i + 1);
	return i;
}

static void take_reply(uint32_t epoch, uint32_t from, uint32_t to,
                       const char *text, int text_len) {
	if (epoch != held_epoch) {      // the numbering changed: everything held is void
		held_epoch = epoch;
		held_from  = CURSOR_TAIL;
		held_to    = CURSOR_TAIL;
		ring_reset();
	}
	view_waiting = false;
	out_pending  = false;

	if (from == CURSOR_NOTICE) {   // shown once, not part of the log
		retitle();
		channel_display_clear();
		if (text_len > 0)
			channel_display_text(text, text_len);
		return;
	}
	// A reply spanning ground we already hold is one the transport gave us twice.
	bool held_already = (held_to != CURSOR_TAIL && from >= held_from && to <= held_to);

	if (text_len > 0 && !held_already) {
		if (asked_back) {
			int wrote = 0;
			while (wrote < text_len && ring_prepend(text[text_len - 1 - wrote]))
				wrote++;
			held_from = from;
			// They asked to see further back, so show what just arrived.
			scrollback.screen_top = ring_oldest();
		} else {
			// Following: hand the whole ring to the writer first, then put the
			// screen back on the tail. Parked: the screen does not move, and the
			// text lands behind it until the seam reaches it.
			if (scrollback.following)
				scrollback.screen_top = scrollback.next;
			int wrote = 0;
			while (wrote < text_len && ring_append(text[wrote]))
				wrote++;
			if (wrote < text_len)
				hal_debug(LOG_WARNING, "channel: ring wedged at the screen, %d byte(s) dropped\n",
				          text_len - wrote);
			held_to = to;
			if (held_from == CURSOR_TAIL)
				held_from = from;
			drain_more = true;    // there may be more behind it; ask again at once
			if (scrollback.following)
				ring_follow();
		}
		view_have_lines = true;
	}
	retitle();
	ring_render();
	hal_debug(LOG_EVERYTHING, "channel: +%d bytes, %u..%u held %u..%u\n",
	          text_len, (unsigned)from, (unsigned)to,
	          (unsigned)held_from, (unsigned)held_to);
}

// ---- taking bytes off the stream --------------------------------------------

// Which way a chunk goes is the host it names, and nothing else: a channel of
// ours is somebody asking, anyone else's is our own host answering.
static void chunk_dispatch(uint32_t peer, const uint8_t *chunk, int total) {
	struct chunk_hdr h;
	memcpy(&h, chunk, sizeof h);
	uint32_t host_id = be32(h.host_id);
	uint16_t room    = be16(h.room);
	uint32_t epoch   = be32(h.epoch);
	uint32_t from    = be32(h.from);
	uint32_t to      = be32(h.to);
	const char *text = (const char *)chunk + CHUNK_HDR;
	int text_len     = total - CHUNK_HDR;

	if (host_id == channel_my_partkey()) {
		serve_request(peer, room, epoch, from, text, text_len);
		return;
	}
	if (peer != view_host || room != view_channel)
		return;
	take_reply(epoch, from, to, text, text_len);
}

// ---- the screen --------------------------------------------------------------

// The link state is netif's answer, not a guess.
static void retitle(void) {
	struct channel_record record;
	const char *name = "channel";
	if (channel_get(view_host, view_channel, &record) && record.name[0])
		name = record.name;

	// The link outranks the fetch: a request that cannot leave is not loading,
	// it is a link the user has to do something about, so say that instead.
	const char *state = "no host";
	struct contact_record contact;
	if (view_host == channel_my_partkey()) {
		state = "ready";
	} else if (contact_get(&contact, view_host)) {
		switch (netif_peer(contact.key)) {
		case NETIF_PEER_UP:
			state = "ready";
			if (view_waiting)
				state = "loading";
			break;
		case NETIF_PEER_TRYING:
			state = "connecting";
			break;
		default:
			state = "offline";
			break;
		}
	}

	static char title[CHANNEL_NAME_MAX + 16];
	snprintf(title, sizeof title, "%s - %s", name, state);
	screen_title(title);
}

void channel_open(uint16_t channel_id) {
	pending_channel = channel_id;
}

bool channel_screen_say(const char *text) {
	if (!view_on_top || !text || !text[0])
		return false;
	scrollback.following = true;      // a line you send lands at the end
	ask_forward(text, (int)strlen(text));
	return true;
}

int app_channel_main(int message, uint32_t param) {
	switch (message) {

	case APP_INIT:
		channel_stream = kernel_listen_stream(PORT_CHANNEL, app_channel_main);
		if (!channel_stream)
			hal_debug(LOG_ERROR, "channel: no stream port\n");
		return 1;

	case APP_FOREGROUND: {
		bool fresh = (param != view_host || pending_channel != view_channel);
		view_host    = param;
		view_channel = pending_channel;
		view_on_top  = true;
		view_set(NULL, NULL, NULL, NULL, NULL, NULL);   // a view with no list
		retitle();
		if (fresh) {
			channel_display_reset();
			view_have_lines = false;
			held_epoch      = 0;   // never a legal epoch, so the first reply resets us
			held_from       = CURSOR_TAIL;
			held_to         = CURSOR_TAIL;
			ring_reset();
		}
		// Coming back asks for what followed what we hold, at the end of it: the
		// host never speaks first, so anything posted while we looked away is
		// only ours once we ask for it.
		scrollback.following = true;
		ask_forward(NULL, 0);
		return 1;
	}

	case APP_BACKGROUND:
		view_on_top = false;
		// The host never speaks first, so what is held goes stale the moment we
		// look away. Coming back asks again; the window we keep is only what
		// fills the screen until the answer lands.
		view_have_lines = false;
		return 1;

	case NOTIFY_PEER_UP:
		if (view_on_top && param == view_host && view_waiting) {
			out_pending = true;    // the chunk refused before the link came up
			out_next_ms = 0;
		}
		return 1;

	// A chunk is never more than CHUNK_MAX and goes out in one stream_write, so
	// it arrives as one whole segment and there is nothing to gather. Keeping
	// CHUNK_MAX at or under stream.c's segment size is what makes that true.
	case NOTIFY_STREAM_DATA: {
		static uint8_t buf[CHUNK_MAX];
		int n = stream_read(channel_stream, param, buf, CHUNK_MAX);
		if (n < CHUNK_HDR)
			return 1;
		struct chunk_hdr h;
		memcpy(&h, buf, sizeof h);
		if (CHUNK_HDR + (int)be16(h.length) != n) {
			hal_debug(LOG_WARNING, "channel: %08x sent %d bytes for a %d byte chunk\n",
			          (unsigned)param, n, CHUNK_HDR + (int)be16(h.length));
			return 1;
		}
		chunk_dispatch(param, buf, n);
		return 1;
	}

	case APP_KEYSTROKE: {
		// Backspace on an empty composer is the leave gesture: declined, so
		// ui.cpp acts on it.
		if ((int)param == VIEW_K_BACKSPACE && !channel_display_has_text())
			return 0;
		// Inside the composer's text PREV/NEXT move the caret; off its edges,
		// and as UP/DOWN, they scroll the log. Only an edge asks the host.
		if ((int)param == VIEW_K_PREV && channel_display_move(-1))
			return 1;
		if ((int)param == VIEW_K_NEXT && channel_display_move(1))
			return 1;
		// Going up parks the screen; text keeps arriving behind it. At the top of
		// the ring the host is asked for the CURSOR_STEP before it.
		if ((int)param == VIEW_K_UP || (int)param == VIEW_K_PREV) {
			scrollback.following = false;
			if (scrollback.screen_top == ring_oldest()) {
				ask_backward();
				return 1;
			}
			scrollback.screen_top = ring_line_back(scrollback.screen_top);
			ring_render();
			return 1;
		}
		if ((int)param == VIEW_K_DOWN || (int)param == VIEW_K_NEXT) {
			if (ring_at_newest()) {
				scrollback.following = true;   // back at the end: ride it again
				ask_forward(NULL, 0);          // and ask for anything new
				return 1;
			}
			scrollback.screen_top = ring_line_forward(scrollback.screen_top);
			// Reaching the end by scrolling is what resumes following.
			if (ring_at_newest())
				scrollback.following = true;
			ring_render();
			return 1;
		}
		// A line you send lands at the end, so sending goes back to following it.
		const char *line = channel_display_key((int)param);
		if (line) {
			scrollback.following = true;
			ask_forward(line, (int)strlen(line));
		}
		return 1;
	}

	case APP_PUMP:
		if (!view_on_top)
			return 1;
		outbox_pump();
		retitle();                      // the link can change with nothing else happening
		channel_display_pump();
		return 1;

	default:
		return 0;
	}
}
