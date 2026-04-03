/*
 * chaoschat.c — Stream-embedded peer-to-peer chat over TCP
 * ─────────────────────────────────────────────────────────
 *
 * CONCEPT
 *   A continuous hex-character stream flows between two peers.
 *   Chat messages are stamped with a tag and embedded inside
 *   the stream; the receiver scans for the tag, extracts the
 *   message, and erases the tag+message from the buffer.
 *
 * TAG FORMAT
 *   <CHATKEY><SEQ>-<HEXLEN>---<HEXDATA>
 *   e.g.  KKs245ff*3-22---48656C6C6F20576F726C64
 *
 *   • CHATKEY  : shared secret, also the search tag.
 *                Must contain at least one non-hex character
 *                so it cannot appear accidentally in the stream.
 *   • SEQ      : monotonically increasing integer (dedup).
 *   • HEXLEN   : number of hex chars in HEXDATA.
 *   • HEXDATA  : uppercase hex-encoded message text.
 *
 * STREAM FLOW
 *   1. User A (listen mode)  starts, waits on chosen port.
 *   2. User B (connect mode) enters A's IP:port and connects.
 *   3. A (the listener / "server") sends 16 KB of random hex
 *      as a warm-up burst; then both sides stream continuously.
 *   4. On Send, the outgoing stream tick embeds the tagged
 *      message surrounded by random hex padding.
 *   5. Receiver scans its rolling buffer, finds the tag,
 *      decodes the message, shows it, then erases the tag
 *      and payload from the buffer.
 *
 * BUILD
 *   make
 *   — or —
 *   gcc -D_GNU_SOURCE -Wall -Wextra -O2 chaoschat.c \
 *       $(pkg-config --cflags --libs gtk+-3.0) -lpthread -o chaoschat
 */

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
/* OpenSSL — link with -lcrypto */
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>

#define SHA256_DIGEST_LENGTH 32   /* 256 bits */


/* ══════════════════════════════════════════════════
 *  Constants
 * ══════════════════════════════════════════════════ */
#define MAX_KEY_LEN          128
#define MAX_MSG_LEN          4096
#define RECV_BUF_SIZE        (512 * 1024)   /* rolling receive window        */
#define RECV_TRIM_TO         (256 * 1024)   /* keep this much after trim     */
#define SEND_CHUNK_SIZE      512            /* hex chars per stream tick     */
#define SEND_INTERVAL_US     30000          /* 30 ms between stream ticks    */
#define INITIAL_STREAM_BYTES (16 * 1024)    /* warm-up burst (bytes)         */
#define MAX_SEQ_TRACK        65536          /* remembered received seq nums  */
#define BACKLOG              1

/* ══════════════════════════════════════════════════
 *  Application state (singleton)
 * ══════════════════════════════════════════════════ */
typedef enum { STATE_IDLE, STATE_CONNECTING, STATE_CHATTING } AppState;


typedef struct {
    unsigned char current_key[SHA256_DIGEST_LENGTH];
    size_t        bytes_processed;
    char          hex_tag[65]; 
    char          chaff_step_buf[16384]; // The missing member
} RatchetState;

typedef struct {
    AppState         state;

    /* Network */
    int              sock;          /* active data socket               */
    int              server_fd;     /* listening socket (server mode)   */
    bool             is_server;     /* true = we accepted the conn      */
    int              my_port;
    char             target_ip[128];
    int              target_port;

    /* Shared secret / tag */
    char             chat_key[MAX_KEY_LEN];
    char             username[64];          /* local display name            */
    char             peer_name[64];         /* filled in on first msg recv   */

    /* Outbound message (one slot; send thread drains it) */
    pthread_mutex_t  out_lock;
    char             out_tag[MAX_MSG_LEN * 2 + MAX_KEY_LEN + 64];
    bool             out_ready;
    int              send_seq;

    /* Received-seq dedup */
    pthread_mutex_t  seq_lock;
    int              seen_seq[MAX_SEQ_TRACK];
    int              seen_count;

    /* Receive rolling buffer */
    pthread_mutex_t  buf_lock;
    char            *recv_buf;
    size_t           recv_len;

    volatile bool    running;

    /* ── GTK widgets ── */
    GtkWidget       *window;
    GtkWidget       *headerbar;   /* CSD titlebar — full CSS control      */
    GtkWidget       *stack;
    GtkWidget       *status_bar;

    /* Setup page */
    GtkWidget       *ent_port;
    GtkWidget       *ent_target;
    GtkWidget       *ent_key;
    GtkWidget       *ent_username;
    GtkWidget       *btn_connect;
    GtkWidget       *spinner;

    /* Chat page */
    GtkTextBuffer   *chat_buf;
    GtkWidget       *chat_view;
    GtkWidget       *ent_msg;
    GtkWidget       *btn_send;
    GtkWidget       *lbl_peer;
    GtkWidget       *stream_indicator;

    RatchetState tx_state; // Transmission ratchet
    RatchetState rx_state; // Receiver ratchet
    
    pthread_mutex_t ratchet_lock;

    char user_name[64];
} Chat;

static Chat C;   /* global singleton */

static bool perform_handshake(int sock, unsigned char *out_seed);
/* ══════════════════════════════════════════════════
 *  Hex utilities
 * ══════════════════════════════════════════════════ */
static const char HEX_UPPER[] = "0123456789ABCDEF";

/* Fill buf[0..n-1] with random uppercase hex chars; NUL-terminate. */
static void rand_hex(char *buf, size_t n)
{
    for (size_t i = 0; i < n; i++)
        buf[i] = HEX_UPPER[rand() & 0xF];
    buf[n] = '\0';
}

/* "48656C6C6F" (hexlen=10) → "Hello"; returns decoded length or -1 */
static int hex_to_str(const char *hex, size_t hexlen, char *out, size_t outmax)
{
    if (hexlen & 1 || hexlen / 2 + 1 > outmax) return -1;
    for (size_t i = 0; i < hexlen; i += 2) {
        char b[3] = { hex[i], hex[i + 1], '\0' };
        out[i / 2] = (char)strtol(b, NULL, 16);
    }
    out[hexlen / 2] = '\0';
    return (int)(hexlen / 2);
}

//----------------------------------
static void evolve_ratchet(RatchetState *s) {
    unsigned char next_hash[32];
    unsigned int len = 0;
    
    // Modern OpenSSL 3.0+ way to do SHA256 (removes deprecation warnings)
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, s->current_key, 32);
    EVP_DigestUpdate(mdctx, s->chaff_step_buf, 16384);
    EVP_DigestFinal_ex(mdctx, next_hash, &len);
    EVP_MD_CTX_free(mdctx);
    
    memcpy(s->current_key, next_hash, 32);
    
    // Update the hex_tag for the next search cycle
    for(int i = 0; i < 32; i++) {
        sprintf(s->hex_tag + (i * 2), "%02X", s->current_key[i]);
    }
    s->hex_tag[64] = '\0';
    s->bytes_processed = 0;
}

/*
 * aes_ctr_crypt — AES-256-CTR encrypt/decrypt (CTR mode is symmetric)
 *
 *  key  : 32 bytes (AES-256) — current ratchet key
 *  seq  : message sequence number — used to derive a unique 16-byte IV
 *
 *  IV derivation: SHA256(current_key || seq_as_4_bytes_big_endian),
 *  take first 16 bytes.  Unique per message; deterministic on both sides;
 *  nonce reuse is impossible as long as seq is monotonic within a ratchet
 *  window (which it is — seq is global and ever-increasing).
 *
 *  Encrypts in-place.  Returns true on success.
 */
static bool aes_ctr_crypt(unsigned char *data, size_t len,
                           const unsigned char *key, uint32_t seq)
{
    /* ── Derive IV: SHA256(key || seq_be) → first 16 bytes ── */
    unsigned char iv_hash[32];
    unsigned char seq_be[4] = {
        (unsigned char)(seq >> 24),
        (unsigned char)(seq >> 16),
        (unsigned char)(seq >>  8),
        (unsigned char)(seq      )
    };

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;
    unsigned int hlen = 0;
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, key, SHA256_DIGEST_LENGTH);
    EVP_DigestUpdate(mdctx, seq_be, 4);
    EVP_DigestFinal_ex(mdctx, iv_hash, &hlen);
    EVP_MD_CTX_free(mdctx);

    /* ── AES-256-CTR (encrypt == decrypt) ── */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int out_len = 0;
    bool ok = true;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv_hash)) {
        ok = false; goto cleanup;
    }
    /* EVP_EncryptUpdate in-place: out == in is supported for CTR mode */
    if (!EVP_EncryptUpdate(ctx, data, &out_len, data, (int)len)) {
        ok = false; goto cleanup;
    }
    /* CTR mode produces no padding; final just flushes internal state */
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, data + out_len, &final_len);

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* ══════════════════════════════════════════════════
 *  Sequence dedup
 * ══════════════════════════════════════════════════ */
/* Returns true if seq was already seen; otherwise records it. */
static bool seq_already_seen(int seq)
{
    pthread_mutex_lock(&C.seq_lock);
    for (int i = 0; i < C.seen_count; i++) {
        if (C.seen_seq[i] == seq) {
            pthread_mutex_unlock(&C.seq_lock);
            return true;
        }
    }
    if (C.seen_count < MAX_SEQ_TRACK)
        C.seen_seq[C.seen_count++] = seq;
    pthread_mutex_unlock(&C.seq_lock);
    return false;
}

/* ══════════════════════════════════════════════════
 *  Thread-safe UI helpers (post to GTK main thread)
 * ══════════════════════════════════════════════════ */
typedef struct { char text[MAX_MSG_LEN + 512]; } IdleStr;

static gboolean idle_status(gpointer p)
{
    gtk_label_set_text(GTK_LABEL(C.status_bar), ((IdleStr *)p)->text);
    free(p);
    return G_SOURCE_REMOVE;
}

/* printf-style; safe to call from any thread */
static void post_status(const char *fmt, ...)
{
    IdleStr *s = malloc(sizeof *s);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(s->text, sizeof s->text, fmt, ap);
    va_end(ap);
    g_idle_add(idle_status, s);
}

/* ─── Chat message display ─── */
typedef struct {
    char from[64];
    char msg[MAX_MSG_LEN + 4];
    bool is_self;
} ChatMsg;

static gboolean idle_chat(gpointer p)
{
    ChatMsg *cm = p;

    /* Timestamp */
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[16];
    strftime(ts, sizeof ts, "%H:%M", t);

    /* Build display line */
    char line[MAX_MSG_LEN + 256];
    snprintf(line, sizeof line, "[%s] %s: %s\n", ts, cm->from, cm->msg);

    GtkTextIter end;
    gtk_text_buffer_get_end_iter(C.chat_buf, &end);

    /* Colour tag for sender label */
    GtkTextTag *tag = NULL;
    if (cm->is_self)
        tag = gtk_text_buffer_create_tag(C.chat_buf, NULL,
                  "foreground", "#89dceb", "weight", PANGO_WEIGHT_BOLD, NULL);
    else
        tag = gtk_text_buffer_create_tag(C.chat_buf, NULL,
                  "foreground", "#f38ba8", "weight", PANGO_WEIGHT_BOLD, NULL);

    /* Timestamp (dim) */
    GtkTextTag *ts_tag = gtk_text_buffer_create_tag(C.chat_buf, NULL,
                  "foreground", "#585b70", NULL);
    char ts_part[32]; snprintf(ts_part, sizeof ts_part, "[%s] ", ts);
    gtk_text_buffer_insert_with_tags(C.chat_buf, &end, ts_part, -1, ts_tag, NULL);

    /* Sender (coloured) */
    gtk_text_buffer_get_end_iter(C.chat_buf, &end);
    char name_part[80]; snprintf(name_part, sizeof name_part, "%s: ", cm->from);
    gtk_text_buffer_insert_with_tags(C.chat_buf, &end, name_part, -1, tag, NULL);

    /* Body */
    gtk_text_buffer_get_end_iter(C.chat_buf, &end);
    char body_part[MAX_MSG_LEN + 8];
    snprintf(body_part, sizeof body_part, "%s\n", cm->msg);
    gtk_text_buffer_insert(C.chat_buf, &end, body_part, -1);

    /* Scroll to bottom */
    gtk_text_buffer_get_end_iter(C.chat_buf, &end);
    gtk_text_buffer_place_cursor(C.chat_buf, &end);
    GtkTextMark *m = gtk_text_buffer_get_insert(C.chat_buf);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(C.chat_view), m);

    free(p);
    return G_SOURCE_REMOVE;
}

static gboolean idle_update_header(gpointer p)
{
    (void)p;
    char hdr[320];
    snprintf(hdr, sizeof hdr,
             "⚡  %s  ↔  %s  ·  port: %d  ·  key: %s",
             C.username,
             C.peer_name[0] ? C.peer_name : "?",
             C.my_port, C.chat_key);
    gtk_label_set_text(GTK_LABEL(C.lbl_peer), hdr);

    /* Also update the CSD titlebar subtitle */
    if (C.headerbar) {
        char sub[128];
        snprintf(sub, sizeof sub, "connected  ·  peer: %s",
                 C.peer_name[0] ? C.peer_name : "?");
        gtk_header_bar_set_subtitle(GTK_HEADER_BAR(C.headerbar), sub);
    }
    return G_SOURCE_REMOVE;
}

static void post_msg(const char *from, const char *msg, bool is_self)
{
    ChatMsg *cm = malloc(sizeof *cm);
    strncpy(cm->from, from, sizeof cm->from - 1);
    cm->from[sizeof cm->from - 1] = '\0';
    strncpy(cm->msg,  msg,  sizeof cm->msg  - 1);
    cm->msg[sizeof cm->msg - 1] = '\0';
    cm->is_self = is_self;
    g_idle_add(idle_chat, cm);
}

/* ─── System / event messages ─── */
static gboolean idle_system(gpointer p)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(C.chat_buf, &end);
    GtkTextTag *tag = gtk_text_buffer_create_tag(C.chat_buf, NULL,
                  "foreground", "#6c7086", "style", PANGO_STYLE_ITALIC, NULL);
    char line[512];
    snprintf(line, sizeof line, "  — %s —\n", (char *)p);
    gtk_text_buffer_insert_with_tags(C.chat_buf, &end, line, -1, tag, NULL);
    free(p);
    return G_SOURCE_REMOVE;
}

static void post_system(const char *msg)
{
    g_idle_add(idle_system, strdup(msg));
}

/* ══════════════════════════════════════════════════
 *  Stream scanner
 *  Called from recv_thread after every read.
 *  Scans recv_buf for tags, extracts & removes them.
 * ══════════════════════════════════════════════════ */
static void scan_and_consume(void)
{
    pthread_mutex_lock(&C.buf_lock);

    /* Search for the 64-char SHA256 hex tag from the rx ratchet */
    char   *hex_key = C.rx_state.hex_tag;
    size_t  hklen   = 64;   /* SHA256 always 64 hex chars */

    char   *buf  = C.recv_buf;
    size_t  blen = C.recv_len;
    size_t  pos  = 0;

    /*
     * FIXED-WIDTH FORMAT (BUG 1 fix — no delimiter collision):
     *   <64-char tag> <8-char seq padded hex> <8-char hexlen padded hex> <hexdata>
     *   Total header after tag: 16 chars before hexdata.
     */
    while (pos + hklen + 16 < blen) {

        void *hit = memmem(buf + pos, blen - pos, hex_key, hklen);
        if (!hit) break;

        char  *p         = (char *)hit;
        size_t tag_start = (size_t)(p - buf);
        p += hklen;

        /* Need at least 16 more chars for seq(8) + hexlen(8) */
        if ((size_t)(p - buf) + 16 > blen) break;

        /* Parse fixed-width SEQ (8 hex chars) */
        char seq_s[9];
        memcpy(seq_s, p, 8); seq_s[8] = '\0';
        p += 8;

        /* Parse fixed-width HEXLEN (8 hex chars) */
        char hlen_s[9];
        memcpy(hlen_s, p, 8); hlen_s[8] = '\0';
        p += 8;

        int seq    = (int)strtol(seq_s,  NULL, 16);
        int hexlen = (int)strtol(hlen_s, NULL, 16);

        if (hexlen <= 0 || hexlen > MAX_MSG_LEN * 2)
            { pos = tag_start + 1; continue; }

        /* Wait for full payload */
        if ((size_t)(p - buf) + (size_t)hexlen > blen) break;

        if (!seq_already_seen(seq)) {
            /* Hex-decode → encrypted bytes */
            unsigned char decoded[MAX_MSG_LEN + 1];
            int dec_len = hex_to_str(p, (size_t)hexlen, (char *)decoded, sizeof decoded);
            if (dec_len > 0) {
                /* AES-256-CTR decrypt */
                aes_ctr_crypt(decoded, (size_t)dec_len,
                              C.rx_state.current_key, (uint32_t)seq);

                /* Split "USERNAME\x1Fbody" */
                char *sep = memchr(decoded, '\x1F', (size_t)dec_len);
                if (sep) {
                    *sep = '\0';
                    /* peer_name now points to a NUL-terminated string of at
                     * most dec_len bytes — cap explicitly for the compiler   */
                    char *peer_name = (char *)decoded;
                    char *body      = sep + 1;
                    if (C.peer_name[0] == '\0') {
                        strncpy(C.peer_name, peer_name, sizeof C.peer_name - 1);
                        C.peer_name[sizeof C.peer_name - 1] = '\0';
                        g_idle_add(idle_update_header, NULL);
                    }
                    post_msg(peer_name, body, false);
                } else {
                    /* Fallback — no separator (older client) */
                    decoded[dec_len] = '\0';
                    post_msg("Peer", (char *)decoded, false);
                }
            }
        }

        /* Erase tag + fixed header + payload from buffer */
        size_t msg_end = (size_t)(p - buf) + (size_t)hexlen;
        memmove(buf + tag_start, buf + msg_end, blen - msg_end);
        blen      -= msg_end - tag_start;
        C.recv_len = blen;
        buf[blen]  = '\0';
        /* Restart search from same offset */
    }

    pthread_mutex_unlock(&C.buf_lock);
}

/* ══════════════════════════════════════════════════
 *  Receive thread
 * ══════════════════════════════════════════════════ */
static void *recv_thread(void *arg) {
    (void)arg;
    char tmp[4096];

    while (C.running) {
        ssize_t n = recv(C.sock, tmp, sizeof tmp - 1, 0);
        if (n <= 0) {
            if (C.running) {
                post_status("Peer disconnected.");
                post_system("connection closed");
            }
            C.running = false;
            break;
        }

        // --- THE FIX: ENSURE EVERY BYTE IS RATCHETED ---
        size_t bytes_processed_from_network = 0;
        while (bytes_processed_from_network < (size_t)n) {
            size_t space = 16384 - C.rx_state.bytes_processed;
            size_t to_copy = ((size_t)n - bytes_processed_from_network < space) ? 
                              ((size_t)n - bytes_processed_from_network) : space;

            memcpy(C.rx_state.chaff_step_buf + C.rx_state.bytes_processed, 
                   tmp + bytes_processed_from_network, to_copy);
            
            C.rx_state.bytes_processed += to_copy;
            bytes_processed_from_network += to_copy;

            if (C.rx_state.bytes_processed >= 16384) {
                evolve_ratchet(&C.rx_state);
            }
        }
        // -----------------------------------------------

        // Push to rolling buffer for the scanner
        pthread_mutex_lock(&C.buf_lock);
        if (C.recv_len + (size_t)n + 1 > RECV_BUF_SIZE) {
            memmove(C.recv_buf, C.recv_buf + (RECV_BUF_SIZE / 2), RECV_BUF_SIZE / 2);
            C.recv_len = RECV_BUF_SIZE / 2;
        }
        memcpy(C.recv_buf + C.recv_len, tmp, n);
        C.recv_len += n;
        C.recv_buf[C.recv_len] = '\0';
        pthread_mutex_unlock(&C.buf_lock);

        scan_and_consume();
    }
    return NULL;
}

/* ══════════════════════════════════════════════════
 *  Send thread
 * ══════════════════════════════════════════════════ */
static bool send_all(int fd, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len && C.running) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return C.running;
}

static void *send_thread(void *arg) {
    (void)arg;
    char chunk[SEND_CHUNK_SIZE + 1];

    while (C.running) {
        pthread_mutex_lock(&C.out_lock);
        
        size_t bytes_to_send;
        char *data_ptr;

        if (C.out_ready) {
            data_ptr = C.out_tag;
            bytes_to_send = strlen(C.out_tag);
        } else {
            rand_hex(chunk, SEND_CHUNK_SIZE);
            data_ptr = chunk;
            bytes_to_send = SEND_CHUNK_SIZE;
        }

        // --- THE FIX: LEAK-PROOF RATCHET FEED ---
        size_t bytes_sent_to_ratchet = 0;
        while (bytes_sent_to_ratchet < bytes_to_send) {
            size_t space = 16384 - C.tx_state.bytes_processed;
            size_t to_copy = (bytes_to_send - bytes_sent_to_ratchet < space) ? 
                              (bytes_to_send - bytes_sent_to_ratchet) : space;
            
            memcpy(C.tx_state.chaff_step_buf + C.tx_state.bytes_processed, 
                   data_ptr + bytes_sent_to_ratchet, to_copy);
            
            C.tx_state.bytes_processed += to_copy;
            bytes_sent_to_ratchet += to_copy;

            if (C.tx_state.bytes_processed >= 16384) {
                evolve_ratchet(&C.tx_state);
            }
        }
        // ----------------------------------------

        if (!send_all(C.sock, data_ptr, bytes_to_send)) {
            C.running = false;
            pthread_mutex_unlock(&C.out_lock);
            break;
        }

        if (C.out_ready) C.out_ready = false;

        pthread_mutex_unlock(&C.out_lock);
        usleep(SEND_INTERVAL_US);
    }
    return NULL;
}

/* ══════════════════════════════════════════════════
 *  Connection thread
 * ══════════════════════════════════════════════════ */
// Update the ConnRes struct so the thread can pass the seed to the UI
typedef struct { 
    bool ok; 
    char err[256]; 
    unsigned char seed[32]; // To store the result of the handshake
} ConnRes;


static void init_ratchet(RatchetState *s, const unsigned char *seed) {
    memcpy(s->current_key, seed, 32);
    s->bytes_processed = 0;
    for(int i = 0; i < 32; i++) {
        sprintf(s->hex_tag + (i * 2), "%02X", s->current_key[i]);
    }
    s->hex_tag[64] = '\0';
}

static gboolean on_connected(gpointer p)
{
    ConnRes *r = p;

    gtk_spinner_stop(GTK_SPINNER(C.spinner));
    gtk_widget_set_visible(C.spinner, FALSE);

    if (r->ok) {
        char hdr[320];
        snprintf(hdr, sizeof hdr,
                 "⚡  %s  ·  port: %d  ·  key: %s  ·  %s",
                 C.username, C.my_port, C.chat_key,
                 C.is_server ? "listening" : "connecting");
        gtk_label_set_text(GTK_LABEL(C.lbl_peer), hdr);
        gtk_stack_set_visible_child_name(GTK_STACK(C.stack), "chat");

        post_status("Stream active — ChaCha20 noise · AES-256-CTR messages · SHA-256 ratchet.");
        post_system("PFS active · X25519 handshake complete · ChaCha20 noise stream running");

        /* * Initialize ratchets using the seed from the background handshake.
         * This seed is a combination of your chat_key AND the ephemeral X25519 secret.
         */
        init_ratchet(&C.tx_state, r->seed);
        init_ratchet(&C.rx_state, r->seed);

        pthread_t t;
        pthread_create(&t, NULL, send_thread, NULL); pthread_detach(t);
        pthread_create(&t, NULL, recv_thread, NULL); pthread_detach(t);
    } else {
        post_status("Error: %s", r->err);
        gtk_widget_set_sensitive(C.btn_connect, TRUE);
    }
    free(r);
    return G_SOURCE_REMOVE;
}

static void *connect_thread(void *arg)
{
    (void)arg;
    ConnRes *r = calloc(1, sizeof *r);

    if (C.is_server) {
        /* ──── Server Mode ──── */
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { snprintf(r->err, 256, "socket: %s", strerror(errno)); goto done; }

        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);

        struct sockaddr_in addr = {0};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons((uint16_t)C.my_port);

        if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
            snprintf(r->err, 256, "bind port %d: %s", C.my_port, strerror(errno));
            close(fd); goto done;
        }
        listen(fd, BACKLOG);
        C.server_fd = fd;
        post_status("Listening on port %d — waiting for peer...", C.my_port);

        struct sockaddr_in cli;
        socklen_t cli_len = sizeof cli;
        C.sock = accept(fd, (struct sockaddr *)&cli, &cli_len);
        close(fd); C.server_fd = -1;

        if (C.sock < 0) {
            if (!C.running) { free(r); return NULL; }
            snprintf(r->err, 256, "accept: %s", strerror(errno));
            goto done;
        }
    } else {
        /* ──── Client Mode ──── */
        post_status("Connecting to %s:%d...", C.target_ip, C.target_port);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { snprintf(r->err, 256, "socket: %s", strerror(errno)); goto done; }

        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);

        /* Bind to MY PORT before connecting so both peers show their chosen
         * port in tcpdump/ss — not a random OS-assigned ephemeral port.   */
        struct sockaddr_in local = {0};
        local.sin_family      = AF_INET;
        local.sin_addr.s_addr = INADDR_ANY;
        local.sin_port        = htons((uint16_t)C.my_port);
        if (bind(fd, (struct sockaddr *)&local, sizeof local) < 0) {
            snprintf(r->err, 256, "bind port %d: %s", C.my_port, strerror(errno));
            close(fd); goto done;
        }

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons((uint16_t)C.target_port);
        inet_pton(AF_INET, C.target_ip, &addr.sin_addr);

        if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
            snprintf(r->err, 256, "connect failed: %s", strerror(errno));
            close(fd); goto done;
        }
        C.sock = fd;
    }

    /* ──── THE HANDSHAKE ──── */
    // This happens while the UI is still showing the spinner
    if (!perform_handshake(C.sock, r->seed)) {
        snprintf(r->err, 256, "Cryptographic handshake failed.");
        close(C.sock);
        r->ok = false;
    } else {
        C.running = true;
        r->ok = true;
    }

done:
    g_idle_add(on_connected, r);
    return NULL;
}

/* ══════════════════════════════════════════════════
 *  GTK callbacks
 * ══════════════════════════════════════════════════ */

static bool perform_handshake(int sock, unsigned char *out_seed) {
    EVP_PKEY *local_key = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    
    // 1. Generate local keypair
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &local_key);
    
    unsigned char local_pub[32], peer_pub[32];
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(local_key, local_pub, &pub_len);

    // 2. Hex-encode to hide in the noise
    char hex_pub[65], hex_peer[65];
    for(int i=0; i<32; i++) sprintf(hex_pub + (i*2), "%02X", local_pub[i]);

    // 3. Swap Public Keys (Sync send/recv)
    if (send(sock, hex_pub, 64, 0) != 64) return false;
    if (recv(sock, hex_peer, 64, MSG_WAITALL) != 64) return false;

    // 4. Decode Peer Public Key
    for(int i=0; i<32; i++) {
        unsigned int val;
        sscanf(hex_peer + (i*2), "%02X", &val);
        peer_pub[i] = (unsigned char)val;
    }

    // 5. Compute Shared Secret
    EVP_PKEY *peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(local_key, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_pkey);
    
    unsigned char shared_secret[32];
    size_t secret_len = 32;
    EVP_PKEY_derive(ctx, shared_secret, &secret_len);

    // 6. Combine with Chat Key (The "Master Seed")
    HMAC(EVP_sha256(), shared_secret, 32, (unsigned char*)C.chat_key, strlen(C.chat_key), out_seed, NULL);

    EVP_PKEY_free(local_key);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(ctx);
    return true;
}

static void on_connect_clicked(GtkButton *b, gpointer u)
{
    (void)b; (void)u;

    const char *port_s   = gtk_entry_get_text(GTK_ENTRY(C.ent_port));
    const char *target_s = gtk_entry_get_text(GTK_ENTRY(C.ent_target));
    const char *key_s    = gtk_entry_get_text(GTK_ENTRY(C.ent_key));
    const char *name_s   = gtk_entry_get_text(GTK_ENTRY(C.ent_username));

    /* ── Validate ── */
    if (!port_s || strlen(port_s) == 0) {
        post_status("Please enter your listening port.");
        return;
    }
    int port = atoi(port_s);
    if (port <= 0 || port > 65535) {
        post_status("Port must be 1–65535.");
        return;
    }
    if (!key_s || strlen(key_s) < 3) {
        post_status("Chat key must be at least 3 characters.");
        return;
    }

    /* Username — default to "User" if blank */
    if (name_s && strlen(name_s) > 0)
        snprintf(C.username, sizeof C.username, "%s", name_s);
    else
        snprintf(C.username, sizeof C.username, "User");
    C.peer_name[0] = '\0';   /* reset on each new connection */

    C.my_port = port;
    strncpy(C.chat_key, key_s, MAX_KEY_LEN - 1);

    /* ── Determine server vs client ── */
    if (!target_s || strlen(target_s) == 0) {
        C.is_server = true;
    } else {
        C.is_server = false;
        char tmp[128];
        strncpy(tmp, target_s, sizeof tmp - 1);
        char *colon = strrchr(tmp, ':');
        if (colon) {
            *colon = '\0';
            C.target_port = atoi(colon + 1);
        } else {
            C.target_port = C.my_port;
        }
        snprintf(C.target_ip, sizeof C.target_ip, "%s", tmp);
    }

    /* ── Launch ── */
    gtk_widget_set_sensitive(C.btn_connect, FALSE);
    gtk_widget_set_visible(C.spinner, TRUE);
    gtk_spinner_start(GTK_SPINNER(C.spinner));

    pthread_t t;
    pthread_create(&t, NULL, connect_thread, NULL);
    pthread_detach(t);
}

static void do_send_message(void)
{
    if (!C.running) return;

    const char *text = gtk_entry_get_text(GTK_ENTRY(C.ent_msg));
    if (!text || strlen(text) == 0) return;

    /* 1. Build plaintext as "USERNAME\x1Fmessage body"
     *    \x1F is ASCII Unit Separator — clean, non-typeable, unambiguous.
     *    Both fields encrypt together so the username is never visible
     *    in the stream.                                                      */
    unsigned char rawmsg[MAX_MSG_LEN];
    size_t name_len = strlen(C.username);
    size_t text_len = strlen(text);
    /* Cap total payload */
    if (name_len + 1 + text_len >= MAX_MSG_LEN)
        text_len = MAX_MSG_LEN - name_len - 2;

    memcpy(rawmsg, C.username, name_len);
    rawmsg[name_len] = '\x1F';                       /* unit separator */
    memcpy(rawmsg + name_len + 1, text, text_len);
    size_t raw_len = name_len + 1 + text_len;

    /* Lock early so seq and key are grabbed atomically */
    pthread_mutex_lock(&C.out_lock);

    uint32_t this_seq = (uint32_t)C.send_seq++;
    aes_ctr_crypt(rawmsg, raw_len, C.tx_state.current_key, this_seq);

    /* 2. Hex-encode the encrypted bytes */
    char hexmsg[MAX_MSG_LEN * 2 + 1];
    for (size_t i = 0; i < raw_len; i++)
        sprintf(hexmsg + i * 2, "%02X", rawmsg[i]);
    hexmsg[raw_len * 2] = '\0';
    int hexlen = (int)(raw_len * 2);

    char *hex_key = C.tx_state.hex_tag;

    /* 3. Build the tag — FIXED-WIDTH format:
     *    <64-char SHA256 hex tag><8-char seq padded hex><8-char hexlen padded hex><hexdata>
     *    No delimiters — all fields are fixed width, no collision possible.
     */
    snprintf(C.out_tag, sizeof C.out_tag,
             "%s%08X%08X%s",
             hex_key, (unsigned int)this_seq, (unsigned int)hexlen, hexmsg);
    
    C.out_ready = true;

    /* 4. Unlock exactly once */
    pthread_mutex_unlock(&C.out_lock); 

    post_msg(C.username, text, true);
    gtk_entry_set_text(GTK_ENTRY(C.ent_msg), "");
}

static void on_send_clicked(GtkButton *b, gpointer u) { (void)b; (void)u; do_send_message(); }

static gboolean on_key_press(GtkWidget *w, GdkEventKey *e, gpointer u)
{
    (void)w; (void)u;
    if (e->keyval == GDK_KEY_Return || e->keyval == GDK_KEY_KP_Enter) {
        do_send_message();
        return TRUE;
    }
    return FALSE;
}

/* ══════════════════════════════════════════════════
 *  CSS theme — Deep Space / Neon Blue  (self-contained)
 *
 *  Uses only GTK3-supported CSS properties.
 *  Fonts: monospace / sans-serif generic families only —
 *  no external font files, no system-font assumptions.
 *  Tested on GTK 3.18 – 3.24.
 * ══════════════════════════════════════════════════ */
static const char *APP_CSS =

    /* ── Base window ── */
    "window {"
    "  background-color: #06060e;"
    "  color: #c8dcff;"
    "}"

    /* ════════════════════════════════
     *  CLIENT-SIDE TITLEBAR (headerbar)
     * ════════════════════════════════ */
    "headerbar {"
    "  background-color: #06060e;"
    "  border-bottom: 1px solid #0f1830;"
    "  padding: 0 10px;"
    "  min-height: 44px;"
    "  box-shadow: 0 2px 12px rgba(0,0,0,0.9);"
    "}"
    "headerbar title {"
    "  font-family: monospace;"
    "  font-size: 13px;"
    "  font-weight: bold;"
    "  color: #00aaff;"
    "}"
    "headerbar subtitle {"
    "  font-family: monospace;"
    "  font-size: 10px;"
    "  color: #1e2d55;"
    "}"

    /* Window control dots — override ALL generic button rules */
    "headerbar button.titlebutton {"
    "  background-color: #1a1a2e;"
    "  border: 1px solid #2a2a45;"
    "  border-radius: 50%;"
    "  padding: 0;"
    "  min-width: 13px;"
    "  min-height: 13px;"
    "  margin: 0 3px;"
    "  box-shadow: none;"
    "}"
    "headerbar button.titlebutton label {"
    "  color: transparent;"
    "  font-size: 1px;"
    "}"
    "headerbar button.titlebutton.close {"
    "  background-color: #c0394b;"
    "  border-color: #8a2535;"
    "}"
    "headerbar button.titlebutton.close:hover {"
    "  background-color: #e84560;"
    "}"
    "headerbar button.titlebutton.minimize {"
    "  background-color: #b07a20;"
    "  border-color: #7a5510;"
    "}"
    "headerbar button.titlebutton.minimize:hover {"
    "  background-color: #d4982a;"
    "}"
    "headerbar button.titlebutton.maximize {"
    "  background-color: #208c60;"
    "  border-color: #106040;"
    "}"
    "headerbar button.titlebutton.maximize:hover {"
    "  background-color: #28b07a;"
    "}"

    /* ════════════════════════════════
     *  SETUP CARD
     * ════════════════════════════════ */
    ".setup-card {"
    "  background-color: #09091a;"
    "  border-radius: 14px;"
    "  padding: 44px 50px;"
    "  border: 1px solid #0f1830;"
    "  box-shadow: 0 0 40px rgba(0,0,0,0.8), 0 0 1px #00aaff;"
    "}"

    ".setup-title {"
    "  font-family: monospace;"
    "  font-size: 28px;"
    "  font-weight: bold;"
    "  color: #00aaff;"
    "}"

    ".setup-sub {"
    "  font-family: monospace;"
    "  font-size: 11px;"
    "  font-style: italic;"
    "  color: #1e2d55;"
    "}"

    ".field-label {"
    "  font-family: monospace;"
    "  font-size: 11px;"
    "  font-weight: bold;"
    "  color: #3a5090;"
    "}"

    /* ════════════════════════════════
     *  ENTRIES
     * ════════════════════════════════ */
    "entry {"
    "  background-color: #06060e;"
    "  color: #c8dcff;"
    "  border-color: #0f1830;"
    "  border-style: solid;"
    "  border-width: 1px;"
    "  border-radius: 7px;"
    "  padding: 9px 14px;"
    "  font-family: monospace;"
    "  font-size: 14px;"
    "}"
    "entry:focus {"
    "  background-color: #06060e;"
    "  border-color: #00aaff;"
    "  border-width: 2px;"
    "  color: #e0f0ff;"
    "  box-shadow: 0 0 10px rgba(0, 170, 255, 0.2);"
    "}"
    "entry:disabled {"
    "  background-color: #09091a;"
    "  color: #1a2040;"
    "}"
    "entry > * {"
    "  color: #1e2d55;"
    "}"

    /* ════════════════════════════════
     *  BUTTONS  (generic — NOT titlebar)
     * ════════════════════════════════ */
    "button {"
    "  background-color: #0055bb;"
    "  color: #e8f4ff;"
    "  border-radius: 7px;"
    "  border: 1px solid #0077ee;"
    "  padding: 9px 22px;"
    "  font-family: monospace;"
    "  font-weight: bold;"
    "  font-size: 13px;"
    "}"
    "button label {"
    "  color: #e8f4ff;"
    "  font-weight: bold;"
    "}"
    "button:hover {"
    "  background-color: #0077ee;"
    "  border-color: #00aaff;"
    "  box-shadow: 0 0 12px rgba(0, 170, 255, 0.35);"
    "}"
    "button:active {"
    "  background-color: #003d99;"
    "  box-shadow: none;"
    "}"
    "button:disabled {"
    "  background-color: #0a0a18;"
    "  border-color: #0f1830;"
    "  color: #1e2d55;"
    "}"
    "button:disabled label {"
    "  color: #1e2d55;"
    "}"

    /* ════════════════════════════════
     *  CHAT HEADER
     * ════════════════════════════════ */
    "#chat-header {"
    "  background-color: #06060e;"
    "  padding: 10px 16px;"
    "  border-bottom: 1px solid #0f1830;"
    "  min-height: 38px;"
    "}"
    "#peer-label {"
    "  font-family: monospace;"
    "  font-size: 12px;"
    "  color: #2a4070;"
    "}"

    /* ════════════════════════════════
     *  CHAT TEXT VIEW
     * ════════════════════════════════ */
    "textview {"
    "  background-color: #03030a;"
    "  color: #c8dcff;"
    "  font-family: monospace;"
    "  font-size: 14px;"
    "}"
    "textview text {"
    "  background-color: #03030a;"
    "  color: #c8dcff;"
    "  font-family: monospace;"
    "  font-size: 14px;"
    "}"

    /* ════════════════════════════════
     *  SCROLLED WINDOW + SCROLLBAR
     * ════════════════════════════════ */
    "scrolledwindow {"
    "  background-color: #03030a;"
    "  border: none;"
    "}"
    "scrolledwindow undershoot.top,"
    "scrolledwindow undershoot.bottom {"
    "  background-color: #03030a;"
    "}"
    "scrollbar {"
    "  background-color: #03030a;"
    "  border: none;"
    "}"
    "scrollbar slider {"
    "  background-color: #0f1830;"
    "  border-radius: 6px;"
    "  min-width: 5px;"
    "  min-height: 5px;"
    "}"
    "scrollbar slider:hover {"
    "  background-color: #1a2a50;"
    "}"

    /* ════════════════════════════════
     *  MESSAGE INPUT ROW
     * ════════════════════════════════ */
    "#input-row {"
    "  background-color: #06060e;"
    "  padding: 12px 14px;"
    "  border-top: 1px solid #0f1830;"
    "}"
    "#msg-entry {"
    "  font-family: monospace;"
    "  font-size: 14px;"
    "  background-color: #03030a;"
    "  border-color: #0f1830;"
    "}"
    "#msg-entry:focus {"
    "  border-color: #00aaff;"
    "  border-width: 2px;"
    "  box-shadow: 0 0 8px rgba(0, 170, 255, 0.2);"
    "}"

    /* Send button — neon teal-green */
    "#send-btn {"
    "  background-color: #007755;"
    "  border-color: #00aa77;"
    "  color: #c0ffe8;"
    "  min-width: 80px;"
    "}"
    "#send-btn label {"
    "  color: #c0ffe8;"
    "  font-weight: bold;"
    "}"
    "#send-btn:hover {"
    "  background-color: #009966;"
    "  border-color: #00cc88;"
    "  box-shadow: 0 0 12px rgba(0, 180, 120, 0.35);"
    "}"
    "#send-btn:active {"
    "  background-color: #005540;"
    "}"
    "#send-btn:disabled {"
    "  background-color: #0a0a18;"
    "  border-color: #0f1830;"
    "  color: #1e2d55;"
    "}"

    /* ════════════════════════════════
     *  STATUS BAR
     * ════════════════════════════════ */
    "#status-bar {"
    "  background-color: #04040b;"
    "  color: #1e2d55;"
    "  font-family: monospace;"
    "  font-size: 11px;"
    "  padding: 5px 14px;"
    "  border-top: 1px solid #09091a;"
    "}"

    /* ════════════════════════════════
     *  SEPARATOR
     * ════════════════════════════════ */
    "separator {"
    "  background-color: #0f1830;"
    "  color: #0f1830;"
    "  min-height: 1px;"
    "  margin-top: 6px;"
    "  margin-bottom: 6px;"
    "}"

    /* ════════════════════════════════
     *  SPINNER
     * ════════════════════════════════ */
    "spinner {"
    "  color: #00aaff;"
    "}";

/* ══════════════════════════════════════════════════
 *  Build — Setup page
 * ══════════════════════════════════════════════════ */
static GtkWidget *make_setup_page(void)
{
    /* Outer centering box */
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_halign(outer, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(outer, GTK_ALIGN_CENTER);
    gtk_widget_set_vexpand(outer, TRUE);

    /* Card frame */
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 18);
    gtk_widget_get_style_context(card);
    gtk_style_context_add_class(gtk_widget_get_style_context(card), "setup-card");
    gtk_box_pack_start(GTK_BOX(outer), card, FALSE, FALSE, 0);

    /* ── Title ── */
    GtkWidget *title = gtk_label_new("⚡  CHAOSCHAT");
    gtk_style_context_add_class(gtk_widget_get_style_context(title), "setup-title");
    gtk_widget_set_halign(title, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(card), title, FALSE, FALSE, 0);

    GtkWidget *sub = gtk_label_new("stream-embedded peer-to-peer chat");
    gtk_style_context_add_class(gtk_widget_get_style_context(sub), "setup-sub");
    gtk_widget_set_halign(sub, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(card), sub, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(card),
        gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 4);

    /* ── Field grid ── */
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 14);
    gtk_box_pack_start(GTK_BOX(card), grid, FALSE, FALSE, 0);

    /* Helper to add a labelled row */
#define ADD_ROW(row, ltext, widget)                                         \
    do {                                                                    \
        GtkWidget *_l = gtk_label_new(ltext);                               \
        gtk_style_context_add_class(gtk_widget_get_style_context(_l),       \
                                    "field-label");                         \
        gtk_widget_set_halign(_l, GTK_ALIGN_END);                           \
        gtk_grid_attach(GTK_GRID(grid), _l, 0, (row), 1, 1);               \
        gtk_widget_set_hexpand((widget), TRUE);                             \
        gtk_widget_set_size_request((widget), 320, -1);                     \
        gtk_grid_attach(GTK_GRID(grid), (widget), 1, (row), 1, 1);         \
    } while (0)

    C.ent_port = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(C.ent_port), "5050");
    ADD_ROW(0, "MY PORT", C.ent_port);

    C.ent_target = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(C.ent_target),
                                   "192.168.x.x:5050   (blank = wait)");
    ADD_ROW(1, "CONNECT TO", C.ent_target);

    C.ent_key = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(C.ent_key),
                                   "KKs245ff*   (must match peer)");
    ADD_ROW(2, "CHAT KEY", C.ent_key);

    C.ent_username = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(C.ent_username),
                                   "YourName   (shown to peer)");
    gtk_entry_set_max_length(GTK_ENTRY(C.ent_username), 32);
    ADD_ROW(3, "USERNAME", C.ent_username);
#undef ADD_ROW

    /* ── Connect button + spinner row ── */
    GtkWidget *btn_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_halign(btn_row, GTK_ALIGN_END);
    gtk_box_pack_start(GTK_BOX(card), btn_row, FALSE, FALSE, 4);

    C.spinner = gtk_spinner_new();
    gtk_widget_set_visible(C.spinner, FALSE);
    gtk_box_pack_start(GTK_BOX(btn_row), C.spinner, FALSE, FALSE, 0);

    C.btn_connect = gtk_button_new_with_label("Connect / Listen");
    g_signal_connect(C.btn_connect, "clicked", G_CALLBACK(on_connect_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(btn_row), C.btn_connect, FALSE, FALSE, 0);

    /* ── Hint ── */
    GtkWidget *hint = gtk_label_new(
        "Leave 'Connect To' blank to listen for an incoming connection");
    gtk_style_context_add_class(gtk_widget_get_style_context(hint), "setup-sub");
    gtk_widget_set_halign(hint, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(card), hint, FALSE, FALSE, 0);

    return outer;
}

/* ══════════════════════════════════════════════════
 *  Build — Chat page
 * ══════════════════════════════════════════════════ */
static GtkWidget *make_chat_page(void)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    /* ── Header ── */
    GtkWidget *hbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_name(hbar, "chat-header");

    C.lbl_peer = gtk_label_new("Connecting…");
    gtk_widget_set_name(C.lbl_peer, "peer-label");
    gtk_widget_set_halign(C.lbl_peer, GTK_ALIGN_START);
    gtk_label_set_ellipsize(GTK_LABEL(C.lbl_peer), PANGO_ELLIPSIZE_END);
    gtk_box_pack_start(GTK_BOX(hbar), C.lbl_peer, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbar, FALSE, FALSE, 0);

    /* ── Chat text view ── */
    C.chat_buf  = gtk_text_buffer_new(NULL);
    C.chat_view = gtk_text_view_new_with_buffer(C.chat_buf);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(C.chat_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(C.chat_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(C.chat_view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(C.chat_view), 12);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(C.chat_view), 12);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(C.chat_view), 10);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(C.chat_view), 10);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll), C.chat_view);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    /* ── Message input row ── */
    GtkWidget *irow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_name(irow, "input-row");

    C.ent_msg = gtk_entry_new();
    gtk_widget_set_name(C.ent_msg, "msg-entry");
    gtk_entry_set_placeholder_text(GTK_ENTRY(C.ent_msg),
                                   "Type a message and press Enter…");
    gtk_widget_set_hexpand(C.ent_msg, TRUE);
    g_signal_connect(C.ent_msg, "key-press-event", G_CALLBACK(on_key_press), NULL);

    C.btn_send = gtk_button_new_with_label("Send");
    gtk_widget_set_name(C.btn_send, "send-btn");
    g_signal_connect(C.btn_send, "clicked", G_CALLBACK(on_send_clicked), NULL);

    gtk_box_pack_start(GTK_BOX(irow), C.ent_msg, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(irow), C.btn_send, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), irow, FALSE, FALSE, 0);

    return vbox;
}

/* ══════════════════════════════════════════════════
 *  Main
 * ══════════════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    srand((unsigned)time(NULL));

    /* Initialise state */
    memset(&C, 0, sizeof C);
    C.sock      = -1;
    C.server_fd = -1;
    C.recv_buf  = calloc(RECV_BUF_SIZE, 1);
    if (!C.recv_buf) { fprintf(stderr, "OOM\n"); return 1; }

    pthread_mutex_init(&C.out_lock, NULL);
    pthread_mutex_init(&C.seq_lock, NULL);
    pthread_mutex_init(&C.buf_lock, NULL);
    pthread_mutex_init(&C.ratchet_lock, NULL);  /* BUG 4 fix */

    gtk_init(&argc, &argv);

    /* Apply CSS */
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css, APP_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    /* Main window */
    C.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(C.window), 720, 540);
    gtk_window_set_position(GTK_WINDOW(C.window), GTK_WIN_POS_CENTER);
    g_signal_connect(C.window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    /* Client-side decorations — gives us 100% CSS control over titlebar +
     * window-control buttons; no more ugly WM-drawn chrome.              */
    C.headerbar = gtk_header_bar_new();
    gtk_header_bar_set_title(GTK_HEADER_BAR(C.headerbar), "⚡  CHAOSCHAT");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(C.headerbar),
                                "stream-embedded p2p");
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(C.headerbar), TRUE);
    gtk_widget_set_name(C.headerbar, "main-header");
    gtk_window_set_titlebar(GTK_WINDOW(C.window), C.headerbar);

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(C.window), root);

    /* Stack (setup ↔ chat) */
    C.stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(C.stack),
                                  GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_stack_set_transition_duration(GTK_STACK(C.stack), 220);
    gtk_stack_add_named(GTK_STACK(C.stack), make_setup_page(), "setup");
    gtk_stack_add_named(GTK_STACK(C.stack), make_chat_page(),  "chat");
    gtk_stack_set_visible_child_name(GTK_STACK(C.stack), "setup");
    gtk_widget_set_vexpand(C.stack, TRUE);
    gtk_box_pack_start(GTK_BOX(root), C.stack, TRUE, TRUE, 0);

    /* Status bar */
    C.status_bar = gtk_label_new(
        "Enter your port and key. Leave 'Connect To' blank to wait.");
    gtk_widget_set_name(C.status_bar, "status-bar");
    gtk_widget_set_halign(C.status_bar, GTK_ALIGN_START);
    gtk_label_set_ellipsize(GTK_LABEL(C.status_bar), PANGO_ELLIPSIZE_END);
    gtk_box_pack_end(GTK_BOX(root), C.status_bar, FALSE, FALSE, 0);

    gtk_widget_show_all(C.window);
    gtk_widget_set_visible(C.spinner, FALSE);   /* hidden until needed */

    gtk_main();

    /* Cleanup */
    C.running = false;
    if (C.sock      >= 0) close(C.sock);
    if (C.server_fd >= 0) close(C.server_fd);
    free(C.recv_buf);
    pthread_mutex_destroy(&C.out_lock);
    pthread_mutex_destroy(&C.seq_lock);
    pthread_mutex_destroy(&C.buf_lock);
    pthread_mutex_destroy(&C.ratchet_lock);

    return 0;
}
