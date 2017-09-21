#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define PEERID "-GT0000-000000000000"
#define PIECE_MAX 1048576
#define BLOCK_MAX 16384
#define MESSAGE_MAX ((BLOCK_MAX) + 9)

enum {
	PWP_CHOKE = 0,
	PWP_UNCHOKE,
	PWP_INTERESTED,
	PWP_UNINTERESTED,
	PWP_HAVE,
	PWP_BITFIELD,
	PWP_REQUEST,
	PWP_PIECE,
	PWP_CANCEL,
	NUM_PWP_TYPES,
	PWP_HANDSHAKE
};

enum {
	THP_NONE,
	THP_STARTED,
	THP_STOPPED,
	THP_COMPLETED
};

enum {
	CONN_CLOSED = 0,
	CONN_INIT,
	CONN_HANDSHAKE,
	CONN_ESTAB
};

enum {
	PEER_CHOKED       = 1<<0,
	PEER_INTERESTED   = 1<<1,
	PEER_AMCHOKED     = 1<<2,
	PEER_AMINTERESTED = 1<<3
};

struct be {
        char *start;
        char *end;
        char *off;
};

struct file {
	char path[PATH_MAX];
	size_t len;
};

struct piece {
	uint8_t *sha1;
	uint8_t *data;
	size_t len;
};

struct peer {
	int sockfd;
	uint8_t conn;
	uint8_t state;
	uint8_t *bitfield;
	struct sockaddr_in peer;
	TAILQ_ENTRY(peer) entries;
};
TAILQ_HEAD(peers, peer);

struct torrent {
	char announce[PATH_MAX];
	struct be meta;
	uint8_t peerid[21];
	uint8_t infohash[20];
	uint8_t *bitfield;
	struct piece *pieces;
	size_t size;
	size_t filnum;
	size_t pcsnum;
	size_t piecelen;
	size_t upload;
	size_t download;
	struct file *files;
	struct peers *peers;
};

int grizzly_load(struct torrent *, char *);
int grizzly_download(struct torrent *to);
int grizzly_finished(struct torrent *to);
