/* cpass2 - scrypt + AES-256-GCM password store. C99, OpenSSL.
 * build: cc -std=c99 -O2 -Wall -o cpass2 cpass2.c -lcrypto
 * layout: $CPASS2_DIR (default ~/.cpass2)
 *   salt      16 random bytes (scrypt salt)
 *   MAIN      encrypted index: "id\tname\n" lines
 *   <hexid>   encrypted entry: password\nusername\nwebsite\nextra...
 * file names on disk are random ids; real names only exist inside MAIN. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifndef CPASS2_CLIP
#define CPASS2_CLIP "xclip -selection clipboard"
#endif
#ifndef CPASS2_TMP
#define CPASS2_TMP "/dev/shm"
#endif

#define MAGIC "CP2\001"
#define SALTLEN 16
#define NONCE 12
#define TAG 16

static char dir[4096];
static unsigned char key[32], salt[SALTLEN];
static struct { char *s; size_t n; } idx;

static void die(const char *m)
{
	fprintf(stderr, "cpass2: %s\n", m);
	OPENSSL_cleanse(key, sizeof key);
	exit(1);
}

static char *ppath(const char *f)
{
	static char p[4200];
	snprintf(p, sizeof p, "%s/%s", dir, f);
	return p;
}

static unsigned char *rfile(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	if (!f) return NULL;
	size_t cap = 4096, len = 0, r;
	unsigned char *b = malloc(cap);
	if (!b) die("oom");
	while ((r = fread(b + len, 1, cap - len, f)) > 0) {
		len += r;
		if (len == cap) { cap *= 2; if (!(b = realloc(b, cap))) die("oom"); }
	}
	fclose(f);
	*n = len;
	return b;
}

static void wfile(const char *path, const unsigned char *b, size_t n)
{
	char tmp[4300];
	snprintf(tmp, sizeof tmp, "%s.tmp", path);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) die("cannot write file");
	FILE *f = fdopen(fd, "wb");
	if (!f || fwrite(b, 1, n, f) != n || fflush(f) || fsync(fd)) die("write failed");
	fclose(f);
	if (rename(tmp, path)) die("rename failed");
}

static unsigned char *enc(const unsigned char *p, size_t n, size_t *olen)
{
	unsigned char *o = malloc(4 + NONCE + n + TAG);
	int l = 0, t = 0;
	if (!o) die("oom");
	memcpy(o, MAGIC, 4);
	if (RAND_bytes(o + 4, NONCE) != 1) die("rand failed");
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	if (!c || !EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, o + 4)) die("enc init");
	if (n && !EVP_EncryptUpdate(c, o + 16, &l, p, (int)n)) die("enc update");
	t = l;
	if (!EVP_EncryptFinal_ex(c, o + 16 + t, &l)) die("enc final");
	t += l;
	if (!EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG, o + 16 + t)) die("tag");
	EVP_CIPHER_CTX_free(c);
	*olen = 16 + t + TAG;
	return o;
}

static unsigned char *dec(const unsigned char *b, size_t n, size_t *olen)
{
	if (n < 4 + NONCE + TAG || memcmp(b, MAGIC, 4)) return NULL;
	size_t cl = n - 4 - NONCE - TAG;
	unsigned char *o = malloc(cl + 1);
	int l = 0, t = 0, ok;
	if (!o) die("oom");
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	if (!c || !EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, b + 4)) die("dec init");
	if (cl && !EVP_DecryptUpdate(c, o, &l, b + 16, (int)cl)) { free(o); return NULL; }
	t = l;
	EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG, (void *)(b + 16 + cl));
	ok = EVP_DecryptFinal_ex(c, o + t, &l) > 0;
	EVP_CIPHER_CTX_free(c);
	if (!ok) { OPENSSL_cleanse(o, cl); free(o); return NULL; }
	o[t + l] = 0;
	*olen = t + l;
	return o;
}

static void read_secret(const char *pr, char *b, size_t sz)
{
	FILE *t = fopen("/dev/tty", "r+");
	struct termios o, n;
	if (!t) die("no tty");
	tcgetattr(fileno(t), &o);
	n = o;
	n.c_lflag &= ~ECHO;
	tcsetattr(fileno(t), TCSAFLUSH, &n);
	fputs(pr, t);
	fflush(t);
	if (!fgets(b, (int)sz, t)) b[0] = 0;
	tcsetattr(fileno(t), TCSAFLUSH, &o);
	fputc('\n', t);
	fclose(t);
	b[strcspn(b, "\n")] = 0;
}

static void derive(char *pw)
{
	if (!EVP_PBE_scrypt(pw, strlen(pw), salt, SALTLEN, 1 << 15, 8, 1, 1 << 27, key, sizeof key))
		die("scrypt failed");
	OPENSSL_cleanse(pw, strlen(pw));
}

static void save_index(void)
{
	size_t n;
	unsigned char *o = enc((unsigned char *)idx.s, idx.n, &n);
	wfile(ppath("MAIN"), o, n);
	free(o);
}

static void unlock(void)
{
	size_t n;
	char pw[256];
	unsigned char *b = rfile(ppath("salt"), &n);
	if (!b || n != SALTLEN) die("store not initialised (run: cpass2 init)");
	memcpy(salt, b, SALTLEN);
	free(b);
	read_secret("master password: ", pw, sizeof pw);
	derive(pw);
	if (!(b = rfile(ppath("MAIN"), &n))) die("MAIN missing");
	idx.s = (char *)dec(b, n, &idx.n);
	free(b);
	if (!idx.s) die("wrong password or corrupt MAIN");
}

/* find "id\tname\n" line; returns line start, *end = after line */
static char *idx_find(const char *name, char **end)
{
	char *p = idx.s, *stop = idx.s + idx.n;
	size_t nl = strlen(name);
	while (p < stop) {
		char *e = memchr(p, '\n', stop - p);
		char *t = e ? memchr(p, '\t', e - p) : NULL;
		if (!e || !t) break;
		if ((size_t)(e - t - 1) == nl && !memcmp(t + 1, name, nl)) { *end = e + 1; return p; }
		p = e + 1;
	}
	return NULL;
}

static void get_id(const char *line, char *id)
{
	size_t i = 0;
	while (line[i] != '\t' && i < 32) { id[i] = line[i]; i++; }
	id[i] = 0;
}

static unsigned char *load_entry(const char *name, size_t *n)
{
	char *end, *l = idx_find(name, &end), id[40], *e = NULL;
	size_t cn;
	if (!l) die("no such entry");
	get_id(l, id);
	unsigned char *b = rfile(ppath(id), &cn);
	if (!b) die("entry file missing");
	unsigned char *p = dec(b, cn, n);
	free(b);
	(void)e;
	if (!p) die("entry corrupt");
	return p;
}

static void store_entry(const char *id, const char *s, size_t n)
{
	size_t on;
	unsigned char *o = enc((const unsigned char *)s, n, &on);
	wfile(ppath(id), o, on);
	free(o);
}

static int cmp(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

static void cmd_ls(void)
{
	char **v = NULL, *p = idx.s, *stop = idx.s + idx.n;
	size_t c = 0, i;
	while (p < stop) {
		char *e = memchr(p, '\n', stop - p), *t;
		if (!e || !(t = memchr(p, '\t', e - p))) break;
		v = realloc(v, (c + 1) * sizeof *v);
		v[c] = strndup(t + 1, e - t - 1);
		c++;
		p = e + 1;
	}
	qsort(v, c, sizeof *v, cmp);
	char last[1024] = "";
	for (i = 0; i < c; i++) {
		char *sl = strrchr(v[i], '/');
		if (!sl) { printf("%s\n", v[i]); continue; }
		size_t dl = sl - v[i];
		if (strlen(last) != dl || strncmp(last, v[i], dl)) {
			printf("%.*s/\n", (int)dl, v[i]);
			snprintf(last, sizeof last, "%.*s", (int)dl, v[i]);
		}
		printf("  %s\n", sl + 1);
	}
}

static void app(char **b, size_t *n, const char *s)
{
	size_t l = strlen(s);
	if (!(*b = realloc(*b, *n + l + 2))) die("oom");
	memcpy(*b + *n, s, l);
	*n += l;
	(*b)[*n] = 0;
}

static char *prompt_entry(size_t *n)
{
	char pw[512], ln[1024], *b = malloc(1);
	*n = 0;
	b[0] = 0;
	read_secret("password: ", pw, sizeof pw);
	app(&b, n, pw); app(&b, n, "\n");
	OPENSSL_cleanse(pw, sizeof pw);
	fputs("username: ", stderr);
	if (!fgets(ln, sizeof ln, stdin)) ln[0] = 0;
	app(&b, n, ln[0] ? ln : "\n");
	fputs("website: ", stderr);
	if (!fgets(ln, sizeof ln, stdin)) ln[0] = 0;
	app(&b, n, ln[0] ? ln : "\n");
	fputs("extra (end with empty line):\n", stderr);
	while (fgets(ln, sizeof ln, stdin) && ln[0] != '\n') app(&b, n, ln);
	return b;
}

static void cmd_add(const char *name)
{
	char *end, id[40], hex[] = "0123456789abcdef";
	unsigned char r[16];
	size_t n, i;
	if (strpbrk(name, "\t\n")) die("bad name");
	if (idx_find(name, &end)) die("entry exists (use edit)");
	char *e = prompt_entry(&n);
	RAND_bytes(r, 16);
	for (i = 0; i < 16; i++) { id[2 * i] = hex[r[i] >> 4]; id[2 * i + 1] = hex[r[i] & 15]; }
	id[32] = 0;
	store_entry(id, e, n);
	OPENSSL_cleanse(e, n);
	free(e);
	idx.s = realloc(idx.s, idx.n + 32 + 1 + strlen(name) + 2);
	idx.n += sprintf(idx.s + idx.n, "%s\t%s\n", id, name);
	save_index();
}

static void cmd_edit(const char *name)
{
	size_t n, tn;
	char *end, *l = idx_find(name, &end), id[40], tmp[256], cmdl[600];
	const char *ed = getenv("EDITOR");
	if (!l) die("no such entry");
	get_id(l, id);
	unsigned char *p = load_entry(name, &n);
	snprintf(tmp, sizeof tmp, "%s/cpass2.XXXXXX", CPASS2_TMP);
	int fd = mkstemp(tmp);
	if (fd < 0) die("mkstemp failed (set CPASS2_TMP)");
	if (write(fd, p, n) != (ssize_t)n) die("tmp write");
	close(fd);
	OPENSSL_cleanse(p, n);
	free(p);
	snprintf(cmdl, sizeof cmdl, "%s '%s'", ed ? ed : "vi", tmp);
	if (system(cmdl)) die("editor failed");
	unsigned char *q = rfile(tmp, &tn);
	if (q) {
		/* overwrite then unlink */
		FILE *f = fopen(tmp, "r+b");
		if (f) { size_t i; for (i = 0; i < tn; i++) fputc(0, f); fclose(f); }
	}
	unlink(tmp);
	if (!q) die("cannot read edited file");
	store_entry(id, (char *)q, tn);
	OPENSSL_cleanse(q, tn);
	free(q);
}

static void cmd_rm(const char *name)
{
	char *end, *l = idx_find(name, &end), id[40];
	if (!l) die("no such entry");
	get_id(l, id);
	unlink(ppath(id));
	memmove(l, end, idx.s + idx.n - end);
	idx.n -= end - l;
	save_index();
}

static void cmd_copy(const char *name)
{
	size_t n;
	unsigned char *p = load_entry(name, &n);
	size_t pl = strcspn((char *)p, "\n");
	FILE *c = popen(CPASS2_CLIP " >/dev/null 2>&1", "w");
	if (!c) die("cannot run clipboard command");
	fwrite(p, 1, pl, c);
	pclose(c);
	OPENSSL_cleanse(p, n);
	free(p);
	puts("[in clipboard]");
}

int main(int argc, char **argv)
{
	const char *d = getenv("CPASS2_DIR"), *h = getenv("HOME");
	if (argc < 2) { fputs("usage: cpass2 init|add|get|ls|edit|rm|copy [name]\n", stderr); return 1; }
	if (d) snprintf(dir, sizeof dir, "%s", d);
	else snprintf(dir, sizeof dir, "%s/.cpass2", h ? h : ".");
	umask(077);
	const char *c = argv[1], *name = argc > 2 ? argv[2] : NULL;

	if (!strcmp(c, "init")) {
		char a[256], b[256];
		struct stat st;
		if (!stat(ppath("salt"), &st)) die("already initialised");
		mkdir(dir, 0700);
		read_secret("new master password: ", a, sizeof a);
		read_secret("repeat: ", b, sizeof b);
		if (strcmp(a, b)) die("passwords differ");
		RAND_bytes(salt, SALTLEN);
		wfile(ppath("salt"), salt, SALTLEN);
		derive(a);
		idx.s = malloc(1);
		idx.n = 0;
		save_index();
		return 0;
	}
	if (!strcmp(c, "ls")) { unlock(); cmd_ls(); return 0; }
	if (!name) die("missing entry name");
	unlock();
	if (!strcmp(c, "add")) cmd_add(name);
	else if (!strcmp(c, "edit")) cmd_edit(name);
	else if (!strcmp(c, "rm")) cmd_rm(name);
	else if (!strcmp(c, "copy")) cmd_copy(name);
	else if (!strcmp(c, "get")) {
		size_t n;
		unsigned char *p = load_entry(name, &n);
		fwrite(p, 1, n, stdout);
		OPENSSL_cleanse(p, n);
		free(p);
	} else die("unknown command");
	OPENSSL_cleanse(key, sizeof key);
	return 0;
}
