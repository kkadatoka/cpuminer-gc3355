/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2013 pooler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#define _GNU_SOURCE

#include <curses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#ifdef WIN32
#include <windows.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif
#include <jansson.h>
#include <curl/curl.h>
#include "compat.h"
#include "miner.h"

#define PROGRAM_NAME		"minerd"
#define DEF_RPC_URL		"http://127.0.0.1:9332/"

#define MINER_VERSION	"v0.9d"

enum workio_commands {
	WC_SUBMIT_WORK,
};

struct workio_cmd {
	enum workio_commands	cmd;
	struct thr_info		*thr;
	union {
		struct work	*work;
	} u;
};

enum sha256_algos {
	ALGO_SCRYPT,		/* scrypt(1024,1,1) */
	ALGO_SHA256D,		/* SHA-256d */
};

static const char *algo_names[] = {
	[ALGO_SCRYPT]		= "scrypt",
	[ALGO_SHA256D]		= "sha256d",
};

#define GC3355_DEFAULT_CHIPS 5
#define API_DEFAUKT_PORT 4028
#define API_QUEUE 16
#define API_STATS "stats"
#define API_MINER_START_TIME "t"
#define API_DEVICES "d"
#define API_CHIPS "c"
#define API_LAST_SHARE "l"
#define API_CHIP_ACCEPTED "ac"
#define API_CHIP_REJECTED "re"
#define API_CHIP_HW_ERRORS "hw"
#define API_CHIP_FREQUENCY "fr"
#define API_CHIP_HASHRATE "ha"
#define API_CHIP_SHARES "sh"
#define REFRESH_INTERVAL 2

struct gc3355_dev {
	int	id;
	int	dev_fd;
	unsigned char chips;
	bool resend;
	char *devname;
	unsigned short *freq;
	uint32_t *last_nonce;
	unsigned long long *hashes;
	double *time_now;
	double *time_spent;
	unsigned short *total_hwe;
	unsigned short *hwe;
	short *adjust;
	unsigned short *steps;
	unsigned int *autotune_accepted;
	unsigned int *accepted;
	unsigned int *rejected;
	double *hashrate;
	unsigned long long *shares;
	unsigned int *last_share;
	bool ready;
};

static char *gc3355_devname = NULL;
static unsigned short opt_frequency = 600;
static char *opt_gc3355_frequency = NULL;
static char opt_gc3355_autotune = 0x0;
static unsigned short opt_gc3355_chips = GC3355_DEFAULT_CHIPS;
static struct gc3355_dev *gc3355_devs;
static unsigned int gc3355_time_start;

bool opt_log = false;
bool opt_curses = true;
bool opt_debug = false;
bool opt_protocol = false;
bool want_stratum = true;
bool have_stratum = false;
static bool opt_quiet = false;
static int opt_retries = -1;
static int opt_fail_pause = 5;
int opt_timeout = 270;
int opt_scantime = 5;
static int opt_n_threads;
static char *rpc_url;
static char *rpc_userpass;
static char *rpc_user, *rpc_pass;
struct thr_info *thr_info;
static int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;
int tui_main_thr_id = -1;
int tui_user_thr_id = -1;
unsigned short opt_api_port = API_DEFAUKT_PORT;
int api_sock;
struct work_restart *work_restart = NULL;
static struct stratum_ctx stratum;

struct display *display;
struct log_buffer *log_buffer = NULL;
time_t time_start;

pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;
pthread_mutex_t tui_lock;

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};
#endif

static char const usage[] = "\
Usage: " PROGRAM_NAME " [OPTIONS]\n\
Options:\n\
  -G, --gc3355=DEV0,DEV1,...,DEVn      					enable GC3355 chip mining mode (default: no)\n\
  -F, --freq=FREQUENCY  								set GC3355 core frequency in NONE dual mode (default: 600)\n\
  -f, --gc3355-freq=DEV0:F0,DEV1:F1,...,DEVn:Fn			individual frequency setting\n\
	  --gc3355-freq=DEV0:F0:CHIP0,...,DEVn:Fn:CHIPn		individual per chip frequency setting\n\
  -A, --gc3355-autotune  								auto overclocking each GC3355 chip (default: no)\n\
  -c, --gc3355-chips=N  								# of GC3355 chips (default: 5)\n\
  -a, --api-port=PORT  									set the JSON API port (default: 4028)\n\
  -t, --text											disable curses tui, output text\n\
  -L, --log												file logging\n\
  -o, --url=URL         								URL of mining server (default: " DEF_RPC_URL ")\n\
  -O, --userpass=U:P    								username:password pair for mining server\n\
  -u, --user=USERNAME   								username for mining server\n\
  -p, --pass=PASSWORD   								password for mining server\n\
  -r, --retries=N       								number of times to retry if a network call fails\n\
														(default: retry indefinitely)\n\
  -R, --retry-pause=N									time to pause between retries, in seconds (default: 30)\n\
  -T, --timeout=N       								network timeout, in seconds (default: 270)\n\
  -q, --quiet           								disable per-thread hashmeter output\n\
  -D, --debug           								enable debug output\n\
  -P, --protocol-dump   								verbose dump of protocol-level activities\n\
  -V, --version         								display version information and exit\n\
  -h, --help            								display this help text and exit\n";

static char const short_options[] = 
	"G:F:f:A:c:a:t:L"
	"PDhp:qr:R:T:o:u:O:V";

static struct option const options[] = {
	{ "gc3355", 1, NULL, 'G' },
	{ "freq", 1, NULL, 'F' },
	{ "gc3355-freq", 1, NULL, 'f' },
	{ "gc3355-autotune", 0, NULL, 'A' },
	{ "gc3355-chips", 1, NULL, 'c' },
	{ "api-port", 1, NULL, 'a' },
	{ "text", 0, NULL, 't' },
	{ "log", 0, NULL, 'L' },
	{ "debug", 0, NULL, 'D' },
	{ "pass", 1, NULL, 'p' },
	{ "quiet", 0, NULL, 'q' },
	{ "protocol-dump", 0, NULL, 'P' },
	{ "retries", 1, NULL, 'r' },
	{ "retry-pause", 1, NULL, 'R' },
	{ "timeout", 1, NULL, 'T' },
	{ "url", 1, NULL, 'o' },
	{ "user", 1, NULL, 'u' },
	{ "userpass", 1, NULL, 'O' },
	{ "version", 0, NULL, 'V' },
	{ "help", 0, NULL, 'h' },
	{ 0, 0, 0, 0 }
};

struct work {
	uint32_t data[32];
	uint32_t *target;
	char *job_id;
	uint32_t work_id;
	unsigned char xnonce2[4];
	unsigned short thr_id;
};

static uint32_t g_prev_target[8];
static uint32_t g_curr_target[8];
static char g_prev_job_id[128];
static char g_curr_job_id[128];
static uint32_t g_prev_work_id = 0;
static uint32_t g_curr_work_id = 0;
static char can_work = 0x1;

static struct work *g_works;
static time_t g_work_time;
static pthread_mutex_t g_work_lock;

static bool submit_work(struct thr_info *thr, const struct work *work_in);

/* added for GC3355 chip miner */
#include "gc3355.h"
/* end */

struct window_lines
{
	char ***str;
	int *width;
	int lines;
	int cols;
	int col;
};

struct window_lines* init_window_lines(int lines, int cols)
{
	int i;
	struct window_lines *wl = malloc(sizeof(struct window_lines));
	wl->str = calloc(lines, sizeof(char**));
	for(i = 0; i < lines; i++)
	{
		wl->str[i] = calloc(cols, sizeof(char*));
	}
	wl->width = calloc(cols, sizeof(int));
	wl->lines = lines;
	wl->cols = cols;
	wl->col = 0;
	return wl;
}

void window_lines_addstr(struct window_lines *wl, int line, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if(wl->str[line][wl->col] != NULL)
		free(wl->str[line][wl->col]);
	int len = vasprintf(&wl->str[line][wl->col], fmt, ap);
	if(len < 0)
	{
		wl->str[line][wl->col] = NULL;
		wl->width[wl->col] = 0;
		applog(LOG_ERR, "window_lines_addstr : vasprintf() failed");
	}
	else if(len > wl->width[wl->col]) wl->width[wl->col] = len;
	wl->col = (wl->col + 1) % wl->cols;
	va_end(ap);
}

void window_lines_print(struct window_lines *wl, WINDOW *win)
{
	int i, j, k;
	for(i = 0; i < wl->lines; i++)
	{
		for(j = 0; j < wl->cols; j++)
		{
			if(wl->str[i][j] != NULL)
			{
				int offset = 1;
				for(k = 0; k < j; k++)
				{
					offset += wl->width[k];
				}
				mvwprintw(win, i, offset, "%s", wl->str[i][j]);
			}
			else
			{
				applog(LOG_ERR, "window_lines_print : col (%d,%d) is NULL", i, j);
			}
		}
	}
}

void window_lines_free(struct window_lines *wl)
{
	int i, j;
	for(i = 0; i < wl->lines; i++)
	{
		for(j = 0; j < wl->cols; j++)
		{
			if(wl->str[i][j] != NULL)
				free(wl->str[i][j]);
		}
		free(wl->str[i]);
	}
	free(wl->str);
	free(wl->width);
	free(wl);
}

static void clean_tui()
{
	del_win(display->top);
	del_win(display->summary);
	del_win(display->stats);
	del_win(display->log);
	free(display);
	endwin();
	clear();
}

static void init_tui()
{
	initscr();
	start_color();
	cbreak();
	keypad(stdscr, TRUE);
	noecho();
	curs_set(0);
	refresh();
}

static void start_tui()
{
	int i, log_height, stats_height;
	struct tm tm, *tm_p;
	char *p;
	struct window_lines *wl;
	display = calloc(1, sizeof(struct display));
	bool has_scroll = false;
	tm_p = localtime(&time_start);
	memcpy(&tm, tm_p, sizeof(tm));
	display->top = new_win(2, COLS, 0, 0);
	display->summary = new_win(3, COLS, display->top->height, 0);
	stats_height = LINES - display->top->height - display->summary->height - TUI_MIN_LOG;
	if(stats_height >= opt_n_threads) stats_height = opt_n_threads;
	else
	{
		if(stats_height < 1) stats_height = 1;
		has_scroll = true;
	}
	display->stats = new_pad(opt_n_threads, COLS, stats_height, COLS, display->top->height + display->summary->height, 0);
	log_height = LINES - display->top->height - display->summary->height - display->stats->height - TUI_SCROLL;
	if(log_height < 1) log_height = 1;
	display->log = new_win(log_height, COLS - 2, display->top->height + display->summary->height + display->stats->height + TUI_SCROLL, 1);
	wmove(display->log->win, 0, 0);
	idlok(display->log->win, true);
	scrollok(display->log->win, true);
	leaveok(display->log->win, true);
	mvwprintw(display->top->win, 0, 1,  "cpuminer-gc3355 (%s) - Started: [%d-%02d-%02d %02d:%02d:%02d]",
		MINER_VERSION,
		tm.tm_year + 1900,
		tm.tm_mon + 1,
		tm.tm_mday,
		tm.tm_hour,
		tm.tm_min,
		tm.tm_sec
	);
	mvwprintw(display->summary->win, 0, 1, "(5s) | 0/0 MH/s | A:0 R:0 HW:0");
	p = strrchr(rpc_url, '/');
	if(p == NULL) p = rpc_url;
	else p++;
	mvwprintw(display->summary->win, 1, 1,  "Connected to %s diff %d with stratum as user %s", p, (int) stratum.job.diff, rpc_user == NULL ? rpc_userpass : rpc_user);
	wl = init_window_lines(opt_n_threads, 4);
	for(i = 0; i < opt_n_threads; i++)
	{
		window_lines_addstr(wl, i, "GSD %d", i);
		window_lines_addstr(wl, i, " | 0 MHz");
		window_lines_addstr(wl, i, " | 0/0 KH/s");
		window_lines_addstr(wl, i, " | A: 0 R: 0 HW: 0");
	}
	window_lines_print(wl, display->stats->win);
	window_lines_free(wl);
	mvwhline(display->top->win, display->top->height - 1, 0, '=', COLS);
	mvwhline(display->summary->win, display->summary->height - 1, 0, '=', COLS);
	mvhline(display->top->height + display->summary->height + display->stats->height + 1, 0, '=', COLS);
	if(has_scroll)
		mvprintw(display->top->height + display->summary->height + display->stats->height, 1, "Scroll with UP and DOWN keys");
	wrefresh(display->top->win);
	wrefresh(display->summary->win);
	prefresh(display->stats->win, 0, 0, display->stats->y, 0, display->stats->height + display->stats->y - 1, COLS);
	wrefresh(display->log->win);
	refresh();
}

static void resize_tui()
{
	pthread_mutex_lock(&tui_lock);
	clean_tui();
	refresh();
	start_tui();
	pthread_mutex_unlock(&tui_lock);
}

static void *tui_user_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	int ch;
	while(opt_curses && (ch = getch()))
	{
		switch(ch)
		{
			case KEY_DOWN:
				pthread_mutex_lock(&tui_lock);
				if(display->stats->py < opt_n_threads - display->stats->height)
				prefresh(display->stats->win, ++display->stats->py, 0, display->stats->y, 0, display->stats->height + display->stats->y - 1, COLS);
				pthread_mutex_unlock(&tui_lock);
				break;
			case KEY_UP:
				pthread_mutex_lock(&tui_lock);
				if(display->stats->py > 0)
				prefresh(display->stats->win, --display->stats->py, 0, display->stats->y, 0, display->stats->height + display->stats->y - 1, COLS);
				pthread_mutex_unlock(&tui_lock);
				break;
			default:
				break;
		}
	}
	return NULL;
}

static void *tui_main_thread(void *userdata)
{
	/* Wait for initialization */
	sleep (5) ;
	struct thr_info *mythr = userdata;
	char *p;
	int i, j;
	struct timeval timestr;
	double hashrate, pool_hashrate, thread_hashrate, thread_pool_hashrate, pool_hashrate_width, hashrate_width;
	unsigned int accepted, rejected, hwe, thread_accepted, thread_rejected, thread_hwe, thread_freq, accepted_width, rejected_width, hwe_width;
	struct window_lines *wl;
	while(opt_curses)
	{
		pthread_mutex_lock(&stats_lock);
		gettimeofday(&timestr, NULL);
		accepted_width = rejected_width = hwe_width = pool_hashrate_width = hashrate_width = 0;
		for(i = 0; i < opt_n_threads; i++)
		{
			thread_hashrate = thread_pool_hashrate = thread_accepted = thread_rejected = thread_hwe = 0;
			if(gc3355_devs[i].ready)
			{
				for(j = 0; j < gc3355_devs[i].chips; j++)
				{
					thread_hashrate += gc3355_devs[i].hashrate[j];
					thread_pool_hashrate += gc3355_devs[i].shares[j];
					thread_accepted += gc3355_devs[i].accepted[j];
					thread_rejected += gc3355_devs[i].rejected[j];
					thread_hwe += gc3355_devs[i].total_hwe[j];
				}
				thread_pool_hashrate = (1 << 16) / ((timestr.tv_sec - gc3355_time_start) / thread_pool_hashrate);
				if(thread_accepted > accepted_width) accepted_width = thread_accepted;
				if(thread_rejected > rejected_width) rejected_width = thread_rejected;
				if(thread_hwe > hwe_width) hwe_width = thread_hwe;
				if(thread_hashrate > hashrate_width) hashrate_width = thread_hashrate;
				if(thread_pool_hashrate > pool_hashrate_width) pool_hashrate_width = thread_pool_hashrate;
			}
		}
		accepted_width = snprintf(NULL, 0, "%d", accepted_width);
		rejected_width = snprintf(NULL, 0, "%d", rejected_width);
		hwe_width = snprintf(NULL, 0, "%d", hwe_width);
		hashrate_width = snprintf(NULL, 0, "%.1lf", hashrate_width / 1000);
		pool_hashrate_width = snprintf(NULL, 0, "%.1lf", pool_hashrate_width / 1000);
		hashrate = pool_hashrate = accepted = rejected = hwe = 0;
		wl = init_window_lines(opt_n_threads, 7);
		for(i = 0; i < opt_n_threads; i++)
		{
			thread_hashrate = thread_pool_hashrate = thread_accepted = thread_rejected = thread_hwe = thread_freq = 0;
			if(gc3355_devs[i].ready)
			{
				for(j = 0; j < gc3355_devs[i].chips; j++)
				{
					thread_hashrate += gc3355_devs[i].hashrate[j];
					thread_pool_hashrate += gc3355_devs[i].shares[j];
					thread_accepted += gc3355_devs[i].accepted[j];
					thread_rejected += gc3355_devs[i].rejected[j];
					thread_hwe += gc3355_devs[i].total_hwe[j];
					thread_freq += gc3355_devs[i].freq[j];
				}
				thread_freq /= gc3355_devs[i].chips;
				pool_hashrate += thread_pool_hashrate;
				thread_pool_hashrate = (1 << 16) / ((timestr.tv_sec - gc3355_time_start) / thread_pool_hashrate);
				hashrate += thread_hashrate;
				accepted += thread_accepted;
				rejected += thread_rejected;
				hwe += thread_hwe;
			}
			window_lines_addstr(wl, i, "GSD %d", i);
			window_lines_addstr(wl, i, " | %d MHz", thread_freq);
			window_lines_addstr(wl, i, " | %*.1lf/%*.1lf KH/s", (int) pool_hashrate_width, thread_pool_hashrate / 1000, (int) hashrate_width, thread_hashrate / 1000);
			window_lines_addstr(wl, i, " | A: %*d", accepted_width, thread_accepted);
			window_lines_addstr(wl, i, " R: %*d", rejected_width, thread_rejected);
			window_lines_addstr(wl, i, " H: %*d", hwe_width, thread_hwe);
			if ( gc3355_devs[i].chips <= 5 )
			{
				/*applog(LOG_INFO,"GSD %d - HW Error Detail: %d@0(%d MHz)=%d, %d@1(%d MHz)=%d, %d@2(%d MHz)=%d, %d@3(%d MHz)=%d, %d@4(%d MHz)=%d, Width=%d", i, i, gc3355_devs[i].freq[0], gc3355_devs[i].hwe[0], i, gc3355_devs[i].freq[1], gc3355_devs[i].hwe[1], i, gc3355_devs[i].freq[2], gc3355_devs[i].hwe[2], i, gc3355_devs[i].freq[3], gc3355_devs[i].hwe[3], i, gc3355_devs[i].freq[4], gc3355_devs[i].hwe[4]), err_width ;*/
				window_lines_addstr(wl, i, " | HW ERR Detail: %d@0(%d MHz)=%d, %d@1(%d MHz)=%d, %d@2(%d MHz)=%d, %d@3(%d MHz)=%d, %d@4(%d MHz)=%d", i, gc3355_devs[i].freq[0], gc3355_devs[i].hwe[0], i, gc3355_devs[i].freq[1], gc3355_devs[i].hwe[1], i, gc3355_devs[i].freq[2], gc3355_devs[i].hwe[2], i, gc3355_devs[i].freq[3], gc3355_devs[i].hwe[3], i, gc3355_devs[i].freq[4], gc3355_devs[i].hwe[4]);
			}
		}
		pool_hashrate = (1 << 16) / ((timestr.tv_sec - gc3355_time_start) / pool_hashrate);
		pthread_mutex_unlock(&stats_lock);
		pthread_mutex_lock(&tui_lock);
		werase(display->stats->win);
		werase(display->summary->win);
		window_lines_print(wl, display->stats->win);
		window_lines_free(wl);
		wl = init_window_lines(1, 1);
		window_lines_addstr(wl, 0, "(%ds) | %.2lf/%.2lf MH/s | A: %d R: %d HW: %d", REFRESH_INTERVAL, pool_hashrate / 1000000, hashrate / 1000000, accepted, rejected, hwe);
		window_lines_print(wl, display->summary->win);
		window_lines_free(wl);
		p = strrchr(rpc_url, '/');
		if(p == NULL) p = rpc_url;
		else p++;
		mvwprintw(display->summary->win, 1, 1, "Connected to %s diff %d with stratum as user %s", p, (int) stratum.job.diff, rpc_user == NULL ? rpc_userpass : rpc_user);
		mvwhline(display->summary->win, display->summary->height - 1, 0, '=', COLS);
		wrefresh(display->summary->win);
		prefresh(display->stats->win, display->stats->py, 0, display->stats->y, 0, display->stats->height + display->stats->y - 1, COLS);
		pthread_mutex_unlock(&tui_lock);
		sleep(REFRESH_INTERVAL);
	}
	return NULL;
}

static bool jobj_binary(const json_t *obj, const char *key,
			void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (unlikely(!tmp)) {
		applog(LOG_ERR, "JSON key '%s' not found", key);
		return false;
	}
	hexstr = json_string_value(tmp);
	if (unlikely(!hexstr)) {
		applog(LOG_ERR, "JSON key '%s' is not a string", key);
		return false;
	}
	if (!hex2bin(buf, hexstr, buflen))
		return false;

	return true;
}

static bool work_decode(const json_t *val, struct work *work)
{
	int i;
	
	if (unlikely(!jobj_binary(val, "data", work->data, sizeof(work->data)))) {
		applog(LOG_ERR, "JSON inval data");
		goto err_out;
	}
	if (unlikely(!jobj_binary(val, "target", work->target, sizeof(work->target)))) {
		applog(LOG_ERR, "JSON inval target");
		goto err_out;
	}

	for (i = 0; i < ARRAY_SIZE(work->data); i++)
		work->data[i] = le32dec(work->data + i);
	for (i = 0; i < ARRAY_SIZE(work->target); i++)
		work->target[i] = le32dec(work->target + i);

	return true;

err_out:
	return false;
}

static void share_result(int result, const char *reason, int thr_id, int chip_id)
{
	int i, j;
	struct timeval timestr;
	pthread_mutex_lock(&stats_lock);
	if(result)
	{
		gc3355_devs[thr_id].accepted[chip_id]++;
		if(opt_gc3355_autotune && gc3355_devs[thr_id].adjust[chip_id] > 0)
		{
			gc3355_devs[thr_id].autotune_accepted[chip_id]++;
		}
	}
	else
		gc3355_devs[thr_id].rejected[chip_id]++;
	gettimeofday(&timestr, NULL);
	gc3355_devs[thr_id].last_share[chip_id] = timestr.tv_sec;
	gc3355_devs[thr_id].shares[chip_id] += stratum.job.diff;
	pthread_mutex_unlock(&stats_lock);
	applog(LOG_INFO, "%s %08x GSD %d@%d",
	   result ? "Accepted" : "Rejected",
	   gc3355_devs[thr_id].last_nonce[chip_id],
	   thr_id, chip_id
	);
	if (reason)
		applog(LOG_INFO, "DEBUG: reject reason: %s", reason);
}

static void restart_threads(void)
{
	int i;
	for (i = 0; i < opt_n_threads; i++)
		work_restart[i].restart = 1;
}

static bool submit_upstream_work(CURL *curl, struct work *work)
{
	json_t *val, *res, *reason;
	char s[345];
	int i;
	bool rc = false;

	if (have_stratum) {
		uint32_t ntime, nonce;
		char *ntimestr, *noncestr, *xnonce2str;

		if (!work->job_id)
			return true;
		le32enc(&ntime, work->data[17]);
		le32enc(&nonce, work->data[19]);
		ntimestr = bin2hex((const unsigned char *)(&ntime), 4);
		noncestr = bin2hex((const unsigned char *)(&nonce), 4);
		xnonce2str = bin2hex(work->xnonce2, 4);
		int chip_id = work->data[19] / (0xffffffff / gc3355_devs[work->thr_id].chips);
		sprintf(s,
			"{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":%d}",
			rpc_user, work->job_id, xnonce2str, ntimestr, noncestr, chip_id << 8 | work->thr_id);
		free(ntimestr);
		free(noncestr);
		free(xnonce2str);
		
		if (unlikely(!stratum_send_line(&stratum, s))) {
			applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
			can_work = 0x0;
			goto out;
		}
		can_work = 0x1;
	}

	rc = true;

out:
	return rc;
}

static const char *rpc_req =
	"{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";

static bool get_upstream_work(CURL *curl, struct work *work)
{
	json_t *val;
	bool rc;
	struct timeval tv_start, tv_end, diff;

	gettimeofday(&tv_start, NULL);
	val = json_rpc_call(curl, rpc_url, rpc_userpass, rpc_req,
			    true, false, NULL);
	gettimeofday(&tv_end, NULL);

	if (have_stratum) {
		if (val)
			json_decref(val);
		return true;
	}

	if (!val)
		return false;

	rc = work_decode(json_object_get(val, "result"), work);

	if (opt_debug && rc) {
		timeval_subtract(&diff, &tv_end, &tv_start);
		applog(LOG_DEBUG, "DEBUG: got new work in %d ms",
		       diff.tv_sec * 1000 + diff.tv_usec / 1000);
	}

	json_decref(val);

	return rc;
}

static void workio_cmd_free(struct workio_cmd *wc)
{
	if (!wc)
		return;

	switch (wc->cmd) {
	case WC_SUBMIT_WORK:
		free(wc->u.work->job_id);
		free(wc->u.work);
		break;
	default: /* do nothing */
		break;
	}

	memset(wc, 0, sizeof(*wc));	/* poison */
	free(wc);
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
	int failures = 0;

	/* submit solution to bitcoin via JSON-RPC */
	while (!submit_upstream_work(curl, wc->u.work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "...terminating workio thread");
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "...retry after %d seconds",
			opt_fail_pause);
		sleep(opt_fail_pause);
	}

	return true;
}

static void *workio_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	CURL *curl;
	bool ok = true;

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL initialization failed");
		return NULL;
	}

	while (ok) {
		struct workio_cmd *wc;
		
		/* wait for workio_cmd sent to us, on our queue */
		wc = tq_pop(mythr->q, NULL);
		if (!wc) {
			ok = false;
			break;
		}

		/* process workio_cmd */
		switch (wc->cmd) {
		case WC_SUBMIT_WORK:
			ok = workio_submit_work(wc, curl);
			break;
		default:		/* should never happen */
			ok = false;
			break;
		}

		workio_cmd_free(wc);
	}

	tq_freeze(mythr->q);
	curl_easy_cleanup(curl);

	return NULL;
}

static bool submit_work(struct thr_info *thr, const struct work *work_in)
{
	struct workio_cmd *wc;
	
	/* fill out work request message */
	wc = calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->u.work = malloc(sizeof(*work_in));
	if (!wc->u.work)
		goto err_out;

	wc->cmd = WC_SUBMIT_WORK;
	wc->thr = thr;
	memcpy(wc->u.work, work_in, sizeof(*work_in));
	wc->u.work->job_id = strdup(wc->u.work->job_id);

	/* send solution to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc))
		goto err_out;

	return true;

err_out:
	workio_cmd_free(wc);
	return false;
}

static void stratum_gen_work(struct stratum_ctx *sctx, struct work *work)
{
	unsigned char merkle_root[64];
	int i;

	work->job_id = g_curr_job_id;
	
	uint32_t xnonce2;
	if(!memcmp(work->xnonce2, "\x00\x00\x00\x00", 4))
	{
		xnonce2 = 0xffffffff / (work->thr_id + 2);
	}
	else
	{
		xnonce2 = (uint32_t)(work->xnonce2[0]) << 24 |
			(uint32_t)(work->xnonce2[1]) << 16 |
			(uint32_t)(work->xnonce2[2]) << 8  |
			(uint32_t)(work->xnonce2[3]);
		if(xnonce2 < (0xffffffff / (work->thr_id + 1)) - 1)
		{
			xnonce2++;
		}
		else
		{
			xnonce2 = 0xffffffff / (work->thr_id + 2);
		}
	}
	unsigned char *coinbase = malloc(sctx->job.coinbase_size);
	memcpy(coinbase, sctx->job.coinbase, sctx->job.coinbase_size);
	unsigned char xnonce2s[4] = {xnonce2 >> 24, xnonce2 >> 16, xnonce2 >> 8, xnonce2};
	memcpy(coinbase + (sctx->job.xnonce2 - sctx->job.coinbase), xnonce2s, 4);
	memcpy(work->xnonce2, xnonce2s, 4);
	
	/* Generate merkle root */
	sha256d(merkle_root, coinbase, sctx->job.coinbase_size);
	for (i = 0; i < sctx->job.merkle_count; i++)
	{
		memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
		sha256d(merkle_root, merkle_root, 64);
	}

	/* Assemble block header */
	memset(work->data, 0, 128);
	work->data[0] = le32dec(sctx->job.version);
	for (i = 0; i < 8; i++)
		work->data[1 + i] = le32dec((uint32_t *)sctx->job.prevhash + i);
	for (i = 0; i < 8; i++)
		work->data[9 + i] = be32dec((uint32_t *)merkle_root + i);
	work->data[17] = le32dec(sctx->job.ntime);
	work->data[18] = le32dec(sctx->job.nbits);
	work->data[20] = 0x80000000;
	work->data[31] = 0x00000280;
	
	work->target = g_curr_target;
	work->work_id = g_curr_work_id;
	
	free(coinbase);
}

static bool stratum_handle_response(char *buf)
{
	json_t *val, *err_val, *res_val, *id_val;
	json_error_t err;
	bool ret = false;

	val = JSON_LOADS(buf, &err);
	if (!val) {
		applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");
	id_val = json_object_get(val, "id");
	
	if (!id_val || json_is_null(id_val))
	{
		applog(LOG_INFO, "Unrecognized JSON response: %s", buf);
		goto out;
	}

	int res_id = (int) json_integer_value(id_val);
	share_result(json_is_true(res_val),
		err_val ? json_string_value(json_array_get(err_val, 1)) : NULL, res_id & 0xff, res_id >> 8);

	ret = true;
out:
	if (val)
		json_decref(val);

	return ret;
}

static void *stratum_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	char *s;
	int i;
	struct timeval timestr;
	int restarted;
	
	stratum.url = tq_pop(mythr->q, NULL);
	if (!stratum.url)
		goto out;
	applog(LOG_INFO, "Starting Stratum on %s", stratum.url);
	
	g_works = calloc(opt_n_threads, sizeof(struct work));
	for(i = 0; i < opt_n_threads; i++)
	{
		g_works[i].thr_id = i;
	}
	gettimeofday(&timestr, NULL);
	g_curr_work_id = (timestr.tv_sec & 0xffff) << 16 | timestr.tv_usec & 0xffff;
	
	while (1) {
		int failures = 0;

		while (!stratum.curl) {
			pthread_mutex_lock(&g_work_lock);
			g_work_time = 0;
			pthread_mutex_unlock(&g_work_lock);
			restart_threads();

			if (!stratum_connect(&stratum, stratum.url) ||
			    !stratum_subscribe(&stratum) ||
			    !stratum_authorize(&stratum, rpc_user, rpc_pass)) {
				stratum_disconnect(&stratum);
				if (opt_retries >= 0 && ++failures > opt_retries) {
					applog(LOG_ERR, "...terminating workio thread");
					tq_push(thr_info[work_thr_id].q, NULL);
					goto out;
				}
				applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
				sleep(opt_fail_pause);
			}
		}

		restarted = 0;
		if (stratum.job.job_id &&
		    (strcmp(stratum.job.job_id, g_curr_job_id) || !g_work_time)) {
			pthread_mutex_lock(&g_work_lock);
			pthread_mutex_lock(&stratum.work_lock);
			applog(LOG_INFO, "New job_id: %s Diff: %d", stratum.job.job_id, (int) (stratum.job.diff));
			g_prev_work_id = g_curr_work_id;
			if (stratum.job.clean)
			{
				applog(LOG_INFO, "Stratum detected new block");
				gettimeofday(&timestr, NULL);
				g_curr_work_id = (timestr.tv_sec & 0xffff) << 16 | timestr.tv_usec & 0xffff;
				restart_threads();
			}
			strcpy(g_prev_job_id, g_curr_job_id);
			for(i = 0; i < 8; i++) g_prev_target[i] = g_curr_target[i];
			for(i = 0; i < opt_n_threads; i++)
			{
				g_works[i].job_id = g_prev_job_id;
				g_works[i].target = g_prev_target;
				g_works[i].work_id = g_prev_work_id;
			}
			strcpy(g_curr_job_id, stratum.job.job_id);
			diff_to_target(g_curr_target, stratum.job.diff / 65536.0);
			for(i = 0; i < opt_n_threads; i++)
			{
				stratum_gen_work(&stratum, &g_works[i]);
			}
			time(&g_work_time);
			restarted = 1;
			pthread_mutex_unlock(&stratum.work_lock);
			pthread_mutex_unlock(&g_work_lock);
		}
		
		if (!stratum_socket_full(&stratum, 60)) {
			applog(LOG_ERR, "Stratum connection timed out");
			s = NULL;
		} else
			s = stratum_recv_line(&stratum);
		if (!s) {
			stratum_disconnect(&stratum);
			applog(LOG_ERR, "Stratum connection interrupted");
			continue;
		}
		if (!stratum_handle_method(&stratum, s))
			stratum_handle_response(s);
		else if(!restarted)
		{
			if(stratum.job.diff != stratum.next_diff && stratum.next_diff > 0)
			{
				applog(LOG_INFO, "Stratum difficulty changed");
				pthread_mutex_lock(&g_work_lock);
				pthread_mutex_lock(&stratum.work_lock);
				restart_threads();
				for(i = 0; i < 8; i++) g_prev_target[i] = g_curr_target[i];
				g_prev_work_id = g_curr_work_id;
				for(i = 0; i < opt_n_threads; i++)
				{
					g_works[i].target = g_prev_target;
					g_works[i].work_id = g_prev_work_id;
				}
				gettimeofday(&timestr, NULL);
				g_curr_work_id = (timestr.tv_sec & 0xffff) << 16 | timestr.tv_usec & 0xffff;
				stratum.job.diff = stratum.next_diff;
				diff_to_target(g_curr_target, stratum.job.diff / 65536.0);
				applog(LOG_INFO, "Dispatching new work to GC3355 threads");
				for(i = 0; i < opt_n_threads; i++)
				{
					stratum_gen_work(&stratum, &g_works[i]);
				}
				pthread_mutex_unlock(&stratum.work_lock);
				pthread_mutex_unlock(&g_work_lock);
			}
		}
		free(s);
	}
	
	free(g_works);

out:
	return NULL;
}

#ifndef WIN32
static void api_request_handler(int sock)
{
    int i, j, read_size, read_pos, buffer_size = 256, err_size = 256;
    char request[buffer_size], *message, *pos, err_msg[err_size];
	const char *api_get;
	json_t *req, *get, *obj, *dev, *devs, *chips, *chip, *err;
	json_error_t json_err;
read:
	memset(err_msg, 0, err_size);
	memset(request, 0, buffer_size);
	read_pos = 0;
    while((read_size = recv(sock, request + read_pos, buffer_size - read_pos, 0)) > 0)
    {
		read_pos += read_size;
		if(read_pos >= buffer_size) goto read;
		if((pos = strchr(request, '\n')) == NULL) continue;
		while((pos = strchr(request, '\r')) != NULL || (pos = strchr(request, '\n')) != NULL)
			*pos = '\0';
		obj = json_object();
		req = JSON_LOADS(request, &json_err);
		if (!req)
		{
			snprintf(err_msg, err_size, "API: JSON decode failed(%d): %s (%s)", json_err.line, json_err.text, request);
			goto err;
		}
		get = json_object_get(req, "get");
		if (!get || !json_is_string(get))
		{
			snprintf(err_msg, err_size, "API: Unrecognized JSON response: %s", request);
			goto err;
		}
		api_get = json_string_value(get);
		if(!strcmp(api_get, API_STATS))
		{
			json_object_set_new(obj, API_MINER_START_TIME, json_integer(gc3355_time_start));
			err = json_integer(0);
			devs = json_object();
			pthread_mutex_lock(&stats_lock);
			for(i = 0; i < opt_n_threads; i++)
			{
				dev = json_object();
				chips = json_array();
				for(j = 0; j < gc3355_devs[i].chips; j++)
				{
					chip = json_object();
					json_object_set_new(chip, API_CHIP_ACCEPTED, json_integer(gc3355_devs[i].accepted[j]));
					json_object_set_new(chip, API_CHIP_REJECTED, json_integer(gc3355_devs[i].rejected[j]));
					json_object_set_new(chip, API_CHIP_HW_ERRORS, json_integer(gc3355_devs[i].total_hwe[j]));
					json_object_set_new(chip, API_CHIP_FREQUENCY, json_integer(gc3355_devs[i].freq[j]));
					json_object_set_new(chip, API_CHIP_HASHRATE, json_integer(gc3355_devs[i].hashrate[j]));
					json_object_set_new(chip, API_CHIP_SHARES, json_integer(gc3355_devs[i].shares[j]));
					json_object_set_new(chip, API_LAST_SHARE, json_integer(gc3355_devs[i].last_share[j]));
					json_array_append_new(chips, chip);
				}
				json_object_set_new(dev, API_CHIPS, chips);
				char *path = gc3355_devs[i].devname;
				char *base = strrchr(path, '/');
				json_object_set_new(devs, base ? base + 1 : path, dev);
			}
			pthread_mutex_unlock(&stats_lock);
			json_object_set_new(obj, API_DEVICES, devs);
		}
		else
		{
			snprintf(err_msg, err_size, "API: Unrecognized Command: %s", api_get);
			goto err;
		}
		applog(LOG_INFO, "API: Command: %s", api_get);
		goto write;
    }
	close(sock);
    return;
err:
	applog(LOG_ERR, "%s", err_msg);
	err = json_integer(1);
	json_object_set_new(obj, "errstr", json_string(err_msg));
write:
	if(req)
		json_decref(req);
	json_object_set_new(obj, "err", err);
	message = json_dumps(obj, JSON_COMPACT);
	json_decref(obj);
	write(sock, message, strlen(message));
	free(message);
	goto read;
}
#endif

#ifndef WIN32
static void *api_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
    int new_socket, c, yes;
    struct sockaddr_in server, client;
	char client_ip[INET_ADDRSTRLEN];
    api_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (api_sock == -1)
    {
        applog(LOG_ERR, "Could not create socket");
		goto out;
    }
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(opt_api_port);
	yes = 1;
	if(setsockopt(api_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
	{
        applog(LOG_ERR, "API: Sockopt failed");
		goto out;
	}
    if(bind(api_sock, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        applog(LOG_ERR, "API: Bind failed");
		goto out;
    }
    listen(api_sock, API_QUEUE);
    c = sizeof(struct sockaddr_in);
    while((new_socket = accept(api_sock, (struct sockaddr *)&client, (socklen_t*)&c)))
    {
		inet_ntop(AF_INET, &(client.sin_addr.s_addr), client_ip, INET_ADDRSTRLEN);
		//applog(LOG_INFO, "API: Client %s connected", client_ip);
		api_request_handler(new_socket);
		usleep(100000);
    }
    if (new_socket < 0)
    {
		applog(LOG_ERR, "API: Accept failed");
		goto out;
    }
out:
	if(api_sock != -1)
	{
		close(api_sock);
	}
	return NULL;
}
#endif

static void show_version_and_exit(void)
{
	printf("%s\n%s\n%s\n", PACKAGE_STRING, curl_version(), MINER_VERSION);
	exit(0);
}

static void show_usage_and_exit(int status)
{
	if (status)
		fprintf(stderr, "Try `" PROGRAM_NAME " --help' for more information.\n");
	else
		printf(usage);
	exit(status);
}

static void parse_arg (int key, char *arg)
{
	char *p;
	int v, i;

	switch(key) {
	case 'G':
		gc3355_devname = strdup(arg);
		break;
	case 'F':
		opt_frequency = atoi(arg);
		break;
	case 'f':
		opt_gc3355_frequency = strdup(arg);
		break;
	case 'A':
		opt_gc3355_autotune = 0x1;
		break;
	case 'c':
		opt_gc3355_chips = atoi(arg);
		break;
	case 'a':
		opt_api_port = atoi(arg);
		break;
	case 't':
		opt_curses = false;
		break;
	case 'L':
		opt_log = true;
		FILE* fp = fopen(LOG_NAME, "w+");
		fclose(fp);
		break;
	case 'q':
		opt_quiet = true;
		break;
	case 'D':
		opt_debug = true;
		break;
	case 'p':
		free(rpc_pass);
		rpc_pass = strdup(arg);
		break;
	case 'P':
		opt_protocol = true;
		break;
	case 'r':
		v = atoi(arg);
		if (v < -1 || v > 9999)	/* sanity check */
			show_usage_and_exit(1);
		opt_retries = v;
		break;
	case 'R':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			show_usage_and_exit(1);
		opt_fail_pause = v;
		break;
	case 'T':
		v = atoi(arg);
		if (v < 1 || v > 99999)	/* sanity check */
			show_usage_and_exit(1);
		opt_timeout = v;
		break;
	case 'u':
		free(rpc_user);
		rpc_user = strdup(arg);
		break;
	case 'o':			/* --url */
		p = strstr(arg, "://");
		if (p) {
			if (strncasecmp(arg, "http://", 7) && strncasecmp(arg, "https://", 8) &&
					strncasecmp(arg, "stratum+tcp://", 14))
				show_usage_and_exit(1);
			free(rpc_url);
			rpc_url = strdup(arg);
		} else {
			if (!strlen(arg) || *arg == '/')
				show_usage_and_exit(1);
			free(rpc_url);
			rpc_url = malloc(strlen(arg) + 8);
			sprintf(rpc_url, "http://%s", arg);
		}
		p = strrchr(rpc_url, '@');
		if (p) {
			char *sp, *ap;
			*p = '\0';
			ap = strstr(rpc_url, "://") + 3;
			sp = strchr(ap, ':');
			if (sp) {
				free(rpc_userpass);
				rpc_userpass = strdup(ap);
				free(rpc_user);
				rpc_user = calloc(sp - ap + 1, 1);
				strncpy(rpc_user, ap, sp - ap);
				free(rpc_pass);
				rpc_pass = strdup(sp + 1);
			} else {
				free(rpc_user);
				rpc_user = strdup(ap);
			}
			memmove(ap, p + 1, strlen(p + 1) + 1);
		}
		have_stratum = !strncasecmp(rpc_url, "stratum", 7);
		break;
	case 'O':			/* --userpass */
		p = strchr(arg, ':');
		if (!p)
			show_usage_and_exit(1);
		free(rpc_userpass);
		rpc_userpass = strdup(arg);
		free(rpc_user);
		rpc_user = calloc(p - arg + 1, 1);
		strncpy(rpc_user, arg, p - arg);
		free(rpc_pass);
		rpc_pass = strdup(p + 1);
		break;
	case 'V':
		show_version_and_exit();
	case 'h':
		show_usage_and_exit(0);
	default:
		show_usage_and_exit(1);
	}
}

static void parse_cmdline(int argc, char *argv[])
{
	int key;

	while (1) {
#if HAVE_GETOPT_LONG
		key = getopt_long(argc, argv, short_options, options, NULL);
#else
		key = getopt(argc, argv, short_options);
#endif
		if (key < 0)
			break;

		parse_arg(key, optarg);
	}
	if (optind < argc) {
		fprintf(stderr, "%s: unsupported non-option argument '%s'\n",
			argv[0], argv[optind]);
		show_usage_and_exit(1);
	}
}

static void clean_up()
{
	if(opt_curses)
	{
		applog(LOG_INFO, "Clean up");
		pthread_mutex_lock(&tui_lock);
		opt_curses = false;
		clean_tui();
		curs_set(1);
		pthread_mutex_unlock(&tui_lock);
	}
	close(api_sock);
	int i;
	for(i = 0; i < opt_n_threads; i++)
	{
		gc3355_close(gc3355_devs[i].dev_fd);	
	}
}

#ifndef WIN32
void signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		applog(LOG_DEBUG, "SIGHUP received");
		break;
	case SIGINT:
		applog(LOG_DEBUG, "SIGINT received, exiting");
		clean_up();
		exit(0);
		break;
	case SIGTERM:
		applog(LOG_DEBUG, "SIGTERM received, exiting");
		clean_up();
		exit(0);
		break;
	case SIGSEGV:
		applog(LOG_DEBUG, "SIGSEGV received, exiting");
		clean_up();
		exit(0);
		break;
	case SIGWINCH:
		applog(LOG_DEBUG, "SIGWINCH received");
		resize_tui();
		break;
	}
}
#endif

int main(int argc, char *argv[])
{
	struct thr_info *thr;
	long flags;
	int i;
	
	time(&time_start);

	rpc_url = strdup(DEF_RPC_URL);
	rpc_user = strdup("");
	rpc_pass = strdup("");

	/* parse command line */
	parse_cmdline(argc, argv);

	pthread_mutex_init(&applog_lock, NULL);
	pthread_mutex_init(&stats_lock, NULL);
	pthread_mutex_init(&tui_lock, NULL);
	pthread_mutex_init(&g_work_lock, NULL);
	pthread_mutex_init(&stratum.sock_lock, NULL);
	pthread_mutex_init(&stratum.work_lock, NULL);

#ifndef WIN32
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGWINCH, signal_handler);
#endif
	
	flags = strncmp(rpc_url, "https:", 6)
	      ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL)
	      : CURL_GLOBAL_ALL;
	if (curl_global_init(flags)) {
		applog(LOG_ERR, "CURL initialization failed");
		return 1;
	}
	
	opt_n_threads = 1;

	if (gc3355_devname != NULL) {
		char *p = gc3355_devname;
		int nn=0;
		do {
			p = strchr(p+1, ',');
			nn++;
		} while(p!=NULL);
		opt_n_threads = nn;
	}
	
	if(opt_curses)
	{
		pthread_mutex_lock(&tui_lock);
		init_tui();
		start_tui();
		pthread_mutex_unlock(&tui_lock);
	}

	struct gc3355_dev devs[opt_n_threads];
	memset(&devs, 0, sizeof(devs));
	gc3355_devs = devs;

	if (!rpc_userpass) {
		rpc_userpass = malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
		if (!rpc_userpass)
			return 1;
		sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
	}

	work_restart = calloc(opt_n_threads, sizeof(*work_restart));
	if (!work_restart)
		return 1;

	thr_info = calloc(opt_n_threads + 6, sizeof(*thr));
	if (!thr_info)
		return 1;

	/* init workio thread info */
	work_thr_id = opt_n_threads;
	thr = &thr_info[work_thr_id];
	thr->id = work_thr_id;
	thr->q = tq_new();
	if (!thr->q)
		return 1;

	/* start work I/O thread */
	if (pthread_create(&thr->pth, NULL, workio_thread, thr)) {
		applog(LOG_ERR, "workio thread create failed");
		return 1;
	}
	
	if (want_stratum) {
		/* init stratum thread info */
		stratum_thr_id = opt_n_threads + 2;
		thr = &thr_info[stratum_thr_id];
		thr->id = stratum_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		/* start stratum thread */
		if (unlikely(pthread_create(&thr->pth, NULL, stratum_thread, thr))) {
			applog(LOG_ERR, "stratum thread create failed");
			return 1;
		}

		if (have_stratum)
			tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
	}
	/* start mining threads */
	if (gc3355_devname != NULL) {
		if (create_gc3355_miner_threads(thr_info, opt_n_threads) != 0)
			return 1;
	
#ifndef WIN32
		/* init api thread info */
		api_thr_id = opt_n_threads + 3;
		thr = &thr_info[api_thr_id];
		thr->id = api_thr_id;
		/* start api thread */
		if (unlikely(pthread_create(&thr->pth, NULL, api_thread, thr))) {
			applog(LOG_ERR, "api thread create failed");
			return 1;
		}
#endif
	}

	if(opt_curses)
	{
		/* init tui thread info */
		tui_main_thr_id = opt_n_threads + 4;
		thr = &thr_info[tui_main_thr_id];
		thr->id = tui_main_thr_id;
		/* start api thread */
		if (unlikely(pthread_create(&thr->pth, NULL, tui_main_thread, thr))) {
			applog(LOG_ERR, "tui main thread create failed");
			return 1;
		}
		/* init tui thread info */
		tui_user_thr_id = opt_n_threads + 5;
		thr = &thr_info[tui_user_thr_id];
		thr->id = tui_user_thr_id;
		/* start api thread */
		if (unlikely(pthread_create(&thr->pth, NULL, tui_user_thread, thr))) {
			applog(LOG_ERR, "tui thread create failed");
			return 1;
		}
	}

	/* main loop - simply wait for workio thread to exit */
	pthread_join(thr_info[work_thr_id].pth, NULL);
	applog(LOG_INFO, "workio thread dead, exiting.");
	
	clean_up();
	
	return 0;
}
