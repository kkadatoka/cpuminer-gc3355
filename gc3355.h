/*
 * Driver for GC3355 chip to mine Litecoin, power by GridChip & GridSeed
 *
 * Copyright 2013 faster <develop@gridseed.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */
 
#ifndef WIN32
#include <termios.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#else
#define htobe16 htons
#define htole16(x) (x)
#define be16toh ntohs
#define le16toh(x) (x)
#define htobe32 htonl
#define htole32(x) (x)
#define be32toh ntohl
#define le32toh(x) (x)
#define htobe64 htonll
#define htole64(x) (x)
#define be64toh ntohll
#define le64toh(x) (x)
char* strtok_r(char *str, const char *delim, char **nextp);
char* strtok_r(char *str, const char *delim, char **nextp)
{
    char *ret;

    if (str == NULL)
    {
        str = *nextp;
    }

    str += strspn(str, delim);

    if (*str == '\0')
    {
        return NULL;
    }

    ret = str;

    str += strcspn(str, delim);

    if (*str)
    {
        *str++ = '\0';
    }

    *nextp = str;

    return ret;
}
#include <windows.h>
#include <winsock2.h>
#include <io.h>
typedef unsigned int speed_t;
#define  B115200  115200
#endif
#include <ctype.h>
#include <gc3355-commands.h>
#include <string.h>

static char can_start = 0x0;

struct chip_freq
{
	struct chip_freq *next;
	char chip_id;
	unsigned short freq;
};

struct dev_freq
{
	struct dev_freq *next;
	char *devname;
	struct chip_freq *chips;
};

static struct dev_freq *dev_freq_root;

#define GC3355_OVERCLOCK_MAX_HWE 3
#define GC3355_OVERCLOCK_ADJUST_MIN 10
#define GC3355_OVERCLOCK_ADJUST_STEPS 3845
#define GC3355_OVERCLOCK_FREQ_STEP 25
#define GC3355_MIN_FREQ 600
#define GC3355_MAX_FREQ 1400
#define GC3355_HASH_SPEED 84.705882
#define GC3355_TRESHOLD 0.98

/* external functions */
extern void scrypt_1024_1_1_256(const uint32_t *input, uint32_t *output,
    uint32_t *midstate, unsigned char *scratchpad);

/* local functions */
static int gc3355_scanhash(struct gc3355_dev *gc3355, struct work *work, unsigned char *scratchbuf, uint32_t *midstate);

/* close UART device */
static void gc3355_close(int fd)
{
	if (fd > 0)
		close(fd);
	return;
}

static void gc3355_exit(struct gc3355_dev *gc3355)
{
	applog(LOG_INFO, "%d: Terminating GC3355 chip mining thread", gc3355->id);
	gc3355_close(gc3355->dev_fd);
	pthread_exit(NULL);
}

/* open UART device */
static int gc3355_open(struct gc3355_dev *gc3355, speed_t baud)
{
#ifdef WIN32
	DWORD	timeout = 1;

	applog(LOG_INFO, "%d: open device %s", gc3355->id, gc3355->devname);
	if (gc3355->dev_fd > 0)
		gc3355_close(gc3355->dev_fd);

	HANDLE hSerial = CreateFile(gc3355->devname, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (unlikely(hSerial == INVALID_HANDLE_VALUE))
	{
		DWORD e = GetLastError();
		switch (e) {
		case ERROR_ACCESS_DENIED:
			applog(LOG_ERR, "%d: Do not have user privileges required to open %s", gc3355->id, gc3355->devname);
			break;
		case ERROR_SHARING_VIOLATION:
			applog(LOG_ERR, "%d: %s is already in use by another process", gc3355->id, gc3355->devname);
			break;
		default:
			applog(LOG_DEBUG, "%d: Open %s failed, GetLastError:%u", gc3355->id, gc3355->devname, e);
			break;
		}
		return -1;
	}

	// thanks to af_newbie for pointers about this
	COMMCONFIG comCfg = {0};
	comCfg.dwSize = sizeof(COMMCONFIG);
	comCfg.wVersion = 1;
	comCfg.dcb.DCBlength = sizeof(DCB);
	comCfg.dcb.BaudRate = baud;
	comCfg.dcb.fBinary = 1;
	comCfg.dcb.fDtrControl = 0;
	comCfg.dcb.fRtsControl = 0;
	comCfg.dcb.fTXContinueOnXoff = 0;
	comCfg.dcb.fDsrSensitivity = 0;
	comCfg.dcb.ByteSize = 8;
	comCfg.dcb.fParity = 0;
	comCfg.dcb.fOutxCtsFlow = 0;
	comCfg.dcb.fOutxDsrFlow = 0;
	comCfg.dcb.fOutX = 0;
	comCfg.dcb.fInX = 0;
	comCfg.dcb.fAbortOnError = 0;
	SetCommConfig(hSerial, &comCfg, sizeof(comCfg));

	// Code must specify a valid timeout value (0 means don't timeout)
	const DWORD ctoms = (timeout * 100);
	COMMTIMEOUTS cto = {ctoms, 0, ctoms, 0, ctoms};
	SetCommTimeouts(hSerial, &cto);

	PurgeComm(hSerial, PURGE_RXABORT);
	PurgeComm(hSerial, PURGE_TXABORT);
	PurgeComm(hSerial, PURGE_RXCLEAR);
	PurgeComm(hSerial, PURGE_TXCLEAR);

	gc3355->dev_fd = _open_osfhandle((intptr_t)hSerial, 0);
	if (gc3355->dev_fd < 0)
		return -1;
	return 0;
#else
	struct termios	my_termios;
	int fd;

	applog(LOG_INFO, "%d: open device %s", gc3355->id, gc3355->devname);
	if (gc3355->dev_fd > 0)
		gc3355_close(gc3355->dev_fd);

    fd = open(gc3355->devname, O_RDWR | O_CLOEXEC | O_NOCTTY | O_SYNC);
	if (fd < 0) {
		if (errno == EACCES)
			applog(LOG_ERR, "%d: Do not have user privileges to open %s", gc3355->id, gc3355->devname);
		else
			applog(LOG_ERR, "%d: failed open device %s", gc3355->id, gc3355->devname);
		return 1;
	}

	tcgetattr(fd, &my_termios);
	cfsetispeed(&my_termios, baud);
	cfsetospeed(&my_termios, baud);
	cfsetspeed(&my_termios,  baud);
	
	my_termios.c_cflag &= ~(CSIZE | PARENB | CSTOPB);
	my_termios.c_cflag |= CS8;
	my_termios.c_cflag |= CREAD;
	my_termios.c_cflag |= CLOCAL;

	my_termios.c_iflag &= ~(IGNBRK | BRKINT | PARMRK |
			ISTRIP | INLCR | IGNCR | ICRNL | IXON);
	my_termios.c_oflag &= ~OPOST;
	my_termios.c_lflag &= ~(ECHO | ECHOE | ECHONL | ICANON | ISIG | IEXTEN);

	// Code must specify a valid timeout value (0 means don't timeout)
	my_termios.c_cc[VTIME] = (cc_t)1;
	my_termios.c_cc[VMIN] = 0;
	
	tcsetattr(fd, TCSANOW, &my_termios);
	tcflush(fd, TCIOFLUSH);
	gc3355->dev_fd = fd;

	return 0;
#endif
}

/* send data to UART */
static int gc3355_write(struct gc3355_dev *gc3355, const void *buf, size_t buflen)
{
	size_t ret = write(gc3355->dev_fd, buf, buflen);
	usleep(10000);
	if (ret != buflen)
	{
		applog(LOG_INFO, "%d: UART write error", gc3355->id);
		gc3355_exit(gc3355);
	}
	return 0;
}

static int gc3355_gets(struct gc3355_dev *gc3355, unsigned char *buf, int read_amount)
{
	int fd;
	unsigned char	*bufhead, *p;
	ssize_t nread = 0;
	
	fd = gc3355->dev_fd;
	memset(buf, 0, read_amount);
	nread = read(fd, buf, read_amount);
	if(nread == -1)
	{
		applog(LOG_ERR, "%d: Read error: %s", gc3355->id, strerror(errno));
		return 1;
	}
	if(nread == 0)
	{
		return -1;
	}
	if (nread != read_amount)
	{
		applog(LOG_ERR, "%d: Read error: Read %d bytes, but expected %d bytes", gc3355->id, nread, read_amount);
		return 1;
	}
	return 0;
}

static void gc3355_send_cmds(struct gc3355_dev *gc3355, const unsigned char *cmds[])
{
	int i;
	for(i = 0; cmds[i] != NULL; i++)
	{
		gc3355_write(gc3355, cmds[i] + 1, cmds[i][0]);
	}
}

static uint32_t gc3355_get_firmware_version(struct gc3355_dev *gc3355)
{
	unsigned char detect_data[16];
	char buf[12];
	int read;
	
	gc3355_send_cmds(gc3355, firmware_request_cmd);
	read = gc3355_gets(gc3355, buf, 12);
	if (read)
	{
		applog(LOG_ERR, "%d: Failed reading firmware version", gc3355->id);
		return -1;
	}
	// firmware response begins with 55aac000 90909090
	if (memcmp(buf, "\x55\xaa\xc0\x00\x90\x90\x90\x90", 8) != 0)
	{
		applog(LOG_ERR, "%d: Invalid response while reading firmware version", gc3355->id);
		return -1;
	}
	uint32_t fw_version = htobe32(*(uint32_t *)(buf + 8));
	return fw_version;
}

static void gc3355_set_core_freq(struct gc3355_dev *gc3355, int chip_id, unsigned short freq)
{
	const uint16_t x = ((freq / 25) * 0x20) + 0x7fe0;
	unsigned char cmds[] = {0x55, 0xaa, 0xe0 + chip_id, 0, 0x05, 0, x & 0xff, x >> 8};
	gc3355_write(gc3355, cmds, 8);
	gc3355->freq[chip_id] = freq - freq % 25;
	applog(LOG_INFO, "%d@%d: Set GC3355 core frequency to %dMhz", gc3355->id, chip_id, gc3355->freq[chip_id]);
}

static unsigned short fix_freq(unsigned short freq)
{
	return freq >= GC3355_MIN_FREQ ? (freq < GC3355_MAX_FREQ ? freq : GC3355_MAX_FREQ) : GC3355_MIN_FREQ;
}

static unsigned short next_freq(struct gc3355_dev *gc3355, int chip_id)
{
	return gc3355->freq[chip_id] <= gc3355->adjust[chip_id] - GC3355_OVERCLOCK_FREQ_STEP ? gc3355->freq[chip_id] + GC3355_OVERCLOCK_FREQ_STEP : gc3355->freq[chip_id];
}

static unsigned short prev_freq(struct gc3355_dev *gc3355, int chip_id)
{
	return gc3355->freq[chip_id] - GC3355_OVERCLOCK_FREQ_STEP >= GC3355_MIN_FREQ ? gc3355->freq[chip_id] - GC3355_OVERCLOCK_FREQ_STEP : gc3355->freq[chip_id];
}

/*
 * miner thread
 */
static void *gc3355_thread(void *userdata)
{
	struct thr_info	*mythr = userdata;
	int thr_id = mythr->id;
	struct gc3355_dev *gc3355;
	struct work work = {0};
	unsigned char *scratchbuf = NULL;
	int i, chips, rc;
	struct timeval timestr;
	struct dev_freq *dev_freq_curr;
	struct chip_freq *chip_freq_curr;
	unsigned char rptbuf[12];
	
	work.job_id = malloc(1);
	work.thr_id = thr_id;
	gettimeofday(&timestr, NULL);
	gc3355 = &gc3355_devs[thr_id];
	gc3355->id = thr_id;
	gc3355->dev_fd = -1;
	gc3355->resend = true;

	scratchbuf = scrypt_buffer_alloc();

	applog(LOG_INFO, "%d: GC3355 chip mining thread started, in SINGLE mode", thr_id);
	if (gc3355_open(gc3355, B115200))
	{
		can_start++;
		gc3355_exit(gc3355);
	}
	// clear read buffer
	read(gc3355->dev_fd, rptbuf, 12);
	memset(rptbuf, 0, 12);
	applog(LOG_INFO, "%d: Open UART device %s", thr_id, gc3355->devname);
	uint32_t fw_version = gc3355_get_firmware_version(gc3355);
	applog(LOG_INFO, "%d: Firmware version: 0x%08x", thr_id, fw_version);
	gc3355->chips = opt_gc3355_chips;
	if((fw_version & 0xffff) == 0x1401)
	{
		gc3355->chips = 5;
		applog(LOG_INFO, "%d: GC3355 5-chip USB-Mini Miner detected", thr_id);
	}
	else if((fw_version & 0xffff) == 0x1402)
	{
		gc3355->chips = 40;
		applog(LOG_INFO, "%d: GC3355 40-chip G-Blade Miner detected", thr_id);
	}
	else
	{
		applog(LOG_INFO, "%d: Unknown GC3355 Miner detected (chips=%d)", thr_id, gc3355->chips);
	}
	
	gc3355->freq = calloc(gc3355->chips, sizeof(unsigned short));
	gc3355->last_nonce = calloc(gc3355->chips, sizeof(uint32_t));
	gc3355->hashes = calloc(gc3355->chips, sizeof(unsigned long long));
	gc3355->time_now = calloc(gc3355->chips, sizeof(double));
	gc3355->time_spent = calloc(gc3355->chips, sizeof(double));
	gc3355->total_hwe = calloc(gc3355->chips, sizeof(unsigned short));
	gc3355->hwe = calloc(gc3355->chips, sizeof(unsigned short));
	gc3355->adjust = calloc(gc3355->chips, sizeof(unsigned short));
	gc3355->steps = calloc(gc3355->chips, sizeof(unsigned short));
	gc3355->autotune_accepted = calloc(gc3355->chips, sizeof(unsigned int));
	gc3355->accepted = calloc(gc3355->chips, sizeof(unsigned int));
	gc3355->rejected = calloc(gc3355->chips, sizeof(unsigned int));
	gc3355->hashrate = calloc(gc3355->chips, sizeof(double));
	gc3355->shares = calloc(gc3355->chips, sizeof(unsigned long long));
	gc3355->last_share = calloc(gc3355->chips, sizeof(unsigned int));
	for(i = 0; i < gc3355->chips; i++)
	{
		gc3355->adjust[i] = GC3355_MAX_FREQ;
		gc3355->last_share[i] = timestr.tv_sec;
		gc3355->freq[i] = fix_freq(opt_frequency);
	}
	
	for(dev_freq_curr = dev_freq_root; dev_freq_curr != NULL; dev_freq_curr = dev_freq_curr->next)
	{
		if(dev_freq_curr->devname != NULL && !strcmp(gc3355->devname, dev_freq_curr->devname))
		{
			for(chip_freq_curr = dev_freq_curr->chips; chip_freq_curr != NULL; chip_freq_curr = chip_freq_curr->next)
			{
				if(chip_freq_curr->chip_id == -1)
				{
					for(i = 0; i < gc3355->chips; i++) gc3355->freq[i] = fix_freq(chip_freq_curr->freq);
				}
				else gc3355->freq[chip_freq_curr->chip_id] = fix_freq(chip_freq_curr->freq);
				if(chip_freq_curr->next == NULL) break;
			}
		}
		if(dev_freq_curr->next == NULL) break;
	}
	
	gc3355_send_cmds(gc3355, single_cmd_init);
	for(i = 0; i < gc3355->chips; i++)
	{
		gc3355_set_core_freq(gc3355, i, gc3355->freq[i]);
	}
	rc = 0;
	uint32_t midstate[8];
	can_start++;
	gc3355->ready = true;
	if(can_start == opt_n_threads)
	{
		for(dev_freq_curr = dev_freq_root; dev_freq_curr != NULL;)
		{
			struct dev_freq *dev_freq_tmp = dev_freq_curr->next;
			if(dev_freq_curr->chips != NULL)
			{
				for(chip_freq_curr = dev_freq_curr->chips->next; chip_freq_curr != NULL;)
				{
					struct chip_freq *chip_freq_tmp = chip_freq_curr->next;
					free(chip_freq_curr);
					chip_freq_curr = chip_freq_tmp;
				}
				free(dev_freq_curr->chips);
				free(dev_freq_curr->devname);
			}
			free(dev_freq_curr);
			dev_freq_curr = dev_freq_tmp;
		}
	}
	while(1)
	{
		if (have_stratum)
		{
			while (can_start < opt_n_threads || !can_work || g_works[thr_id].job_id == NULL || time(NULL) >= g_work_time + 120)
			usleep(100000);
		}
		if (work_restart[thr_id].restart || memcmp(work.data, g_works[thr_id].data, 76))
		{
			pthread_mutex_lock(&g_work_lock);
			for(i = 0; i < 32; i++)
				work.data[i] = g_works[thr_id].data[i];
			work.target = g_works[thr_id].target;
			free(work.job_id);
			work.job_id = strdup(g_works[thr_id].job_id);
			work.work_id = g_works[thr_id].work_id;
			for(i = 0; i < 4; i++)
				work.xnonce2[i] = g_works[thr_id].xnonce2[i];
			pthread_mutex_unlock(&g_work_lock);
			sha256_init(midstate);
			sha256_transform(midstate, work.data, 0);
			gc3355->resend = true;
		}
		else
		{
			gc3355->resend = false;
		}
		work_restart[thr_id].restart = 0;
		
		rc = gc3355_scanhash(gc3355, &work, scratchbuf, midstate);
		if(rc == -1)
		{
			continue;
		}
		if (rc && !submit_work(mythr, &work))
			break;
	}
	gc3355_exit(gc3355);
}

/* scan hash in GC3355 chips */
static int gc3355_scanhash(struct gc3355_dev *gc3355, struct work *work, unsigned char *scratchbuf, uint32_t *midstate)
{
	uint32_t *pdata = work->data;
	const uint32_t *ptarget = work->target;
	int i, ret;
	unsigned char *ph;
	int thr_id = gc3355->id;
	unsigned char rptbuf[12];
	struct timeval timestr;
	double time_now;
	
	if (gc3355->resend)
	{
		applog(LOG_DEBUG, "%d: Dispatching new work to GC3355 cores (0x%x)", gc3355->id, work->work_id);
		unsigned char bin[156];
		// swab for big endian
		uint32_t midstate2[8];
		uint32_t data2[20];
		uint32_t target2[8];
		for(i = 0; i < 19; i++)
		{
			data2[i] = htole32(pdata[i]);
			if(i >= 8) continue;
			target2[i] = htole32(ptarget[i]);
			midstate2[i] = htole32(midstate[i]);
		}
		data2[19] = 0;
		memset(bin, 0, sizeof(bin));
		memcpy(bin, "\x55\xaa\x1f\x00", 4);
		memcpy(bin+4, (unsigned char *)target2, 32);
		memcpy(bin+36, (unsigned char *)midstate2, 32);
		memcpy(bin+68, (unsigned char *)data2, 80);
		memcpy(bin+148, "\xff\xff\xff\xff", 4);
		memcpy(bin+152, (unsigned char[]){work->work_id >> 24, work->work_id >> 16, work->work_id >> 8, work->work_id}, 4);
		// clear read buffer
		read(gc3355->dev_fd, rptbuf, 12);
		memset(rptbuf, 0, 12);
		gc3355_send_cmds(gc3355, single_cmd_reset);
		gc3355_write(gc3355, bin, 156);
		gc3355->resend = false;
		gettimeofday(&timestr, NULL);
		time_now = timestr.tv_sec + timestr.tv_usec / 1000000.0;
		for(i = 0; i < gc3355->chips; i++)
		{
			gc3355->time_now[i] = time_now;
			gc3355->last_nonce[i] = i * (0xffffffff / gc3355->chips);
		}
	}
	
	while(!work_restart[thr_id].restart && (ret = gc3355_gets(gc3355, (unsigned char *)rptbuf, 12)) <= 0 && !work_restart[thr_id].restart)
	{
		if (rptbuf[0] == 0x55 || rptbuf[1] == 0x20)
		{
			uint32_t nonce, work_id, hash[8];
			const uint32_t Htarg = ptarget[7];
			unsigned char bin[32];
			int stop, chip_id;
			unsigned short freq;
			unsigned int add_hashes = 0;
			unsigned char add_hwe = 0;
			
			if(rptbuf[2] || rptbuf[3])
			{
				applog(LOG_DEBUG, "%d: Invalid response: (0x5520%02x%02x%02x%02x%02x%02x)", gc3355->id, rptbuf[2], rptbuf[3], rptbuf[4], rptbuf[5], rptbuf[6], rptbuf[7]);
				continue;
			}
			
			// swab for big endian
			memcpy((unsigned char *)&nonce, rptbuf+4, 4);
			nonce = htole32(nonce);
			memcpy((unsigned char *)&work_id, rptbuf+8, 4);
			work_id = htobe32(work_id);
			memcpy(pdata+19, &nonce, sizeof(nonce));
			scrypt_1024_1_1_256(pdata, hash, midstate, scratchbuf);
			ph = (unsigned char *)&nonce;
			for(i=0; i<4; i++)
				sprintf(bin+i*2, "%02x", *(ph++));
				
			stop = 1;
			chip_id = nonce / (0xffffffff / gc3355->chips);
			if(work_id != g_curr_work_id)
			{
				applog(LOG_DEBUG, "%d@%d: Work_id differs (%08x != %08x)", gc3355->id, chip_id, work_id, g_curr_work_id);
				continue;
			}
			if(work_restart[thr_id].restart || !can_work)
			{
				applog(LOG_DEBUG, "%d@%d: Scanhash restart requested", gc3355->id, chip_id);
				gc3355->last_nonce[chip_id] = nonce;
				break;
			}
			gettimeofday(&timestr, NULL);
			time_now = timestr.tv_sec + timestr.tv_usec / 1000000.0;
			freq = gc3355->freq[chip_id];
			if (hash[7] <= Htarg && fulltest(hash, ptarget))
			{
				add_hashes = nonce - gc3355->last_nonce[chip_id];
				applog(LOG_DEBUG, "%d@%d %dMHz: Got nonce %s, Hash <= Htarget! (0x%x)", gc3355->id, chip_id, freq, bin, work_id);
			}
			else
			{
				add_hwe = 1;
				stop = -1;
				applog(LOG_DEBUG, "%d@%d %dMHz: Got nonce %s, Invalid nonce! (%d/%d) (0x%x)", gc3355->id, chip_id, freq, bin, gc3355->hwe[chip_id] + 1, GC3355_OVERCLOCK_MAX_HWE, work_id);
			}
			pthread_mutex_lock(&stats_lock);
			gc3355->hashes[chip_id] += add_hashes;
			gc3355->total_hwe[chip_id] += add_hwe;
			gc3355->hwe[chip_id] += add_hwe;
			gc3355->time_spent[chip_id] += time_now - gc3355->time_now[chip_id];
			gc3355->hashrate[chip_id] = gc3355->hashes[chip_id] / gc3355->time_spent[chip_id];
			if(!add_hwe)
				gc3355->last_nonce[chip_id] = nonce;
			else
				gc3355->last_nonce[chip_id] = chip_id * (0xffffffff / gc3355->chips);
			gc3355->time_now[chip_id] = time_now;
			if(opt_gc3355_autotune && gc3355->adjust[chip_id] > 0)
			{
				gc3355->steps[chip_id] += stratum.job.diff;
				if(gc3355->hwe[chip_id] >= GC3355_OVERCLOCK_MAX_HWE || (gc3355->hwe[chip_id] > 0 && (GC3355_OVERCLOCK_ADJUST_STEPS / 2) / stratum.job.diff >= 2 && gc3355->steps[chip_id] >= GC3355_OVERCLOCK_ADJUST_STEPS / 2 && gc3355->hashrate[chip_id] < GC3355_HASH_SPEED * freq * 0.8))
				{
					freq = prev_freq(gc3355, chip_id);
					gc3355->adjust[chip_id] = freq;
				}
				else
				{
					unsigned short steps = GC3355_OVERCLOCK_ADJUST_STEPS - gc3355->steps[chip_id];
					if(GC3355_OVERCLOCK_ADJUST_MIN > gc3355->autotune_accepted[chip_id] && steps < stratum.job.diff * (GC3355_OVERCLOCK_ADJUST_MIN - gc3355->autotune_accepted[chip_id]))
					{
						steps = stratum.job.diff * (GC3355_OVERCLOCK_ADJUST_MIN - gc3355->autotune_accepted[chip_id]);
					}
					if(gc3355->hashrate[chip_id] < GC3355_HASH_SPEED * freq * GC3355_TRESHOLD)
					{
						unsigned short prev_f = prev_freq(gc3355, chip_id);
						if(gc3355->steps[chip_id] >= GC3355_OVERCLOCK_ADJUST_STEPS && gc3355->autotune_accepted[chip_id] >= GC3355_OVERCLOCK_ADJUST_MIN)
						{
							if(prev_f != freq)
							{
								freq = prev_f;
								gc3355->adjust[chip_id] = freq;
							}
							else
							{
								gc3355->adjust[chip_id] = -1;
								applog(LOG_DEBUG, "%d@%d: autotune stopped", gc3355->id, chip_id);
							}
						}
						else
						{
							applog(LOG_DEBUG, "%d@%d: ~%d steps until frequency adjusts to %dMHz", gc3355->id, chip_id, steps, prev_f);
						}
					}
					else
					{
						unsigned short next_f = next_freq(gc3355, chip_id);
						if(gc3355->steps[chip_id] >= GC3355_OVERCLOCK_ADJUST_STEPS)
						{
							if(next_f != freq)
								freq = next_f;
							else
							{
								gc3355->adjust[chip_id] = -1;
								applog(LOG_DEBUG, "%d@%d: autotune stopped", gc3355->id, chip_id);
							}
						}
						else
						{

							if(next_f != freq)
								applog(LOG_DEBUG, "%d@%d: ~%d steps until frequency adjusts to %dMHz", gc3355->id, chip_id, steps, next_f);
							else
								applog(LOG_DEBUG, "%d@%d: ~%d steps until autotune stops", gc3355->id, chip_id, steps);
						}
					}
				}
				if(freq != gc3355->freq[chip_id])
				{
					gc3355->hashes[chip_id] = 0;
					gc3355->time_spent[chip_id] = 0;
					gc3355_set_core_freq(gc3355, chip_id, freq);
					gc3355->hwe[chip_id] = 0;
					gc3355->steps[chip_id] = 0;
					gc3355->autotune_accepted[chip_id] = 0;
				}
			}
			pthread_mutex_unlock(&stats_lock);
			return stop;
		}
		else if(ret == 0)
		{
			applog(LOG_DEBUG, "%d: Invalid header: (0x%02x%02x%02x%02x)", gc3355->id, rptbuf[0], rptbuf[1], rptbuf[2], rptbuf[3]);
			continue;
		}
		usleep(100000);
	}
	return 0;
}

/*
 * create miner thread
 */
static int create_gc3355_miner_threads(struct thr_info *thr_info, int opt_n_threads)
{
	struct thr_info *thr;
	int i;
	unsigned short freq;
	unsigned char found, chip_id;
	char *p, *pd, *end, *str, *end2, *tmp;
	struct dev_freq *dev_freq_curr;
	struct dev_freq *dev_freq_new;
	struct chip_freq *chip_freq_curr;
	struct chip_freq *chip_freq_new;
	struct timeval timestr;
	
	gettimeofday(&timestr, NULL);
	gc3355_time_start = timestr.tv_sec;
	
	i = 0;
	dev_freq_root = calloc(1, sizeof(struct dev_freq));
	if(opt_gc3355_frequency != NULL)
	{
		pd = opt_gc3355_frequency;
		while((str = strtok_r(pd, ",", &end)))
		{
			//devname
			tmp = strtok_r(str, ":", &end2);
			found = 0;
			for(dev_freq_curr = dev_freq_root; dev_freq_curr != NULL; dev_freq_curr = dev_freq_curr->next)
			{
				if(dev_freq_curr->devname != NULL && !strcmp(dev_freq_curr->devname, tmp))
				{
					found = 1;
					break;
				}
				if(dev_freq_curr->next == NULL) break;
			}
			// freq
			freq = atoi(strtok_r(NULL, ":", &end2));
			if(!found)
			{
				if(dev_freq_curr->devname != NULL)
				{
					dev_freq_new = calloc(1, sizeof(struct dev_freq));
					dev_freq_curr->next = dev_freq_new;
				}
				else dev_freq_new = dev_freq_curr;
				dev_freq_new->devname = strdup(tmp);
				dev_freq_new->chips = calloc(1, sizeof(struct chip_freq));
				dev_freq_new->chips->chip_id = -2;
				dev_freq_curr = dev_freq_new;
			}
			// chip_id
			if((tmp = strtok_r(NULL, ":", &end2)))
			{
				chip_id = atoi(tmp);
				found = 0;
				for(chip_freq_curr = dev_freq_curr->chips; chip_freq_curr->next != NULL; chip_freq_curr = chip_freq_curr->next)
				{
					if(chip_freq_curr->chip_id == chip_id)
					{
						found = 1;
						break;
					}
				}
				if(!found)
				{
					chip_freq_new = calloc(1, sizeof(struct chip_freq));
					chip_freq_curr->next = chip_freq_new;
					chip_freq_new->chip_id = chip_id;
					chip_freq_new->freq = freq;
				}
			}
			else
			{
				dev_freq_curr->chips->chip_id = -1;
				dev_freq_curr->chips->freq = freq;
			}
			pd = end;
			i++;
		}
	}
	pd = gc3355_devname;
	for (i = 0; i < opt_n_threads; i++)
	{
		thr = &thr_info[i];
		thr->id = i;
		
		p = strchr(pd, ',');
		if(p != NULL)
			*p = '\0';
		gc3355_devs[i].devname = strdup(pd);
		pd = p + 1;

		pthread_attr_t attrs;
		pthread_attr_init(&attrs);
		if(unlikely(pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED)))
		{
			applog(LOG_ERR, "%d: Failed to detach GC3355 chip mining thread", thr->id);
			return 1;
		}
		if (unlikely(pthread_create(&thr->pth, &attrs, gc3355_thread, thr)))
		{
			applog(LOG_ERR, "%d: GC3355 chip mining thread create failed", thr->id);
			return 1;
		}
		usleep(100000);
	}
	free(gc3355_devname);
	return 0;
}