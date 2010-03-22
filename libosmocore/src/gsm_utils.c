/*
 * (C) 2008 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

//#include <openbsc/gsm_data.h>
#include <osmocore/utils.h>
#include <osmocore/gsm_utils.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#include "../config.h"

/* GSM 03.38 6.2.1 Charachter packing */
int gsm_7bit_decode(char *text, const uint8_t *user_data, uint8_t length)
{
	int i = 0;
	int l = 0;

        /* FIXME: We need to account for user data headers here */
	i += l;
	for (; i < length; i ++)
		*(text ++) =
			((user_data[(i * 7 + 7) >> 3] <<
			  (7 - ((i * 7 + 7) & 7))) |
			 (user_data[(i * 7) >> 3] >>
			  ((i * 7) & 7))) & 0x7f;
	*text = '\0';

	return i - l;
}


/* GSM 03.38 6.2.1 Charachter packing */
int gsm_7bit_encode(uint8_t *result, const char *data)
{
	int i,j = 0;
	unsigned char ch1, ch2;
	int shift = 0;

	for ( i=0; i<strlen(data); i++ ) {

		ch1 = data[i] & 0x7F;
		ch1 = ch1 >> shift;
		ch2 = data[(i+1)] & 0x7F;
		ch2 = ch2 << (7-shift);

		ch1 = ch1 | ch2;

		result[j++] = ch1;

		shift++;

		if ((shift == 7) && (i+1<strlen(data))) {
			shift = 0;
			i++;
		}
	}

	return i;
}

/* determine power control level for given dBm value, as indicated
 * by the tables in chapter 4.1.1 of GSM TS 05.05 */
int ms_pwr_ctl_lvl(enum gsm_band band, unsigned int dbm)
{
	switch (band) {
	case GSM_BAND_450:
	case GSM_BAND_480:
	case GSM_BAND_750:
	case GSM_BAND_900:
	case GSM_BAND_810:
	case GSM_BAND_850:
		if (dbm >= 39)
			return 0;
		else if (dbm < 5)
			return 19;
		else {
			/* we are guaranteed to have (5 <= dbm < 39) */
			return 2 + ((39 - dbm) / 2);
		}
		break;
	case GSM_BAND_1800:
		if (dbm >= 36)
			return 29;
		else if (dbm >= 34)	
			return 30;
		else if (dbm >= 32)
			return 31;
		else if (dbm == 31)
			return 0;
		else {
			/* we are guaranteed to have (0 <= dbm < 31) */
			return (30 - dbm) / 2;
		}
		break;
	case GSM_BAND_1900:
		if (dbm >= 33)
			return 30;
		else if (dbm >= 32)
			return 31;
		else if (dbm == 31)
			return 0;
		else {
			/* we are guaranteed to have (0 <= dbm < 31) */
			return (30 - dbm) / 2;
		}
		break;
	}
	return -EINVAL;
}

int ms_pwr_dbm(enum gsm_band band, uint8_t lvl)
{
	lvl &= 0x1f;

	switch (band) {
	case GSM_BAND_450:
	case GSM_BAND_480:
	case GSM_BAND_750:
	case GSM_BAND_900:
	case GSM_BAND_810:
	case GSM_BAND_850:
		if (lvl < 2)
			return 39;
		else if (lvl < 20)
			return 39 - ((lvl - 2) * 2) ;
		else
			return 5;
		break;
	case GSM_BAND_1800:
		if (lvl < 16)
			return 30 - (lvl * 2);
		else if (lvl < 29)
			return 0;
		else
			return 36 - ((lvl - 29) * 2);
		break;
	case GSM_BAND_1900:
		if (lvl < 16)
			return 30 - (lvl * 2);
		else if (lvl < 30)
			return -EINVAL;
		else
			return 33 - (lvl - 30);
		break;
	}
	return -EINVAL;
}

/* According to TS 08.05 Chapter 8.1.4 */
int rxlev2dbm(uint8_t rxlev)
{
	if (rxlev > 63)
		rxlev = 63;

	return -110 + rxlev;
}

/* According to TS 08.05 Chapter 8.1.4 */
uint8_t dbm2rxlev(int dbm)
{
	int rxlev = dbm + 110;

	if (rxlev > 63)
		rxlev = 63;
	else if (rxlev < 0)
		rxlev = 0;

	return rxlev;
}

const char *gsm_band_name(enum gsm_band band)
{
	switch (band) {
	case GSM_BAND_450:
		return "GSM450";
	case GSM_BAND_480:
		return "GSM450";
	case GSM_BAND_750:
		return "GSM750";
	case GSM_BAND_810:
		return "GSM810";
	case GSM_BAND_850:
		return "GSM850";
	case GSM_BAND_900:
		return "GSM900";
	case GSM_BAND_1800:
		return "DCS1800";
	case GSM_BAND_1900:
		return "PCS1900";
	}
	return "invalid";
}

enum gsm_band gsm_band_parse(const char* mhz)
{
	while (*mhz && !isdigit(*mhz))
		mhz++;

	if (*mhz == '\0')
		return -EINVAL;

	switch (strtol(mhz, NULL, 10)) {
	case 450:
		return GSM_BAND_450;
	case 480:
		return GSM_BAND_480;
	case 750:
		return GSM_BAND_750;
	case 810:
		return GSM_BAND_810;
	case 850:
		return GSM_BAND_850;
	case 900:
		return GSM_BAND_900;
	case 1800:
		return GSM_BAND_1800;
	case 1900:
		return GSM_BAND_1900;
	default:
		return -EINVAL;
	}
}


#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
void generate_backtrace()
{
	int i, nptrs;
	void *buffer[100];
	char **strings;

	nptrs = backtrace(buffer, ARRAY_SIZE(buffer));
	printf("backtrace() returned %d addresses\n", nptrs);

	strings = backtrace_symbols(buffer, nptrs);
	if (!strings)
		return;

	for (i = 1; i < nptrs; i++)
		printf("%s\n", strings[i]);

	free(strings);
}
#endif

enum gsm_band gsm_arfcn2band(uint16_t arfcn)
{
	if (arfcn & ARFCN_PCS)
		return GSM_BAND_1900;
	else if (arfcn <= 124)
		return GSM_BAND_900;
	else if (arfcn >= 955 && arfcn <= 1023)
		return GSM_BAND_900;
	else if (arfcn >= 128 && arfcn <= 251)
		return GSM_BAND_850;
	else if (arfcn >= 512 && arfcn <= 885)
		return GSM_BAND_1800;
	else if (arfcn >= 259 && arfcn <= 293)
		return GSM_BAND_450;
	else if (arfcn >= 306 && arfcn <= 340)
		return GSM_BAND_480;
	else if (arfcn >= 350 && arfcn <= 425)
		return GSM_BAND_810;
	else if (arfcn >= 438 && arfcn <= 511)
		return GSM_BAND_750;
	else
		return GSM_BAND_1800;
}

/* Convert an ARFCN to the frequency in MHz * 10 */
uint16_t gsm_arfcn2freq10(uint16_t arfcn, int uplink)
{
	uint16_t freq10_ul;
	uint16_t freq10_dl;

	if (arfcn & ARFCN_PCS) {
		/* DCS 1900 */
		arfcn &= ~ARFCN_PCS;
		freq10_ul = 18502 + 2 * (arfcn-512);
		freq10_dl = freq10_ul + 800;
	} else if (arfcn <= 124) {
		/* Primary GSM + ARFCN 0 of E-GSM */
		freq10_ul = 8900 + 2 * arfcn;
		freq10_dl = freq10_ul + 450;
	} else if (arfcn >= 955 && arfcn <= 1023) {
		/* E-GSM and R-GSM */
		freq10_ul = 8900 + 2 * (arfcn - 1024);
		freq10_dl = freq10_ul + 450;
	} else if (arfcn >= 128 && arfcn <= 251) {
		/* GSM 850 */
		freq10_ul = 8242 + 2 * (arfcn - 128);
		freq10_dl = freq10_ul + 450;
	} else if (arfcn >= 512 && arfcn <= 885) {
		/* DCS 1800 */
		freq10_ul = 17102 + 2 * (arfcn - 512);
		freq10_dl = freq10_ul + 950;
	} else if (arfcn >= 259 && arfcn <= 293) {
		/* GSM 450 */
		freq10_ul = 4506 + 2 * (arfcn - 259);
		freq10_dl = freq10_ul + 100;
	} else if (arfcn >= 306 && arfcn <= 340) {
		/* GSM 480 */
		freq10_ul = 4790 + 2 * (arfcn - 306);
		freq10_dl = freq10_ul + 100;
	} else if (arfcn >= 350 && arfcn <= 425) {
		/* GSM 810 */
		freq10_ul = 8060 + 2 * (arfcn - 350);
		freq10_dl = freq10_ul + 450;
	} else if (arfcn >= 438 && arfcn <= 511) {
		/* GSM 750 */
		freq10_ul = 7472 + 2 * (arfcn - 438);
		freq10_dl = freq10_ul + 300;
	} else
		return 0xffff;

	if (uplink)
		return freq10_ul;
	else
		return freq10_dl;
}

void gsm_fn2gsmtime(struct gsm_time *time, uint32_t fn)
{
	time->fn = fn;
	time->t1 = time->fn / (26*51);
	time->t2 = time->fn % 26;
	time->t3 = time->fn % 51;
	time->tc = (time->fn / 51) % 8;
}

uint32_t gsm_gsmtime2fn(struct gsm_time *time)
{
	/* TS 05.02 Chapter 4.3.3 TDMA frame number */
	return (51 * ((time->t3 - time->t2 + 26) % 26) + time->t3 + (26 * 51 * time->t1));
}
