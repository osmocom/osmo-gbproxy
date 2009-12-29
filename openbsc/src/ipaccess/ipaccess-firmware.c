/* Routines for parsing an ipacces SDP firmware file */

/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <openbsc/debug.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PART_LENGTH 138

struct sdp_firmware {
	char magic[4];
	char more_magic[4];
	u_int32_t header_length;
	u_int32_t file_length;
	char sw_part[20];
	char text1[122];
	u_int16_t part_length;
	/* stuff i don't know */
} __attribute__((packed));

struct sdp_header_entry {
	u_int16_t something1;
	char text1[64];
	char time[12];
	char date[14];
	char text2[10];
	char text3[20];
	u_int32_t something2;
	u_int32_t addr1;
	u_int32_t addr2;
	u_int32_t something3;
} __attribute__((packed));

static_assert(sizeof(struct sdp_header_entry) == 138, right_entry);

/* more magic, the second "int" in the header */
static char more_magic[] = { 0x10, 0x02, 0x00, 0x0 };


static void analyze_file(int fd)
{
	struct sdp_firmware *firmware_header;
	struct stat stat;
	char buf[4096];
	int rc, i;

	rc = read(fd, buf, sizeof(*firmware_header));
	if (rc < 0) {
		perror("can not read header");
		return;
	}

	firmware_header = (struct sdp_firmware *) &buf[0];
	if (strncmp(firmware_header->magic, " SDP", 4) != 0) {
		fprintf(stderr, "Wrong magic.\n");
		return;
	}

	if (memcmp(firmware_header->more_magic, more_magic, 4) != 0) {
		fprintf(stderr, "Wrong more magic.\n");
		return;
	}

	printf("Printing header information:\n");
	printf("header_length: %u\n", ntohl(firmware_header->header_length));
	printf("file_length: %u\n", ntohl(firmware_header->file_length));
	printf("sw_part: %.20s\n", firmware_header->sw_part);
	printf("text1: %.120s\n", firmware_header->text1);
	printf("items: %u (rest %u)\n", ntohs(firmware_header->part_length) / PART_LENGTH,
		ntohs(firmware_header->part_length) % PART_LENGTH);

	/* verify the file */
	if (fstat(fd, &stat) == -1) {
		perror("Can not stat the file");
		return;
	}

	if (ntohl(firmware_header->file_length) != stat.st_size) {
		fprintf(stderr, "The filesize and the header do not match.\n");
		return;
	}

	if (ntohs(firmware_header->part_length) % PART_LENGTH != 0) {
		fprintf(stderr, "The part length seems to be wrong.\n");
		return;
	}

	/* look into each firmware now */
	for (i = 0; i < ntohs(firmware_header->part_length) / PART_LENGTH; ++i) {
		struct sdp_header_entry entry;
		unsigned int offset = sizeof(struct sdp_firmware);
		offset += i * 138;

		if (lseek(fd, offset, SEEK_SET) != offset) {
			fprintf(stderr, "Can not seek to the offset: %u.\n", offset);
			return;
		}

		rc = read(fd, &entry, sizeof(entry));
		if (rc != sizeof(entry)) {
			fprintf(stderr, "Can not read the header entry.\n");
			return;
		}

		printf("Header Entry: %d\n", i);
		printf("\tsomething1: %u\n", ntohs(entry.something1));
		printf("\ttext1: %.64s\n", entry.text1);
		printf("\ttime: %.12s\n", entry.time);
		printf("\tdate: %.14s\n", entry.date);
		printf("\ttext2: %.10s\n", entry.text2);
		printf("\ttext3: %.20s\n", entry.text3);
		printf("\tsomething2: 0x%x\n", ntohl(entry.something2));
		printf("\taddr1: 0x%x\n", entry.addr1);
		printf("\taddr2: 0x%x\n", entry.addr2);
		printf("\tsomething3: 0x%x\n", ntohl(entry.something3));
	}
}

int main(int argc, char** argv)
{
	int i, fd;

	for (i = 1; i < argc; ++i) {
		printf("Opening possible firmware '%s'\n", argv[i]);
		fd = open(argv[i], O_RDONLY);
		if (!fd) {
			perror("nada");
			continue;
		}

		analyze_file(fd);
	}

	return EXIT_SUCCESS;
}
