#pragma once

#include <stdio.h>
#include <osmocom/core/linuxlist.h>

#define DEBUG
#include <osmocom/core/logging.h>

/* Debug Areas of the code */
enum {
	DGPRS,
	DOBJ,
	DIGPP,
	Debug_LastEntry,
};

extern const struct log_info log_info;
