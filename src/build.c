/* Build identifier shown in /VERSION and 004 ("20260921-c2d1aa0", "-dirty"
 * if built from uncommitted changes). The Makefile defines SEKURIRCD_BUILD
 * and rebuilds this file whenever any other object is rebuilt. */
#include "server.h"

#ifndef SEKURIRCD_BUILD
#define SEKURIRCD_BUILD "dev"
#endif

const char sekurircd_build[] = SEKURIRCD_BUILD;
