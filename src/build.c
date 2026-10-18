/* Build identifier shown in /VERSION and 004 ("20260921-c2d1aa0", "-dirty"
 * if built from uncommitted changes). The Makefile defines SEKURIRCD_BUILD
 * and rebuilds this file whenever any other object is rebuilt. */
#include "server.h"
#include "version.h"

#ifndef SEKURIRCD_BUILD
#define SEKURIRCD_BUILD "dev"
#endif
#ifndef SEKURIRCD_VERSION_SUFFIX
#define SEKURIRCD_VERSION_SUFFIX ""
#endif

const char sekurircd_build[] = SEKURIRCD_BUILD;
const char sekurircd_version[] = SEKURIRCD_VERSION SEKURIRCD_VERSION_SUFFIX; /* "1.2.3", or "1.2.3-git" between releases */
