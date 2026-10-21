/* Single source of truth for the version string (mirrors sekurircd/__init__.py's
 * role in the Python daemon: bump this, nothing else). */
#ifndef SEKURIRCD_VERSION_H
#define SEKURIRCD_VERSION_H
#define SEKURIRCD_VERSION "1.2.5"
extern const char sekurircd_version[]; /* build.c: SEKURIRCD_VERSION, plus "-git.<commit date>" off a release tag */
#endif
