/* map.c — 把生成的档案表实例化（gp6.1 只在 6.1 上用） */
#define _GNU_SOURCE
#include "ghost.h"
#include "map_6.1.h"

const ghost_map *g_map; /* pick by uname; NULL = refuse */
char g_release[128];
