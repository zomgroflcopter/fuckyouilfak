/*
 ___________             __     _____.___.
 \_   _____/_ __   ____ |  | __ \__  |   | ____  __ __
  |    __)|  |  \_/ ___\|  |/ /  /   |   |/  _ \|  |  \
  |     \ |  |  /\  \___|    <   \____   (  <_> )  |  /
  \___  / |____/  \___  >__|_ \  / ______|\____/|____/
      \/              \/     \/  \/
 .___.__   _____        __     ._.
 |   |  |_/ ____\____  |  | __ | |
 |   |  |\   __\\__  \ |  |/ / | |
 |   |  |_|  |   / __ \|    <   \|
 |___|____/__|  (____  /__|_ \  __
                     \/     \/  \/
 Fuck You Ilfak!
 IDA Pro 9.0 Beta 2 macOS x64 Fix Loader
 (c) fG! 2024 - reverser@put.as - https://reverse.put.as
 
 log.h
 
 */

#pragma once

#define ERROR_MSG(fmt, ...) fprintf(stderr, "[ERROR] " fmt " \n", ## __VA_ARGS__)
#define WARNING_MSG(fmt, ...) fprintf(stderr, "[WARNING] " fmt " \n", ## __VA_ARGS__)
#define OUTPUT_MSG(fmt, ...) fprintf(stdout, fmt " \n", ## __VA_ARGS__)
#if DEBUG == 0
#   define DEBUG_MSG(fmt, ...) do {} while (0)
#else
#   define DEBUG_MSG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ## __VA_ARGS__)
#endif
