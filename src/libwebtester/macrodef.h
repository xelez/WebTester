/**
 * WebTester Server - server of on-line testing system
 *
 * Deifferent MACRO defenitions
 *
 * Copyright 2008 Sergey I. Sharybin <g.ulairi@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef _macrodef_h_
#define _macrodef_h_

#include <libwebtester/smartinclude.h>

BEGIN_HEADER

#include <libwebtester/core-debug.h>
#include <libwebtester/log.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define MALLOC_ZERO(__ptr,__size) \
  { \
    __ptr=malloc (__size); \
    memset (__ptr, 0, __size); \
  }

#define SAFE_FREE(a) \
  if (a) { free (a); a=0; }

#ifndef MIN
#define MIN(a,b) \
  ((a)<(b)?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) \
  ((a)>(b)?(a):(b))
#endif

#define PACK_ARGS(__text,__buf,__size) \
  va_list ap;\
  strcpy (__buf, "");\
  va_start (ap, __text);\
  vsnprintf (__buf, __size, __text, ap); \
  va_end (ap);

#define SET_ERROR(__text,__args...) \
  { \
    if (__error) \
      sprintf (__error, __text, ##__args); \
  }


#define MSEC_COUNT (1000)
#define USEC_COUNT (1000*1000)
#define NSEC_COUNT (1000*1000*1000)

#define RESET_LE(__self,__b,__newval) \
  if (__self<=__b) __self=__newval

#define RESET_LEZ(__self,__newval) \
  RESET_LE (__self, 0, __newval)


#define ITOL(a) (0x00000000L+a)

#define CHECK_TIME_DELTA(__self, __timestamp, __delta) \
  (tv_usec_cmp (timedist (__self, __timestamp), __delta)>0)


#define _INFO(__text,__args...)      core_print (MSG_INFO, __text, ##__args)
#define _ERROR(__text,__args...)     core_print (MSG_ERROR, __text, ##__args)
#define _WARNING(__text,__args...)   core_print (MSG_WARNING, __text, ##__args)

#define STAT_PERMS(__m) \
  ((__m).st_mode&00777)

#define LOG(__module, __text, __args...) \
  log_printf (__module ": " __text, ##__args);

#ifdef __DEBUG
#define DEBUG_LOG(__module, __text, __args...) \
  log_printf ("[DEBUG] "  __module ": " __text, ##__args)
#else
#ifdef USER_DEBUG
#define DEBUG_LOG(__module, __text, __args...) \
  { \
    if (core_is_debug_mode ()) \
      log_printf ("[DEBUG] "  __module ": " __text, ##__args); \
  }
#else
#define DEBUG_LOG(__module, __text, __args...)
#endif
#endif

#define LEAP_YEAR(__y) \
  (  ( ((__y)%4==0 && (__y)%100!=0) || ((__y)%400==0) )?(1):(0) )

#define SET_FLAG(__flags, __f)   (__flags)|=(__f)
#define TEST_FLAG(__flags, __f)  ((__flags)&(__f))
#define CLEAR_FLAG(__flags, __f) ((__flags)&=~(__f))

#define BUF_SIZE(a)  sizeof (a)

END_HEADER

#endif
