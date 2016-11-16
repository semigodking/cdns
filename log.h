#ifndef LOG_H_WED_AUG_12_22_36_50_2015
#define LOG_H_WED_AUG_12_22_36_50_2015

#include <stdarg.h>
#include <stdbool.h>

#ifndef _WIN32
#include <syslog.h>
#else
#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but significant condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */
#define LOG_MASK(pri) (1 << (pri))
#endif
#define MAX_LOG_LENGTH 512

#define log_errno(prio, msg...) _log_write(__FILE__, __LINE__, __func__, 1, prio, ## msg)
#define log_error(prio, msg...) _log_write(__FILE__, __LINE__, __func__, 0, prio, ## msg)

int log_preopen(const char * ident, const char *dst, bool log_debug, bool log_info);
void log_open();
int log_level_enabled(int priority);

void _log_vwrite(const char *file, int line, const char *func, int do_errno, int priority, const char *fmt, va_list ap);

void _log_write(const char *file, int line, const char *func, int do_errno, int priority, const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__ (( format (printf, 6, 7) ))
#endif
;

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* LOG_H_WED_AUG_12_22_36_50_2015 */

