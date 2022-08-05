/*
 * MIT License
 *
 * Copyright (c) 2021 Jianhui Zhao <zhaojh329@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __LOG_H
#define __LOG_H

#include <syslog.h>
#include <string.h>

extern int __log_level__;

void log_level(int level);

/* This is useful. The code in the parameter is not executed when the log level is lower than the set value */
#define log(priority, fmt...)                          \
    do {                                               \
        int pri = LOG_PRI(priority);                   \
                                                       \
        if (pri <= __log_level__)                      \
            ___log(pri, fmt);                          \
    } while (0)
#define log_check(priority) (LOG_PRI(priority) <= __log_level__)

#define log_debug(fmt...)     log(LOG_DEBUG, fmt)
#define log_info(fmt...)      log(LOG_INFO, fmt)
#define log_warn(fmt...)      log(LOG_WARNING, fmt)
#define log_err(fmt...)       log(LOG_ERR, fmt)
#define log_debug_check()     log_check(LOG_DEBUG)
#define log_info_check()      log_check(LOG_INFO)
#define log_warn_check()      log_check(LOG_WARNING)
#define log_err_check()       log_check(LOG_ERR)

__attribute__((format(printf, 2, 3)))
void ___log(int priority, const char *fmt, ...);

#endif
