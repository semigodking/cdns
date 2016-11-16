/* cdns - Cure DNS
 * Copyright (C) 2016 Zhuofei Wang <semigodking@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <argp.h>
#include <errno.h>
#include "event2/event.h"
#include "util.h"
#include "log.h"
#include "cfg.h"

#define DEFAULT_CONFIG_FILE "/etc/cdns.json"

static const char * program_name = "cdns";
static const char program_doc[] =
"cdns - version: 1.0\n"
"Copyright (C) 2016 Zhuofei Wang <semigodking@gmail.com>\n"
"\n"
"cdns cures your DNS.";

struct arg_data 
{
    char  * config_file; /* path to config file */
};

/*  Define options */
static struct argp_option options[] =
{
    {"config", 'c', "path", 0, "Path to config file (Default: " DEFAULT_CONFIG_FILE ")"},
    {0}
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
    struct arg_data *data = (struct arg_data *)state->input;
    switch (key)
    {
    case 'c':
        data->config_file = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

/*
   The ARGP structure itself.
*/
static struct argp arg_def = {options, parse_opt, "", program_doc};
static struct arg_data prog_arg = {.config_file = DEFAULT_CONFIG_FILE,
                                };

/*----------------------------------------------------------------------
-----------------------------------------------------------------------*/
static void start_server();
static int init_signal_handlers(struct event_base * base);
static bool write_pidfile(const char * pidfile);

struct {
    bool    daemon;
    char *  log;
    bool    log_debug;
    bool    log_info;
    char *  pidfile;
} g_app_cfg = { true, "syslog:daemon", false, true, NULL};

config_item global_cfg_items[] = {{.key = "daemon",
                         .type = cdt_bool,
                         .value = &g_app_cfg.daemon,
                        },
                        {.key = "log",
                         .type = cdt_string,
                         .value = &g_app_cfg.log,
                        },
                        {.key = "log_debug",
                         .type = cdt_bool,
                         .value = &g_app_cfg.log_debug,
                        },
                        {.key = "log_info",
                         .type = cdt_bool,
                         .value = &g_app_cfg.log_info,
                        },
                        {.key = "pidfile",
                         .type = cdt_string,
                         .value = &g_app_cfg.pidfile,
                        },
                        {.key = NULL,}
                       };

extern config_item cdns_cfg_items[];
config_item app_cfg_items[] = {{.key = "global",
                         .type = cdt_object,
                         .subitems = &global_cfg_items[0],
                        },
                        {.key = "cdns",
                         .type = cdt_object,
                         .subitems = &cdns_cfg_items[0],
                        },
                        {.key = NULL,}
                       }; 

static void init_global_cfg()
{
    /* init with default config */
}

bool cdns_validate_cfg();
int cdns_init_server(struct event_base * base);
void cdns_debug_dump();
 
int main (int argc, char * argv[])
{
    /* Handle arguments */
    argp_parse (&arg_def, argc, argv, 0, 0, &prog_arg);

    /* init globals */
    init_global_cfg();

    /* Load configurations */
    if (!cfg_loadf(prog_arg.config_file, &app_cfg_items[0]))
        return -1;

    /* Verify configurations */
    if (!cdns_validate_cfg())
        return -1;

    /* Setup logging */
    if (log_preopen("cdns", g_app_cfg.log, g_app_cfg.log_debug, g_app_cfg.log_info)) {
        fprintf(stderr, "Failed to set up logging.\n");
        return -1; 
    } 
    log_open();

#ifndef _WIN32
    if (g_app_cfg.daemon) {
        if (daemon(1, 0)) {
            log_errno(LOG_ERR, "daemon");
            return -1;
        }
    }
#endif
    if (g_app_cfg.pidfile)
        write_pidfile(g_app_cfg.pidfile);
        
#ifdef _WIN32
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        log_error(LOG_ERR, "WSAStartup failed with error: %d\n", err);
        return -1;
    }
#endif

    /* Start serving */    
    start_server(); 

#ifdef _WIN32
    WSACleanup();
#endif
    /* Clean up before exit */
    return 0;
}

/*--------------- CUT --------------------*/
static void terminate(int sig, short what, void *_arg)
{
    struct event_base * base = _arg;

    if (event_base_loopbreak(base) != 0)
        log_error(LOG_WARNING, "event_loopbreak");

}

static void sigusr1_handler(int sig, short what, void *_arg)
{
    cdns_debug_dump();
}

static int init_signal_handlers(struct event_base * base)
{
    struct event * terminators[2];
    struct event * dumper = NULL;
    int exit_signals[2] = {SIGTERM, SIGINT};
    int i;

    /* Setup signals that terminate program */
    memset(terminators, 0, sizeof(terminators));
    assert(SIZEOF_ARRAY(exit_signals) == SIZEOF_ARRAY(terminators));
    for (i = 0; i < SIZEOF_ARRAY(exit_signals); i++) {
        terminators[i] = evsignal_new(base, exit_signals[i], terminate, base);
        if (!terminators[i]) {
            log_errno(LOG_ERR, "evsignal_new");
            goto fail; 
        }
        if (evsignal_add(terminators[i], NULL) != 0) {
            log_errno(LOG_ERR, "evsignal_add");
            goto fail; 
        }
    }

#ifndef _WIN32
    /* Do not panic due to broken pipe. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGPIPE, &sa, NULL)  == -1)
        goto fail; 

    dumper = evsignal_new(base, SIGUSR1, sigusr1_handler, NULL);
    if (!dumper) {
        log_errno(LOG_ERR, "evsignal_new");
        goto fail;
    }
    if (evsignal_add(dumper, NULL) != 0) {
        log_errno(LOG_ERR, "evsignal_add");
        goto fail;
    }
#endif

    return 0;

fail:
    if (dumper) {
        if (evsignal_del(dumper) != 0)
            log_errno(LOG_WARNING, "evsignal_del");
        event_free(dumper);
    }

    for (i = 0; i < SIZEOF_ARRAY(exit_signals); i++) {
        if (terminators[i]) {
            if (evsignal_del(terminators[i]) != 0)
                log_errno(LOG_WARNING, "evsignal_del");
            event_free(terminators[i]);
        }
    }

    return -1;
}


static void start_server()
{
    struct event_base * base = event_base_new();

    if (!base) {
        log_error(LOG_ERR, "Unable to initialize libevent base"); 
        return;
    }
    // Handling signals with events ensures no race condition
    if (init_signal_handlers(base))
        return;
    if (cdns_init_server(base))
        return;

    log_error(LOG_INFO, "%s started", program_name); 
    event_base_dispatch(base);
    event_base_free(base);
}


static bool write_pidfile(const char * pidfile)
{
    FILE * f;
    if (pidfile) {
        f = fopen(pidfile, "w");
        if (!f) {
            log_error(LOG_WARNING, "Unable to open pidfile for write: %s", pidfile);
            return false;
        }
        fprintf(f, "%d\n", getpid());
        fclose(f);
        return true;
    }
    return false;
}

