/* support.c - support functions for pam_tacplus.c
 * 
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 *
 * See `CHANGES' file for revision history.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include "support.h"
#include "pam_tacplus.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h> /* isspace() */

/* tacacs server information */
tacplus_server_t tac_srv[TAC_PLUS_MAXSERVERS];
struct addrinfo tac_srv_addr[TAC_PLUS_MAXSERVERS];
struct sockaddr tac_sock_addr[TAC_PLUS_MAXSERVERS];
struct sockaddr_in6 tac_sock6_addr[TAC_PLUS_MAXSERVERS];

int tac_srv_no = 0;

char tac_service[64];
char tac_protocol[64];
char tac_prompt[64];
char *__vrfname=NULL;
char tac_source_ip[64];

/* source address */
struct addrinfo tac_source_addr;
struct sockaddr tac_source_sock_addr;
struct sockaddr_in6 tac_source_sock6_addr;

void _pam_log(int err, const char *format,...) {
    char msg[256];
    va_list args;

    va_start(args, format);
    vsnprintf(msg, sizeof(msg), format, args);
    openlog("PAM-tacplus", LOG_PID, LOG_AUTH);
    syslog(err, "%s", msg);
    va_end(args);
    closelog();
}

char *_pam_get_user(pam_handle_t *pamh) {
    int retval;
    char *user;

    retval = pam_get_user(pamh, (void *)&user, "Username: ");
    if (retval != PAM_SUCCESS || user == NULL || *user == '\0') {
        _pam_log(LOG_ERR, "unable to obtain username");
        user = NULL;
    }
    return user;
}

char *_pam_get_terminal(pam_handle_t *pamh) {
    int retval;
    char *tty;

    retval = pam_get_item(pamh, PAM_TTY, (void *)&tty);
    if (retval != PAM_SUCCESS || tty == NULL || *tty == '\0') {
        tty = ttyname(STDIN_FILENO);
        if(tty == NULL || *tty == '\0')
            tty = "unknown";
    }
    return tty;
}

char *_pam_get_rhost(pam_handle_t *pamh) {
    int retval;
    char *rhost;

    retval = pam_get_item(pamh, PAM_RHOST, (void *)&rhost);
    if (retval != PAM_SUCCESS || rhost == NULL || *rhost == '\0') {
        rhost = "unknown";
    }
    return rhost;
}

int converse(pam_handle_t * pamh, int nargs, const struct pam_message *message,
    struct pam_response **response) {

    int retval;
    struct pam_conv *conv;

    if ((retval = pam_get_item (pamh, PAM_CONV, (const void **)&conv)) == PAM_SUCCESS) {
        retval = conv->conv(nargs, &message, response, conv->appdata_ptr);

        if (retval != PAM_SUCCESS) {
            _pam_log(LOG_ERR, "(pam_tacplus) converse returned %d", retval);
            _pam_log(LOG_ERR, "that is: %s", pam_strerror (pamh, retval));
        }
    } else {
        _pam_log (LOG_ERR, "(pam_tacplus) converse failed to get pam_conv");
    }

    return retval;
}

/* stolen from pam_stress */
int tacacs_get_password (pam_handle_t * pamh, int flags
    ,int ctrl, char **password) {

    const void *pam_pass;
    char *pass = NULL;

    if (ctrl & PAM_TAC_DEBUG)
        syslog (LOG_DEBUG, "%s: called", __FUNCTION__);

    if ( (ctrl & (PAM_TAC_TRY_FIRST_PASS | PAM_TAC_USE_FIRST_PASS))
        && (pam_get_item(pamh, PAM_AUTHTOK, &pam_pass) == PAM_SUCCESS)
        && (pam_pass != NULL) ) {
         if ((pass = strdup(pam_pass)) == NULL)
              return PAM_BUF_ERR;
    } else if ((ctrl & PAM_TAC_USE_FIRST_PASS)) {
         _pam_log(LOG_WARNING, "no forwarded password");
         return PAM_PERM_DENIED;
    } else {
         struct pam_message msg;
         struct pam_response *resp = NULL;
         int retval;

         /* set up conversation call */
         msg.msg_style = PAM_PROMPT_ECHO_OFF;

         if (!tac_prompt[0]) {
             msg.msg = "Password: ";
         } else {
             msg.msg = tac_prompt;
         }

         if ((retval = converse (pamh, 1, &msg, &resp)) != PAM_SUCCESS)
             return retval;

         if (resp != NULL) {
             if (resp->resp == NULL && (ctrl & PAM_TAC_DEBUG))
                 _pam_log (LOG_DEBUG, "pam_sm_authenticate: NULL authtok given");

             pass = resp->resp;    /* remember this! */
             resp->resp = NULL;

             free(resp);
             resp = NULL;
         } else {
             if (ctrl & PAM_TAC_DEBUG) {
               _pam_log (LOG_DEBUG, "pam_sm_authenticate: no error reported");
               _pam_log (LOG_DEBUG, "getting password, but NULL returned!?");
             }
             return PAM_CONV_ERR;
         }
    }

    /*
       FIXME *password can still turn out as NULL
       and it can't be free()d when it's NULL
    */
    *password = pass;       /* this *MUST* be free()'d by this module */

    if(ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: obtained password", __FUNCTION__);

    return PAM_SUCCESS;
}

/*
 * Set tacacs server addrinfo.
 */
void set_tacacs_server_addr(int tac_srv_no, struct addrinfo* server) {
    tac_srv[tac_srv_no].addr = &(tac_srv_addr[tac_srv_no]);
    memcpy(tac_srv[tac_srv_no].addr, server, sizeof(struct addrinfo));

    if (server->ai_family == AF_INET6) {
        tac_srv[tac_srv_no].addr->ai_addr = (struct sockaddr *)&(tac_sock6_addr[tac_srv_no]);
        memcpy(tac_srv[tac_srv_no].addr->ai_addr, server->ai_addr, sizeof(struct sockaddr_in6));
    }
    else {
        tac_srv[tac_srv_no].addr->ai_addr = &(tac_sock_addr[tac_srv_no]);
        memcpy(tac_srv[tac_srv_no].addr->ai_addr, server->ai_addr, sizeof(struct sockaddr));
    }

    tac_srv[tac_srv_no].addr->ai_canonname = NULL;
    tac_srv[tac_srv_no].addr->ai_next = NULL;
}

/* set source ip address for the outgoing tacacs packets */
void set_source_ip(const char *tac_source_ip) {

    struct addrinfo hints, *source_address;
    int rv;

    /* set the source ip address for the tacacs packets */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((rv = getaddrinfo(tac_source_ip, NULL, &hints,
                          &source_address)) != 0) {
        _pam_log(LOG_ERR, "error setting the source ip information");
    } else {
        memcpy(&tac_source_addr, source_address, sizeof(struct addrinfo));

        if (source_address->ai_family == AF_INET6) {
            tac_source_addr.ai_addr = (struct sockaddr *)&(tac_source_sock6_addr);
            memcpy(tac_source_addr.ai_addr, source_address->ai_addr, sizeof(struct sockaddr_in6));
        }
        else {
            tac_source_addr.ai_addr = &(tac_source_sock_addr);
            memcpy(tac_source_addr.ai_addr, source_address->ai_addr, sizeof(struct sockaddr));
        }

        freeaddrinfo(source_address);
        _pam_log(LOG_DEBUG, "source ip is set");
    }
}

/*
 * Parse one arguments.
 * Use this method for both:
 *    1. command line parameter
 *    2. config file
 */
int _pam_parse_arg (const char *arg, char* current_secret, uint current_secret_buffer_size) {
    int ctrl = 0;

    if (!strcmp (arg, "debug")) { /* all */
        ctrl |= PAM_TAC_DEBUG;
    } else if (!strcmp (arg, "use_first_pass")) {
        ctrl |= PAM_TAC_USE_FIRST_PASS;
    } else if (!strcmp (arg, "try_first_pass")) { 
        ctrl |= PAM_TAC_TRY_FIRST_PASS;
    } else if (!strncmp (arg, "service=", 8)) { /* author & acct */
        xstrcpy (tac_service, arg + 8, sizeof(tac_service));
    } else if (!strncmp (arg, "protocol=", 9)) { /* author & acct */
        xstrcpy (tac_protocol, arg + 9, sizeof(tac_protocol));
    } else if (!strncmp (arg, "prompt=", 7)) { /* authentication */
        xstrcpy (tac_prompt, arg + 7, sizeof(tac_prompt));
        /* Replace _ with space */
        int chr;
        for (chr = 0; chr < strlen(tac_prompt); chr++) {
            if (tac_prompt[chr] == '_') {
                tac_prompt[chr] = ' ';
            }
        }
    } else if (!strncmp (arg, "login=", 6)) {
        xstrcpy (tac_login, arg + 6, sizeof(tac_login));
    } else if (!strcmp (arg, "acct_all")) {
        ctrl |= PAM_TAC_ACCT;
    } else if (!strncmp (arg, "server=", 7)) { /* authen & acct */
        if(tac_srv_no < TAC_PLUS_MAXSERVERS) { 
            struct addrinfo hints, *servers, *server;
            int rv;
            char *close_bracket, *server_name, *port, server_buf[256];

            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC;  /* use IPv4 or IPv6, whichever */
            hints.ai_socktype = SOCK_STREAM;

            if (strlen(arg + 7) >= sizeof(server_buf)) {
                _pam_log(LOG_ERR, "server address too long, sorry");
                return ctrl;
            }
            strcpy(server_buf, arg + 7);

            if (*server_buf == '[' && (close_bracket = strchr(server_buf, ']')) != NULL) { /* Check for URI syntax */
                server_name = server_buf + 1;
                port = strchr(close_bracket, ':');
                *close_bracket = '\0';
            } else { /* Fall back to traditional syntax */
                server_name = server_buf;
                port = strchr(server_buf, ':');
            }
            if (port != NULL) {
                *port = '\0';
                port++;
            }
            if ((rv = getaddrinfo(server_name, (port == NULL) ? "49" : port, &hints, &servers)) == 0) {
                for(server = servers; server != NULL && tac_srv_no < TAC_PLUS_MAXSERVERS; server = server->ai_next) {
                    /* set server address with allocate memory */
                    set_tacacs_server_addr(tac_srv_no, server);

                    /* copy secret to key */
                    snprintf(tac_srv[tac_srv_no].key, sizeof(tac_srv[tac_srv_no].key), "%s", current_secret);
                    tac_srv_no++;
                }

                /* release servers memory */
                freeaddrinfo(servers);
            } else {
                _pam_log (LOG_ERR,
                    "skip invalid server: %s (getaddrinfo: %s)",
                    server_name, gai_strerror(rv));
            }
        } else {
            _pam_log(LOG_ERR, "maximum number of servers (%d) exceeded, skipping",
                TAC_PLUS_MAXSERVERS);
        }
    } else if (!strncmp (arg, "secret=", 7)) {
        int i;

        /* points right into arg (which is const) */
        snprintf(current_secret, current_secret_buffer_size, "%s", arg + 7);

        /* if 'secret=' was given after a 'server=' parameter, fill in the current secret */
        for(i = tac_srv_no-1; i >= 0; i--) {
            if (tac_srv[i].key != NULL)
                break;

            /* copy secret to key */
            snprintf(tac_srv[i].key, sizeof(tac_srv[i].key), "%s", current_secret);
        }
    } else if (!strncmp (arg, "timeout=", 8)) {
        /* FIXME atoi() doesn't handle invalid numeric strings well */
        tac_timeout = atoi(arg + 8);

        if (tac_timeout < 0) {
            tac_timeout = 0;
        } else { 
            tac_readtimeout_enable = 1;
        }
    } else if(!strncmp(arg, "vrf=", 4)) {
        __vrfname = strdup(arg + 4);
    } else if (!strncmp (arg, "source_ip=", strlen("source_ip="))) {
        /* source ip for the packets */
        strncpy (tac_source_ip, arg + strlen("source_ip="), sizeof(tac_source_ip));
        set_source_ip (tac_source_ip);
    } else {
        _pam_log (LOG_WARNING, "unrecognized option: %s", arg);
    }

    return ctrl;
}    /* _pam_parse_arg */


/*
 * Parse config file.
 */
int parse_config_file(const char *file) {
    FILE *config_file;
    char line_buffer[256];
    int ctrl = 0;

    config_file = fopen(file, "r");
    if(config_file == NULL) {
        _pam_log(LOG_ERR, "Failed to open config file %s: %m", file);
        return 0;
    }

    char current_secret[256];
    memset(current_secret, 0, sizeof(current_secret));
    while (fgets(line_buffer, sizeof line_buffer, config_file)) {
        if(*line_buffer == '#' || isspace(*line_buffer))
            continue; /* skip comments and blank line. */
        strtok(line_buffer, " \t\n\r\f");
        ctrl |= _pam_parse_arg(line_buffer, current_secret, sizeof(current_secret));
    }

    fclose(config_file);
    return ctrl;
}
int _pam_parse (int argc, const char **argv) {
    int ctrl = 0;
    char current_secret[256];
    memset(current_secret, 0, sizeof(current_secret));

    /* otherwise the list will grow with each call */
    memset(tac_srv, 0, sizeof(tacplus_server_t) * TAC_PLUS_MAXSERVERS);
    tac_srv_no = 0;

    tac_service[0] = 0;
    tac_protocol[0] = 0;
    tac_prompt[0] = 0;
    tac_login[0] = 0;
    tac_source_ip[0] = 0;

    for (ctrl = 0; argc-- > 0; ++argv) {
        ctrl |= _pam_parse_arg(*argv, current_secret, sizeof(current_secret));
    }

    if (ctrl & PAM_TAC_DEBUG) {
        int n;

        _pam_log(LOG_DEBUG, "%d servers defined", tac_srv_no);

        for(n = 0; n < tac_srv_no; n++) {
            _pam_log(LOG_DEBUG, "server[%d] { addr=%s, key='%c*****' }", n, tac_ntop(tac_srv[n].addr->ai_addr), tac_srv[n].key[0]);
        }

        _pam_log(LOG_DEBUG, "tac_service='%s'", tac_service);
        _pam_log(LOG_DEBUG, "tac_protocol='%s'", tac_protocol);
        _pam_log(LOG_DEBUG, "tac_prompt='%s'", tac_prompt);
        _pam_log(LOG_DEBUG, "tac_login='%s'", tac_login);
        _pam_log(LOG_DEBUG, "tac_source_ip='%s'", tac_source_ip);
    }

    return ctrl;
}    /* _pam_parse */
