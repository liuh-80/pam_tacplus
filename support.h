/* support.h - support functions for pam_tacplus.c
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

#ifndef PAM_TACPLUS_SUPPORT_H
#define PAM_TACPLUS_SUPPORT_H

#include "libtac.h"

#include <security/pam_modules.h>

/* pam_tacplus command line options */
#define PAM_TAC_DEBUG 0x01
#define PAM_TAC_ACCT  0x02 /* account on all specified servers */
#define PAM_TAC_USE_FIRST_PASS 0x04
#define PAM_TAC_TRY_FIRST_PASS 0x08

typedef struct {
    struct addrinfo *addr;
    char key[256];
} tacplus_server_t;

extern tacplus_server_t tac_srv[TAC_PLUS_MAXSERVERS];
extern int tac_srv_no;

extern char tac_service[64];
extern char tac_protocol[64];
extern char tac_prompt[64];

int _pam_parse (int, const char **);
unsigned long _resolve_name (char *);
unsigned long _getserveraddr (char *serv);
int tacacs_get_password (pam_handle_t *, int, int, char **);
int converse (pam_handle_t *, int, const struct pam_message *, struct pam_response **);
void _pam_log (int, const char *, ...);
void *_xcalloc (size_t);
char *_pam_get_user(pam_handle_t *);
char *_pam_get_terminal(pam_handle_t *);
char *_pam_get_rhost(pam_handle_t *);

/*
 * Parse config file.
 */
int parse_config_file(const char *file);

/*
 * Free tacacs server addrinfo.
 */
void free_tacacs_server_addr();

#endif  /* PAM_TACPLUS_SUPPORT_H */

