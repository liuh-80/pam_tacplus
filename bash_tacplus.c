#include <stdio.h>
#include <stdarg.h>

#include "libtac.h"
#include "support.h"

const char *tacacs_config_file = "/etc/tacplus_servers";

/* Tacacs server config data */
typedef struct {
    struct addrinfo *address;
    const char *key;
} tacacs_server_t;

/* Tacacs servers */
static tacacs_server_t tacacs_servers[TAC_PLUS_MAXSERVERS];

/*
 * Output verbose log.
 */
void output_verbose_log (const char *format, ...)
{
  /* RODO: change to write log file*/
  va_list args;

  fprintf (stderr, "TACACS+: ");

  va_start (args, format);

  vfprintf (stderr, format, args);
  fprintf (stderr, "\n");

  va_end (args);
}

/*
 * Output error message.
 */
void output_error (const char *format, ...)
{
  va_list args;

  fprintf (stderr, "TACACS+: ");

  va_start (args, format);

  vfprintf (stderr, format, args);
  fprintf (stderr, "\n");

  va_end (args);
}

/*
 * Tacacs plugin initialization.
 */
void plugin_init ()
{
    output_verbose_log("tacacs plugin initialize.");
}

/*
 * Tacacs plugin release.
 */
void plugin_uninit ()
{
    output_verbose_log("tacacs plugin un-initialize.");
}

/*
 * Tacacs authorization.
 */
int on_shell_execve (cmd, argv)
     char *cmd;
     char **argv;
{
    output_error("tacacs plugin on_shell_execve: %s", cmd);
	return 1;
}