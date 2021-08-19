#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "libtac.h"
#include "support.h"

const char *tacacs_config_file = "/etc/tacplus_servers";

/* Tacacs server config data */
typedef struct {
    struct addrinfo *address;
    const char *key;
} tacacs_server_t;

/* Tacacs control flag */
static int tacacs_ctrl;

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
  va_end (args);
}

/*
 * Output debug message.
 */
void output_debug (const char *format, ...)
{
  if ((tacacs_ctrl & PAM_TAC_DEBUG) == 0) {
      return;
  }

  va_list args;
  va_start (args, format);

  output_error (format, args);

  va_end (args);
}


int send_authorization_message(
    int tac_fd,
    const char *user,
    const char *tty,
    const char *host,
    uint16_t taskid,
    const char *cmd,
    char **args,
    int argc)
{
    char buf[128];
    struct tac_attrib *attr;
    int retval;
    struct areply re;
    int i;

    attr=(struct tac_attrib *)xcalloc(1, sizeof(struct tac_attrib));

    snprintf(buf, sizeof buf, "%hu", taskid);
    tac_add_attrib(&attr, "task_id", buf);
    tac_add_attrib(&attr, "protocol", "ssh");
    tac_add_attrib(&attr, "service", "shell");

    tac_add_attrib(&attr, "cmd", (char*)cmd);

    for(i=1; i<argc; i++) {
        // TACACS protocol allow max 255 bytes per argument. 'cmd-arg' will take 7 bytes.
        char tbuf[248];
        const char *arg;
        if(strlen(args[i]) >= sizeof(tbuf)) {
            snprintf(tbuf, sizeof tbuf, "%s", args[i]);
            arg = tbuf;
        }
        else {
            arg = args[i];
        }
        
        tac_add_attrib(&attr, "cmd-arg", (char *)arg);
    }

    re.msg = NULL;
    retval = tac_author_send(tac_fd, (char *)user, (char *)tty, (char *)host, attr);

    if(retval < 0) {
            output_error("send of authorization message failed: %s\n", strerror(errno));
    }
    else {
        retval = tac_author_read(tac_fd, &re);
        if (retval < 0) {
            output_debug("authorization response failed: %d\n", retval);
        }
        else if(re.status == AUTHOR_STATUS_PASS_ADD ||
                    re.status == AUTHOR_STATUS_PASS_REPL) {
            retval = 0;
        }
        else  {
            output_debug("command not authorized (%d)\n", re.status);
            retval = 1;
        }
    }

    tac_free_attrib(&attr);
    if(re.msg != NULL) {
        free(re.msg);
    }

    return retval;
}

/*
 * Send tacacs authorization request.
 */
int tacacs_authorization(
    const char *user,
    const char *tty,
    const char *host,
    const char *cmd,
    char **args,
    int argc)
{
    int result = 1, server_idx, server_fd, connected_servers=0;
    uint16_t task_id = (uint16_t)getpid();

    for(server_idx = 0; server_idx < tac_srv_no; server_idx++) {
        server_fd = tac_connect_single(tac_srv[server_idx].addr, tac_srv[server_idx].key, NULL, tac_timeout);
        if(server_fd < 0) {
            // connect to tacacs server failed
            output_debug("Failed to connecting to %s to request authorization for %s: %s\n", tac_ntop(tac_srv[server_idx].addr->ai_addr), cmd, strerror(errno));
            continue;
        }
        
        // increase connected servers 
        connected_servers++;
        result = send_authorization_message(server_fd, user, tty, host, task_id, cmd, args, argc);
        close(server_fd);
        if(result) {
            // authorization failed
            output_debug("%s not authorized from %s\n", cmd, tac_ntop(tac_srv[server_idx].addr->ai_addr));
        }
        else {
            // authorization successed
            output_debug("%s authorized command %s\n", cmd, tac_ntop(tac_srv[server_idx].addr->ai_addr));
            break;
        }
    }

    // can't connect to any server
    if(!connected_servers) {
        result = -2;
        output_debug("Failed to connect to TACACS server(s)\n");
    }
    
    return result;
}

/*
 * Send authorization request.
 */
int authorization_with_host_and_tty(const char *user, const char *cmd, char **argv, int argc)
{
    // try get host name
    char hostname[64];
    memset(&hostname, 0, sizeof(hostname));
    
    (void)gethostname(hostname, sizeof(hostname) -1);
    if (!hostname[0]) {
        snprintf(hostname, sizeof(hostname), "UNK");
        output_debug("Failed to determine hostname, passing %s\n", hostname);
    }

    // try get tty name
    char ttyname[64];
    memset(&ttyname, 0, sizeof(ttyname));
    
    int i;
    for(i=0; i<3; i++) {
        int result;
        if (isatty(i)) {
            result = ttyname_r(i, ttyname, sizeof(ttyname) -1);
            if (result) {
                output_debug("Failed to get tty name for fd %d: %s\n", i, strerror(result));
            }
            break;
        }
    }
    
    if (!ttyname[0]) {
        snprintf(ttyname, sizeof(ttyname), "UNK");
        output_debug("Failed to determine tty, passing %s\n", ttyname);
    }

    // send tacacs authorization request
    return tacacs_authorization(user, ttyname, hostname, cmd, argv, argc);
}

/*
 * Tacacs plugin initialization.
 */
void plugin_init ()
{
    // load config file: tacacs_config_file
    tacacs_ctrl = parse_config_file (tacacs_config_file);

    output_verbose_log("tacacs plugin initialized.\n");
    output_verbose_log("tacacs config:\n");
    int server_idx;
    for(server_idx = 0; server_idx < tac_srv_no; server_idx++) {
        output_verbose_log ("Server %d, address:%s, key:%s\n", server_idx, tac_ntop(tac_srv[server_idx].addr->ai_addr),tac_srv[server_idx].key);
    }
}

/*
 * Tacacs plugin release.
 */
void plugin_uninit ()
{
    output_verbose_log("tacacs plugin un-initialize.");
    free_tacacs_server_addr();
}

/*
 * Tacacs authorization.
 */
int on_shell_execve (char *user, int shell_level, char *cmd, char **argv)
{
    output_verbose_log ("Authorization parameters:\n");
    output_verbose_log ("    Shell level: %d\n", shell_level);
    output_verbose_log ("    Current user: %s\n", user);
    output_verbose_log ("    Command full path: %s\n", cmd);
    output_verbose_log ("    Parameters:\n");
    char **parameter_array_pointer = argv;
    int argc = 0;
    while (*parameter_array_pointer != 0) {
        // output parameter
        output_verbose_log ("        %s\n", *parameter_array_pointer);
        
        // move to next parameter
        parameter_array_pointer++;
	argc++;
    }
    
    // when shell_level > 1, it's a recursive command in shell script.
    if (shell_level > 2) {
        output_verbose_log ("Recursive command %s ignored.\n", cmd);
        return 0;
    }

    int ret = authorization_with_host_and_tty(user, cmd, argv, argc);
    switch (ret) {
        case 0:
            output_verbose_log ("%s authorize successed by TACACS+ with given arguments\n", cmd);
        break;
        case 2:
            /*  -2 means no servers, so already a message */
            output_verbose_log ("%s not authorized by TACACS+ with given arguments, not executing\n", cmd);
        break;
        default:
            output_verbose_log ("%s authorize failed by TACACS+ with given arguments, not executing\n", cmd);
        break;
    }
    
    return ret;
}
