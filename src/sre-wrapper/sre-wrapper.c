#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <ctype.h>
#include <sys/wait.h>
#include <limits.h>

#define SUDO_BIN  "/usr/bin/sudo"

static const char *get_sre_bin(void)
{
    static char sre_path[PATH_MAX];
    char exe[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len < 0) return NULL;
    exe[len] = '\0';

    char *slash = strrchr(exe, '/');
    if (!slash) return NULL;
    *slash = '\0'; /* exe is now the bin directory */

    if (strlen(exe) + sizeof("/../sbin/sre") > PATH_MAX) return NULL;
    char tmp[PATH_MAX * 2];
    snprintf(tmp, sizeof(tmp), "%s/../sbin/sre", exe);
    if (!realpath(tmp, sre_path)) return NULL;
    return sre_path;
}

static int valid_username(const char *s)
{
    if (!s || !*s) return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && *s != '.' && *s != '_' && *s != '-')
            return 0;
    return 1;
}

/* Extract the X11 magic cookie from the student's X authority and export it as
   SRE_XAUTH_COOKIE.  Best-effort: if there is no X session / no xauth / no
   cookie, the variable is simply not set (non-fatal — CLI/headless use must
   still work).  The value is hex-validated again on the sre side before it is
   injected into any container. */
static void set_xauth_cookie(void)
{
    FILE *f = popen("xauth list 2>/dev/null", "r");
    if (!f) return;

    char line[1024];
    char *first = fgets(line, sizeof(line), f);
    pclose(f);
    if (!first) return;

    /* line looks like: "hostname/unix:0  MIT-MAGIC-COOKIE-1  a1b2c3d4..." —
       take the 3rd whitespace-separated token. */
    strtok(line, " \t\n");              /* address */
    strtok(NULL, " \t\n");              /* protocol name */
    char *cookie = strtok(NULL, " \t\n");
    if (!cookie || !*cookie) return;

    for (const char *p = cookie; *p; p++)
        if (!isxdigit((unsigned char)*p)) return;

    setenv("SRE_XAUTH_COOKIE", cookie, 1);
}

int main(int argc, char *argv[])
{
    struct passwd *pw = getpwuid(getuid());
    if (!pw) {
        fprintf(stderr, "sre-wrapper: cannot determine username\n");
        return 1;
    }

    const char *username = pw->pw_name;
    if (!valid_username(username)) {
        fprintf(stderr, "sre-wrapper: invalid username: '%s'\n", username);
        return 1;
    }

    if (setenv("USER_USERNAME", username, 1) != 0) {
        perror("sre-wrapper: setenv");
        return 1;
    }

    set_xauth_cookie();

    /* Build: sudo SRE_BIN --user [original args...] */
    char **new_argv = malloc((argc + 3) * sizeof(char *));
    if (!new_argv) {
        perror("sre-wrapper: malloc");
        return 1;
    }

    const char *sre_bin = get_sre_bin();
    if (!sre_bin) {
        fprintf(stderr, "sre-wrapper: cannot locate sre binary\n");
        return 1;
    }

    int i = 0;
    new_argv[i++] = SUDO_BIN;
    new_argv[i++] = (char *)sre_bin;
    new_argv[i++] = "--user";
    for (int j = 1; j < argc; j++)
        new_argv[i++] = argv[j];
    new_argv[i] = NULL;

    /* fork so this process stays alive as grandparent of sre —
       /proc checks in sre verify grandparent exe == sre-wrapper */
    pid_t pid = fork();
    if (pid < 0) {
        perror("sre-wrapper: fork");
        return 1;
    }
    if (pid == 0) {
        execv(SUDO_BIN, new_argv);
        perror("sre-wrapper: execv");
        _exit(1);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("sre-wrapper: waitpid");
        return 1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
