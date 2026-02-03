/*
 * sandbox-exec-persistent: Persistent Landlock sandbox helper for AgentShepherd
 *
 * Optimized version that applies Landlock once at startup, then accepts
 * commands via stdin and forks to execute them.
 *
 * Protocol:
 *   1. Startup: prints "READY\n" when Landlock is applied
 *   2. For each command:
 *      - Read: "<nargs>\n<total_bytes>\n<arg0>\0<arg1>\0...<argN>\0"
 *      - Fork, exec command, wait
 *      - Write: "EXIT <code>\n"
 *   3. Exit on EOF
 *
 * Build: gcc -O2 -D_GNU_SOURCE -o sandbox-exec-persistent sandbox_linux_persistent.c
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(
    const struct landlock_ruleset_attr *attr, size_t size, __u32 flags)
{
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(int ruleset_fd, enum landlock_rule_type type,
                                     const void *attr, __u32 flags)
{
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(int ruleset_fd, __u32 flags)
{
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

static int detect_landlock_abi(void)
{
    long abi = syscall(__NR_landlock_create_ruleset, NULL, 0,
                       LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        return 0;
    }
    return (int)abi;
}

static int is_safe_path(const char *path)
{
    if (!path || !*path) return 0;
    if (path[0] != '/') return 0;
    if (strcmp(path, "/") == 0) return 0;
    if (strstr(path, "/../") != NULL || strstr(path, "/./") != NULL) return 0;
    size_t len = strlen(path);
    if (len >= 3 && strcmp(path + len - 3, "/..") == 0) return 0;
    if (len >= 2 && strcmp(path + len - 2, "/.") == 0) return 0;
    return 1;
}

static int add_path_rule(int ruleset_fd, const char *path, __u64 access)
{
    if (!is_safe_path(path)) return 0;

    char resolved[PATH_MAX];
    const char *use_path = path;

    if (realpath(path, resolved) != NULL) {
        if (!is_safe_path(resolved)) return 0;
        use_path = resolved;
    }

    int fd = open(use_path, O_PATH | O_CLOEXEC);
    if (fd < 0) return 0;

    struct landlock_path_beneath_attr attr = {
        .allowed_access = access,
        .parent_fd = fd,
    };

    int ret = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    close(fd);
    return ret;
}

static int apply_landlock(const char *paths_env, int abi)
{
    if (abi == 0) abi = detect_landlock_abi();
    if (abi == 0) {
        fprintf(stderr, "ERROR Landlock not available\n");
        return -1;
    }

    __u64 access_fs =
        LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR |
        LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SOCK |
        LANDLOCK_ACCESS_FS_MAKE_FIFO |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        LANDLOCK_ACCESS_FS_MAKE_SYM;

    if (abi >= 2) access_fs |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) access_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;

    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = access_fs,
    };

    int ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "ERROR landlock_create_ruleset: %s\n", strerror(errno));
        return -1;
    }

    if (paths_env && *paths_env) {
        char *paths = strdup(paths_env);
        if (!paths) {
            close(ruleset_fd);
            return -1;
        }
        char *saveptr = NULL;
        char *path = strtok_r(paths, ":", &saveptr);
        while (path) {
            add_path_rule(ruleset_fd, path, access_fs);
            path = strtok_r(NULL, ":", &saveptr);
        }
        free(paths);
    } else {
        /* Fallback paths if LANDLOCK_PATHS not set. Should match DefaultAllowPaths()
         * in internal/sandbox/paths.go. /proc excluded to protect API keys in
         * /proc/<pid>/cmdline and /proc/<pid>/environ. */
        const char *default_paths[] = {
            "/bin", "/usr", "/lib", "/lib64", "/tmp", "/var",
            "/dev", "/etc", "/sys", "/run", "/opt", "/sbin",
            NULL
        };
        for (int i = 0; default_paths[i]; i++) {
            add_path_rule(ruleset_fd, default_paths[i], access_fs);
        }
        const char *home = getenv("HOME");
        if (home) add_path_rule(ruleset_fd, home, access_fs);
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        close(ruleset_fd);
        return -1;
    }

    if (landlock_restrict_self(ruleset_fd, 0)) {
        close(ruleset_fd);
        return -1;
    }

    close(ruleset_fd);
    return 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Apply Landlock to this process */
    const char *paths_env = getenv("LANDLOCK_PATHS");
    const char *abi_env = getenv("LANDLOCK_ABI");
    int abi = 0;
    if (abi_env) {
        char *endptr;
        long val = strtol(abi_env, &endptr, 10);
        if (*endptr == '\0' && val >= 0 && val <= 100) {
            abi = (int)val;
        }
    }

    if (apply_landlock(paths_env, abi) < 0) {
        return 127;
    }

    /* Signal ready */
    printf("READY\n");
    fflush(stdout);

    /* Disable buffering for protocol */
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Main loop */
    char line[64];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        /* Parse nargs */
        int nargs = atoi(line);
        if (nargs <= 0 || nargs > 1024) {
            fprintf(stderr, "ERROR invalid nargs\n");
            continue;
        }

        /* Parse total size */
        if (fgets(line, sizeof(line), stdin) == NULL) break;
        int total_size = atoi(line);
        if (total_size <= 0 || total_size > 1024 * 1024) {
            fprintf(stderr, "ERROR invalid size\n");
            continue;
        }

        /* Read argument data */
        char *data = (char *)malloc((size_t)total_size + 1);
        if (!data) {
            fprintf(stderr, "ERROR malloc\n");
            continue;
        }

        size_t nread = fread(data, 1, (size_t)total_size, stdin);
        if (nread != (size_t)total_size) {
            free(data);
            fprintf(stderr, "ERROR short read\n");
            continue;
        }
        data[total_size] = '\0';

        /* Build argv */
        char **cmd_argv = (char **)malloc(((size_t)nargs + 1) * sizeof(char *));
        if (!cmd_argv) {
            free(data);
            fprintf(stderr, "ERROR malloc argv\n");
            continue;
        }

        char *p = data;
        for (int i = 0; i < nargs; i++) {
            cmd_argv[i] = p;
            p += strlen(p) + 1;
        }
        cmd_argv[nargs] = NULL;

        /* Fork and exec */
        pid_t pid = fork();
        if (pid < 0) {
            printf("EXIT 127\n");
            free(cmd_argv);
            free(data);
            continue;
        }

        if (pid == 0) {
            /* Child: redirect stdout/stderr to /dev/null to avoid mixing with protocol */
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
            execvp(cmd_argv[0], cmd_argv);
            _exit(127);
        }

        /* Parent: wait */
        int status;
        waitpid(pid, &status, 0);

        int exit_code;
        if (WIFEXITED(status)) {
            exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            exit_code = 128 + WTERMSIG(status);
        } else {
            exit_code = 1;
        }

        printf("EXIT %d\n", exit_code);

        free(cmd_argv);
        free(data);
    }

    return 0;
}
