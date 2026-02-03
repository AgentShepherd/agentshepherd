/*
 * sandbox-exec: Seatbelt sandbox helper for AgentShepherd (macOS)
 *
 * This helper binary applies Seatbelt (sandbox-exec) restrictions and then
 * execs the target command. This ensures the parent process (AgentShepherd)
 * remains unrestricted.
 *
 * Usage: sandbox-exec-darwin -p <profile_path> <command> [args...]
 *
 * Build: clang -O2 -o sandbox-exec main.c (on macOS)
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Path to macOS sandbox-exec binary */
#define SANDBOX_EXEC_PATH "/usr/bin/sandbox-exec"

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "Usage: sandbox-exec-darwin -p <profile_path> <command> [args...]\n");
        return 1;
    }

    /* Parse arguments */
    if (strcmp(argv[1], "-p") != 0) {
        fprintf(stderr, "sandbox-exec-darwin: expected -p <profile_path>\n");
        return 1;
    }

    const char *profile_path = argv[2];
    char **cmd_argv = &argv[3];

    /* Verify profile exists */
    if (access(profile_path, R_OK) != 0) {
        fprintf(stderr, "sandbox-exec-darwin: cannot read profile: %s: %s\n",
                profile_path, strerror(errno));
        return 127;
    }

    /* Build arguments for sandbox-exec:
     * sandbox-exec -f <profile> <command> [args...]
     */
    int cmd_argc = argc - 3;
    int new_argc = 3 + cmd_argc + 1;  /* sandbox-exec -f profile cmd... NULL */
    char **new_argv = malloc((size_t)new_argc * sizeof(char *));
    if (!new_argv) {
        fprintf(stderr, "sandbox-exec-darwin: malloc failed\n");
        return 127;
    }

    new_argv[0] = SANDBOX_EXEC_PATH;
    new_argv[1] = "-f";
    new_argv[2] = (char *)profile_path;
    for (int i = 0; i < cmd_argc; i++) {
        new_argv[3 + i] = cmd_argv[i];
    }
    new_argv[new_argc - 1] = NULL;

    /* Execute via sandbox-exec */
    execv(SANDBOX_EXEC_PATH, new_argv);

    /* If we get here, exec failed */
    fprintf(stderr, "sandbox-exec-darwin: exec %s: %s\n",
            SANDBOX_EXEC_PATH, strerror(errno));
    free(new_argv);
    return 127;
}
