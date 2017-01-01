#ifndef SAFERUN_H
#define SAFERUN_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/wait.h>

#ifdef __cplusplus
extern "C" {
#endif
    
#define SRUN2_PATH "/usr/local/bin/srun2"

enum testing_result_t {
    TESTING_OK = 0, /**< Clean exit, no errors */
    TESTING_RE = 1, /**< Runtime error */
    TESTING_TL = 2, /**< Time limit exceeded */
    TESTING_ML = 3, /**< Memory limit exceeded */
    TESTING_SV = 4, /**< Security Violation */
    TESTING_SC = 5, /**< System crash */
	TESTING_WA = 6,
	TESTING_PE = 7,
	TESTING_RESULT_COUNT = 8 /**< constant, always max +1 */
};

static char *testing_result_to_str[] = {
		"OK", "RE", "TL", "ML", "SV", "CR", "WA", "PE"
};

typedef struct saferun_params_t {
    const char *dir;
    const char *chroot;
    const char *redirect_stdin;
    const char *redirect_stdout;
    const char *redirect_stderr;
    
    int memory_limit; // in KBytes
    int time_limit; // in Milliseconds

    // output
    int status;
    bool exited;
    int exit_code;
} saferun_params_t;
    
static int saferun(const char *cmd, saferun_params_t *params) {
    const int FULL_CMD_LEN = 1024; 
    char full_cmd[FULL_CMD_LEN];
    snprintf(full_cmd, FULL_CMD_LEN,
            "%s -d %s --mem %d --time %d",
            SRUN2_PATH, params->dir, params->memory_limit, params->time_limit);
    
    if (params->chroot) {
        strncat(full_cmd, " --chroot ", FULL_CMD_LEN);
        strncat(full_cmd, params->chroot, FULL_CMD_LEN);
    }

    if (params->redirect_stdin) {
        strncat(full_cmd, " --redirect-stdin ", FULL_CMD_LEN);
        strncat(full_cmd, params->redirect_stdin, FULL_CMD_LEN);
    }
    if (params->redirect_stdout) {
        strncat(full_cmd, " --redirect-stdout ", FULL_CMD_LEN);
        strncat(full_cmd, params->redirect_stdout, FULL_CMD_LEN);
    }
    
    if (params->redirect_stderr) {
        strncat(full_cmd, " --redirect-stderr ", FULL_CMD_LEN);
        strncat(full_cmd, params->redirect_stderr, FULL_CMD_LEN);
    }
    
    strncat(full_cmd, " -- ", FULL_CMD_LEN);
    strncat(full_cmd, cmd, FULL_CMD_LEN);
    
    fprintf(stderr, "saferun: %s\n", full_cmd);
    
    FILE *pipe = popen(full_cmd, "r");
    if (!pipe)
        return -1;

    int result;
    fscanf(pipe, "%*s %d %*s %*s %*s %d", &result, &params->status);
    params->exited = WIFEXITED(params->status);
    if (params->exited)
    	params->exit_code = WEXITSTATUS(params->status);

    int exit_code = pclose(pipe);
    if (exit_code == 0) {
        return result;
    } else {
        return -1;
    }
}


#ifdef __cplusplus
}
#endif

#endif /* SAFERUN_H */

