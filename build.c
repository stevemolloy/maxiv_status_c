#include <string.h>
#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#define NOB_EXPERIMENTAL_DELETE_OLD
#include "src/nob.h"

#define BINNAME "maxiv_status"

#define SRCDIR "src"
#define BINDIR "bin"

#define CFLAGS "-Wall", "-Wextra", "-Wshadow", "-Wvla", "-ggdb"
#define LIBS "-lssl", "-lcrypto"

int main(int argc, char **argv) {
    NOB_GO_REBUILD_URSELF(argc, argv);

    Cmd cmd = {0};
    bool run_exe = false;

    const char* programname = shift_args(&argc, &argv);

    while (argc > 0) {
        const char *arg = shift_args(&argc, &argv);

        if (strcmp(arg, "run") == 0) run_exe = true;
        else {
            nob_log(ERROR, "Argument not recognised: %s", arg);
            return 1;
        }
    }

    mkdir_if_not_exists(BINDIR);

    cmd_append(&cmd, "cc");
    cmd_append(&cmd, CFLAGS);
    cmd_append(&cmd, "-o", BINDIR"/"BINNAME);
    cmd_append(&cmd, SRCDIR"/main.c");
    cmd_append(&cmd, SRCDIR"/lib.c");
    cmd_append(&cmd, LIBS);
    if (!cmd_run(&cmd)) return 1;

    if (run_exe) {
        cmd_append(&cmd, "./"BINDIR"/"BINNAME);
        if (!cmd_run(&cmd)) return 1;
    }

    return 0;
}

