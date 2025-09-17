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

    mkdir_if_not_exists(BINDIR);

    Cmd cmd = {0};

    cmd_append(&cmd, "cc");
    cmd_append(&cmd, CFLAGS);
    cmd_append(&cmd, "-o", BINDIR"/"BINNAME);
    cmd_append(&cmd, SRCDIR"/main.c");
    cmd_append(&cmd, LIBS);
    cmd_run(&cmd);

    const char* programname = shift_args(&argc, &argv);

    if (argc > 0) {
        const char *arg = shift_args(&argc, &argv);
        if (strcmp(arg, "run") == 0) {
            cmd_append(&cmd, "./"BINDIR"/"BINNAME);
            cmd_run(&cmd);
        } else {
            nob_log(ERROR, "Argument not recognised: %s", arg);
            return 1;
        }
    }

    return 0;
}

