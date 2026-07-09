/* CWE-78 (patched): fixed program via execlp; input passed as an argument.
 * The taint engine must NOT flag this: the program path is constant and the
 * untrusted value is an argv entry, not a shell command line.
 */
#include <unistd.h>

void run_cmd(char *name) {
    /* SAFE: constant program; no shell is involved */
    execlp("/bin/echo", "echo", name, (char *)0);
}

void handle(char *input) {
    run_cmd(input);
}
