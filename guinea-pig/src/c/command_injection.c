/* CWE-78: OS Command Injection
 * An untrusted string flows through a helper into system().
 * Expected detecting family: sast
 */
#include <stdlib.h>

void run_cmd(char *name) {
    /* VULNERABLE SINK: shell command from untrusted input */
    system(name);
}

void handle(char *input) {
    run_cmd(input);
}
