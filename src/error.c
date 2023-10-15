#include "error.h"

void exit_error(err_t err, const char* message) {
    fprintf(stderr, "Error: %s", message);
    exit(err);
}