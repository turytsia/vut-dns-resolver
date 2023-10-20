/**
 * @file error.c
 * @brief Error Handling Function Implementation
 *
 * This C source file, "error.c," contains the implementation of the error handling function
 * `exit_error`. This function takes an error code and a descriptive error message as input,
 * prints the error message to the standard error stream (stderr), and exits the program
 * with the provided error code. It is used to gracefully handle and report errors in a DNS
 * query utility.
 *
 * @author Oleksandr Turytsia (xturyt00)
 * @date October 18, 2023
 */
#include "error.h"

 /**
  * @brief Exit the program with an error message and code.
  *
  * This function is responsible for exiting the program with an error message and the provided error code.
  *
  * @param err The error code to be returned to the system.
  * @param message A descriptive error message to be printed to the standard error stream.
  */
void exit_error(int err, const char* message) {
    fprintf(stderr, "Error: %s\n", message);
    exit(err);
}