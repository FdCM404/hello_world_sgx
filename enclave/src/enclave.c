#include "enclave_t.h"
#include <string.h>

void ecall_hello_world(void)
{
    const char *my_string = "Hello SGX World!";

    ocall_print_string(my_string);
}