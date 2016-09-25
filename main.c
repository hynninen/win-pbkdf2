#include <stdlib.h>
#include "pbkdf2_hmac_test.h"

int main(int argc, char *argv[])
{
    int r = pbkdf2_hmac_test_rfc6070();
    
    return (r == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
