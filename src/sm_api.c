#include <stdio.h>
#include <stdlib.h>
#include "sm_api.h"

/** Third Party Library **/
#include "../lib/khttp/khttp.h"
#include "../lib/khttp/http_parser.h"
#include "../lib/parson/parson.h"

int sm_test() {
    printf("Hello Server Manager API!\n");
    return 0;
}
