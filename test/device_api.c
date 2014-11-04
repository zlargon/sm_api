#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/sm_api.h"

// Global Variable
static struct {
    const char * server_url;
    const char * api_key;
    const char * api_secret;
    const char * username;
    const char * password;

    char gid   [SM_DEVICE_GID_LEN];
    char token [SM_DEVICE_TOKEN_LEN];

} Global = {
    .server_url = "https://s5.securepilot.com",
    .api_key    = "HA-45058956",
    .api_secret = "0744424235",
    .username   = "cbadef000033",
    .password   = "afnuy6yv"
};

int test_device_digest_login() {
    puts("\n03. sm_device_digest_login");

    SM_Device_Account device_account = {0};
    if (sm_device_digest_login(Global.server_url, Global.username, Global.password, &device_account) != 0) {
        return -1;
    }

    printf("         mac = %s\n", device_account.mac);
    printf("         gid = %s\n", device_account.gid);
    printf("         pin = %s\n", device_account.pin);
    printf("       token = %s\n", device_account.token);
    printf("  expiration = %s\n", device_account.expiration);
    printf("service_list = ");
    int i;
    for (i = 0; i < SM_DEVICE_SERVICE_COUNT; i++) {
        if (strlen(device_account.service_list[i]) != 0) {
            if (i > 0) printf(", ");
            printf("%s", device_account.service_list[i]);
        }
    }
    puts("");

    // set gid, token to global varibale
    memset(Global.gid,   0, SM_DEVICE_GID_LEN);
    memset(Global.token, 0, SM_DEVICE_TOKEN_LEN);

    strcpy(Global.gid,   device_account.gid);
    strcpy(Global.token, device_account.token);
    return 0;
}

int main() {
    test_device_digest_login();
    return EXIT_SUCCESS;
}
