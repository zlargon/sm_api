#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/sm_api.h"

// Global Variable
static struct {
    const char * server_url;
    char uid   [SM_USER_UID_LEN];
    char token [SM_USER_TOKEN_LEN];
} Global = {
    .server_url = "https://s5.securepilot.com"
};

int test_user_digest_login() {
    puts("\n06. sm_user_digest_login");

    SM_User_Account user_account = {0};
    if (sm_user_digest_login(Global.server_url, "test_account", "gemtek2014", "863664029282422", "com.gemtek.sample", &user_account) != 0) {
        return -1;
    }

    printf("  username = %s\n", user_account.username);
    printf("       uid = %s\n", user_account.uid);
    printf("     email = %s\n", user_account.email);
    printf("  email_vd = %d\n", user_account.email_vd);
    printf("        cc = %s\n", user_account.cc);
    printf("    mobile = %s\n", user_account.mobile);
    printf("     token = %s\n", user_account.token);
    printf("expiration = %s\n", user_account.expiration);

    // set uid, token to global varibale
    memset(Global.uid,   0, SM_USER_UID_LEN);
    memset(Global.token, 0, SM_USER_TOKEN_LEN);
    strcpy(Global.uid,   user_account.uid);
    strcpy(Global.token, user_account.token);
    return 0;
}

int main() {
    test_user_digest_login();
    return EXIT_SUCCESS;
}
