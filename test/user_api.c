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
    const char * mobile_id;
    const char * app_id;

    char uid   [SM_USER_UID_LEN];
    char token [SM_USER_TOKEN_LEN];

} Global = {
    .server_url = "https://s5.securepilot.com",
    .api_key    = "HA-45058956",
    .api_secret = "0744424235",
    .username   = "test_account",
    .password   = "gemtek2014",
    .mobile_id  = "863664029282422",
    .app_id     = "com.gemtek.sample"
};

int test_user_digest_login() {
    puts("\n06. sm_user_digest_login");

    SM_User_Account user_account = {0};
    if (sm_user_digest_login(Global.server_url, (char *)Global.username, (char *)Global.password, Global.mobile_id, Global.app_id, &user_account) != 0) {
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

int test_user_get_service_info() {
    SM_Service_Info service_info = {0};

    // MSG
    puts("\n12. sm_user_get_service_info: MSG");
    if (sm_user_get_service_info(Global.server_url, Global.token, Global.api_key, "MSG", &service_info) != 0) {
        return -1;
    }
    printf("          id = %s\n", service_info.mqtt.id);
    printf("         pwd = %s\n", service_info.mqtt.pwd);
    printf("      server = %s\n", service_info.mqtt.server);
    printf("        port = %d\n", service_info.mqtt.port);
    printf("   client_id = %s\n", service_info.mqtt.client_id);
    printf("       topic = %s\n", service_info.mqtt.topic);
    printf("system_topic = %s\n", service_info.mqtt.system_topic);

    // RELAY
    puts("\n12. sm_user_get_service_info: RELAY");
    if (sm_user_get_service_info(Global.server_url, Global.token, Global.api_key, "RELAY", &service_info) != 0) {
        return -1;
    }
    printf("          id = %s\n", service_info.relay.id);
    printf("         pwd = %s\n", service_info.relay.pwd);
    printf("      server = %s\n", service_info.relay.server);
    printf("        port = %d\n", service_info.relay.port);

    // CVR
    puts("\n12. sm_user_get_service_info: CVR");
    if (sm_user_get_service_info(Global.server_url, Global.token, Global.api_key, "CVR", &service_info) != 0) {
        return -1;
    }
    printf("          id = %s\n", service_info.cvr.id);
    printf("         pwd = %s\n", service_info.cvr.pwd);
    printf("      server = %s\n", service_info.media.server);
    printf("        port = %d\n", service_info.media.port);
    printf("   live_port = %d\n", service_info.media.live_port);
    return 0;
}

int test_user_get_service_all() {
    SM_Service_Info service_info = {0};
    puts("\n20. sm_user_get_service_all");
    if (sm_user_get_service_all(Global.server_url, Global.token, Global.api_key, &service_info) != 0) {
        return -1;
    }

    printf(" mqtt.id           = %s\n", service_info.mqtt.id);
    printf(" mqtt.pwd          = %s\n", service_info.mqtt.pwd);
    printf(" mqtt.server       = %s\n", service_info.mqtt.server);
    printf(" mqtt.port         = %d\n", service_info.mqtt.port);
    printf(" mqtt.client_id    = %s\n", service_info.mqtt.client_id);
    printf(" mqtt.topic        = %s\n", service_info.mqtt.topic);
    printf(" mqtt.system_topic = %s\n", service_info.mqtt.system_topic);
    puts("");
    printf("relay.id           = %s\n", service_info.relay.id);
    printf("relay.pwd          = %s\n", service_info.relay.pwd);
    printf("relay.server       = %s\n", service_info.relay.server);
    printf("relay.port         = %d\n", service_info.relay.port);
    puts("");
    printf("  cvr.id           = %s\n", service_info.cvr.id);
    printf("  cvr.pwd          = %s\n", service_info.cvr.pwd);
    puts("");
    printf("media.server       = %s\n", service_info.media.server);
    printf("media.port         = %d\n", service_info.media.port);
    printf("media.live_port    = %d\n", service_info.media.live_port);
    return 0;
}

int main() {
    test_user_digest_login();
    test_user_get_service_info();
    test_user_get_service_all();
    return EXIT_SUCCESS;
}
