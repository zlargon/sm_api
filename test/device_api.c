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

int test_device_get_service_info() {
    SM_Service_Info service_info = {0};

    // MSG
    puts("\n08. sm_device_get_service_info: MSG");
    if (sm_device_get_service_info(Global.server_url, Global.token, Global.api_key, "MSG", &service_info) != 0) {
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
    puts("\n08. sm_device_get_service_info: RELAY");
    if (sm_device_get_service_info(Global.server_url, Global.token, Global.api_key, "RELAY", &service_info) != 0) {
        return -1;
    }
    printf("          id = %s\n", service_info.relay.id);
    printf("         pwd = %s\n", service_info.relay.pwd);
    printf("      server = %s\n", service_info.relay.server);
    printf("        port = %d\n", service_info.relay.port);

    // CVR
    puts("\n08. sm_device_get_service_info: CVR");
    if (sm_device_get_service_info(Global.server_url, Global.token, Global.api_key, "CVR", &service_info) != 0) {
        return -1;
    }
    printf("          id = %s\n",   service_info.cvr.id);
    printf("         pwd = %s\n",   service_info.cvr.pwd);
    printf("      server = %s\n",   service_info.cvr.server);
    printf("        port = %d\n",   service_info.cvr.port);
    printf("  start_time = %lld\n", service_info.cvr.start_time);
    printf("    end_time = %lld\n", service_info.cvr.end_time);

    return 0;
}

int test_device_get_service_all() {
    SM_Service_Info service_info = {0};
    puts("\n14. sm_device_get_service_all");
    if (sm_device_get_service_all(Global.server_url, Global.token, Global.api_key, &service_info) != 0) {
        return -1;
    }

    printf(" mqtt.id           = %s\n",   service_info.mqtt.id);
    printf(" mqtt.pwd          = %s\n",   service_info.mqtt.pwd);
    printf(" mqtt.server       = %s\n",   service_info.mqtt.server);
    printf(" mqtt.port         = %d\n",   service_info.mqtt.port);
    printf(" mqtt.client_id    = %s\n",   service_info.mqtt.client_id);
    printf(" mqtt.topic        = %s\n",   service_info.mqtt.topic);
    printf(" mqtt.system_topic = %s\n\n", service_info.mqtt.system_topic);

    printf("relay.id           = %s\n",   service_info.relay.id);
    printf("relay.pwd          = %s\n",   service_info.relay.pwd);
    printf("relay.server       = %s\n",   service_info.relay.server);
    printf("relay.port         = %d\n\n", service_info.relay.port);

    printf("  cvr.id           = %s\n",   service_info.cvr.id);
    printf("  cvr.pwd          = %s\n",   service_info.cvr.pwd);
    printf("  cvr.server       = %s\n",   service_info.cvr.server);
    printf("  cvr.port         = %d\n",   service_info.cvr.port);
    printf("  cvr.start_time   = %lld\n", service_info.cvr.start_time);
    printf("  cvr.end_time     = %lld\n", service_info.cvr.end_time);
    return 0;
}

int test_device_get_user_list() {
    puts("\n11. sm_device_get_user_list");
    SM_User_Account * user_list = NULL;
    int ret = sm_device_get_user_list(
        Global.server_url,
        Global.token,
        Global.api_key,
        &user_list                      // alloc: user_list
    );

    if (ret != 0) {
        return -1;
    }

    if (user_list == NULL) {
        puts("no user");
        return 0;
    }

    int i = 1;
    SM_User_Account * ptr;
    for (ptr = user_list; ptr != NULL; ptr = ptr->next) {
        printf("%2d.\n"
            "username = %s\n"
            "   email = %s\n"
            "     uid = %s\n\n",
            i++,
            ptr->username,
            ptr->email,
            ptr->uid
        );
    }
    puts("");

    sm_user_account_free(user_list);    // free: user_list
    return 0;
}

int main() {
    test_device_digest_login();
    test_device_get_service_info();
    test_device_get_service_all();
    test_device_get_user_list();
    return EXIT_SUCCESS;
}
