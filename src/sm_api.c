#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sm_api.h"

/** Third Party Library **/
#include "../lib/khttp/khttp.h"
#include "../lib/khttp/http_parser.h"
#include "../lib/parson/parson.h"

#define STRINGIFY(s) #s
#define sm_check_string(var) __sm_check_string(var, STRINGIFY(var), __func__)
#define sm_check_not_null(var) __sm_check_not_null(var, STRINGIFY(var), __func__)

int __sm_check_string(const char * var, const char * var_name, const char * func);
int __sm_check_not_null(const void * var, const char * var_name, const char * func);


/** USER API **/

// 06. sm_user_digest_login
int sm_user_digest_login(
        const char * server_url,
  /* const */ char * username,
  /* const */ char * password,
        const char * device_id,
        const char * app_identifier,
        SM_User_Account * user_account) {

    // check arguments
    if (sm_check_string(server_url)     ||
        sm_check_string(username)       ||
        sm_check_string(password)       ||
        sm_check_string(device_id)      ||
        sm_check_string(app_identifier) ||
        sm_check_not_null(user_account) != 0) {
        return -1;
    }

    memset(user_account, 0, sizeof(SM_User_Account));

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/user/login?device_id=%s&app_identifier=%s", server_url, device_id, app_identifier);

    khttp_ctx *ctx = khttp_new();                                              /* alloc: ctx */
    khttp_set_uri(ctx, url);
    khttp_set_username_password(ctx, username, password, KHTTP_AUTH_DIGEST);
    khttp_ssl_skip_auth(ctx);
    int ret = khttp_perform(ctx);
    if (ret != 0) {
        khttp_destroy(ctx);                                                     /* free: ctx */
        return ret;
    }

    // check HTTP status code
    if (ctx->hp.status_code != 200) {
        printf("%s: HTTP status code = %d\n", __func__, ctx->hp.status_code);   // Error Level
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        khttp_destroy(ctx);                                                     /* free: ctx */
        return ctx->hp.status_code;
    }

    // JSON parse
    JSON_Value * root_value = json_parse_string((const char *)ctx->body);       /* alloc: root_value */
    JSON_Object * json_body = json_value_get_object(root_value);
    if (json_body == NULL) {
        printf("%s: JSON parse failed\n", __func__);    // Error Level
        printf("body = %s\n", (const char *)ctx->body);
        json_value_free(root_value);
        khttp_destroy(ctx);                                                     /* free: root_value, ctx */
        return -1;
    }

    // check status code
    int statusCode = (int) json_object_dotget_number(json_body, "status.code");
    if (statusCode != 1211) {
        printf("body = %s\n", (const char *)ctx->body);
        json_value_free(root_value);
        khttp_destroy(ctx);                                                     /* free: root_value, ctx */
        return statusCode;
    }

    const char * uid        = json_object_dotget_string(json_body, "info.account.uid");
    const char * email      = json_object_dotget_string(json_body, "info.account.email");
    const char * email_vd   = json_object_dotget_string(json_body, "info.account.email_vd");
    const char * cc         = json_object_dotget_string(json_body, "info.account.cc");
    const char * mobile     = json_object_dotget_string(json_body, "info.account.mobile");
    const char * token      = json_object_dotget_string(json_body, "global_session.token");
    const char * expiration = json_object_dotget_string(json_body, "global_session.expiration");

    // copy the value to 'user_account'
    strncpy(user_account->username, username, SM_USER_NAME_LEN);
    if (email_vd   != NULL) user_account->email_vd = strcmp(email_vd, "true") == 0 ? 1 : 0;
    if (uid        != NULL) strncpy(user_account->uid,        uid,        SM_USER_UID_LEN);
    if (email      != NULL) strncpy(user_account->email,      email,      SM_USER_EMAIL_LEN);
    if (cc         != NULL) strncpy(user_account->cc,         cc,         SM_USER_CC_LEN);
    if (mobile     != NULL) strncpy(user_account->mobile,     mobile,     SM_USER_MOBILE_LEN);
    if (token      != NULL) strncpy(user_account->token,      token,      SM_USER_TOKEN_LEN);
    if (expiration != NULL) strncpy(user_account->expiration, expiration, SM_USER_EXPIRATION_LEN);

    json_value_free(root_value);
    khttp_destroy(ctx);                                                         /* free: root_value, ctx */
    return 0;
}

// 12. sm_user_get_service_info
int sm_user_get_service_info(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * service,
        SM_Service_Info * service_info) {

    // check arguments
    if (sm_check_string(server_url)     ||
        sm_check_string(token)          ||
        sm_check_string(api_key)        ||
        sm_check_string(service)        ||
        sm_check_not_null(service_info) != 0) {
        return -1;
    }
    memset(service_info, 0, sizeof(SM_Service_Info));

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/user/get_service_info", server_url);

    // set post body
    char post_body[2048] = {0};
    snprintf(post_body, sizeof(post_body), "token=%s&api_key=%s&service=%s", token, api_key, service);

    khttp_ctx *ctx = khttp_new();                                               /* alloc: ctx */
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    int ret = khttp_perform(ctx);
    if (ret != 0) {
        khttp_destroy(ctx);                                                     /* free: ctx */
        return ret;
    }

    // check HTTP status code
    if (ctx->hp.status_code != 200) {
        printf("%s: HTTP status code = %d\n", __func__, ctx->hp.status_code);   // Error Level
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        khttp_destroy(ctx);                                                     /* free: ctx */
        return ctx->hp.status_code;
    }

    // JSON parse
    JSON_Value * root_value = json_parse_string((const char *)ctx->body);       /* alloc: root_value */
    JSON_Object * json_body = json_value_get_object(root_value);
    if (json_body == NULL) {
        printf("%s: JSON parse failed\n", __func__);    // Error Level
        printf("body = %s\n", (const char *)ctx->body);
        json_value_free(root_value);
        khttp_destroy(ctx);                                                     /* free: root_value, ctx */
        return -1;
    }

    // check status code
    int statusCode = (int) json_object_dotget_number(json_body, "status.code");
    if (statusCode != 1211) {
        printf("body = %s\n", (const char *)ctx->body);
        json_value_free(root_value);
        khttp_destroy(ctx);                                                     /* free: root_value, ctx */
        return statusCode;
    }

    // get MSG, RELAY, CVR field
    if (strcmp(service, "MSG") == 0) {
        const char * mqtt_id           = json_object_dotget_string(json_body, "info.account.id");
        const char * mqtt_pwd          = json_object_dotget_string(json_body, "info.account.pwd");
        const char * mqtt_server       = json_object_dotget_string(json_body, "info.profile.mqtt_server");
        const char * mqtt_server_port  = json_object_dotget_string(json_body, "info.profile.mqtt_server_port");
        const char * mqtt_client_id    = json_object_dotget_string(json_body, "info.profile.client_id");
        const char * mqtt_topic        = json_object_dotget_string(json_body, "info.profile.topic");
        const char * mqtt_system_topic = json_object_dotget_string(json_body, "info.profile.system_notification_topic");

        // copy the value to 'service_info->mqtt'
        if (mqtt_id           != NULL) strncpy(service_info->mqtt.id,           mqtt_id,           SM_SERVICE_ID_LEN);
        if (mqtt_pwd          != NULL) strncpy(service_info->mqtt.pwd,          mqtt_pwd,          SM_SERVICE_PWD_LEN);
        if (mqtt_server       != NULL) strncpy(service_info->mqtt.server,       mqtt_server,       SM_SERVICE_SERVER_LEN);
        if (mqtt_server_port  != NULL) service_info->mqtt.port = atoi(mqtt_server_port);
        if (mqtt_client_id    != NULL) strncpy(service_info->mqtt.client_id,    mqtt_client_id,    SM_SERVICE_MQTT_CLINET_ID_LEN);
        if (mqtt_topic        != NULL) strncpy(service_info->mqtt.topic,        mqtt_topic,        SM_SERVICE_MQTT_TOPIC_LEN);
        if (mqtt_system_topic != NULL) strncpy(service_info->mqtt.system_topic, mqtt_system_topic, SM_SERVICE_MQTT_TOPIC_LEN);
    }

    else if (strcmp(service, "RELAY") == 0) {
        const char * relay_id          = json_object_dotget_string(json_body, "info.account.id");
        const char * relay_pwd         = json_object_dotget_string(json_body, "info.account.pwd");
        const char * relay_server      = json_object_dotget_string(json_body, "info.profile.relay_server");
        const char * relay_server_port = json_object_dotget_string(json_body, "info.profile.relay_server_port");

        // copy the value to 'service_info->relay'
        if (relay_id          != NULL) strncpy(service_info->relay.id,     relay_id,     SM_SERVICE_ID_LEN);
        if (relay_pwd         != NULL) strncpy(service_info->relay.pwd,    relay_pwd,    SM_SERVICE_PWD_LEN);
        if (relay_server      != NULL) strncpy(service_info->relay.server, relay_server, SM_SERVICE_SERVER_LEN);
        if (relay_server_port != NULL) service_info->relay.port = atoi(relay_server_port);
    }

    else if (strcmp(service, "CVR") == 0) {
        const char * cvr_id                 = json_object_dotget_string(json_body, "info.account.id");
        const char * cvr_pwd                = json_object_dotget_string(json_body, "info.account.pwd");
        const char * media_server           = json_object_dotget_string(json_body, "info.profile.media_server");
        const char * media_server_port      = json_object_dotget_string(json_body, "info.profile.media_server_port");
        const char * media_server_live_port = json_object_dotget_string(json_body, "info.profile.media_server_liveport");

        // copy the value to 'service_info->cvr'
        if (cvr_id                 != NULL) strncpy(service_info->cvr.id,       cvr_id,       SM_SERVICE_ID_LEN);
        if (cvr_pwd                != NULL) strncpy(service_info->cvr.pwd,      cvr_pwd,      SM_SERVICE_PWD_LEN);
        if (media_server           != NULL) strncpy(service_info->media.server, media_server, SM_SERVICE_SERVER_LEN);
        if (media_server_port      != NULL) service_info->media.port      = atoi(media_server_port);
        if (media_server_live_port != NULL) service_info->media.live_port = atoi(media_server_live_port);
    }

    else {
        printf("%s: not support service '%s' JSON parsing\n", __func__, service);
        printf("body = %s\n", (const char *)ctx->body);
    }

    json_value_free(root_value);
    khttp_destroy(ctx);                                                         /* free: root_value, ctx */
    return 0;
}

// 20. sm_user_get_service_all
int sm_user_get_service_all(
        const char * server_url,
        const char * token,
        const char * api_key,
        SM_Service_Info * service_info) {

    // check arguments
    if (sm_check_string(server_url)     ||
        sm_check_string(token)          ||
        sm_check_string(api_key)        ||
        sm_check_not_null(service_info) != 0) {
        return -1;
    }
    memset(service_info, 0, sizeof(SM_Service_Info));

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/user/get_service_all", server_url);

    // set post body
    char post_body[2048] = {0};
    snprintf(post_body, sizeof(post_body), "token=%s&api_key=%s", token, api_key);

    khttp_ctx *ctx = khttp_new();                                               /* alloc: ctx */
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    int ret = khttp_perform(ctx);
    if (ret != 0) {
        khttp_destroy(ctx);                                                     /* free: ctx */
        return ret;
    }

    // check HTTP status code
    if (ctx->hp.status_code != 200) {
        printf("%s: HTTP status code = %d\n", __func__, ctx->hp.status_code);   // Error Level
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        khttp_destroy(ctx);                                                     /* free: ctx */
        return ctx->hp.status_code;
    }

    // JSON parse
    JSON_Value * root_value = json_parse_string((const char *)ctx->body);       /* alloc: root_value */
    JSON_Object * json_body = json_value_get_object(root_value);
    if (json_body == NULL) {
        printf("%s: JSON parse failed\n", __func__);    // Error Level
        printf("body = %s\n", (const char *)ctx->body);
        json_value_free(root_value);
        khttp_destroy(ctx);                                                     /* free: root_value, ctx */
        return -1;
    }

    // check status code
    int statusCode = (int) json_object_dotget_number(json_body, "status.code");
    if (statusCode != 1200) {
        printf("body = %s\n", (const char *)ctx->body);
        json_value_free(root_value);
        khttp_destroy(ctx);                                                     /* free: root_value, ctx */
        return statusCode;
    }

    // get MSG, RELAY, CVR value
    const char * mqtt_id                = json_object_dotget_string(json_body, "MSG.account.id");
    const char * mqtt_pwd               = json_object_dotget_string(json_body, "MSG.account.pwd");
    const char * mqtt_server            = json_object_dotget_string(json_body, "MSG.profile.mqtt_server");
    const char * mqtt_server_port       = json_object_dotget_string(json_body, "MSG.profile.mqtt_server_port");
    const char * mqtt_client_id         = json_object_dotget_string(json_body, "MSG.profile.client_id");
    const char * mqtt_topic             = json_object_dotget_string(json_body, "MSG.profile.topic");
    const char * mqtt_system_topic      = json_object_dotget_string(json_body, "MSG.profile.system_notification_topic");

    const char * relay_id               = json_object_dotget_string(json_body, "RELAY.account.id");
    const char * relay_pwd              = json_object_dotget_string(json_body, "RELAY.account.pwd");
    const char * relay_server           = json_object_dotget_string(json_body, "RELAY.profile.relay_server");
    const char * relay_server_port      = json_object_dotget_string(json_body, "RELAY.profile.relay_server_port");

    const char * cvr_id                 = json_object_dotget_string(json_body, "CVR.account.id");
    const char * cvr_pwd                = json_object_dotget_string(json_body, "CVR.account.pwd");
    const char * media_server           = json_object_dotget_string(json_body, "CVR.profile.media_server");
    const char * media_server_port      = json_object_dotget_string(json_body, "CVR.profile.media_server_port");
    const char * media_server_live_port = json_object_dotget_string(json_body, "CVR.profile.media_server_liveport");

    // copy the value to 'service_info'
    if (mqtt_id                != NULL) strncpy(service_info->mqtt.id,           mqtt_id,           SM_SERVICE_ID_LEN);
    if (mqtt_pwd               != NULL) strncpy(service_info->mqtt.pwd,          mqtt_pwd,          SM_SERVICE_PWD_LEN);
    if (mqtt_server            != NULL) strncpy(service_info->mqtt.server,       mqtt_server,       SM_SERVICE_SERVER_LEN);
    if (mqtt_server_port       != NULL) service_info->mqtt.port = atoi(mqtt_server_port);
    if (mqtt_client_id         != NULL) strncpy(service_info->mqtt.client_id,    mqtt_client_id,    SM_SERVICE_MQTT_CLINET_ID_LEN);
    if (mqtt_topic             != NULL) strncpy(service_info->mqtt.topic,        mqtt_topic,        SM_SERVICE_MQTT_TOPIC_LEN);
    if (mqtt_system_topic      != NULL) strncpy(service_info->mqtt.system_topic, mqtt_system_topic, SM_SERVICE_MQTT_TOPIC_LEN);

    if (relay_id               != NULL) strncpy(service_info->relay.id,          relay_id,          SM_SERVICE_ID_LEN);
    if (relay_pwd              != NULL) strncpy(service_info->relay.pwd,         relay_pwd,         SM_SERVICE_PWD_LEN);
    if (relay_server           != NULL) strncpy(service_info->relay.server,      relay_server,      SM_SERVICE_SERVER_LEN);
    if (relay_server_port      != NULL) service_info->relay.port = atoi(relay_server_port);

    if (cvr_id                 != NULL) strncpy(service_info->cvr.id,            cvr_id,            SM_SERVICE_ID_LEN);
    if (cvr_pwd                != NULL) strncpy(service_info->cvr.pwd,           cvr_pwd,           SM_SERVICE_PWD_LEN);
    if (media_server           != NULL) strncpy(service_info->media.server,      media_server,      SM_SERVICE_SERVER_LEN);
    if (media_server_port      != NULL) service_info->media.port      = atoi(media_server_port);
    if (media_server_live_port != NULL) service_info->media.live_port = atoi(media_server_live_port);

    json_value_free(root_value);
    khttp_destroy(ctx);                                                         /* free: root_value, ctx */
    return 0;
}


/** Internal Function **/

int __sm_check_string(const char * var, const char * var_name, const char * func) {
    if (var == NULL || strlen(var) <= 0) {
        printf("%s: '%s' should not be NULL or empty\n", func, var_name); // Error Level
        return -1;
    }
    return 0;
}

int __sm_check_not_null(const void * var, const char * var_name, const char * func) {
    if (var == NULL) {
        printf("%s: '%s' should not be NULL or empty\n", func, var_name); // Error Level
        return -1;
    }
    return 0;
}
