#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "sm_api.h"

/** Third Party Library **/
#include "../lib/khttp/khttp.h"
#include "../lib/khttp/http_parser.h"
#include "../lib/parson/parson.h"

#define SM_SHA1_LEN  SHA_DIGEST_LENGTH * 2 + 1

#define STRINGIFY(s) #s
#define sm_check_string(var) __sm_check_string(var, STRINGIFY(var), __func__)
#define sm_check_not_null(var) __sm_check_not_null(var, STRINGIFY(var), __func__)
#define _return(ret) _ret = ret; goto _return;

int __sm_check_string(const char * var, const char * var_name, const char * func);
int __sm_check_not_null(const void * var, const char * var_name, const char * func);
int sm_http_perform(khttp_ctx * ctx, JSON_Value ** json_value, JSON_Object ** json_object, const char * func);
int sm_crypto_SHA1(const char * string, char sha1[/* SM_SHA1_LEN */]);
int sm_generate_api_token(const char * api_secret, char api_token[/* SM_SHA1_LEN */], time_t * current_time);


/** USER API **/

// 06. sm_user_digest_login
int sm_user_digest_login(
        const char * server_url,
        const char * username,
        const char * password,
        const char * device_id,
        const char * app_identifier,
        SM_User_Account * user_account) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url)     ||
        sm_check_string(username)       ||
        sm_check_string(password)       ||
        sm_check_string(device_id)      ||
        sm_check_string(app_identifier) ||
        sm_check_not_null(user_account) != 0) {
        _return(-1);
    }

    memset(user_account, 0, sizeof(SM_User_Account));

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/user/login?device_id=%s&app_identifier=%s", server_url, device_id, app_identifier);

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_username_password(ctx, (char *)username, (char *)password, KHTTP_AUTH_DIGEST);
    khttp_ssl_skip_auth(ctx);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1211) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
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

    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 12. sm_user_get_service_info
int sm_user_get_service_info(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * service,
        SM_Service_Info * service_info) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url)     ||
        sm_check_string(token)          ||
        sm_check_string(api_key)        ||
        sm_check_string(service)        ||
        sm_check_not_null(service_info) != 0) {
        _return(-1);
    }
    memset(service_info, 0, sizeof(SM_Service_Info));

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/user/get_service_info", server_url);

    // set post body
    char post_body[2048] = {0};
    snprintf(post_body, sizeof(post_body), "token=%s&api_key=%s&service=%s", token, api_key, service);

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1211) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
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

    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 18. sm_user_add_device
int sm_user_add_device(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * api_secret,
        const char * device_mac,
        const char * device_pin,
        const char * device_info) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url) ||
        sm_check_string(token)      ||
        sm_check_string(api_key)    ||
        sm_check_string(api_secret) ||
        sm_check_string(device_mac) ||
        sm_check_string(device_pin) != 0) {
        _return(-1);
    }

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/user/add_device", server_url);

    // generate 'current_time' and 'api_token'
    time_t current_time = 0;
    char api_token[SM_SHA1_LEN] = {0};
    sm_generate_api_token(api_secret, api_token, &current_time);

    // check device info
    int has_device_info = device_info != NULL && strlen(device_info) > 0;

    // set post body
    char post_body[512] = {0};
    snprintf(post_body, 512,
        "token=%s&api_key=%s&api_token=%s&time=%ld&device_id=%s&pin=%s%s%s",
        token,
        api_key,
        api_token,
        current_time,
        device_mac,
        device_pin,
        has_device_info ? "&device_info=" : "",
        has_device_info ? device_info : ""
    );

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1231) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
    }

    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 20. sm_user_get_service_all
int sm_user_get_service_all(
        const char * server_url,
        const char * token,
        const char * api_key,
        SM_Service_Info * service_info) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url)     ||
        sm_check_string(token)          ||
        sm_check_string(api_key)        ||
        sm_check_not_null(service_info) != 0) {
        _return(-1);
    }
    memset(service_info, 0, sizeof(SM_Service_Info));

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/user/get_service_all", server_url);

    // set post body
    char post_body[2048] = {0};
    snprintf(post_body, sizeof(post_body), "token=%s&api_key=%s", token, api_key);

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1200) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
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

    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}


/** DEVICE API **/

// 02. sm_device_activation
int sm_device_activation(const char * server_url, const char * device_mac) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url) ||
        sm_check_string(device_mac) != 0) {
        _return(-1);
    }

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/device/activation", server_url);

    // set post body
    char post_body[128] = {0};
    snprintf(post_body, 128, "device_id=%s", device_mac);

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1226) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
    }

    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 03. sm_device_digest_login
int sm_device_digest_login(
        const char * server_url,
        const char * username,
        const char * password,
        SM_Device_Account * device_account) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url)       ||
        sm_check_string(username)         ||
        sm_check_string(password)         ||
        sm_check_not_null(device_account) != 0) {
        _return(-1);
    }
    memset(device_account, 0, sizeof(SM_Device_Account));

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/device/login", server_url);

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_username_password(ctx, (char *)username, (char *)password, KHTTP_AUTH_DIGEST);
    khttp_ssl_skip_auth(ctx);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1221) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
    }

    const char * mac        = json_object_dotget_string(json_body, "info.account.mac");
    const char * gid        = json_object_dotget_string(json_body, "info.account.gid");
    const char * pin        = json_object_dotget_string(json_body, "info.account.pin");
    const char * token      = json_object_dotget_string(json_body, "global_session.token");
    const char * expiration = json_object_dotget_string(json_body, "global_session.expiration");

    // copy the value to 'device_account'
    if (mac        != NULL) strncpy(device_account->mac,        mac,        SM_DEVICE_MAC_LEN);
    if (gid        != NULL) strncpy(device_account->gid,        gid,        SM_DEVICE_GID_LEN);
    if (pin        != NULL) strncpy(device_account->pin,        pin,        SM_DEVICE_PIN_LEN);
    if (token      != NULL) strncpy(device_account->token,      token,      SM_DEVICE_TOKEN_LEN);
    if (expiration != NULL) strncpy(device_account->expiration, expiration, SM_DEVICE_EXPIRATION_LEN);

    size_t i;
    const JSON_Array * service_list = json_object_dotget_array(json_body, "info.service_list");
    for (i = 0; i < json_array_get_count(service_list); i++) {
        const JSON_Object * obj = json_array_get_object(service_list, i);
        const char * type = json_object_get_string(obj, "type");
        if (type != NULL) {
            strncpy(device_account->service_list[i], type, SM_DEVICE_SERVICE_NAME_LEN);
        }
    }

    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 04. sm_device_certificate_login
int sm_device_certificate_login(
        const char * server_url,
        const char * cert_path,
        const char * key_path,
        SM_Device_Account * device_account) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url)       ||
        sm_check_string(cert_path)        ||
        sm_check_string(key_path)         ||
        sm_check_not_null(device_account) != 0) {
        _return(-1);
    }
    memset(device_account, 0, sizeof(SM_Device_Account));

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/device/login", server_url);

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_ssl_set_cert_key(ctx, (char *)cert_path, (char *)key_path, NULL);
    khttp_ssl_skip_auth(ctx);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1221) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
    }

    const char * mac        = json_object_dotget_string(json_body, "info.account.mac");
    const char * gid        = json_object_dotget_string(json_body, "info.account.gid");
    const char * pin        = json_object_dotget_string(json_body, "info.account.pin");
    const char * token      = json_object_dotget_string(json_body, "global_session.token");
    const char * expiration = json_object_dotget_string(json_body, "global_session.expiration");

    // copy the value to 'device_account'
    if (mac        != NULL) strncpy(device_account->mac,        mac,        SM_DEVICE_MAC_LEN);
    if (gid        != NULL) strncpy(device_account->gid,        gid,        SM_DEVICE_GID_LEN);
    if (pin        != NULL) strncpy(device_account->pin,        pin,        SM_DEVICE_PIN_LEN);
    if (token      != NULL) strncpy(device_account->token,      token,      SM_DEVICE_TOKEN_LEN);
    if (expiration != NULL) strncpy(device_account->expiration, expiration, SM_DEVICE_EXPIRATION_LEN);

    size_t i;
    const JSON_Array * service_list = json_object_dotget_array(json_body, "info.service_list");
    for (i = 0; i < json_array_get_count(service_list); i++) {
        const JSON_Object * obj = json_array_get_object(service_list, i);
        const char * type = json_object_get_string(obj, "type");
        if (type != NULL) {
            strncpy(device_account->service_list[i], type, SM_DEVICE_SERVICE_NAME_LEN);
        }
    }

    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 08. sm_device_get_service_info
int sm_device_get_service_info(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * service,
        SM_Service_Info * service_info) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url)     ||
        sm_check_string(token)          ||
        sm_check_string(api_key)        ||
        sm_check_string(service)        ||
        sm_check_not_null(service_info) != 0) {
        _return(-1);
    }
    memset(service_info, 0, sizeof(SM_Service_Info));

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/device/get_service_info", server_url);

    // set post body
    char post_body[2048] = {0};
    snprintf(post_body, sizeof(post_body), "token=%s&api_key=%s&service=%s", token, api_key, service);

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1221) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
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
        const char * cvr_id          = json_object_dotget_string(json_body, "info.account.id");
        const char * cvr_pwd         = json_object_dotget_string(json_body, "info.account.pwd");
        const char * cvr_server      = json_object_dotget_string(json_body, "info.profile.cvr_server");
        const char * cvr_server_port = json_object_dotget_string(json_body, "info.profile.cvr_server_port");
        const char * cvr_start_time  = json_object_dotget_string(json_body, "info.pay_service.RECORDING.period.start_time");
        const char * cvr_end_time    = json_object_dotget_string(json_body, "info.pay_service.RECORDING.period.end_time");

        // copy the value to 'service_info->cvr'
        if (cvr_id          != NULL) strncpy(service_info->cvr.id,     cvr_id,     SM_SERVICE_ID_LEN);
        if (cvr_pwd         != NULL) strncpy(service_info->cvr.pwd,    cvr_pwd,    SM_SERVICE_PWD_LEN);
        if (cvr_server      != NULL) strncpy(service_info->cvr.server, cvr_server, SM_SERVICE_SERVER_LEN);
        if (cvr_server_port != NULL) service_info->cvr.port       = atoi(cvr_server_port);
        if (cvr_start_time  != NULL) service_info->cvr.start_time = strtoll(cvr_start_time, NULL, 10);
        if (cvr_end_time    != NULL) service_info->cvr.end_time   = strtoll(cvr_end_time,   NULL, 10);
    }

    else {
        printf("%s: not support service '%s' JSON parsing\n", __func__, service);
        printf("body = %s\n", (const char *)ctx->body);
    }

    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 09. sm_device_reset_default
int sm_device_reset_default(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * api_secret) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url) ||
        sm_check_string(token)      ||
        sm_check_string(api_key)    ||
        sm_check_string(api_secret) != 0) {
        _return(-1);
    }

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/device/reset_default", server_url);

    // generate 'current_time' and 'api_token'
    time_t current_time = 0;
    char api_token[SM_SHA1_LEN] = {0};
    sm_generate_api_token(api_secret, api_token, &current_time);

    // set post body
    char post_body[256] = {0};
    snprintf(post_body, 256,
        "token=%s&api_key=%s&api_token=%s&time=%ld",
        token,
        api_key,
        api_token,
        current_time
    );

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1227) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
    }

    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 11. sm_device_get_user_list
int sm_device_get_user_list(
        const char * server_url,
        const char * token,
        const char * api_key,
        SM_User_Account ** user_list) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;
    *user_list = NULL;

    // check arguments
    if (sm_check_string(server_url) ||
        sm_check_string(token)      ||
        sm_check_string(api_key)    != 0) {
        _return(-1);
    }

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/device/get_user_list", server_url);

    // set post body
    char post_body[512] = {0};
    snprintf(post_body, 512, "token=%s&api_key=%s", token, api_key);

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1240) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
    }

    // get 'user_list' and convert into linked list
    size_t i;
    const JSON_Array * json_users = json_object_dotget_array(json_body, "user_list");
    SM_User_Account * root = NULL;
    SM_User_Account * ptr  = NULL;
    for (i = 0; i < json_array_get_count(json_users); i++) {
        const JSON_Object * obj = json_array_get_object(json_users, i);
        const char * username   = json_object_get_string(obj, "username");
        const char * email      = json_object_get_string(obj, "email");
        const char * uid        = json_object_get_string(obj, "uid");

        // memory alloc the new user entry
        if (root == NULL) {
            // the first user entry
            root = (SM_User_Account *) malloc(sizeof(SM_User_Account));
            ptr = root;
        } else {
            // the others user entry
            ptr->next = (SM_User_Account *) malloc(sizeof(SM_User_Account));
            ptr = ptr->next;
        }

        // check ptr
        if (ptr == NULL) {
            printf("%s: out of memory\n", __func__);
            sm_user_account_free(root);
            _return(-1);
        }

        // set user entry
        memset(ptr, 0, sizeof(SM_User_Account));
        if (username != NULL) strncpy(ptr->username, username, SM_USER_NAME_LEN);
        if (email    != NULL) strncpy(ptr->email,    email,    SM_USER_EMAIL_LEN);
        if (uid      != NULL) strncpy(ptr->uid,      uid,      SM_USER_UID_LEN);
        ptr->next = NULL;
    }

    // set user_list
    *user_list = root;
    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 11-2. sm_user_account_free
void sm_user_account_free(SM_User_Account * user_account) {
    if (user_account == NULL) {
        return;
    }

    if (user_account->next != NULL) {
        // recursive
        sm_user_account_free(user_account->next);
        user_account->next = NULL;
    }

    // debug log
    // printf("free user '%s'\n", user_account->username);

    free((void *)user_account);
};

// 12. sm_device_add_user
int sm_device_add_user(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * api_secret,
        const char * user_id,
        const char * device_info) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url) ||
        sm_check_string(token)      ||
        sm_check_string(api_key)    ||
        sm_check_string(api_secret) ||
        sm_check_string(user_id)    != 0) {
        _return(-1);
    }

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/device/add_user", server_url);

    // generate 'current_time' and 'api_token'
    time_t current_time = 0;
    char api_token[SM_SHA1_LEN] = {0};
    sm_generate_api_token(api_secret, api_token, &current_time);

    // check device info
    int has_device_info = device_info != NULL && strlen(device_info) > 0;

    // set post body
    char post_body[256] = {0};
    snprintf(post_body, 256,
        "token=%s&api_key=%s&api_token=%s&time=%ld&user_id=%s%s%s",
        token,
        api_key,
        api_token,
        current_time,
        user_id,
        has_device_info ? "&device_info=" : "",
        has_device_info ? device_info : ""
    );

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1231) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
    }

    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 13. sm_device_remove_user
int sm_device_remove_user(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * api_secret,
        const char * user_id) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url) ||
        sm_check_string(token)      ||
        sm_check_string(api_key)    ||
        sm_check_string(api_secret) ||
        sm_check_string(user_id)    != 0) {
        _return(-1);
    }

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/device/rm_user", server_url);

    // generate 'current_time' and 'api_token'
    time_t current_time = 0;
    char api_token[SM_SHA1_LEN] = {0};
    sm_generate_api_token(api_secret, api_token, &current_time);

    // set post body
    char post_body[256] = {0};
    snprintf(post_body, 256,
        "token=%s&api_key=%s&api_token=%s&time=%ld&user_id=%s",
        token,
        api_key,
        api_token,
        current_time,
        user_id
    );

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1234) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
    }

    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 14. sm_device_get_service_all
int sm_device_get_service_all(
        const char * server_url,
        const char * token,
        const char * api_key,
        SM_Service_Info * service_info) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url)     ||
        sm_check_string(token)          ||
        sm_check_string(api_key)        ||
        sm_check_not_null(service_info) != 0) {
        _return(-1);
    }
    memset(service_info, 0, sizeof(SM_Service_Info));

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/v1/device/get_service_all", server_url);

    // set post body
    char post_body[2048] = {0};
    snprintf(post_body, sizeof(post_body), "token=%s&api_key=%s", token, api_key);

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 1200) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
    }

    // get MSG, RELAY, CVR value
    const char * mqtt_id           = json_object_dotget_string(json_body, "MSG.account.id");
    const char * mqtt_pwd          = json_object_dotget_string(json_body, "MSG.account.pwd");
    const char * mqtt_server       = json_object_dotget_string(json_body, "MSG.profile.mqtt_server");
    const char * mqtt_server_port  = json_object_dotget_string(json_body, "MSG.profile.mqtt_server_port");
    const char * mqtt_client_id    = json_object_dotget_string(json_body, "MSG.profile.client_id");
    const char * mqtt_topic        = json_object_dotget_string(json_body, "MSG.profile.topic");
    const char * mqtt_system_topic = json_object_dotget_string(json_body, "MSG.profile.system_notification_topic");

    const char * relay_id          = json_object_dotget_string(json_body, "RELAY.account.id");
    const char * relay_pwd         = json_object_dotget_string(json_body, "RELAY.account.pwd");
    const char * relay_server      = json_object_dotget_string(json_body, "RELAY.profile.relay_server");
    const char * relay_server_port = json_object_dotget_string(json_body, "RELAY.profile.relay_server_port");

    const char * cvr_id            = json_object_dotget_string(json_body, "CVR.account.id");
    const char * cvr_pwd           = json_object_dotget_string(json_body, "CVR.account.pwd");
    const char * cvr_server        = json_object_dotget_string(json_body, "CVR.profile.cvr_server");
    const char * cvr_server_port   = json_object_dotget_string(json_body, "CVR.profile.cvr_server_port");
    const char * cvr_start_time    = json_object_dotget_string(json_body, "CVR.pay_service.RECORDING.period.start_time");
    const char * cvr_end_time      = json_object_dotget_string(json_body, "CVR.pay_service.RECORDING.period.end_time");


    // copy the value to 'service_info'
    if (mqtt_id           != NULL) strncpy(service_info->mqtt.id,           mqtt_id,           SM_SERVICE_ID_LEN);
    if (mqtt_pwd          != NULL) strncpy(service_info->mqtt.pwd,          mqtt_pwd,          SM_SERVICE_PWD_LEN);
    if (mqtt_server       != NULL) strncpy(service_info->mqtt.server,       mqtt_server,       SM_SERVICE_SERVER_LEN);
    if (mqtt_server_port  != NULL) service_info->mqtt.port = atoi(mqtt_server_port);
    if (mqtt_client_id    != NULL) strncpy(service_info->mqtt.client_id,    mqtt_client_id,    SM_SERVICE_MQTT_CLINET_ID_LEN);
    if (mqtt_topic        != NULL) strncpy(service_info->mqtt.topic,        mqtt_topic,        SM_SERVICE_MQTT_TOPIC_LEN);
    if (mqtt_system_topic != NULL) strncpy(service_info->mqtt.system_topic, mqtt_system_topic, SM_SERVICE_MQTT_TOPIC_LEN);

    if (relay_id          != NULL) strncpy(service_info->relay.id,          relay_id,          SM_SERVICE_ID_LEN);
    if (relay_pwd         != NULL) strncpy(service_info->relay.pwd,         relay_pwd,         SM_SERVICE_PWD_LEN);
    if (relay_server      != NULL) strncpy(service_info->relay.server,      relay_server,      SM_SERVICE_SERVER_LEN);
    if (relay_server_port != NULL) service_info->relay.port = atoi(relay_server_port);

    if (cvr_id            != NULL) strncpy(service_info->cvr.id,            cvr_id,            SM_SERVICE_ID_LEN);
    if (cvr_pwd           != NULL) strncpy(service_info->cvr.pwd,           cvr_pwd,           SM_SERVICE_PWD_LEN);
    if (cvr_server        != NULL) strncpy(service_info->cvr.server,        cvr_server,        SM_SERVICE_SERVER_LEN);
    if (cvr_server_port   != NULL) service_info->cvr.port       = atoi(cvr_server_port);
    if (cvr_start_time    != NULL) service_info->cvr.start_time = strtoll(cvr_start_time, NULL, 10);
    if (cvr_end_time      != NULL) service_info->cvr.end_time   = strtoll(cvr_end_time,   NULL, 10);

    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}


/** MEC API **/

// 01. sm_mec_send_message
int sm_mec_send_message(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * api_secret,
        int          qos,
        int          send_type,
        long         expire,
        const char * target_id,
        const char * message) {

    int _ret;
    char * post_body = NULL;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;

    // check arguments
    if (sm_check_string(server_url) ||
        sm_check_string(token)      ||
        sm_check_string(api_key)    ||
        sm_check_string(api_secret) ||
        sm_check_string(target_id)  ||
        sm_check_string(message)    != 0) {
        _return(-1);
    }

    if (qos != SM_MQTT_OQS_AT_MOST_ONCE  &&
        qos != SM_MQTT_OQS_AT_LEAST_ONCE &&
        qos != SM_MQTT_OQS_AT_EXACTLY_ONCE) {
        printf("%s: qos (%d) should be %s(%d), %s(%d) or %s(%d)\n", __func__, qos,
            STRINGIFY(SM_MQTT_OQS_AT_MOST_ONCE),    SM_MQTT_OQS_AT_MOST_ONCE,
            STRINGIFY(SM_MQTT_OQS_AT_LEAST_ONCE),   SM_MQTT_OQS_AT_LEAST_ONCE,
            STRINGIFY(SM_MQTT_OQS_AT_EXACTLY_ONCE), SM_MQTT_OQS_AT_EXACTLY_ONCE
        );
        _return(-1);
    }

    if (send_type != SM_MQTT_SEND_TYPE_RELIABLE &&
        send_type != SM_MQTT_SEND_TYPE_REALTIME) {
        printf("%s: send_type (%d) should be %s(%d) or %s(%d)\n", __func__, send_type,
            STRINGIFY(SM_MQTT_SEND_TYPE_RELIABLE), SM_MQTT_SEND_TYPE_RELIABLE,
            STRINGIFY(SM_MQTT_SEND_TYPE_REALTIME), SM_MQTT_SEND_TYPE_REALTIME
        );
        _return(-1);
    }

    if (expire < 0) {
        printf("%s: expire (%ld) should not be negative\n", __func__, expire);
        _return(-1);
    }

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/mec_msg/v1/send", server_url);

    // generate 'current_time' and 'api_token'
    time_t current_time = 0;
    char api_token[SM_SHA1_LEN] = {0};
    sm_generate_api_token(api_secret, api_token, &current_time);

    // set post body
    size_t post_body_len = strlen(message) + 512;
    post_body = (char *) calloc(post_body_len, sizeof(char));
    if (post_body == NULL) {
        printf("%s: out of memory\n", __func__);
        _return(-1);
    }
    snprintf(post_body, post_body_len,
        "token=%s&api_key=%s&api_token=%s&time=%ld&qos=%d&type=%d&expire=%ld&dst=%s&text=%s",
        token,
        api_key,
        api_token,
        current_time,
        qos,
        send_type,
        expire,
        target_id,
        message
    );

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 2221) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
    }

    _return(0);

_return:
    if (post_body  != NULL) free((void *)post_body);
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 02. sm_mec_get_message
int sm_mec_get_message(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * api_secret,
        long         serial,
        SM_MEC_Message ** mec_message_list) {

    int _ret;
    khttp_ctx * ctx = NULL;
    JSON_Value * root_value = NULL;
    *mec_message_list = NULL;

    // check arguments
    if (sm_check_string(server_url) ||
        sm_check_string(token)      ||
        sm_check_string(api_key)    ||
        sm_check_string(api_secret) != 0) {
        _return(-1);
    }

    if (serial < 0) {
        printf("%s: serial (%ld) should not be negative\n", __func__, serial);
        _return(-1);
    }

    // set URL
    char url[SM_URL_LEN] = {0};
    snprintf(url, sizeof(url), "%s/mec_msg/v1/get", server_url);

    // generate 'current_time' and 'api_token'
    time_t current_time = 0;
    char api_token[SM_SHA1_LEN] = {0};
    sm_generate_api_token(api_secret, api_token, &current_time);

    // set post body
    char post_body[512] = {0};
    snprintf(post_body, 512,
        "token=%s&api_key=%s&api_token=%s&time=%ld&serial=%ld",
        token,
        api_key,
        api_token,
        current_time,
        serial
    );

    ctx = khttp_new();
    khttp_set_uri(ctx, url);
    khttp_set_method(ctx, KHTTP_POST);
    khttp_ssl_skip_auth(ctx);
    khttp_set_post_data(ctx, post_body);

    JSON_Object * json_body = NULL;
    int ret = sm_http_perform(ctx, &root_value, &json_body, __func__);
    if (ret != 2222) {
        if (ctx->body != NULL) {
            printf("body = %s\n", (const char *)ctx->body);
        }
        _return(ret);
    }

    // get 'ret_msg.messages' and convert into linked list
    size_t i;
    const JSON_Array * json_messages = json_object_dotget_array(json_body, "ret_msg.messages");
    SM_MEC_Message * root = NULL;
    SM_MEC_Message * ptr  = NULL;
    for (i = 0; i < json_array_get_count(json_messages); i++) {
        const JSON_Object * obj = json_array_get_object(json_messages, i);
        const char * src     =  json_object_get_string(obj, "src");
        const char * content =  json_object_get_string(obj, "content");
        long serial    = (long) json_object_get_number(obj, "serial");
        long timestamp = (long) json_object_get_number(obj, "timestamp");
        long ttl       = (long) json_object_get_number(obj, "ttl");

        // memory alloc the new message entry
        if (root == NULL) {
            // the first message entry
            root = (SM_MEC_Message *) malloc(sizeof(SM_MEC_Message));
            ptr = root;
        } else {
            // the others message entry
            ptr->next = (SM_MEC_Message *) malloc(sizeof(SM_MEC_Message));
            ptr = ptr->next;
        }

        // check ptr
        if (ptr == NULL) {
            printf("%s: out of memory\n", __func__);
            sm_mec_free_message(root);
            _return(-1);
        }

        // set message entry
        memset(ptr, 0, sizeof(SM_MEC_Message));
        strncpy(ptr->src, src, SM_USER_UID_LEN);                            // 1. src
        ptr->content = (char *) calloc(strlen(content) + 1, sizeof(char));  // 2. content
        strncpy(ptr->content, content, strlen(content));
        ptr->serial    = serial;                                            // 3. serial
        ptr->timestamp = timestamp;                                         // 4. timestamp
        ptr->ttl       = ttl;                                               // 5. ttl
        ptr->next      = NULL;                                              // 6. next
    }

    // set mec_message_list
    *mec_message_list = root;
    _return(0);

_return:
    if (root_value != NULL) json_value_free(root_value);
    if (ctx        != NULL) khttp_destroy(ctx);
    return _ret;
}

// 03. sm_mec_free_message
void sm_mec_free_message(SM_MEC_Message * mec_message) {
    if (mec_message == NULL) {
        return;
    }

    if (mec_message->next != NULL) {
        // recursive
        sm_mec_free_message(mec_message->next);
        mec_message->next = NULL;
    }

    // debug log
    // printf("free message '%s'\n", mec_message->content);

    free((void *)mec_message->content);
    mec_message->content = NULL;
    free((void *)mec_message);
};


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

int sm_crypto_SHA1(const char * string, char sha1[/* SM_SHA1_LEN */]) {
    // check arguments
    if (sm_check_string(string) ||
        sm_check_not_null(sha1) != 0) {
        return -1;
    }
    memset(sha1, 0, SM_SHA1_LEN);

    // generate bytes sha1
    unsigned char bytes[SHA_DIGEST_LENGTH] = {0};
    SHA1((const unsigned char *)string, strlen(string), bytes);

    // convert bytes to string
    int i;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(sha1 + i * 2, "%02x", bytes[i]);
    }

    return 0;
}

int sm_generate_api_token(const char * api_secret, char api_token[/* SM_SHA1_LEN */], time_t * current_time) {
    if (sm_check_string(api_secret)     ||
        sm_check_not_null(api_token)    ||
        sm_check_not_null(current_time) != 0) {
        return -1;
    }
    memset(api_token, 0, SM_SHA1_LEN);
    *current_time = time(NULL);

    char string[128] = {0};
    snprintf(string, 128, "%s%ld", api_secret, *current_time);

    return sm_crypto_SHA1((const char*)string, api_token);
}

int sm_http_perform(khttp_ctx * ctx, JSON_Value ** json_value, JSON_Object ** json_object, const char * func) {
    *json_value  = NULL;
    *json_object = NULL;

    if (sm_check_not_null(ctx) != 0) {
        return -1;
    }

    int ret = khttp_perform(ctx);
    if (ret != 0) {
        return ret;
    }

    // check HTTP status code
    if (ctx->hp.status_code != 200) {
        printf("%s: HTTP status code = %d\n", func, ctx->hp.status_code);   // Error Level
        return ctx->hp.status_code;
    }

    // JSON parse
    JSON_Value * root_value = json_parse_string(ctx->body);
    JSON_Object * json_body = json_value_get_object(root_value);
    if (json_body == NULL) {
        printf("%s: JSON parse failed\n", func);    // Error Level
        json_value_free(root_value);
        return -1;
    }

    // set json_value and json_object
    *json_value  = root_value;
    *json_object = json_body;

    // return status code
    return (int) json_object_dotget_number(json_body, "status.code");
}
