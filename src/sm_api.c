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
    if (root_value == NULL) {
        printf("%s: JSON parse failed\n", __func__);    // Error Level
        printf("body = %s\n", (const char *)ctx->body);
        khttp_destroy(ctx);                                                     /* free: ctx */
        return -1;
    }

    // check the JSON type
    if (json_value_get_type(root_value) != JSONObject) {
        goto json_parse_failure;                                                /* free: root_value, ctx */
    }

    // get JSON Object
    JSON_Object * json_body = json_value_get_object(root_value);
    if (json_body == NULL) {
        goto json_parse_failure;                                                /* free: root_value, ctx */
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

json_parse_failure:
    printf("%s: JSON parse failed\n", __func__);    // Error Level
    printf("body = %s\n", (const char *)ctx->body);
    json_value_free(root_value);
    khttp_destroy(ctx);
    return -1;
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
