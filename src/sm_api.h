#ifndef __SM_API_H
#define __SM_API_H

#define SM_URL_LEN  2048

/** Struct: SM_User_Account **/
#define SM_USER_NAME_LEN        256
#define SM_USER_UID_LEN         256
#define SM_USER_EMAIL_LEN       256
#define SM_USER_CC_LEN          256
#define SM_USER_MOBILE_LEN      256
#define SM_USER_TOKEN_LEN       256
#define SM_USER_EXPIRATION_LEN  256

typedef struct {
    char username   [SM_USER_NAME_LEN];
    char uid        [SM_USER_UID_LEN];
    char email      [SM_USER_EMAIL_LEN];
    int  email_vd;
    char cc         [SM_USER_CC_LEN];
    char mobile     [SM_USER_MOBILE_LEN];
    char token      [SM_USER_TOKEN_LEN];
    char expiration [SM_USER_EXPIRATION_LEN];
} SM_User_Account;


/** Struct: SM_Service_Info **/
#define SM_SERVICE_ID_LEN             64
#define SM_SERVICE_PWD_LEN            64
#define SM_SERVICE_SERVER_LEN         256
#define SM_SERVICE_MQTT_CLINET_ID_LEN 256
#define SM_SERVICE_MQTT_TOPIC_LEN     128

typedef struct {
    // MQTT
    struct {
        char  id           [SM_SERVICE_ID_LEN];
        char  pwd          [SM_SERVICE_PWD_LEN];
        char  server       [SM_SERVICE_SERVER_LEN];
        int   port;
        char  client_id    [SM_SERVICE_MQTT_CLINET_ID_LEN];
        char  topic        [SM_SERVICE_MQTT_TOPIC_LEN];
        char  system_topic [SM_SERVICE_MQTT_TOPIC_LEN];
    } mqtt;

    // Relay
    struct {
        char  id           [SM_SERVICE_ID_LEN];
        char  pwd          [SM_SERVICE_PWD_LEN];
        char  server       [SM_SERVICE_SERVER_LEN];
        int   port;
    } relay;

    // CVR
    struct {
        char  id           [SM_SERVICE_ID_LEN];
        char  pwd          [SM_SERVICE_PWD_LEN];
        char  server       [SM_SERVICE_SERVER_LEN];
        int   port;
        long  start_time;
        long  end_time;
    } cvr;

    // Media
    struct {
        char  server       [SM_SERVICE_SERVER_LEN];
        int   port;
        int   live_port;
    } media;
} SM_Service_Info;


/** USER API **/

/*
 * 06. sm_user_digest_login
 * https://docs.google.com/a/gemteks.com/document/d/1O0_ItXjhFbenkJ17cLVSuKn3XTPHUun-q7B4dGVB9iE/edit#heading=h.z4kh06nubag
 *
 * @param server_url
 * @param username
 * @param password
 * @param device_id
 * @param app_identifier
 * @param user_account
 * @return = 0    success
 *         < 0    parameters failure, HTTP failure or JSON parse failure
 *         XXX    HTTP error status code
 *         XXXX   Server Manager error status code
 */
int sm_user_digest_login(
        const char * server_url,
        const char * username,
        const char * password,
        const char * device_id,
        const char * app_identifier,
        SM_User_Account * user_account);

/*
 * 12. sm_user_get_service_info
 * https://docs.google.com/a/gemteks.com/document/d/1O0_ItXjhFbenkJ17cLVSuKn3XTPHUun-q7B4dGVB9iE/edit#heading=h.q31pfzimunmz
 *
 * @param server_url
 * @param token
 * @param api_token
 * @param service
 * @param service_info
 * @return = 0    success
 *         < 0    parameters failure, HTTP failure or JSON parse failure
 *         XXX    HTTP error status code
 *         XXXX   Server Manager error status code
 */
int sm_user_get_service_info(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * service,
        SM_Service_Info * service_info);

/* 20. sm_user_get_service_all
 * https://docs.google.com/a/gemteks.com/document/d/1O0_ItXjhFbenkJ17cLVSuKn3XTPHUun-q7B4dGVB9iE/edit#heading=h.4js1iuaksnd2
 *
 * @param server_url
 * @param token
 * @param api_token
 * @param service_info
 * @return = 0    success
 *         < 0    parameters failure, HTTP failure or JSON parse failure
 *         XXX    HTTP error status code
 *         XXXX   Server Manager error status code
 */
int sm_user_get_service_all(
        const char * server_url,
        const char * token,
        const char * api_key,
        SM_Service_Info * service_info);

#endif
