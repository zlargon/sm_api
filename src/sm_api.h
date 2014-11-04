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

typedef struct SM_User_Account {
    char username   [SM_USER_NAME_LEN];
    char uid        [SM_USER_UID_LEN];
    char email      [SM_USER_EMAIL_LEN];
    int  email_vd;
    char cc         [SM_USER_CC_LEN];
    char mobile     [SM_USER_MOBILE_LEN];
    char token      [SM_USER_TOKEN_LEN];
    char expiration [SM_USER_EXPIRATION_LEN];
    struct SM_User_Account * next;
} SM_User_Account;

/** Struct: SM_Device_Account **/
#define SM_DEVICE_MAC_LEN           256
#define SM_DEVICE_GID_LEN           256
#define SM_DEVICE_PIN_LEN           256
#define SM_DEVICE_TOKEN_LEN         256
#define SM_DEVICE_EXPIRATION_LEN    256
#define SM_DEVICE_SERVICE_COUNT     10
#define SM_DEVICE_SERVICE_NAME_LEN  32

typedef struct SM_Device_Account {
    char mac        [SM_DEVICE_MAC_LEN];
    char gid        [SM_DEVICE_GID_LEN];
    char pin        [SM_DEVICE_PIN_LEN];
    char token      [SM_DEVICE_TOKEN_LEN];
    char expiration [SM_DEVICE_EXPIRATION_LEN];
    char service_list[SM_DEVICE_SERVICE_COUNT][SM_DEVICE_SERVICE_NAME_LEN];
} SM_Device_Account;

/** Struct: SM_Service_Info **/
#define SM_SERVICE_ID_LEN             64
#define SM_SERVICE_PWD_LEN            64
#define SM_SERVICE_SERVER_LEN         256
#define SM_SERVICE_MQTT_CLINET_ID_LEN 256
#define SM_SERVICE_MQTT_TOPIC_LEN     128

typedef struct SM_Service_Info {
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
        char      id       [SM_SERVICE_ID_LEN];
        char      pwd      [SM_SERVICE_PWD_LEN];
        char      server   [SM_SERVICE_SERVER_LEN];
        int       port;
        long long start_time;
        long long end_time;
    } cvr;

    // Media
    struct {
        char  server       [SM_SERVICE_SERVER_LEN];
        int   port;
        int   live_port;
    } media;
} SM_Service_Info;


/** Struct: SM_MEC_Message **/
typedef struct SM_MEC_Message {
    char   src[SM_USER_UID_LEN];
    char * content; // alloc
    long   serial;
    long   timestamp;
    long   ttl;
    struct SM_MEC_Message * next;
} SM_MEC_Message;


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


/** DEVICE API **/

/*
 * 03. sm_device_digest_login
 * https://docs.google.com/a/gemteks.com/document/d/1Ve6e-1oF0yb-MAV8Kh6kBTny0wTrK8BHDCqNcV7gZE4/edit#heading=h.e0v5rapmh0lf
 *
 * @param server_url
 * @param username
 * @param password
 * @param device_account
 * @return = 0    success
 *         < 0    parameters failure, HTTP failure or JSON parse failure
 *         XXX    HTTP error status code
 *         XXXX   Server Manager error status code
 */
int sm_device_digest_login(
        const char * server_url,
        const char * username,
        const char * password,
        SM_Device_Account * device_account);

/*
 * 08. sm_device_get_service_info
 * https://docs.google.com/a/gemteks.com/document/d/1Ve6e-1oF0yb-MAV8Kh6kBTny0wTrK8BHDCqNcV7gZE4/edit#heading=h.rurnksd06q31
 *
 * @param server_url
 * @param token
 * @param api_key
 * @param service
 * @param service_info
 * @return = 0    success
 *         < 0    parameters failure, HTTP failure or JSON parse failure
 *         XXX    HTTP error status code
 *         XXXX   Server Manager error status code
 */
int sm_device_get_service_info(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * service,
        SM_Service_Info * service_info);

/*
 * 11. sm_device_get_user_list
 * https://docs.google.com/a/gemteks.com/document/d/1Ve6e-1oF0yb-MAV8Kh6kBTny0wTrK8BHDCqNcV7gZE4/edit#heading=h.kyk5jimd8wzm
 *
 * @param server_url
 * @param token
 * @param api_key
 *
 * @return = 0    success
 *         < 0    parameters failure, HTTP failure or JSON parse failure
 *         XXX    HTTP error status code
 *         XXXX   Server Manager error status code
 */
int sm_device_get_user_list(
        const char * server_url,
        const char * token,
        const char * api_key,
        SM_User_Account ** user_list);

/* 14. sm_device_get_service_all
 * https://docs.google.com/a/gemteks.com/document/d/1Ve6e-1oF0yb-MAV8Kh6kBTny0wTrK8BHDCqNcV7gZE4/edit#heading=h.hs7e4bx2bo45
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
int sm_device_get_service_all(
        const char * server_url,
        const char * token,
        const char * api_key,
        SM_Service_Info * service_info);


/** MEC API **/

enum SM_MQTT_OQS {
    SM_MQTT_OQS_AT_MOST_ONCE    = 0,
    SM_MQTT_OQS_AT_LEAST_ONCE   = 1,
    SM_MQTT_OQS_AT_EXACTLY_ONCE = 2
};

enum SM_MQTT_SEND_TYPE {
    SM_MQTT_SEND_TYPE_RELIABLE  = 0,
    SM_MQTT_SEND_TYPE_REALTIME  = 1
};

/* 01. sm_mec_send_message
 * https://docs.google.com/a/gemteks.com/document/d/1rcvGr_lrOClHl2cI5TwV8XByEW4tCaK7O5MlxSnHer4/edit#heading=h.9a1nn85am3gi
 *
 * @param server_url
 * @param token
 * @param api_token
 * @param api_secret
 * @param qos        enum SM_MQTT_OQS:
 *                   SM_MQTT_OQS_AT_MOST_ONCE    (0) : at most once
 *                   SM_MQTT_OQS_AT_LEAST_ONCE   (1) : at least once
 *                   SM_MQTT_OQS_AT_EXACTLY_ONCE (2) : exactly once
 *
 * @param send_type  enum SM_MQTT_SEND_TYPE:
 *                   SM_MQTT_SEND_TYPE_RELIABLE  (0) : notify and get
 *                   SM_MQTT_SEND_TYPE_REALTIME  (1) : push only
 * @param expire
 * @param target_id
 * @param message
 * @return = 0    success
 *         < 0    parameters failure, HTTP failure or JSON parse failure
 *         XXX    HTTP error status code
 *         XXXX   Server Manager error status code
 */
int sm_mec_send_message(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * api_secret,
        int          qos,
        int          send_type,
        long         expire,
        const char * target_id,
        const char * message);

/* 02. sm_mec_get_message
 * https://docs.google.com/a/gemteks.com/document/d/1rcvGr_lrOClHl2cI5TwV8XByEW4tCaK7O5MlxSnHer4/edit#heading=h.nd38bgr0hq9b
 *
 * @param server_url
 * @param token
 * @param api_token
 * @param api_secret
 * @param serial
 * @param mec_message_list
 * @return = 0    success
 *         < 0    parameters failure, HTTP failure or JSON parse failure
 *         XXX    HTTP error status code
 *         XXXX   Server Manager error status code
 */
int sm_mec_get_message(
        const char * server_url,
        const char * token,
        const char * api_key,
        const char * api_secret,
        long         serial,
        SM_MEC_Message ** mec_message_list);

/* 03. sm_mec_free_message
 *
 * @param mec_message
 */
void sm_mec_free_message(SM_MEC_Message * mec_message);

#endif
