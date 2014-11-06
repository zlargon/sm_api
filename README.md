sm_api
======
Service Manager HTTP API


#### 1. USER API (4)
```
06. sm_user_digest_login
12. sm_user_get_service_info
18. sm_user_add_device
20. sm_user_get_service_all
```

#### 2. DEVICE API (9)
```
02. sm_device_activation
03. sm_device_digest_login
04. sm_device_certificate_login
08. sm_device_get_service_info
09. sm_device_reset_default
11. sm_device_get_user_list
12. sm_device_add_user
13. sm_device_remove_user
14. sm_device_get_service_all
```

#### 3. MEC API (2)
```
01. sm_mec_send_message
02. sm_mec_get_message
```

#### 4. The other function
```
* sm_user_account_free
* sm_mec_free_message
* sm_qiwo_device_registration
```


How to git clone the project with submodule
----
```
git clone --recursive https://github.com/zlargon/sm_api.git
```
or
```
git clone https://github.com/zlargon/sm_api.git
git submodule init
git submodule update
```


How to build on OS X
----
replace the `Makefile` in khttp library
```
cd lib/khttp
cp Makefile.mac Makefile
```
