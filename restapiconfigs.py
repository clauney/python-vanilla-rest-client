azure_iot_rest_api_config = {
        'api_auth_info': {  # API-SPECIFIC AUTH CONFIG
                'authmethod': 'sas',  #supported: 'user_and_pass', 'sas', 'token', None
                'sas': { #this will mean token is regenerated every time a request is made
                        'request_token_ttl_seconds': 3600, #timeout for the SAS token, in seconds
                        'request_token_passed_in': 'headers', #supported: headers
                        'request_token_name': 'Authorization',
                        },
                },
#        'api_base_url': 'https://uberdongle-iothub-poc.azure-devices.net',
        'api_base_url': 'https://tempsrpt-iothub-poc.azure-devices.net',
        'api_base_queryparams': {'api-version': '2018-06-30', },
        'api_base_headers': {'Content-Type': 'application/json', },
#        'api_response_format': 'json', #doing this dynamically now
        'api_endpoints': {
                'devices': '/devices', #for messages, post to devices with: '{}/devices/{}/messages/events',
                'query': '/devices/query',
                'twins': '/twins',
                },
        'api_functions': {},
        }

slack_webhook_config = {
        'api_auth_info': {  # API-SPECIFIC AUTH CONFIG
                'authmethod': None,  #supported: 'user_and_pass','sas','token',None
                },
        'api_base_url': 'https://hooks.slack.com/services',
        'api_base_queryparams': {},
        'api_base_headers': {},
#        'api_request_format': 'json', #supported: json, everything else = raw text. please gods, no XML ever.
#        'api_response_format': 'text', #doing this dynamically now
#        'api_version': '',
        'api_endpoints': {
                '#dev_cl_slackbot': '/T025EE5RS/BCJBZJK5W/shBPUXAZC7vlPdZ6Wf21ap1w',
                '#iot-dev': '/T025EE5RS/BCJGDCQRF/4qRyCUFaTyQyvZUooD8RiHA9',
                '#temp_iot_pilot':'/T025EE5RS/BCK3GAHT5/zjSE7Jk0wk4vE2mD4stFhYUz',
                },
        'api_functions': {
                },
        }

pagerduty_api_config = {
        'api_auth_info': {  # API-SPECIFIC AUTH CONFIG
                'authmethod': 'token',  #supported: 'user_and_pass','sas','token',None
                'token': {
                        'request_token_passed_in': 'headers', #supported: headers
                        'request_token_name': 'Authorization',
                        },
                },
        'api_base_url': 'https://api.pagerduty.com',
        'api_base_queryparams': {},
        'api_base_headers': {},
#        'api_version': '',
#        'api_request_format': 'json', #supported: json, everything else = raw text. please gods, no XML ever.
        'api_response_format': 'json', #supported: json, everything else = raw text. please gods, no XML ever.
        'api_endpoints': {
                'incidents': '/incidents',
                },
        'api_functions': {
                'nope': {
                        'endpoint': 'incidents',
                        'function_endpoint_suffix': '',
                        'request': 'post',
                        },
                },
        }

machineq_api_config = {
#        'old_api_auth_info': {  # API-SPECIFIC AUTH CONFIG
#                'authmethod': 'user_and_pass',  #supported: 'user_and_pass','sas','token',None
#                'user_and_pass': {
#                        'authcreds_passed_in': 'data', #supported: data, headers
#                        'authcreds_username_key': 'username', #name of username header/key/param
#                        'authcreds_password_key': 'password',  #name of password header/key/param
#                        'authenticate_url': 'https://api.machineq.net/v1/login',
#                        'authenticate_http_method': 'post',
#                        'authenticate_http_response_format': 'json', #supported: json (later others if needed. NEVER XML DEAR GOD PLEASE)
#                        'authenticate_response_parse': True, #should response JSON be parsed, to pull a key/value/etc
#                        'authenticate_response_parse_function': lambda resp : resp.get('token'),
#                        'request_token_passed_in': 'headers', #supported: headers
#                        'request_token_name': 'Grpc-Metadata-Authorization',
#                        },
#                },
        'api_auth_info': {  # API-SPECIFIC AUTH CONFIG
                'authmethod': 'oauth2',  #supported: 'oauth2', 'user_and_pass', 'sas', 'token', None
                'oauth2': {
                        'authcreds_passed_in': 'headers', #supported: data, headers
#                        'auth_scheme': 'basic', #do we need to handle this? check, code later if digest or other stuff needs support
#                        'authcreds_basicauth_key': 'Authorization', #I think this is the same for all basic auth, put in later if need
                        'authenticate_url': 'https://oauth.machineq.net/oauth2/token',
                        'authenticate_http_method': 'post',
                        'authenticate_http_response_format': 'json', # supported: 'json' (or None) -> parse http auth response as json.
                                                                     #  'text' or 'raw' or 'dinosaur' will just pull pure text
                        'authenticate_response_parse': True, # should response JSON be parsed, to pull a key/value/etc.
                                                             # Default: True. To turn off, use False
                        'authenticate_response_parse_function': lambda resp : resp.get('access_token'),
                        #'request_token_type': 'bearer', #Going to assume this for now, code other conditions later if needed
                        'request_token_passed_in': 'headers', #supported: headers
                        'request_token_name': 'Authorization',
                        },
                },
        'api_base_url': 'https://api.machineq.net',
        'api_base_queryparams': {}, #could put api-version or other params here
        'api_base_headers': {"Accept": "application/json"}, #great place for Accept, maybe api versions, etc.
#        'api_request_format': 'json', #supported: json, everything else = raw text. please gods, no XML ever.
        'api_response_format': 'json', #supported: json, everything else = raw text. please gods, no XML ever.
        'api_endpoints': {
                'login': '/v1/login',
                'devices': '/v1/devices',
                'gateways': '/v1/gateways',
                'outputprofiles': '/v1/outputprofiles',
                'groups': '/v1/groups/devices',
                'account': '/v1/account',
                'connectivityplans': '/v1/connectivityplans',
                'decodertypes': '/v1/decodertypes',
                'deviceprofiles': '/v1/deviceprofiles',
                'logs': '/v1/logs',
                },

        'api_functions': {
                'get_devices': {
                        'endpoint': 'devices',
                        'function_endpoint_suffix': '',
                        'request': 'get',
                        },
                'create_device': {
                        'endpoint': 'devices',
                        'function_endpoint_suffix': '',
                        'request': 'post',
                        },
                'get_gateways': {
                        'endpoint': 'gateways',
                        'function_endpoint_suffix': '',
                        'request': 'get',
                        },
                'update_gateway': {
                        'endpoint': 'gateways',
                        'function_endpoint_suffix': '',
                        'request': 'patch',
                        },
                'update_device': {
                        'endpoint': 'devices',
                        'function_endpoint_suffix': '',
                        'request': 'patch',
                        },
                'get_outputprofiles': {
                        'endpoint': 'outputprofiles',
                        'function_endpoint_suffix': '',
                        'request': 'get',
                        },
                'get_groups': {
                        'endpoint': 'groups',
                        'function_endpoint_suffix': '',
                        'request': 'get',
                        },
                },
        }




