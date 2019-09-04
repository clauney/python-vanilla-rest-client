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
        'api_base_url': 'https://s00175ioths03.azure-devices.net',
        'api_base_queryparams': {'api-version': '2018-06-30', },
        'api_base_headers': {'Content-Type': 'application/json', },
        'api_response_format': 'json', #supported: json, everything else = raw text. please gods, no XML ever.
        'api_endpoints': {
                'devices': '/devices', #for messages, post to devices with: '{}/devices/{}/messages/events',
                'query': '/devices/query',
                'twins': '/twins',
                },
        'api_functions': {},
        }

azure_svc_fabric_rest_api_config = {
        'api_auth_info': {  # API-SPECIFIC AUTH CONFIG
                'authmethod': 'sas',  #supported: 'user_and_pass', 'sas', 'token', None
                'sas': { #this will mean token is regenerated every time a request is made
                        'request_token_ttl_seconds': 3600, #timeout for the SAS token, in seconds
                        'request_token_passed_in': 'headers', #supported: headers
                        'request_token_name': 'Authorization',
                        },
                },
#        'api_base_url': 'https://uberdongle-iothub-poc.azure-devices.net',
        'api_base_url': 'https://s00175ioths03.azure-devices.net',
        'api_base_queryparams': {'api-version': '2018-06-30', },
        'api_base_headers': {'Content-Type': 'application/json', },
        'api_response_format': 'json', #supported: json, everything else = raw text. please gods, no XML ever.
        'api_endpoints': {
                'devices': '/devices', #for messages, post to devices with: '{}/devices/{}/messages/events',
                'query': '/devices/query',
                'twins': '/twins',
                },
        'api_functions': {},
        }
