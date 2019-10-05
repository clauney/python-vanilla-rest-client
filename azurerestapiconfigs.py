azure_iot_rest_api_config = {
        'api_auth_info': {
                'authmethod': 'sas',
                'sas': { # this will mean token is regenerated every time a request is made
                        'request_token_ttl_seconds': 3600, # timeout for the SAS token, in seconds
                        'request_token_passed_in': 'headers',
                        'request_token_name': 'Authorization',
                        },
                },
        'api_base_url': 'https://<YOUR-IOTHUB-NAME>.azure-devices.net',
        'api_base_queryparams': {'api-version': '2018-06-30', },
        'api_base_headers': {'Content-Type': 'application/json', },
        'api_endpoints': {
                'devices': '/devices', #for messages, post to devices with: '{}/devices/{}/messages/events',
                'query': '/devices/query',
                'twins': '/twins',
                },
        'api_functions': {},
        }

