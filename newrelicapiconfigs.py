configdict = {
        'api_auth_info': {  # API-SPECIFIC AUTH CONFIG
                'authmethod': 'token',  #supported: 'user_and_pass', 'sas', 'token', None
                'token': {
                        'request_token_passed_in': 'headers', #supported: headers
                        'request_token_name': 'X-Insert-Key',
                        },
                },
#        'api_base_url': 'https://uberdongle-iothub-poc.azure-devices.net',
        'api_base_url': 'https://insights-collector.newrelic.com/v1/accounts/1307518',
        'api_base_queryparams': {},
        'api_base_headers': {'Content-Type': 'application/json', 'Accept': 'application/json', },
        'api_response_format': 'json', #supported: json, everything else = raw text. please gods, no XML ever.
        'api_endpoints': {
                'events': '/events', #post event data here
#                'query': '/query',
                },
        'api_functions': {},
        }
