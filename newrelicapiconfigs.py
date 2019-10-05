configdict = {
        'api_auth_info': {
                'authmethod': 'token',
                'token': {
                        'request_token_passed_in': 'headers',
                        'request_token_name': 'X-Insert-Key',
                        },
                },
        'api_base_url': 'https://insights-collector.newrelic.com/v1/accounts/<YOUR ACCT #>',
        'api_base_queryparams': {},
        'api_base_headers': {'Content-Type': 'application/json', 'Accept': 'application/json', },
        'api_endpoints': {
                'events': '/events', # post event data here
#                'query': '/query', # integrating thiså
                },
        'api_functions': {},
        }
