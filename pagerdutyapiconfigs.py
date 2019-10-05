pagerduty_events_api_config = {
        'api_auth_info': {  
                'authmethod': 'token',
                'token': {
                        'request_token_passed_in': 'headers',
                        'request_token_name': 'Authorization',
                        },
                },
        'api_base_url': 'https://api.pagerduty.com',
        'api_base_queryparams': {},
        'api_base_headers': {'From': '<INCIDENT_SENDER@EXAMPLE.COM>',
                             'Accept': 'application/vnd.pagerduty+json;version=2',},
        'api_endpoints': {
                'incidents': '/incidents',
                },
        'api_functions': {
                'post_incident': {
                        'endpoint': 'incidents',
                        'function_endpoint_suffix': '',
                        'request': 'post',
                        },
                },
        }

