machineq_api_config = {
        'api_auth_info': {
                'authmethod': 'oauth2',
                'oauth2': {
                        'authcreds_passed_in': 'headers',
                        'authenticate_url': 'https://oauth.machineq.net/oauth2/token',
                        'authenticate_http_method': 'post',
                        'authenticate_http_response_format': 'json',
                        'authenticate_response_parse': True,
                        'authenticate_response_parse_function': lambda resp : resp.get('access_token'),
                        'request_token_passed_in': 'headers',
                        'request_token_name': 'Authorization',
                        },
                },
        'api_base_url': 'https://api.machineq.net',
        'api_base_queryparams': {},
        'api_base_headers': {'Accept': 'application/json'},
        'api_endpoints': {
                'login': '/v1/login',
                'devices': '/v1/devices',
                'gateways': '/v1/gateways',
                'outputprofiles': '/v1/outputprofiles',
                'groups': '/v1/groups/devices',
                'account': '/v1/account',
                'serviceprofiles': '/v1/serviceprofiles',
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

