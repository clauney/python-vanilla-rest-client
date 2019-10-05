slack_webhook_config = {
        'api_auth_info': {
                'authmethod': None,
                },
        'api_base_url': 'https://hooks.slack.com/services',
        'api_base_queryparams': {},
        'api_base_headers': {},
        'api_endpoints': {
                '#your-slack-channel': '/YOUR/WEBHOOK/URL', # slack webhook URL includes a secret, so treat it like one
                '#other-slack-channel': '/OTHER/WEBHOOK/URL',
                },
        'api_functions': {
                },
        }
