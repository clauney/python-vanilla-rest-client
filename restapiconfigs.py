# =============================================================================
# # USAGE
# auth_method_none_rest_client = ApiClient(your_config_dict)
# auth_method_token_rest_client = ApiClient(your_config_dict,
#                                           token=your_token)
# auth_method_user_and_pass_client = ApiClient(your_config_dict,
#                                            username=your_username,
#                                            password=your_pass) #!!!! will become auth_name, auth_auth_secret
# auth_method_oauth2_client = ApiClient(your_config_dict,
#                                       username=your_username,
#                                       password=your_pass) #!!!! will become auth_name, auth_auth_secret
# auth_method_http_signature_client = ApiClient(your_config_dict,
#                                               auth_name=key_id_or_name,
#                                               auth_secret=secret_key)
# auth_method_sas_client = ApiClient(your_config_dict,
#                                    auth_name=policyname_or_keyname,
#                                    auth_secret=secret_key)
# =============================================================================

# GENERAL LAYOUT
basic_api_config = {
        'api_auth_info': {  # Authentication config info. SEE SECTIONS BELOW for examples
                },          # SUPPORTED: None, 'token', 'oauth2', 'http_signature', 'sas', 'hawk', 'user_and_pass'
                            # (NOTE: user_and_pass is older special case likely to be merged into oauth2/other

        'api_base_url': 'https://base.url.com/api/v1', #the base URL to call. endpoints are appended to this for calls
        'api_base_queryparams': { # optional query params to append to URI on every call 
                'foo': 'bar' # adds or extends URI query params with "foo=bar" on every call
                }, 
        'api_base_headers': {  # optional HTTP headers to pass on every call
                'Accept': 'application/json',
                },
        'api_endpoints': {
                'some-endpoint': '/endpoint', # describes endpoints that you can easily call with the call_api_by_endpoint method
                },
        'api_functions': {
                'nope': {
                        'endpoint': 'incidents', # describes functions (endpoint + method + suffix) that you can easily call with the call_api_by_function method
                        'function_endpoint_suffix': '',
                        'request': 'post',
                        },
                },
        }

# AUTH CONFIG
authmethod_none_config = {
        'api_auth_info': {
                'authmethod': None, #that's all, folks
                },
        }

authmethod_token_config = {
        'api_auth_info': {
                'authmethod': 'token',
                'token': {
                        'request_token_passed_in': 'headers', #supported: headers, data
                        'request_token_name': 'Authorization', # the key name for the req header/req data, often 'Authorization'
                        },
                },
        }

authmethod_user_and_pass_config = {
        'api_auth_info': {
                'authmethod': 'user_and_pass',
                'user_and_pass': {
                        'authcreds_passed_in': 'data', #supported: data, headers
                        'authcreds_username_key': 'username', #name of username header/key/param
                        'authcreds_password_key': 'password',  #name of password header/key/param
                        'authenticate_url': 'https://api.machineq.net/v1/login', # auth endpoint (separate config because can sometimes be outside of API tree)
                        'authenticate_http_method': 'post',
                        'authenticate_http_response_format': 'json', # supported: 'json', *
                                                                     # 'json': parse http auth response as json
                                                                     # 'text' (or 'raw' or 'dinosaur' or or or) will just pull the response as raw text to use
                        'authenticate_response_parse': True, # should response be parsed, to grab a k:v or add / subtract text. Otherwise just stores raw text
                                                             # Default: True. To turn off, use False
                        'authenticate_response_parse_function': lambda resp : resp.get('token'),
                        'request_token_passed_in': 'headers', #supported: headers
                        'request_token_name': 'Grpc-Metadata-Authorization',
                        },
                },
        }

authmethod_oauth2_config = {
        'api_auth_info': {
                'authmethod': 'oauth2',
                'oauth2': {
                        'authcreds_passed_in': 'headers', #supported: data, headers
#                        'auth_scheme': 'basic', #do we need to handle other than basic? check, code later if digest or other stuff needs support
#                        'authcreds_basicauth_key': 'Authorization', #I think this is the same for all basic auth, put in later if need
                        'authenticate_url': 'https://oauth.someapi.com/oauth2/token',
                        'authenticate_http_method': 'post',
                        'authenticate_http_response_format': 'json', # supported: 'json', *
                                                                     # 'json': parse http auth response as json
                                                                     # 'text' (or 'raw' or 'dinosaur' or or or) will just pull the response as raw text to use
                        'authenticate_response_parse': True, # should response be parsed, to grab a k:v or add / subtract text. Otherwise just stores raw text
                                                             # Default: True. To turn off, use False
                        'authenticate_response_parse_function': lambda resp : resp.get('access_token'),
                        #'request_token_type': 'bearer', #Going to assume this for now, code other conditions later if needed
                        'request_token_passed_in': 'headers', #supported: headers
                        'request_token_name': 'Authorization',
                        },
                },
        }

authmethod_httpsignature_config = {
        'api_auth_info': {
                'authmethod': 'http_signature',
                'http_signature': {
                        'hash_algorithm': 'sha256', #supported: sha256, sha512, sha1
                        'timestamp_format': 'rfc2822', # supported: 'iso8601' ('2019-09-09T16:00:53.579423+00:00'),
                                                       #            'rfc2822' ('Tue, 08 Sep 2015 10:06:04 GMT')
                        'request_token_passed_in': 'headers', #supported: headers
                        'request_token_name': 'Authorization',
                        },
                },
        }

authmethod_sas_config = {
        'api_auth_info': {
                'authmethod': 'sas', # SAS is like MSFT special case of signature,
                'sas': {             # token is built to insert into every request
                        'request_token_ttl_seconds': 3600, # timeout for the SAS token, in seconds
                        'request_token_passed_in': 'headers',
                        'request_token_name': 'Authorization',
                        },
                },
        }

