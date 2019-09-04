#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jul 18 11:43:17 2018

@author: clauney
"""

'''
!!!! TODO - APIClient class
    --done--ttl parsing to know when to just re-up the token
    1c. retrier for timeouts, etc.
    --done--implement request_token_passed_in
'''

##########################################################
# need all this for logging, if for nothing else
import os
import datetime
import logging
default_console_logging_level = 'verbose' #'verbose', 'basic', None
default_file_logging_level = 'basic'
##########################################################


import hmac
import base64
import urllib.parse
import urllib.request
import requests
import time

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning) # sigh, bad APIs

#from functools import partial #stopped using this, doing lambda instead

# ENVIRONMENTAL / OVERALL DEFAULTS THAT EXIST OUTSIDE OF API CLIENT CONFIGLOAD
default_log_level = default_console_logging_level  #'verbose', 'basic', None
http_response_codes_do_reauth = [400, 401, 402, 403, 405, 406, 407] #these can all be indicative of permissions issue in various scenarios
http_response_codes_do_retry = range(500,600) # anything 5xx

#%%

# =============================================================================
# #
# # this was for handling cases where dev machine config for openssl made the world explode
# # no longer needed, but leaving in in case it recurs or someone else needs
# #
# from ssl import PROTOCOL_TLSv1_2
# class Tls12HttpAdapter(requests.adapters.HTTPAdapter):
#     """"Transport adapter" that allows us to use Tls12."""
#     def init_poolmanager(self, connections, maxsize, block=False):
#         lumberjack.info('POOLMGR connections: %s, maxsize: %s, block: %s', connections, maxsize, block)
#         self.poolmanager = requests.packages.urllib3.poolmanager.PoolManager(
#             num_pools=connections*2, maxsize=maxsize*4,
#             block=block, ssl_version=PROTOCOL_TLSv1_2, retries=5)
# requests.packages.urllib3.disable_warnings() #to make it shut up about the disabled verify stuff
# tls_adapter = Tls12HttpAdapter()
# basesession = requests.sessions.Session()
# basesession.mount('https://', tls_adapter)
# basesession.mount('', tls_adapter)
# basesession.mount('http://', tls_adapter)
# =============================================================================

#%%
# BASE API CLIENT CLASS
class ApiClient():
    _token = None
    _default_loglevel = default_log_level
    def __init__(self, api_config_dict, **kwargs):
        '''(dict, **kwargs) -> None
        KWARGS:
        loglevel=None|'basic'|'verbose'
        foo1=ApiClient(username='foo', password='bar')
        foo2=ApiClient(token='blahblahblah')
        foo3=ApiClient(auth_name='foo', auth_secret='bar')
        '''
        self.name = api_config_dict.get('api_base_url', '').replace('http', '').lstrip('s').lstrip('://')
        lumberjack.info('%s INIT STARTED for api with url: %s', self.name.upper(), api_config_dict.get('api_base_url'))
        self.loglevel = self._default_loglevel
        if 'loglevel' in kwargs:
            self.change_loglevel(kwargs['loglevel'])
        self._config = api_config_dict
        self._auth_method = self._config['api_auth_info']['authmethod']
        ######### this sets configs from various auth method kwargs ###########
        self._token = kwargs.get('token') #we want this None
        if kwargs.get('username'): self._apiuser = kwargs.get('username')
        if kwargs.get('password'): self._apipass = kwargs.get('password')
        self._sas_key = kwargs.get('auth_secret')
        self._sas_policyname = kwargs.get('auth_name')
        #######################################################################
        self.api_endpoints = self._config['api_endpoints']
        self.api_functions = self._config['api_functions']
        self.base_url = self._config['api_base_url']
        self.base_queryparams = self._config.get('api_base_queryparams', {})
        self.base_headers = self._config.get('api_base_headers', {})
#        self.api_request_format = self._config.get('api_request_format') # handled by requests based on json vs. data kwargs
#        self.api_response_format = self._config('api_response_format') # done dynamically now based on 'application/json' in Content-Type response header
#        self.api_version = self._config.get('api_version') # deprecated, just put it in the base URL or endpoint
        self._gen_auth_token()
        lumberjack.info('%s INIT FINISHED. endpoints: %s', self.name.upper(), self.api_endpoints)
    def change_loglevel(self, newvalue):
        '''(str)->None
        For input param in [None, 'basic', 'verbose'], will set the console output
        level to that valueu.
        '''
        if newvalue in [None, 'basic', 'verbose']:
            self.loglevel = newvalue
    def _gen_auth_token(self):
        if self._auth_method == 'user_and_pass':
            self._token = self._auth_username()
        elif self._auth_method == 'oauth2':
            self._token = self._auth_oauth2()
        elif self._auth_method == 'token':
            pass
        elif self._auth_method == None:
            pass #self._token is None from the initial kwargs
        elif self._auth_method == 'sas':
            self._sas_token_ttl = self._config['api_auth_info'][self._auth_method].get('request_token_ttl_seconds', 30)
#            self._sas_format_string = 'SharedAccessSignature sr={}&sig={}&se={}&skn={}' #!!! trying to do both policy and non-policy things 
            self._sas_format_string = 'SharedAccessSignature sr={}&sig={}&se={}'
        return self._token
    def token(self, *args, **kwargs):
        if self._auth_method == 'sas':
            lumberjack.debug('SAS token request: args: %s, kwargs: %s', args, kwargs)
            return self._get_sas_token(*args, **kwargs)
        elif self._auth_method in ['oauth2', 'user_and_pass', 'token', None]:
            return self._token
        else:
            lumberjack.error('YO! ERROR! self._auth_method is whack. Should be in ["sas", "user_and_pass", "token", None]')
            raise NotImplementedError
    def _auth_username(self):
        pass_authcreds_via = self._config['api_auth_info'][self._auth_method].get('authcreds_passed_in', 'data')
        user_field_name = self._config['api_auth_info'][self._auth_method]['authcreds_username_key']
        pass_field_name = self._config['api_auth_info'][self._auth_method]['authcreds_password_key']
        req_data = {}
        req_headers = self.base_headers.copy()
        url = self._config['api_auth_info'][self._auth_method]['authenticate_url']
        method = self._config['api_auth_info'][self._auth_method]['authenticate_http_method']
        if pass_authcreds_via == 'data':
            req_data = {**req_data, user_field_name: self._apiuser, pass_field_name: self._apipass}
        elif pass_authcreds_via == 'headers':
            req_headers = {**req_headers, user_field_name: self._apiuser, pass_field_name: self._apipass}
        resp = self._request(method, url, json=req_data, headers=req_headers)        
        return self._parse_auth_response(resp)
    def _auth_oauth2(self):
#        self._oldloglevel = self.loglevel
#        self.loglevel = 'verbose'
        lumberjack.info('getting oauth2 token')
        pass_authcreds_via = self._config['api_auth_info'][self._auth_method].get('authcreds_passed_in', 'headers')
        req_data = {'grant_type': 'client_credentials'} #this is standard oauth2 basic auth stuff
        req_headers = self.base_headers.copy()
        url = self._config['api_auth_info'][self._auth_method]['authenticate_url']
        method = self._config['api_auth_info'][self._auth_method]['authenticate_http_method']
        if pass_authcreds_via == 'data':
            req_data['client_id'] = self._apiuser
            req_data['client_secret'] = self._apipass
        elif pass_authcreds_via == 'headers':
            header_key = 'Authorization' #!!!! this should to be changed to support a configured header name
            header_val = 'Basic {}' #!!!! maybe more than basic later
            auth_bytes = b':'.join([self._apiuser.encode('latin1', errors='ignore'), self._apipass.encode('latin1', errors='ignore')])
            auth_str = base64.b64encode(auth_bytes).strip().decode(errors='ignore')
            lumberjack.debug('oauth2 auth bytes: %s, auth string: %s', auth_bytes, auth_str)
            req_headers[header_key] = header_val.format(auth_str)
        lumberjack.debug('oauth2 request headers: %s, request data: %s', req_headers, req_data)
        resp = self._request(method, url, data=req_data, headers=req_headers)
        lumberjack.debug('oauth2 token got this text and about to parse: %s', resp.text)
        parsed = self._parse_auth_response(resp)
        lumberjack.debug('oauth2 new token: %s', 'Bearer ' + parsed)
        return 'Bearer ' + parsed
    def _parse_auth_response(self, resp):
        lumberjack.debug('decoding this response text: %s', resp.text)
        if self._config['api_auth_info'][self._auth_method].get('authenticate_http_response_format', 'json') == 'json':
            resp = resp.json()
        else:
            resp = resp.text
        lumberjack.debug('after decoding, response is now: %s', resp)
        if self._config['api_auth_info'][self._auth_method].get('authenticate_response_parse', True):
            parsefunc = self._config['api_auth_info'][self._auth_method]['authenticate_response_parse_function']
            resp = parsefunc(resp)
        lumberjack.debug('after parsing, response is now: %s', resp)
        return resp
    def _parse_function_config(self, function):
        '''(str)->str, dict, bool
        Returns the request type ('get', 'post'), request URL, and a boolean 
        which is True if the request *doesn't* need authorization, for the function
        named by the 'function' input parameter.
        '''
        reqtype = self.api_functions.get(function, {}).get('request', '')
        endptname = self.api_functions.get(function, {}).get('endpoint', '')
        funcsuffix = self.api_functions.get(function, {}).get('function_endpoint_suffix', '')
        funcurl = self.base_url + self.api_endpoints.get(endptname) + funcsuffix
        return funcurl, reqtype
    def _request(self, req_method, req_url, **kwargs):
        '''
        KWARGS:
            * ignore_cert_errors (bool=False): ignore SSL cert errors
            * others (doc!!) #!!!!
            
        cm.aziot_client._request('delete', 'https://tempsrpt-iothub-poc.azure-devices.net/devices/cpltest', headers={'User-Agent': 'python-requests/2.21.0', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive', 'If-Match': '*', 'Authorization': 'SharedAccessSignature sr=tempsrpt-iothub-poc.azure-devices.net&sig=fEkIvv5sTigUMdBzjckQwIzf9MivIigbcJRH9s8cfAk%3D&se=1550694866&skn=manageDevices', 'Content-Type': 'application/json', 'Content-Length': '0'}, params={'api-version': '2018-06-30'})
        '''
        lumberjack.debug('request kwargs: %s', kwargs)
        testkwargs = [k for k in kwargs]
        for k in testkwargs:
            if kwargs.get(k) == None:
                kwargs.pop(k)
        lumberjack.debug('request kwargs after clearing empties: %s', kwargs)
        respobj = requests.request(req_method, req_url, **kwargs)
        return respobj
    def _handler_call_api(self, req_method, req_url, **kwargs):
        '''
        KWARGS:
            * ignore_cert_errors (bool=False): ignore SSL cert errors
            * others (doc!!) #!!!!
        '''
        req_data = kwargs.get('data', {})
        req_headers = kwargs.get('headers', {})
        req_params = kwargs.get('params', {})
        verify_ssl = kwargs.pop('ignore_cert_errors', False) != True
        reqtoken = self.token(url=req_url, **kwargs)
        lumberjack.debug('reqtoken: %s', reqtoken)
        lumberjack.debug('headers before token %s', req_headers)
        if reqtoken:
            if self._config.get('api_auth_info', {}).get('self._auth_method', {}).get('request_token_passed_in', 'headers') == 'headers':
                req_headers[self._config['api_auth_info'][self._auth_method]['request_token_name']] = reqtoken
            else:
                req_data[self._config['api_auth_info'][self._auth_method]['request_token_name']] = reqtoken
        lumberjack.debug('headers after token %s', req_headers)
        
        all_headers = {**self.base_headers, **req_headers}
        all_params = {**self.base_queryparams, **req_params}

        lumberjack.info('REQUEST! method: %s, url: %s', req_method, req_url)
        lumberjack.debug('config base headers: %s', self.base_headers)
        lumberjack.debug('passed req headers: %s', req_headers)
        lumberjack.debug('all headers: %s', all_headers)
        lumberjack.debug('config base params: %s', self.base_queryparams)
        lumberjack.debug('passed query params: %s', req_params)
        lumberjack.debug('all query params: %s', all_params)
        lumberjack.debug('before req data: %s', req_data)
        lumberjack.debug('verify ssl? %s', verify_ssl)
        respobj = self._request(req_method, req_url, headers=all_headers, json=req_data, params=all_params, verify=verify_ssl)
        lumberjack.info('RESPONSE! status code: %s', respobj.status_code)
        if respobj.status_code in http_response_codes_do_reauth:
            lumberjack.warn('OOPS, got HTTP response code: %s, with headers: %s, content as text: %s',
                            respobj.status_code, respobj.headers, respobj.text)
            lumberjack.warn('WILL REGEN AUTH TOKEN AND RETRY ONCE')
            self._gen_auth_token()
            reqtoken = self.token(url=req_url, **kwargs)
            lumberjack.warn('NEW AUTH TOKEN: %s', reqtoken)
            all_headers[self._config['api_auth_info'][self._auth_method]['request_token_name']] = reqtoken
            lumberjack.warn('NEW REQ HEADERS: %s', all_headers)
            respobj = self._request(req_method, req_url, headers=all_headers, json=req_data, params=all_params, verify=verify_ssl)
        if respobj.status_code in http_response_codes_do_retry:
            lumberjack.error('AACK, got HTTP response code: %s, with headers: %s, content as text: %s',
                            respobj.status_code, respobj.headers, respobj.text)
            lumberjack.warn('WILL WAIT 5 SEC AND RETRY ONCE')
            time.sleep(5)
            respobj = self._request(req_method, req_url, headers=all_headers, json=req_data, params=all_params, verify=verify_ssl)
        lumberjack.debug('request url from respobj: %s', respobj.request.url)
        lumberjack.debug('request headers from respobj: %s', respobj.request.headers)
        lumberjack.debug('request body from respobj: %s', respobj.request.body)
        lumberjack.debug('reponse object: %s', dir(respobj))
        lumberjack.debug('response headers: %s', respobj.headers)                    
#        lumberjack.debug('responseobj request body: %s', respobj.request.body)            
#        lumberjack.debug('response content as bytes: %s', respobj.content) #this is way too much for debug logs
#        lumberjack.debug('response content as text: %s', respobj.text) #this is way too much for debug logs
        lumberjack.debug('response content length: %s', len(respobj.content))
        lumberjack.debug('response encoding: %s', respobj.encoding)
        if respobj:
            if respobj.headers.get('Content-Length') == '0':
                return {'response': True, 'status_code': respobj.status_code, 'headers': respobj.headers}
            elif 'application/json' in respobj.headers.get('Content-Type', '').lower(): #.lower() because sigh
#                lumberjack.debug('response json: %s', respobj.json()) #this is way too much for debug logs
                return respobj.json()
            else:
                return respobj.text
        else:
            return {'response': False, 'status_code': None}
#        if self.api_response_format == 'json': #removed from config
#            lumberjack.debug('response json: %s', respobj.json())
#            respobj=respobj.json()
#        else:
#            respobj=respobj.text
#        return respobj
    def _call_api_by_endpoint(self, endpoint, req_method='get', **kwargs):
        '''(str,kwargs)->objects
        returns the data of the response object for the api function matching the input string
        Supported kwargs: 
            headers(dict): kv pairs to be passed as HTTP request headers
            data(dict): kv pairs to be passed as part of an HTTP POST
            params(dict): kv pairs to be passed as parameters in the URL
            dynamic_endpoint_suffix(str): string to add to end of endpoint URL
                (after baseurl+endpoint+function_suffix). This is often used
                to reference a particular device in a collection by a unique ID.
        >>>mq_client._call_api_by_endpoint('groups')
        {'Groups': [{'ExternalType': 'string', 'Id': 'd4VB8HaF', 'Name': 'SBUX-LAB'}]}
        >>>slack_client._call_api_by_endpoint('#dev_cl_slackbot', 'post', data={"text": 'testing slack webhook'})
        '''
        endpturl = self.base_url + self.api_endpoints.get(endpoint)
        req_dyn_suffix = kwargs.get('dynamic_endpoint_suffix','')
        req_url = endpturl + req_dyn_suffix
        return self._handler_call_api(req_method, req_url, **kwargs)
    def _call_api_by_function(self, function, **kwargs):
        '''(str,kwargs)->objects
        returns the data of the response object for the api function matching the input string
        Supported kwargs: 
            headers(dict): kv pairs to be passed as HTTP request headers
            data(dict): kv pairs to be passed as part of an HTTP POST
            params(dict): kv pairs to be passed as parameters in the URL
            dynamic_endpoint_suffix(str): string to add to end of endpoint URL
                (after baseurl+endpoint+function_suffix). This is often used
                to reference a particular device in a collection by a unique ID.
        >>>cm.mq_client._call_api_by_function('get_devices',dynamic_endpoint_suffix='/'+'4883C7DF30081306')
        {'ActivationType': 'OTAA',
         'ConnectivityPlan': 'comcast-cs/starbucks-cp',
         'CreatedAt': '2018-06-12T19:54:03.117200Z',
         'DecoderType': 'G0xfYyeF',
         'DevEUI': '4883C7DF30081306',
         'DeviceProfile': 'LORA/GenericA.1.0.2_FCC_Rx2-SF12',
         'Name': '15253|BrkRm1 - Breakfast Tray Delivery|SPEC TBD',
         'OutputProfile': 'Y2wPglDh',
         'Payload': [{'Data': {'humidity': '82.5', 'temperature': '4.2'},
           'Time': '2018-07-26T19:12:38.046Z'}],
         'Ref': '343903',
         'UpdatedAt': '2018-07-26T19:11:59.000Z',
         'UpdatedBy': 'AlUVzi56'}
        '''
        func_url, req_method = self._parse_function_config(function)
        req_dyn_suffix = kwargs.get('dynamic_endpoint_suffix', '')
        req_url = func_url + req_dyn_suffix
        return self._handler_call_api(req_method, req_url, **kwargs)
# =============================================================================
#     def _call_api_by_function(self, function, **kwargs):
#         '''(str,kwargs)->objects
#         returns the data of the response object for the api function matching the input string
#         Supported kwargs: 
#             headers(dict): kv pairs to be passed as HTTP request headers
#             data(dict): kv pairs to be passed as part of an HTTP POST
#             params(dict): kv pairs to be passed as parameters in the URL
#             dynamic_endpoint_suffix(str): string to add to end of endpoint URL
#                 (after baseurl+endpoint+function_suffix). This is often used
#                 to reference a particular device in a collection by a unique ID.
#         >>>cm.mq_client._call_api_by_function('get_devices',dynamic_endpoint_suffix='/'+'4883C7DF30081306')
#         {'ActivationType': 'OTAA',
#          'ConnectivityPlan': 'comcast-cs/starbucks-cp',
#          'CreatedAt': '2018-06-12T19:54:03.117200Z',
#          'DecoderType': 'G0xfYyeF',
#          'DevEUI': '4883C7DF30081306',
#          'DeviceProfile': 'LORA/GenericA.1.0.2_FCC_Rx2-SF12',
#          'Name': '15253|BrkRm1 - Breakfast Tray Delivery|SPEC TBD',
#          'OutputProfile': 'Y2wPglDh',
#          'Payload': [{'Data': {'humidity': '82.5', 'temperature': '4.2'},
#            'Time': '2018-07-26T19:12:38.046Z'}],
#          'Ref': '343903',
#          'UpdatedAt': '2018-07-26T19:11:59.000Z',
#          'UpdatedBy': 'AlUVzi56'}
#         '''
#         func_url, req_method = self._parse_function_config(function)
#         req_data = kwargs.get('data', {})
#         req_headers = kwargs.get('headers', {})
#         req_params = kwargs.get('params', {})
#         req_dyn_suffix = kwargs.get('dynamic_endpoint_suffix', '')
#         req_url = func_url + req_dyn_suffix
#         reqtoken = self.token(url=req_url, **kwargs)
#         if reqtoken:
#             req_headers[self._config['api_auth_info'][self._auth_method]['request_token_name']] = reqtoken
#         return self._handler_call_api(req_method, req_url, req_params, req_headers, req_data)
# =============================================================================
# =============================================================================
#     def _call_api_by_endpoint(self, endpoint, req_method='get', **kwargs):
#         '''(str,kwargs)->objects
#         returns the data of the response object for the api function matching the input string
#         Supported kwargs: 
#             headers(dict): kv pairs to be passed as HTTP request headers
#             data(dict): kv pairs to be passed as part of an HTTP POST
#             params(dict): kv pairs to be passed as parameters in the URL
#             dynamic_endpoint_suffix(str): string to add to end of endpoint URL
#                 (after baseurl+endpoint+function_suffix). This is often used
#                 to reference a particular device in a collection by a unique ID.
#         >>>mq_client._call_api_by_endpoint('groups')
#         {'Groups': [{'ExternalType': 'string', 'Id': 'd4VB8HaF', 'Name': 'SBUX-LAB'}]}
#         >>>slack_client._call_api_by_endpoint('#dev_cl_slackbot', 'post', data={"text": 'testing slack webhook'})
#         '''
#         endpturl = self.base_url + self.api_endpoints.get(endpoint)
#         req_data = kwargs.get('data',{})
#         req_headers = kwargs.get('headers',{})
#         req_params = kwargs.get('params',{})
#         req_dyn_suffix = kwargs.get('dynamic_endpoint_suffix','')
#         req_url = endpturl + req_dyn_suffix
#         reqtoken = self.token(url=req_url, **kwargs)
#         lumberjack.debug('reqtoken: %s', reqtoken)
#         lumberjack.debug('headers before token %s', req_headers)
#         if reqtoken:
#             req_headers[self._config['api_auth_info'][self._auth_method]['request_token_name']] = reqtoken
#         lumberjack.debug('headers after token %s', req_headers)
#         return self._handler_call_api(req_method, req_url, req_params, req_headers, req_data)
# =============================================================================
# =============================================================================
#     def _handler_call_api(self, req_method, req_url, req_params, req_headers, req_data):
#         all_headers = {**req_headers, **self.base_headers}
#         all_params = {**req_params, **self.base_queryparams}
#         lumberjack.info('REQUEST! method: %s, url: %s', req_method, req_url)
#         lumberjack.debug('config base headers: %s', self.base_headers)
#         lumberjack.debug('passed req headers: %s', req_headers)
#         lumberjack.debug('all headers: %s', all_headers)
#         lumberjack.debug('config base params: %s', self.base_queryparams)
#         lumberjack.debug('passed query params: %s', req_params)
#         lumberjack.debug('all query params: %s', all_params)
#         lumberjack.debug('before req data: %s', req_data)
#         respobj = self._request(req_method, req_url, headers=all_headers, json=req_data, params=all_params)
#         lumberjack.info('RESPONSE! status code: %s', respobj.status_code)
#         if respobj.status_code in [400, 401, 403]:
#             lumberjack.warn('OOPS, got a 4xx HTTP response code: %s, with headers: %s, content as text: %s',
#                             respobj.status_code, respobj.headers, respobj.text)
#             lumberjack.warn('WILL REGEN AUTH TOKEN AND RETRY ONCE')
#             self._gen_auth_token()
#             respobj = self._request(req_method, req_url, headers=all_headers, json=req_data, params=all_params)
#         lumberjack.info('RESPONSE! status code: %s', respobj.status_code)
#         lumberjack.debug('responseobj request body: %s', respobj.request.body)            
# #        lumberjack.debug('response content as bytes: %s', respobj.content) #this is way too much for debug logs
# #        lumberjack.debug('response content as text: %s', respobj.text) #this is way too much for debug logs
#         lumberjack.debug('response content length: %s', len(respobj.content))
#         lumberjack.debug('response encoding: %s', respobj.encoding)
#         if respobj:
#             if respobj.headers.get('Content-Length') == '0':
#                 return {'response': True, 'status_code': respobj.status_code, 'headers': respobj.headers}
#             elif 'application/json' in respobj.headers.get('Content-Type', '').lower(): #.lower() because sigh
# #                lumberjack.debug('response json: %s', respobj.json()) #this is way too much for debug logs
#                 return respobj.json()
#             else:
#                 return respobj.text
#         else:
#             return {'response': False, 'status_code': None}
# =============================================================================
    def _retrier(self, function, tries, retrydelay, *args, **kwargs):
        soldier_on=kwargs.get('continue_on_exception', False)
        kwargs.pop('continue_on_exception', None)
        resp = None
        lumberjack.debug('args: %s, kwargs: %s', args, kwargs)
        for i in range(tries):
            lumberjack.debug('try #%s', i+1)
            try:
                resp = function(*args, **kwargs)
            except:
                lumberjack.error('oops, exception getting response from function %s with args %s and kwargs %s', function, args, kwargs)
                if i < tries - 1: # i is zero indexed
                    time.sleep(retrydelay)
                    lumberjack.error('will try again. retries allowed: %s, on try #%s', tries, i)
                    continue
                else:
                    lumberjack.error('aack! too many retries, raising exception')
                    if soldier_on:
                        continue
                    else:
                        raise
            lumberjack.debug('success on try #%s', i+1)
            break
        return resp
    def _build_sas_expiry(self, ttl_seconds):
        '''(int)->int
        Returns a SAS expiry timecode (se) for an expiry time equal to the 
        current time plus ttl_seconds.
        >>>_build_sas_expiry(3600)
        1546626418
        '''
        return int(time.time()) + ttl_seconds
    def _sas_sign_url_format_func(self, url_str):
        '''(str)->str
        Returns a string representing the SAS string to sign (sr) for a given request URL.
        >>>_sas_sign_url_format_func('https://uberdongle-iothub-poc.azure-devices.net/devices/ubercloverx')
        'uberdongle-iothub-poc.azure-devices.net'
        '''
        return url_str.lower().split('/')[2]
    def _get_sas_token(self, *args, **kwargs):
        '''(kwargs)->str
        Returns a SAS token for the given URL provided by kwarg 'url'
        >>>_get_sas_token(url='https://uberdongle-iothub-poc.azure-devices.net/devices/ubercloverx')
        'SharedAccessSignature sr=uberdongle-iothub-poc.azure-devices.net&sig=k9GKuVqhvnINFT4rlIeMNpZLzNiXRg2Ce9opZsAyvGs%3D&se=1546626117&skn=device_and_twin_read'
        '''
        lumberjack.debug('Generating SAS token!')
        deviceid = kwargs.get('dynamic_endpoint_suffix')
        lumberjack.debug('deviceid: %s', deviceid)
        url_to_sign = self._sas_sign_url_format_func(kwargs.get('url'))
        lumberjack.debug('url_to_sign: %s', url_to_sign)
        url_to_sign_encoded = urllib.parse.quote(url_to_sign, safe='')
        lumberjack.debug('url_to_sign_encoded: %s', url_to_sign_encoded)
        timestamp = self._build_sas_expiry(self._sas_token_ttl)
        lumberjack.debug('timestamp: %s', timestamp)
        h = hmac.new(base64.urlsafe_b64decode(self._sas_key),         #CPLEDIT
                    msg = "{0}\n{1}".format(url_to_sign_encoded, timestamp).encode('utf-8'),
                    digestmod = 'sha256')
        _sas = self._sas_format_string.format(
                url_to_sign_encoded,
                urllib.parse.quote(base64.b64encode(h.digest()), safe = ''),
                timestamp)
        lumberjack.debug('sas-y string: %s', _sas)
        _sas = _sas + '&skn=' + self._sas_policyname if self._sas_policyname else _sas
        lumberjack.debug('sas-y-er result: %s', _sas)
        return _sas
#%%
std_logging_levels = {
        'verbose': logging.DEBUG,
        'basic': logging.INFO,
        None: logging.ERROR
        }
logdatetimestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
os.makedirs('./logs', exist_ok=True)


formatter = logging.Formatter('%(asctime)s %(levelname)s: %(name)s / %(funcName)s(%(lineno)s) %(message)s')

if __name__ == '__main__':
    #doing stuff to run locally
    lumberjack = logging.getLogger('restapiclient_standalone')
    logfilename = './logs/restapiclient_standalone-'+logdatetimestamp+'.log'
    lumberjack.setLevel(logging.DEBUG)
    fh = logging.FileHandler(logfilename)
    fh.setLevel(std_logging_levels.get(default_file_logging_level, logging.INFO))
    fh.setFormatter(formatter)
    # add the handlers to logger
    lumberjack.addHandler(fh)
    lumberjack.info('REST API CLIENT INIT: running independently, so firing up logging to logfile')
else:
    lumberjack = logging.getLogger('shared-restapiclient')

ch = logging.StreamHandler()
ch.setLevel(std_logging_levels.get(default_console_logging_level, logging.DEBUG))
ch.setFormatter(formatter)
lumberjack.addHandler(ch)

lumberjack.warning('REST API CLIENT INIT: imported and initialized')
