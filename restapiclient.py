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
from datetime import datetime, timezone
import logging
default_console_logging_level = 'verbose' #'verbose', 'basic', None
default_file_logging_level = 'basic'
##########################################################

import re
import hmac
import base64
import urllib.parse
import urllib.request
import requests
import time
import json
# Azure webapp linux started breaking, couldn't pip install this, taking out for now
# =============================================================================
# from requests_hawk import HawkAuth
# =============================================================================
import pytz
import hashlib
import binascii
# =============================================================================
# from requests_http_signature import HTTPSignatureAuth 
# # not using this yet, but it's interesting, and potentially easier, if we could make this work better:
# # requests.get(url, auth=HTTPSignatureAuth(key=compass_apigee._auth_secret.encode(), key_id=willie.compass_apigee._auth_name, headers=['(request-target)', 'date']))
# =============================================================================

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning) # sigh, bad APIs

#from functools import partial #stopped using this, doing lambda instead

# ENVIRONMENTAL / OVERALL DEFAULTS THAT EXIST OUTSIDE OF API CLIENT CONFIGLOAD
default_log_level = default_console_logging_level  #'verbose', 'basic', None
http_response_codes_do_reauth = [400, 401, 402, 403, 405, 406, 407] #these can all be indicative of permissions issue in various scenarios
#!!!! http_response_codes_do_retry = range(500, 600) # anything 5xx
http_response_codes_do_retry = range(500, 600) # anything 5xx
default_timeout_sec = None
default_retry_sec = 5

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
    auth_bypass = False #this determines if we bypass all that clever auth stuff and just us a library / kwarg / etc.
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
        self.auth_method = self._config['api_auth_info']['authmethod']
        ######### this sets configs from various auth method kwargs ###########
        self._token = kwargs.get('token', None) #I know None is default response to a failed .get() but I specifically want it None so making it explicit
        if kwargs.get('username'): self._apiuser = kwargs.get('username') #!!!! merge with auth_name
        if kwargs.get('password'): self._apipass = kwargs.get('password') #!!!! merge with auth_secret
#        self._sas_key = kwargs.get('auth_secret')
#        self._sas_policyname = kwargs.get('auth_name')
        self._auth_secret = kwargs.get('auth_secret') # for sas, the SAS key. for hawk or signature, the private/secret key.
        self._auth_name = kwargs.get('auth_name') # for sas, the SAS policy name. for hawk or signature, the key ID
        #######################################################################
        self.api_endpoints = self._config['api_endpoints'] # have to have this
        self.api_functions = self._config.get('api_functions', {}) #this is optional
        self.base_url = self._config['api_base_url'] # have to have this
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
        if self.auth_method == 'user_and_pass':
            self._token = self._auth_username()
        elif self.auth_method == 'oauth2':
            self._token = self._auth_oauth2()
        elif self.auth_method == 'sas':
            self._sas_token_ttl = self._config['api_auth_info'][self.auth_method].get('request_token_ttl_seconds', 30)
            self._auth_sig_format_string = 'SharedAccessSignature sr={}&sig={}&se={}'
# =============================================================================
#         elif self.auth_method == 'hawk':
#             self.auth_bypass = True
# =============================================================================
        elif self.auth_method == 'http_signature':
            self._auth_sig_format_string = 'Signature keyId="{}",algorithm="hmac-{}",headers="{}",signature="{}"'
            self._hash_algorithm = self._config['api_auth_info'][self.auth_method].get('hash_algorithm', 'sha256')
            self._timestamp_format = self._config['api_auth_info'][self.auth_method].get('timestamp_format', 'iso8601')
# =============================================================================
#         elif self.auth_method in ['token', None]: #not really needed
#             pass
# =============================================================================
# =============================================================================
#         return self._token #no need to return this
# =============================================================================
    def token(self, *args, **kwargs):
        if self.auth_method == 'sas':
            lumberjack.debug('SAS token request: args: %s, kwargs: %s', args, kwargs)
            return self._get_sas_token(*args, **kwargs)
        elif self.auth_method == 'http_signature':
            lumberjack.debug('Signature token request: args: %s, kwargs: %s', args, kwargs)
            return self._get_signature_token(*args, **kwargs)
        elif self.auth_method in ['oauth2', 'user_and_pass', 'token', None, 'hawk']:
            return self._token
        else:
            lumberjack.error('YO! ERROR! self.auth_method is whack. Should be in ["sas", "http_signature", "hawk", "user_and_pass", "token", None]')
            raise NotImplementedError
    def auth_bypass_func(self, *args, **kwargs):
        if self.auth_method == 'hawk':
# =============================================================================
#             return HawkAuth(id=self._auth_name, key=self._auth_secret)
# =============================================================================
            return None
    def _auth_username(self):
        pass_authcreds_via = self._config['api_auth_info'][self.auth_method].get('authcreds_passed_in', 'data')
        user_field_name = self._config['api_auth_info'][self.auth_method]['authcreds_username_key']
        pass_field_name = self._config['api_auth_info'][self.auth_method]['authcreds_password_key']
        req_data = {}
        req_headers = self.base_headers.copy()
        url = self._config['api_auth_info'][self.auth_method]['authenticate_url']
        method = self._config['api_auth_info'][self.auth_method]['authenticate_http_method']
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
        pass_authcreds_via = self._config['api_auth_info'][self.auth_method].get('authcreds_passed_in', 'headers')
        req_data = {'grant_type': 'client_credentials'} #this is standard oauth2 basic auth stuff
        req_headers = self.base_headers.copy()
        url = self._config['api_auth_info'][self.auth_method]['authenticate_url']
        method = self._config['api_auth_info'][self.auth_method]['authenticate_http_method']
        if pass_authcreds_via == 'data':
            req_data['client_id'] = self._apiuser
            req_data['client_secret'] = self._apipass
        elif pass_authcreds_via == 'headers':
            header_key = 'Authorization' #!!!! this should to be changed to support a configured header name
            header_val = 'Basic {}' #!!!! maybe more than basic later
            auth_bytes = b':'.join([self._apiuser.encode('latin1', errors='ignore'), self._apipass.encode('latin1', errors='ignore')])
            auth_str = base64.b64encode(auth_bytes).strip().decode(errors='ignore') #!!!! note: use urlsafe_b64encode?
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
        if self._config['api_auth_info'][self.auth_method].get('authenticate_http_response_format', 'json') == 'json':
            resp = resp.json()
        else:
            resp = resp.text
        lumberjack.debug('after decoding, response is now: %s', resp)
        if self._config['api_auth_info'][self.auth_method].get('authenticate_response_parse', True):
            parsefunc = self._config['api_auth_info'][self.auth_method]['authenticate_response_parse_function']
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
            * timeout

            * others (doc!!) #!!!!
            
        _request('delete',
                 'https://tempsrpt-iothub-poc.azure-devices.net/devices/cpltest',
                  headers={'User-Agent': 'python-requests/2.21.0', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive', 'If-Match': '*', 'Authorization': 'SharedAccessSignature sr=tempsrpt-iothub-poc.azure-devices.net&sig=fEkIvv5sTigUMdBzjckQwIzf9MivIigbcJRH9s8cfAk%3D&se=1550694866&skn=manageDevices', 'Content-Type': 'application/json', 'Content-Length': '0'},
                  params={'api-version': '2018-06-30'},
                  )
        '''
        lumberjack.debug('request kwargs: %s', kwargs)
        testkwargs = [k for k in kwargs]
        for k in testkwargs:
            if kwargs.get(k) == None:
                kwargs.pop(k)
        lumberjack.debug('request kwargs after clearing empties: %s', kwargs)
        try:
            return requests.request(req_method, req_url, **kwargs)
        except (requests.Timeout) as oops:
            lumberjack.exception('TIMEOUT ON REQUEST! %s', oops)
        except (requests.RequestException) as oopser:
            lumberjack.exception('SOME UNKNOWN REQUEST THING! %s', oopser)

    def _handler_call_api(self, req_method, req_url, **kwargs):
        '''
        KWARGS:
            * ignore_cert_errors (bool=False): ignore SSL cert errors
            * timeout
            * retry_interval
            
            * headers
            * data
            * params
        '''
        requestlib_kwargs = {}
        req_data = kwargs.get('data', {})
        req_headers = kwargs.get('headers', {})
        req_params = kwargs.get('params', {})
        verify_ssl = kwargs.pop('ignore_cert_errors', False) != True

        if self.auth_method == 'http_signature':
            req_headers['Digest'] = self._get_message_digest(req_data)
            req_headers['Date'] = self._sig_sign_timestamp()
            if not kwargs.get('headers'): #this ensures that even if headers wasn't a kwarg, now it is
                kwargs['headers'] = req_headers
        
        timeout = kwargs['timeout'] if kwargs.get('timeout') else default_timeout_sec
        retry_interval = kwargs['retry_interval'] if 'retry_interval' in kwargs else default_retry_sec

        if timeout and type(timeout) in [float, tuple, int]:
            requestlib_kwargs['timeout'] = timeout
        if self.auth_bypass:
            requestlib_kwargs['auth'] = self.auth_bypass_func(**kwargs)
        else:
            reqtoken = self.token(url=req_url, method=req_method, **kwargs)
            lumberjack.debug('reqtoken: %s', reqtoken)
            lumberjack.debug('headers before token %s', req_headers)
            if reqtoken:
                if self._config.get('api_auth_info', {}).get(self.auth_method, {}).get('request_token_passed_in', 'headers') == 'headers':
                    req_headers[self._config['api_auth_info'][self.auth_method]['request_token_name']] = reqtoken
                else:
                    req_data[self._config['api_auth_info'][self.auth_method]['request_token_name']] = reqtoken
        
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
        lumberjack.debug('requestlib_kwargs: %s', requestlib_kwargs)
        respobj = self._request(req_method,
                                req_url,
                                headers=all_headers if all_headers else None,
                                json=req_data if req_data else None,
                                params=all_params if all_params else None,
                                verify=verify_ssl,
                                **requestlib_kwargs)
        if not type(respobj) == requests.models.Response:
            lumberjack.warning('NO RESPONSE! TIMEOUT LIKELY')
            lumberjack.warning('NO RESPONSE! respobj type: %s, dir: %s', type(respobj), dir(respobj))
            return {'response': False, 'status_code': None}
        else:
            lumberjack.info('RESPONSE! status code: %s', respobj.status_code)
            if respobj.status_code in http_response_codes_do_reauth:
                lumberjack.warn('OOPS, got HTTP response code: %s, with headers: %s, content as text: %s',
                                respobj.status_code, respobj.headers, respobj.text)
                lumberjack.warn('WILL REGEN AUTH TOKEN AND RETRY ONCE')
                if self.auth_bypass:
                    requestlib_kwargs['auth'] = self.auth_bypass_func(**kwargs)
                else:
                    self._gen_auth_token()
                    reqtoken = self.token(url=req_url, **kwargs)
                    lumberjack.warn('NEW AUTH TOKEN: %s', reqtoken)
                    all_headers[self._config['api_auth_info'][self.auth_method]['request_token_name']] = reqtoken
                    lumberjack.warn('NEW REQ HEADERS: %s', all_headers)
                    respobj = self._request(req_method,
                                            req_url,
                                            headers=all_headers if all_headers else None,
                                            json=req_data if req_data else None,
                                            params=all_params if all_params else None,
                                            verify=verify_ssl,
                                            **requestlib_kwargs)
                    lumberjack.warn('RESPONSE TO RETRY! status code: %s', respobj.status_code)
                    lumberjack.debug('RETRY RESPONSE CONTENT as text: %s', respobj.text)
    #        if respobj and respobj.status_code in http_response_codes_do_retry and retry_interval:
            if respobj.status_code in http_response_codes_do_retry and retry_interval:
                lumberjack.error('AACK, got HTTP response code: %s, with headers: %s, content as text: %s',
                                respobj.status_code, respobj.headers, respobj.text)
                lumberjack.warn('WILL WAIT 5 SEC AND RETRY ONCE')
                time.sleep(retry_interval)
                respobj = self._request(req_method,
                                        req_url,
                                        headers=all_headers if all_headers else None,
                                        json=req_data if req_data else None,
                                        params=all_params if all_params else None,
                                        verify=verify_ssl,
                                        **requestlib_kwargs)
                lumberjack.warn('RESPONSE TO RETRY! status code: %s', respobj.status_code)
                lumberjack.debug('RETRY RESPONSE CONTENT as text: %s', respobj.text)
            lumberjack.debug('response headers: %s', respobj.headers)
            lumberjack.debug('request url from respobj: %s', respobj.request.url)
            lumberjack.debug('request headers from respobj: %s', respobj.request.headers)
            lumberjack.debug('request body from respobj: %s', respobj.request.body)
            lumberjack.debug('reponse object: %s', dir(respobj))
            lumberjack.debug('response status code: %s', respobj.status_code)
    #        lumberjack.debug('responseobj request body: %s', respobj.request.body)            
    #        lumberjack.debug('response content as bytes: %s', respobj.content) #this is way too much for debug logs
    #        lumberjack.debug('response content as text: %s', respobj.text) #this is way too much for debug logs
            lumberjack.debug('response content length: %s', len(respobj.content))
            lumberjack.debug('response encoding: %s', respobj.encoding)
            if respobj.headers.get('Content-Length') == '0':
                return {'response': True, 'status_code': respobj.status_code, 'headers': respobj.headers}
            elif 'application/json' in respobj.headers.get('Content-Type', '').lower(): #.lower() because sigh
#                lumberjack.debug('response json: %s', respobj.json()) #this is way too much for debug logs
                return respobj.json()
            else:
                return respobj.text
# =============================================================================
# # removed, dynamic now
#         if self.api_response_format == 'json':
#             lumberjack.debug('response json: %s', respobj.json())
#             respobj=respobj.json()
#         else:
#             respobj=respobj.text
#         return respobj
# =============================================================================

    def _call_api_by_endpoint(self, endpoint, req_method='get', **kwargs):
        '''(str,kwargs)->objects
        returns the data of the response object for the api function matching the input string, using
        the method specified (or 'get' if no method is specified). kwargs can customize the request.
        
        Supported kwargs:
            * headers(dict): kv pairs to be passed as HTTP request headers
            * data(dict): kv pairs to be passed as part of an HTTP POST
            * params(dict): kv pairs to be passed as parameters in the URL
            * dynamic_endpoint_suffix(str): string to add to end of endpoint URL
                (after baseurl+endpoint+function_suffix). This is often used
                to reference a particular device in a collection by a unique ID.
            * ignore_cert_errors (bool=False): ignore SSL cert errors
            * timeout
            * retry_interval
            
        >>>slack_client._call_api_by_endpoint('#dev_cl_slackbot', 'post', data={"text": 'testing slack webhook'})

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
            * headers(dict): kv pairs to be passed as HTTP request headers
            * data(dict): kv pairs to be passed as part of an HTTP POST
            * params(dict): kv pairs to be passed as parameters in the URL
            * dynamic_endpoint_suffix(str): string to add to end of endpoint URL
                (after baseurl+endpoint+function_suffix). This is often used
                to reference a particular device in a collection by a unique ID.
            * ignore_cert_errors (bool=False): ignore SSL cert errors
            * timeout
            * retry_interval

        >>>cm.mq_client._call_api_by_function('get_devices', dynamic_endpoint_suffix='/'+'4883C7DF30081306')
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
        h = hmac.new(base64.urlsafe_b64decode(self._auth_secret),
                    msg = "{0}\n{1}".format(url_to_sign_encoded, timestamp).encode('utf-8'),
                    digestmod = 'sha256')
        _sas = self._auth_sig_format_string.format(
                url_to_sign_encoded,
                urllib.parse.quote(base64.b64encode(h.digest()), safe = ''), #!!!! note: use urlsafe_b64encode?
                timestamp)
        lumberjack.debug('sas-y string: %s', _sas)
        _sas = _sas + '&skn=' + self._auth_name if self._auth_name else _sas
        lumberjack.debug('sas-y-er result: %s', _sas)
        return _sas

    def _sig_sign_url_format_func(self, url_str):
        '''(str)->str
        Returns the URI for inserting into signature data for the given URL
        >>>_sig_sign_url_format_func('https://foo.bar.com/what/idk?things=stuff')
        '/what/idk?things=stuff'
        '''
        uri = re.sub('^https?://[^/]+/', '/', url_str)
#        uri = uri.split('?')[0] #!!!! Not sure if this should strip query params or not, prob should, but no api logic to test against right now, figure out later
        return uri

    def _sig_sign_timestamp(self):
        '''(str)->str
        Returns a string representing the string to sign (sr) for a given request URL.
        >>>_sig_sign_timestamp('https://foo.bar.com/what/idk?things=stuff')
        '/what/idk?things=stuff'
#        '/what/idk'
        '''
        if self._config.get('somedamntimezonethingineedtodo', 'GMT') == 'UTC': #!!!!
            use_tz = timezone.utc
        elif self._config.get('somedamntimezonethingineedtodo', 'GMT') == 'GMT': #!!!!
            use_tz = pytz.timezone('GMT')
        
        if self._timestamp_format == 'rfc2822':
            return datetime.now(use_tz).strftime('%a, %d %b %Y %H:%M:%S %Z')
        elif self._timestamp_format == 'iso8601':
            return datetime.now(timezone.utc).isoformat()

    def _get_message_digest(self, data={}):
        '''(dict)->str
        Returns a message digest for the given data set
        
        '''
        data = json.dumps(data) if data else ''
        data_hash = self.hash_algorithm(data.encode('utf-8'))
        data_hash_b64 = base64.b64encode(data_hash.digest()) # don't need urlsafe because not going to be put directly into html
        algstr = 'sha' if 'sha' in self._hash_algorithm else 'rsa'
        hashname = '{}-{}'.format(algstr, self._hash_algorithm.replace(algstr, ''))
        digest_str = '{}={}'.format(hashname, data_hash_b64.decode('utf-8'))
        lumberjack.debug('data: %s, data hash: %s, data hash b64 encoded: %s, digest string: %s',
                         data, binascii.hexlify(data_hash.digest()), data_hash_b64, digest_str)
        return digest_str

    @property
    def hash_algorithm(self):
        if self._hash_algorithm == 'sha256':
            return hashlib.sha256
        elif self._hash_algorithm == 'sha512':
            return hashlib.sha512
        elif self._hash_algorithm == 'sha1':
            return hashlib.sha1
        elif self._hash_algorithm == 'sha384':
            return hashlib.sha384

    def _get_signature_token(self, *args, **kwargs): #!!!! edit for http sig scheme logic
        '''(kwargs)->str
        Returns an HTTP signature token for the given URL provided by kwarg 'url' based on info
        in the headers kwarg (Date and Digest)
        
        >>>_get_signature_token(url='foo')
        'foo'

        KWARGS REQUIRED:
            url (str='/')
            method (str='get')
            headers (dict with Date and Digest)
            
        KWARGS SUPPORTED:
            headers (dict)
            params (dict)
            data (dict)
        '''
        headers = kwargs.get('headers', {}) # need this because some of the signature action comes with it
        lumberjack.debug('incoming headers: %s', headers)        
        header_list = ['(request-target)', 'date', 'digest'] #!!!! next: make this settable, fields & order
        header_names = ' '.join(header_list)
        method = kwargs.get('method', 'get')
        target_url = kwargs.get('url', '/') #!!!! may have to put params into this, will test when I have a test API to hit
        uri = self._sig_sign_url_format_func(target_url)
#        params = kwargs.get('params', {}) #these could be worked into URL, figure out later once have API to test against
        dtstr = headers.get('Date', self._sig_sign_timestamp())
        digest_str = headers.get('Digest', self._get_message_digest(kwargs.get('data', {})))
        headdict = {
                '(request-target)': method.lower() + ' ' + uri.lower(),
                'date': dtstr,
                'digest': digest_str,
                }
        sig_base = '\n'.join(['{}: {}'.format(k, headdict[k]) for k in header_list])
        lumberjack.debug('sign_base: %s', sig_base)
        h = hmac.new(self._auth_secret.encode('utf-8'),
                     msg=sig_base.encode('utf-8'),
                     digestmod=self._hash_algorithm,
                     )
        # populating: 'Signature keyId="{}",algorithm="hmac-{}",headers="{}",signature="{}"'
        sigtoken = self._auth_sig_format_string.format(
                self._auth_name,
                self._hash_algorithm,
                header_names,
#                urllib.parse.quote(base64.b64encode(h.digest()), safe = ''), #probably the way to go?
                base64.b64encode(h.digest()).decode('utf-8'), # no messing about but would maybe break HTTP request. But it works, figure out this vs #1
#                base64.urlsafe_b64encode(h.digest()).decode('utf-8'), # encoding is safe but changes stuff
                )
        lumberjack.debug('a buffet of encoding choices! basic b64: %s, urlsafe b64: %s, urllib parsed b64: %s',
                         base64.b64encode(h.digest()).decode('utf-8'),
                         base64.urlsafe_b64encode(h.digest()).decode('utf-8'),
                         urllib.parse.quote(base64.b64encode(h.digest()), safe = ''))
        lumberjack.debug('http sig token: %s', sigtoken)
        return sigtoken

#%%
std_logging_levels = {
        'verbose': logging.DEBUG,
        'basic': logging.INFO,
        None: logging.ERROR
        }

appname = 'restapiclient'

console_log_level = std_logging_levels.get(default_console_logging_level, logging.DEBUG)
file_log_level = std_logging_levels.get(default_file_logging_level, logging.INFO)
not_disabled = [l for l in [console_log_level, file_log_level, logging.WARN] if l > 0] #forces logging to WARN if no handlers have loglevels

formatter = logging.Formatter('%(asctime)s %(levelname)s: %(name)s / %(funcName)s(%(lineno)s) %(message)s')

lumberjack = logging.getLogger(appname)

loglevel_overall = min(not_disabled)  # NOTE!! this acts like a cutoff for handler logging,
lumberjack.setLevel(loglevel_overall) # so this has to be set to the highest loglevel of
                                      # any of the handlers in order to honor those settings

if __name__ == '__main__':
    lumberjack.info('REST API CLIENT INIT: running independently, so firing up logfile handler')
    logdir = './logs'
    os.makedirs(logdir, exist_ok=True)
    logdatetimestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    logfilename = logdir + '/' + appname + logdatetimestamp + '-' + '.log'

    lj_file_handlers = [h for h in lumberjack.handlers if h.name == appname and type(h) in [logging.FileHandler]]
    if not lj_file_handlers:
        fh = logging.FileHandler(logfilename)
        fh.setLevel(file_log_level)
        fh.setFormatter(formatter)
        fh.name = appname
        lumberjack.addHandler(fh)
        lumberjack.info('Added file handler to Lumberjack.')
    else:
        fh = lj_file_handlers[0]
        lumberjack.warning('Lumberjack has a file handler already, not adding another')

lj_console_handlers = [h for h in lumberjack.handlers if h.name == appname and type(h) == logging.StreamHandler]
if not lj_console_handlers:
    ch = logging.StreamHandler()
    ch.setLevel(console_log_level)
    ch.name = appname
    ch.setFormatter(formatter)
    lumberjack.addHandler(ch)
    lumberjack.info('Added console handler to Lumberjack.')
else:
    ch = lj_console_handlers[0]
    lumberjack.warning('Lumberjack has a console handler already, not adding another')
lumberjack.warning('DONE WITH INIT OF LOGGING STREAM HANDLER, level: %s', console_log_level)

lumberjack.info('REST API CLIENT INIT: imported and initialized')
