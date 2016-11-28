# import the logging library
import logging
import json
from django.utils.encoding import force_text
from rest_framework import serializers, viewsets

from django.http import HttpResponseRedirect

from rest_framework.response import Response
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework import status
from ioteca_service_apps.utils.security import log_params

# Get an instance of a logger
log = logging.getLogger(__name__)


import socket
import re
#import requests
import webbrowser
import urllib
#import urlparse
import uuid
import base64


defaultResponseHeaders = 'Cache-Control: no-cache, no-store, must-revalidate\n' +\
    'Pragma: no-cache\n' +\
    'Expires: 0\n'

sessionMap = {}
clientId = '1mDR3zdKmNxeMHoqSJfOfX4JBwSvw93zRK2GaZ61'
clientSecret = 'dYdgBysUnR4hr3JpREHPyVsUnVw42uGgyIoc3ThsYI1pQOhKuGNhIuYe2Oc0ClPSNMhR3WFEO33uaISItfigJLPkAh22JpBkBABOQbaQuhhnTDBKVmNnEfTm6q2km3u4'
redirectUri = 'http://localhost:9000/api/auths/callback/'


def checkSession(path):
    # Parse URL and querystring
    url = urlparse.urlparse(path)
    qs = urlparse.parse_qs(url.query)

    # Look for existing session
    sessionKey = ''
    sessionKeyArray = qs.get('sessionKey')
    if sessionKeyArray is not None:
        sessionKey = sessionKeyArray[0]

    if sessionKey != '':
        # Return existing session
        session = sessionMap.get(sessionKey)

        # Log session key if session is found
        if session is not None:
            print ('Session key: ' + sessionKey)
        else:
            print ('Invalid session key encountered!')

        # Will return the session or None of session key wasn't found
        return session
    elif qs.get('code') is not None:
        # No session, but have an oauth code. Create a session
        accessToken = getTokenFromCode(qs.get('code'))

        # Check token
        if accessToken is None:
            return None

        # Create session object
        sessionKey = str(uuid.uuid4())
        session = {
            'access_token': accessToken,
            'session_key': sessionKey
        }
        sessionMap[sessionKey] = session

        # Return new session
        return session
    else:
        # Didn't find a session key or an oauth code
        return None


def getTokenFromCode(code):
    # Prepare for POST /oauth/token request
    requestHeaders = {
        'Authorization': 'Basic ' + base64.b64encode(clientId + ':' + clientSecret),
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    requestBody = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirectUri
    }

    # Get token
    # response = requests.post(
    #    'https://login.mypurecloud.com/oauth/token', data=requestBody, headers=requestHeaders)

    # Check response
    if response.status_code == 200:
        responseJson = response.json()
        return responseJson['access_token']
    else:
        print ('Failure: ' + str(response.status_code) + ' - ' + response.reason)
        return None


class LoginView(APIView):
    """
    View to list routers of menu.
    """

    def get(self, request, format=None):
        """

        """

        requestBody = {
            'grant_type': 'authorization_code',
            'client_id': '1mDR3zdKmNxeMHoqSJfOfX4JBwSvw93zRK2GaZ61',
            'client_secret': 'dYdgBysUnR4hr3JpREHPyVsUnVw42uGgyIoc3ThsYI1pQOhKuGNhIuYe2Oc0ClPSNMhR3WFEO33uaISItfigJLPkAh22JpBkBABOQbaQuhhnTDBKVmNnEfTm6q2km3u4',
            'code': self.request.GET.get('code'),
            'redirect_uri': redirectUri
        }

        return Response('bRNjmocTta9NUqTZzdjy')
