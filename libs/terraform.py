#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Library used to interact with the Terraform APIs
"""

import json
from botocore.vendored import requests      # Required to run in Lambda
import logging
import sys

__author__ = "Lucas Halbert"
__copyright__ = "Copyright 2022, www.lhalbert.xyz"
__credits__ = ["Lucas Halbert"]
__license__ = "BSD 3-Clause License"
__version__ = "0.0.1"
__maintainer__ = "Lucas Halbert"
__email__ = "contactme@lhalbert.xyz"
__status__ = "Development"
__date__ = "04/18/2022"

class VariableSetAPI:
    """
    Terraform VariableSetAPI Class to assist in querying TF APIs
    """

    _base_uri = 'https://app.terraform.io/api/v2'
    
    def __init__(self, token=None, varset_id=None, logger=None):
        """
        Terraform VariableSetAPI Class init method

        Method to initialize the VariableSetAPI Class. Assists in Querying
        the Terraform VariableSet APIs.

        :param token: The organization token used to authenticate with the API
            (default is None)
        :type token: str
        :param varset_id: The Variable Set ID to target
            (default is None)
        :type varset_id: str
        :param logger: A logger session
            (default is None)
        :type logger: logging.RootLogger
        """
        if logger:
            self.logger = logger
        else:
            # Initialize logging
            self.logger = logging.getLogger()
            self.logger.setLevel(logging.INFO)

            # Log to Stdout
            streamHandler = logging.StreamHandler(sys.stdout)
            self.logger.addHandler(streamHandler)

        # Ensure token has been provided
        if not token:
            raise Exception("An API Token is required.")
        
        # Ensure varset_id has been provided
        if not varset_id:
            raise Exception("A varset_id is required.")
        
        self._token = token
        self._varset_id = varset_id
        self.session = requests.Session()
        self.session.headers.update(self._generate_header(self._token))


    @property
    def varset_id(self):
        return self._varset_id


    @staticmethod
    def _generate_header(token):
        """
        Protect staticmethod to generate request header

        :param token: The organization token used to authenticate with the API
        :type name: str
        :returns: The generated requests header
        :rtype: dict
        """
        return {
            "Authorization": "Bearer {}".format(token),
            "Content-Type": "application/vnd.api+json",
        }


    def find_varset_var_id_by_name(self, var_name=None):
        """
        Public method to find variable ID by name

        :param var_name: The name of the variable to find
            (default is None)
        :type name: str
        :returns: The found variable ID
        :rtype: str
        """
        if not var_name:
            raise Exception("A variable name must be passed to this method")

        var_id = None
        uri = self._base_uri + '/varsets/' + self._varset_id + '/relationships/vars'

        try:
            response = self.session.get(
                uri,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            self.logger.Critical("An exception occurred while finding varset variable ID by name: {}".format(err))
        except Exception as err:
            self.logger.Critical("An exception occurred while finding varset variable ID by name: {}".format(err))
        except:
            self.logger.Critical("An unknown exception occurred while finding varset variable ID by name.")
        else:
            # Find var ID by name
            for i in response.json()['data']:
                if i['attributes']['key'] == var_name:
                    var_id = i['id']
        finally:
            return var_id


    def patch_varset_variable(self, var_id=None, value=None, sensitive=True):
        """
        Public method to update variable set variable

        :param var_id: The variable ID to update
        :type name: str
        :param value: The value to update the variable to
            (default is None)
        :type value: str
            (default is None)
        :param sensitive: Whether or not the variable is sensitive
        :type sensitive: str
            (default is True)
        :returns: Whether or not the variable was successfully updated
        :rtype: bool
        """
        updated = False
        
        if not var_id:
            raise Exception("A variable ID is required")
        
        if not value:
            raise Exception("An variable value must be provided")
        
        uri = self._base_uri + '/varsets/' + self._varset_id + '/relationships/vars/' + var_id
        
        # generate Payload
        payload = {
            "data": {
                "type": "vars",
                "attributes": {
                    "value": value,
                }
            }
        }
       
        try:
            response = self.session.patch(
                uri,
                data=json.dumps(payload)
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            self.logger.Critical("An exception occurred while patching the varset variable: {}".format(err))
        except Exception as err:
            self.logger.Critical("An exception occurred while patching the varset variable: {}".format(err))
        except:
            self.logger.Critical("An unknown exception occurred while patching the varset variable.")
        else:
            if response.status_code == 200:
                updated = True
            else:
                self.logger.warn("Response code other than 200 returned: {}".format(response.json()))
                raise Exception("Response code other than 200 returned: {}".format(response.json()))
        finally:
            return updated