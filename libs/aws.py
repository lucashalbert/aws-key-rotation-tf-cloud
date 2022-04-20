#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Library used interact with the AWS APIs
"""

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

class User:
    """
    AWS User Class to store user related structured data
    """

    def __init__(self, session=None, username=None, logger=None):
        """
        AWS User Class init method

        Method to populate a user object based on the passed username.
        Queries the AWS APIs using helper methods to pull in relevant
        user data.

        :param session: A boto3 Session used to interact with the AWS APIs
            (default is None)
        :type session: boto3.Session
        :param username: The Username to query IAM for
            (default is None)
        :type username: str
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

        if not session:
            raise Exception("Session must be passed to the User class")
        self.session = session

        if not username:
            raise Exception("Username must be passed to the User class")
        
        # Fetch user details from IAM
        user = self._find_user(username)
        
        self.username = user['UserName']
        self.arn = user['Arn']
        self.id = user['UserId']
        self.create_date = user['CreateDate']

        access_keys = []
        for key in self._list_access_keys():

            # Create a UserAccessKey object from the returned list of keys
            access_keys.append(UserAccessKey(
                session = self.session,
                id = key['access_key_id'],
                status = key['status'],
                create_date = key['create_date'],
                logger=self.logger,
            ))

        self.access_keys = access_keys


    @property
    def username(self):
        return self._username
    @username.setter
    def username(self, value):
        self.logger.debug("Setting username value to: {}".format(value))
        self._username = value


    @property
    def id(self):
        return self._id
    @id.setter
    def id(self, value):
        self.logger.debug("Setting id value to: {}".format(value))
        self._id = value


    @property
    def arn(self):
        return self._arn
    @arn.setter
    def arn(self, value):
        self.logger.debug("Setting arn value to: {}".format(value))
        self._arn = value


    @property
    def create_date(self):
        return self._create_date
    @create_date.setter
    def create_date(self, value):
        self.logger.debug("Setting create_date value to: {}".format(value))
        self._create_date = value


    @property
    def access_keys(self):
        return self._access_keys
    @access_keys.setter
    def access_keys(self, value):
        self.logger.debug("Setting access_keys value to: {}".format(value))
        self._access_keys = value
    @access_keys.deleter
    def access_keys(self, value):
        del self._access_keys
    

    def _list_all_users(self):
        """
        Private class method to list all users in AWS account

        :returns: a list of users
        :rtype: list
        """
        users = []
        iam_client = self.session.client('iam')
        try:
            all_users = iam_client.list_users(MaxItems=300)['Users']
        except iam_client.exceptions.ServiceFailureException as err:
            self.logger.critical("An exception occurred while listing users: {}".format(err))
        except Exception as err:
            self.logger.critical("An exception occurred while listing users: {}".format(err))
        except:
            self.logger.critical("An unknown exception occurred while listing users")
        else:
            self.logger.debug("All users have been listed")
            users = all_users
        finally:
            del iam_client
            return users


    def _find_user(cls, username=None):
        """
        Private class method to find a user by username

        :returns: found user details
        :rtype: dictionary
        """
        user_dict = None
        for user in cls._list_all_users():
            if username in user['UserName']:
                cls.logger.debug("Found User: {}".format(username))
                user_dict = user
                break
        
        if user_dict is None:
            self.logger.debug("User '{}' could not be found".format(username))
        return user_dict


    def _list_access_keys(self):
        """
        Private class method to a user's access keys

        :returns: a list of user access key dictionaries
        :rtype: list
        """
        user_access_keys=[]
        iam_client = self.session.client('iam')
        try:
            access_keys = iam_client.list_access_keys(UserName=self.username)
        except iam_client.exceptions.NoSuchEntityException as err:
            self.logger.critical("An exception occurred while listing user access keys: {}".format(err))
        except iam_client.exceptions.ServiceFailureException as err:
            self.logger.critical("An exception occurred while listing user access keys: {}".format(err))
        except Exception as err:
            self.logger.critical("An exception occurred while listing user access keys: {}".format(err))
        except:
            self.logger.critical("An unknown exception occurred while listing user access keys")
        else:
            # Some user may have 2 access keys.
            for key in access_keys['AccessKeyMetadata']:
                key_details={}
                # if (days:=time_diff(keys['CreateDate'])) >= days_filter and keys['Status']==status_filter:
                key_details['username']=key['UserName']
                key_details['access_key_id']=key['AccessKeyId']
                key_details['create_date'] = key['CreateDate']
                key_details['status']=key['Status']
                user_access_keys.append(key_details)
        finally:
            del iam_client
            return user_access_keys
    

    def disable_access_key(self, access_key_id):
        """
        Public class method to disable a given user access key

        :param access_key_id: A specific AccessKey ID
        :type access_key_id: str
        :returns: Whether or not the access key was disabled
        :rtype: bool
        """
        disabled = False
        iam_client = self.session.client("iam")
        try:
            iam_client.update_access_key(
                UserName=self.username,
                AccessKeyId=access_key_id,
                Status="Inactive"
            )
        except iam_client.exceptions.NoSuchEntityException as err:
            self.logger.critical("An exception occurred while disabling user access key '{}': {}".format(access_key_id, err))
        except iam_client.exceptions.LimitExceededException as err:
            self.logger.critical("An exception occurred while disabling user access key '{}': {}".format(access_key_id, err))
        except iam_client.exceptions.ServiceFailureException as err:
            self.logger.critical("An exception occurred while disabling user access key '{}': {}".format(access_key_id, err))
        except Exception as err:
            self.logger.critical("An exception occurred while disabling user access key '{}': {}".format(access_key_id, err))
        except:
            self.logger.critical("An unknown exception occurred while disabling user access key '{}'".format(access_key_id))
        else:
            self.logger.info("Access key '{}' for user {} has been successfully disabled".format(access_key_id, self.username))
            disabled = True
        finally:
            del iam_client
            return disabled
    

    def delete_access_key(self, access_key_id):
        """
        Public class method to delete a given user access key

        :param access_key_id: A specific AccessKey ID
        :type access_key_id: str
        :returns: Whether or not the access key was deleted
        :rtype: bool
        """
        deleted = False
        iam_client = self.session.client('iam')
        try:
            iam_client.delete_access_key(
                UserName=self.username,
                AccessKeyId=access_key_id
            )
        except iam_client.exceptions.NoSuchEntityException as err:
            self.logger.critical("An exception occurred while deleting user access key '{}': {}".format(access_key_id, err))
        except iam_client.exceptions.LimitExceededException as err:
            self.logger.critical("An exception occurred while deleting user access key '{}': {}".format(access_key_id, err))
        except iam_client.exceptions.ServiceFailureException as err:
            self.logger.critical("An exception occurred while deleting user access key '{}': {}".format(access_key_id, err))
        except Exception as err:
            self.logger.critical("An exception occurred while deleting user access key '{}': {}".format(access_key_id, err))
        except:
            self.logger.critical("An unknown exception occurred while deleting user access key '{}'".format(access_key_id))
        else:
            self.logger.info("Access key '{}' for user {} has been successfully deleted".format(access_key_id, self.username))
            deleted = True
        finally:
            del iam_client
            return deleted
    

    def create_access_key(self):
        """
        Public class method to create a new user access key

        :returns: Newly created access key ID
        :rtype: str
        """
        access_key_metadata = None
        new_id = False
        iam_client = self.session.client('iam')
        try:
            access_key_metadata = iam_client.create_access_key(
                UserName=self.username
            )
        except iam_client.exceptions.NoSuchEntityException as err:
            self.logger.critical("An exception occurred while creating new access key: {}".format(err))
        except iam_client.exceptions.LimitExceededException  as err:
            self.logger.critical("An exception occurred while creating new access key: {}".format(err))
        except iam_client.exceptions.ServiceFailureException  as err:
            self.logger.critical("An exception occurred while creating new access key: {}".format(err))
        except Exception as err:
            self.logger.critical("An exception occurred while creating new access key: {}".format(err))
        except:
            self.logger.critical("An unknown exception occurred while creating new access key")
        else:            
            new_key = UserAccessKey(
                session = self.session,
                id = access_key_metadata['AccessKey']['AccessKeyId'],
                secret = access_key_metadata['AccessKey']['SecretAccessKey'],
                status = access_key_metadata['AccessKey']['Status'],
                create_date = access_key_metadata['AccessKey']['CreateDate'],
                logger=self.logger,
            )
            self.access_keys.append(new_key)
            new_id = access_key_metadata['AccessKey']['AccessKeyId']
        finally:
            del iam_client
            return new_id
    


class UserAccessKey:
    """
    AWS UserAccessKey Class to store AccessKey related structured data
    """
    access_keys=[]

    def __init__(self, session=None, id=None, secret=None, status=None, create_date=None, last_used=None, logger=None):
        """
        AWS UserAccessKey Class init method

        Method to populate a UserAccessKey object. Queries the AWS APIs 
        using helper methods to pull in relevant user AccessKey data.

        :param session: A boto3 Session used to interact with the AWS APIs
            (default is None)
        :type session: boto3.Session
        :param id: The AccessKey id
            (default is None)
        :type id: str
        :param secret: The AccessKey secret
            (default is None)
        :type secret: str
        :param status: The AccessKey status (Active/Inactive)
            (default is None)
        :type status: str
        :param create_date: The datetime that the AccessKey was created
            (default is None)
        :type create_date: datetime
        :param last_used: The datetime that the AccessKey was last used
            (default is None)
        :type last_used: datetime
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

        if session:
            self.session = session
        if id:
            self.id = id
        if secret:
            self.secret = secret
        if status:
            self.status = status
        if create_date:
            self.create_date = create_date
        if last_used:
            self.last_used = last_used

        # Get last used Date
        self._last_used()


    @property
    def id(self):
        self.logger.debug("Getting id value")
        return self._id
    @id.setter
    def id(self, value):
        self.logger.debug("Setting id value to: {}".format(value))
        self._id = value


    @property
    def status(self):
        self.logger.debug("Getting status value")
        return self._status
    @status.setter
    def status(self, value):
        self.logger.debug("Setting status value to: {}".format(value))
        self._status = value


    @property
    def secret(self):
        self.logger.debug("Getting secret value")
        return self._secret
    @secret.setter
    def secret(self, value):
        self.logger.debug("Setting secret value to: {}".format(value))
        self._secret = value


    @property
    def create_date(self):
        """The create_date property"""
        self.logger.debug("Getting create_date value")
        return self._create_date
    @create_date.setter
    def create_date(self, value):
        self.logger.debug("Setting create_date value to: {}".format(value))
        self._create_date = value


    @property
    def last_used(self):
        """The last_used property"""
        self.logger.debug("Getting last_used value")
        return self._last_used
    @last_used.setter
    def last_used(self, value):
        self.logger.debug("Setting last_used value to: {}".format(value))
        self._last_used = value


    def _last_used(self):
        """
        Private class method to get the last used datetime for given AccessKey

        :returns: The last_used datetime
        :rtype: datetime
        """
        iam_client = self.session.client("iam")
        try:
            response = iam_client.get_access_key_last_used(
                AccessKeyId=self.id
            )
        except iam_client.Client.exceptions.NoSuchEntityException as err:
            self.logger.critical("An exception occurred while getting access key last used time: {}".format(err))
        except Exception as err:
            self.logger.critical("An exception occurred while getting access key last used time: {}".format(err))
        except:
            self.logger.critical("An unknown exception occurred while getting access key last used time")
        else:
            if 'LastUsedDate' not in response['AccessKeyLastUsed']:
                last_used = "Never"
            else:
                last_used = response['AccessKeyLastUsed']['LastUsedDate']
        finally:
            del iam_client
            self.last_used = last_used



class SSMParameter:
    """
    AWS SSMParameter Class to query data from the SSM Parameter Store
    """
    def __init__(self, session=None, logger=None):
        """
        AWS SSMParameter Class init method

        Method to initialize the SSMParameter Class. Assists in Querying
        the AWS APIs using helper methods to pull in relevant SSM data.

        :param session: A boto3 Session used to interact with the AWS APIs
            (default is None)
        :type session: boto3.Session
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

        if not session:
            raise Exception("A boto session is required by the SSMParamter class")
        self.session = session


    def get_parameter(self, name=None, region=None):
        """
        Public class method to get parameters from SSM Parameter Store

        :param name: The Paramter name/path
        :type name: str
        :param region: The SSM region to query
        :type region: str
        :returns: The parameter value
        :rtype: str if parameter type is string, list if parameter type is StringList
        """
        value = None

        if not region:
            raise Exception("Region is a required parameter")

        ssm_client = self.session.client('ssm',
            region_name=region
        )

        try:
            response = ssm_client.get_parameter(
                Name=name,
                WithDecryption=True
            )
        except ssm_client.exceptions.InternalServerError as err:
            self.logger.critical("An exception occurred while getting parameter: {}".format(err))
        except ssm_client.exceptions.InvalidKeyId as err:
            self.logger.critical("An exception occurred while getting parameter: {}".format(err))
        except ssm_client.exceptions.ParameterNotFound as err:
            self.logger.critical("An exception occurred while getting parameter: {}".format(err))
        except ssm_client.exceptions.ParameterVersionNotFound as err:
            self.logger.critical("An exception occurred while getting parameter: {}".format(err))
        except Exception as err:
            self.logger.critical("An exception occurred while getting parameter: {}".format(err))
        except:
            self.logger.critical("An unknown exception occurred while getting parameter")
        else:
            if response['Parameter']['Type'] == 'StringList':
                value = response['Parameter']['Value'].split(",")
            else:
                value = response['Parameter']['Value']
        finally:
            return value