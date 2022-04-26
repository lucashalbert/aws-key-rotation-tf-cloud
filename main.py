#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script used rotate AWS service account API keys, and
to update terraform Variable Set variables.
"""

__author__ = "Lucas Halbert"
__copyright__ = "Copyright 2022, www.lhalbert.xyz"
__credits__ = ["Lucas Halbert"]
__license__ = "BSD 3-Clause License"
__version__ = "0.0.1"
__maintainer__ = "Lucas Halbert"
__email__ = "contactme@lhalbert.xyz"
__status__ = "Development"
__date__ = "04/19/2022"

import boto3
import botocore
from botocore.exceptions import ClientError
from boto3.session import Session
from typing import Tuple
import datetime
import json
import os
import sys
import logging
from libs.aws import User,UserAccessKey,SSMParameter
from libs.terraform import VariableSetAPI

################################################
### --- Default configuration parameters --- ###
################################################
# Default Account to check for access keys needing rotation
aws_user = 'restricted_service_account_user'

# Default ARN of role to assume
role_arn =  'arn:aws:iam::123456789012:role/RoleName'

# Default Session Name
session_name = "DefaultSessionName"

# Default Desired Key Age
desired_key_age = 30

# Default Desired Key Resoltuion
desired_key_resolution = "days"      # One of the following; ['microseconds', 'seconds', 'days']

# Default SSM Region
ssm_param_region = "us-east-1"

# Default Terraform Organization Token SSM path
ssm_tf_org_token_path = "/TerraformCloud/OrganizationToken"

# Default Terraform Variable Set ID SSM path
ssm_tf_varset_id_path = "/TerraformCloud/VarsetID"

# Dictionary of terraform variable set variable names
terraform_variable_names = [
    {
        "key": "AWS_ACCESS_KEY_ID",
        "sensitive": False
    },
    {
        "key": "AWS_SECRET_ACCESS_KEY",
        "sensitive": True
    }
]


# Initialize logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Test event JSON
event = {
    "version": "0",
    "id": "53dc4d37-cffa-4f76-80c9-8b7d4a4d2eaa",
    "detail-type": "Scheduled Event",
    "source": "aws.events",
    "account": "123456789012",
    "time": "2015-10-08T16:53:06Z",
    "region": "us-east-1",
    "resources": [
        "arn:aws:events:us-east-1:123456789012:rule/my-scheduled-rule"
    ],
    "detail": {}
}
context = "a context"


def assumed_role_session(role_arn: str, session_name: str = None, base_session: botocore.session.Session = None):
    """
    Performs a role assumption and returns a boto3 session

    Function to calculate the difference in time between the
    passed 'time' variable and 'now()' with a configurable
    resolution.

    :param role_arn: The Amazon Resource Name (ARN) of the role to assume
    :type role_arn: str
    :param session_name: An identifier for the assumed role session
        (default is None)
    :type session_name: str
    :param base_session: a pre-existing botocore session
        (default is None)
    :type base_session: botocore.session.Session
    :returns: an assumed role session
    :rtype: boto3.Session
    """

    base_session = base_session or boto3.session.Session()._session
    fetcher = botocore.credentials.AssumeRoleCredentialFetcher(
        client_creator = base_session.create_client,
        source_credentials = base_session.get_credentials(),
        role_arn = role_arn,
        extra_args = {
            'RoleSessionName': session_name
        }
    )
    creds = botocore.credentials.DeferredRefreshableCredentials(
        method = 'assume-role',
        refresh_using = fetcher.fetch_credentials,

    )
    botocore_session = botocore.session.Session()
    botocore_session._credentials = creds
    return boto3.Session(botocore_session = botocore_session)


def time_diff(time=None, resolution="days"):
    """
    Calculates difference in between 'time' and 'now()'

    Function to calculate the difference in time between the
    passed 'time' variable and 'now()' with a configurable
    resolution.

    :param time: a datetime object less than 'now()'
        (default is None)
    :type time: datetime object
    :param resolution: a string denoting resolution period
        (default is "days") - must be one of the following: ['microseconds', 'seconds', 'days']
    :type resolution: str
    :returns: time difference
    :rtype: int
    """

    # Verify that a None/null time has not been passed
    if time is None:
        raise Exception("'time' can't be 'None'")

    # Ensure a valid resolution has been specified
    if resolution not in ['microseconds', 'seconds', 'days']:
        raise Exception("'resolution' must be one of the following: ['microseconds', 'seconds', 'days']")

    # Get now in UTC
    now = datetime.datetime.now(datetime.timezone.utc)

    # Calculate the time difference
    diff = now-time

    # Verify that the time difference is positive (aka not in the future)
    if diff.total_seconds() < 0:
        raise Exception("'time' must be in the past")

    # Return the time differential in the given resolution
    return getattr(diff, resolution)


def key_needs_rotation(key: UserAccessKey) -> Tuple[bool, int]:
    """
    Checks if the passed UserAccessKey requires rotation
    
    Function to determine if the UserAccessKey requires
    rotation based on age of the access key.

    :param key: The key to check
    :type key: UserAccessKey object
    :returns: (bool, key_age)
        (True, key_age) if key needs rotation
        (False, key_age) if key does not need rotations
    :rtype: Tuple(bool, int)
    """

    needs_rotation = None
    key_age = None

    # Get age of key
    try:
        key_age = time_diff(
            time=key.create_date,
            resolution=desired_key_resolution
        )
    except Exception as err:
        logger.critical("An exception occurred while checking if key needs rotation: {}".format(err))
    except:
        logger.critical("An unknown exception occurred while checking if key needs rotation.")
    else:
        if key_age >= desired_key_age and key.status == "Active":
            needs_rotation = True
    finally:
        return needs_rotation, key_age


def parse_env_vars():
    """
    Function to parse environment variables for configuration
    parameters
    """

    # Account to check for access keys needing rotation
    if os.environ.get("AWS_USER"):
        global aws_user
        aws_user = os.environ.get("AWS_USER")

    # ARN of role to assume
    if os.environ.get("ROLE_ARN"):
        global role_arn
        role_arn = os.environ.get("ROLE_ARN")

    # Session Name
    if os.environ.get("SESSION_NAME"):
        global session_name
        session_name = os.environ.get("SESSION_NAME")

    # Desired Key Age
    if os.environ.get("DESIRED_KEY_AGE"):
        global desired_key_age
        desired_key_age = int(os.environ.get("DESIRED_KEY_AGE"))

    # Desired Key Resolution
    if os.environ.get("DESIRED_KEY_RESOLUTION"):
        global desired_key_resolution
        desired_key_resolution = os.environ.get("DESIRED_KEY_RESOLUTION")

    # SSM Region
    if os.environ.get("SSM_PARAM_REGION"):
        global ssm_param_region
        ssm_param_region = os.environ.get("SSM_PARAM_REGION")

    # Terraform Organization Token SSM path
    if os.environ.get("SSM_TF_ORG_TOKEN_PATH"):
        global ssm_tf_org_token_path
        ssm_tf_org_token_path = os.environ.get("SSM_TF_ORG_TOKEN_PATH")

    # Terraform Variable Set ID SSM path
    if os.environ.get("SSM_TF_VARSET_ID_PATH"):
        global ssm_tf_varset_id_path
        ssm_tf_varset_id_path = os.environ.get("SSM_TF_VARSET_ID_PATH")


# Main Entrypoint
def main():
    """
    Main entrypoint
    """

    # Parse environment variables for configuration parameters
    parse_env_vars()

    # Perform role assumption
    session = assumed_role_session(role_arn=role_arn, session_name=session_name)

    # Create a new User object
    user = User(session=session,
        username=aws_user,
        logger=logger
    )

    logger.debug("---------   User Info   ---------")
    logger.debug(user.__dict__)

    logger.debug("---- User Access Keys ----")
    
    # Loop through all user object access keys
    for idx, key in enumerate(user.access_keys):
        logger.debug(key.__dict__)

        key_age = None
    
        # Check if key needs rotation
        needs_rotation, key_age = key_needs_rotation(key)
        
        if not needs_rotation:
            logger.info("AccessKey '{}'({}) for user '{}' is {} {} old and does not need rotating...".format(key.id, key.status, user.username, key_age, desired_key_resolution))
            continue

        logger.info("AccessKey '{}'({}) for user '{}' is {} {} old and needs rotating...".format(key.id, key.status, user.username, key_age, desired_key_resolution))
            
        if key.status == "Active":
            # Disable access key
            if user.disable_access_key(key.id):                
                key.status = "Inactive"
            else:
                logger.warning("Failed to disable UserAccessKey '{}'".format(key.id)) 

        if key.status == "Inactive":
            # Delete access key
            if not user.delete_access_key(key.id):
                logger.warning("Failed to delete UserAccessKey '{}'".format(key.id))
                break
        
            # Pop old access key from list
            user.access_keys.pop(idx)
            
            # Create new Access Key
            new_key_id = user.create_access_key()
            
            # If no new key created, break out of for loop
            if not new_key_id:
                logger.warning("Failed to create a new AccessKey.")
                break

            # Query SSM for Terraform Cloud Organization auth token
            token = SSMParameter(
                session=session,
                logger=logger,
            ).get_parameter(
                name=ssm_tf_org_token_path,
                region=ssm_param_region
            )

            # Query SSM for Terraform Cloud variable set ID
            varset_id = SSMParameter(
                session=session,
                logger=logger,
            ).get_parameter(
                name=ssm_tf_varset_id_path,
                region=ssm_param_region
            )

            # Instantiate a new terraform_API connection
            tf_api = VariableSetAPI(
                token=token,
                varset_id=varset_id,
                logger=logger
            )
            
            # Loop through terraform variable names and update each
            for i in terraform_variable_names:     
                value = None 
                
                # find the key id within the user object matching the new key_id
                found = next((key for key in user.access_keys if key.id == new_key_id), None)
                if not found:
                    raise Exception("The newly created key id '{}' could not be found in the user.access_keys".format(new_key_id))

                # Set appropriate value based on key name
                if i["key"] == "AWS_ACCESS_KEY_ID":                  
                    value = found.id
                
                # Set appropriate value based on key name
                if i["key"] == "AWS_SECRET_ACCESS_KEY":
                    value = found.secret
                
                # Find variable ID
                var_id = tf_api.find_varset_var_id_by_name(i["key"])
                if not var_id:
                    raise Exception("No Variable ID Found that matches name '{}'".format(i['key']))

                # Attempt to Update TF variable
                if tf_api.patch_varset_variable(
                        var_id=var_id,
                        value=value,
                        sensitive=i["sensitive"]
                ):
                    logger.info("Terraform Variable {} ({}) updated successfully".format(i['key'], var_id))
                else:
                    logger.warning("Terraform Variable {} ({}) failed to be update ".format(i['key'], var_id))

# Lambda entrypoint
def lambda_handler(event, context):
    """
    Lambda Handler Entrypoint

    Logs event data and then calls main()

    :param event: Event passed to handler
    :type event: dict
    :param context: AWS Context passed to handler
    :type context: AWS context object
    :returns: None
    """

    # Nothing Special to do here. Just log event/context and call main
    logger.info(event)
    main()


if __name__ == "__main__":
    # Log to Stdout if running locally
    streamHandler = logging.StreamHandler(sys.stdout)
    logger.addHandler(streamHandler)

    # Call main
    main()