import os
import json
import base64
from typing import Any, Dict, List, Optional, Union
import bcrypt
from ipaddress import ip_network, ip_address
import boto3  # type: ignore
from botocore.exceptions import ClientError  # type: ignore


def lambda_handler(
    event, context
):  # type: (Dict[str, str], Any) -> Dict[str, Union[str, List[str]]]
    """Authenticate user based on the authentication type and generate a UserModel
    dictionary if user is authenticated. If user is not authenticated, return an empty
    dictionary. Please note that type hints are not accurrate for this function.

    Args:
        event (Dict[str, str]): Lambda event containing username, password, serverId,
        protocol, sourceIp. For more details, please refer to the AWS documentation:
        https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-concepts.html
        context (Context): Please refer to AWS documentation:
        https://docs.aws.amazon.com/lambda/latest/dg/python-context.html

    Returns:
        [type]: [description]
    """
    if os.environ.get("SecretsManagerRegion") is None:
        print("No authentication method set")
        return {}

    # Get the required parameters
    required_param_list = ["serverId", "username", "protocol", "sourceIp"]
    for parameter in required_param_list:
        if parameter not in event:
            print("Incoming " + parameter + " missing - Unexpected")
            return {}

    input_serverId = event["serverId"]
    input_username = event["username"]
    input_protocol = event["protocol"]
    input_sourceIp = event["sourceIp"]
    input_password = event.get("password", "")

    print(
        "ServerId: {}, Username: {}, Protocol: {}, SourceIp: {}".format(
            input_serverId, input_username, input_protocol, input_sourceIp
        )
    )

    # Check for password and set authentication type appropriately.
    # No password means SSH auth
    print("Start User Authentication Flow")
    if input_password != "":
        print("Using PASSWORD authentication")
        authentication_type = "PASSWORD"
    else:
        if input_protocol == "FTP" or input_protocol == "FTPS":
            print("Empty password not allowed for FTP/S")
            return {}
        print("Using SSH authentication")
        authentication_type = "SSH"

    # Retrieve user details. For all key-value pairs stored in the SecretManager
    # use protocol-specific secret if found, otherwise generic ones. Platform-specific
    # secrets are prefixed with the protocol name.
    # e.g. If the protocol is SFTP and both SFTPPassword and Password exist, favour
    # SFTPPassword over Password.
    secret_dict = get_secret(input_username)

    if secret_dict:
        # Check if user's password matches the one stored in the SecretManager
        user_authenticated = authenticate_user(
            authentication_type, secret_dict, input_password, input_protocol
        )
        # Check if user's IP address is in the allowed IP address list
        ip_match = check_ipaddress(secret_dict, input_sourceIp, input_protocol)

        # If user is authenticated and IP address is in the allowed IP address list,
        # build and return a UserModel dictionary
        if user_authenticated and ip_match:
            print(
                "User authenticated, calling build_response with: "
                + authentication_type
            )
            return build_response(secret_dict, authentication_type, input_protocol)
        else:
            print("User failed authentication returning an empty response")
            return {}
    else:
        # No secret found, or something went wrong and exception was thrown.
        # Most likely the object name is not there, check the logs for more details.
        print("Secrets Manager exception thrown - Returning empty response")
        # Return an empty data response meaning the user was not authenticated
        return {}


def lookup(
    secret_dict, key, input_protocol
):  # type: (Dict[str, str], str, str) -> Optional[str]
    """Return protocol specific secret value from secret_dict. If no secret found for
    the given protocol, return generic secret value (without protocol prefix).

    Args:
        secret_dict (Dict[str, str]): Secret manager values.
        key (str): Key to retrieve from secret_dict. A key can be either of Password,
        Role, Policy, AcceptedIpNetwork, HomeDirectory, HomeDirectoryDetails, or
        PublicKey.
        input_protocol (str): Protocol, SSH, FTP or FTPS.

    Returns:
        Optional[str]: Protocol specific secret value from secret_dict. If no secret
        found for the given protocol, looks up for a generic secret value (without
        protocol prefix) and returns it. If no generic secret value found, return None.
    """
    if input_protocol + key in secret_dict:
        print("Found protocol-specified {}".format(key))
        return secret_dict[input_protocol + key]
    else:
        return secret_dict.get(key, None)


def check_ipaddress(
    secret_dict, input_sourceIp, input_protocol
):  # type: (Dict[str, str], str, str) -> bool
    """Check if the source IP address is in the allowed IP address list.

    Args:
        secret_dict (Dict[str, str]): Secret manager values.
        input_sourceIp (str): Source IP address feed from AWS Transfer service.
        input_protocol (str): Protocol, SSH, FTP or FTPS.

    Returns:
        bool: True if IP address is in the allowed IP address list, False otherwise.
    """
    accepted_ip_network = lookup(secret_dict, "AcceptedIpNetwork", input_protocol)
    if not accepted_ip_network:
        # No IP provided so skip checks
        print("No IP range provided - Skip IP check")
        return True

    # TODO: Allow for multiple IP ranges
    net = ip_network(accepted_ip_network)
    if ip_address(input_sourceIp) in net:
        print("Source IP address is in allowed CIDR")
        return True
    else:
        print("Source IP address not in range")
        return False


def authenticate_user(
    auth_type, secret_dict, input_password, input_protocol
):  # type: (str, Dict[str, str], str, str) -> bool
    """Authenticate user based on the authentication type. Returns True if auth_type is
    password and passwords match or auth_type is SSH.

    Args:
        auth_type (str): Authentication type, either `SSH` or `PASSWORD`.
        secret_dict (Dict[str, str]): Secret manager values.
        input_password (str): Input password, will be checked against hashed password.
        input_protocol (str): Protocol, SSH, FTP or FTPS.

    Returns:
        bool: True if user is authenticated or False if not.
    """
    # Function returns True if: auth_type is password and passwords match
    # or auth_type is SSH.
    # Otherwise returns False
    if auth_type == "SSH":
        # Place for additional checks in future
        print("Skip password check as SSH login request")
        return True
    # auth_type could only be SSH or PASSWORD
    else:
        # Retrieve the password from the secret if exists
        password = lookup(secret_dict, "Password", input_protocol)
        if not password:
            print(
                "Unable to authenticate user - \
                No field match in Secret for password"
            )
            return False

        if bcrypt.checkpw(input_password.encode("utf-8"), password.encode("utf-8")):
            print("Password match")
            return True
        else:
            print(
                "Unable to authenticate user - \
                    Incoming password does not match stored"
            )
            return False


# Build out our response data for an authenticated response
def build_response(
    secret_dict, auth_type, input_protocol
):  # type: (Dict[str, str], str, str) -> Dict[str, Union[str, List[str]]]
    """Build authenticated user's response for AWS Transfer service as defined in the
    spec.

    Args:
        secret_dict (Dict[str, str]): Secret manager values.
        auth_type (str): Authentication type, either `SSH` or `PASSWORD`.
        input_protocol (str): Protocol, SSH, FTP or FTPS.

    Returns:
        Dict[str, str]: Returns a dictionary of the response data containing Role,
        Policy, HomeDirectoryDetails (if specified), HomeDirectoryType
        (if HomeDirectoryDetails specified), PublicKey (as list) if auth_type is SSH,
        HomeDirectory if specified. Please note that HomeDirectoryType is mutually
        exclusive with HomeDirectoryDetails.
    """
    response_data = {}  # type: Dict[str, Union[str, List[str]]]
    # Check for each key value pair. These are required so set to empty string if
    # missing
    role = lookup(secret_dict, "Role", input_protocol)
    if role:
        response_data["Role"] = role
    else:
        print("No field match for role - Set empty string in response")
        response_data["Role"] = ""

    # These are optional so ignore if not present
    policy = lookup(secret_dict, "Policy", input_protocol)
    if policy:
        response_data["Policy"] = policy

    # External Auth providers support chroot
    # and virtual folder assignments so we'll check for that
    home_directory_details = lookup(secret_dict, "HomeDirectoryDetails", input_protocol)
    if home_directory_details:
        print(
            "HomeDirectoryDetails found - "
            "Applying setting for virtual folders - "
            "Note: Cannot be used in conjunction with key: HomeDirectory"
        )
        response_data["HomeDirectoryDetails"] = home_directory_details
        # If we have a virtual folder setup
        # then we also need to set HomeDirectoryType to "Logical"
        print("Setting HomeDirectoryType to LOGICAL")
        response_data["HomeDirectoryType"] = "LOGICAL"

    # Note that HomeDirectory and HomeDirectoryDetails / Logical mode
    # can't be used together but we're not checking for this
    home_directory = lookup(secret_dict, "HomeDirectory", input_protocol)
    if home_directory:
        print(
            "HomeDirectory found - Note: "
            "Cannot be used in conjunction with key: HomeDirectoryDetails"
        )
        response_data["HomeDirectory"] = home_directory

    if auth_type == "SSH":
        public_key = lookup(secret_dict, "PublicKey", input_protocol)
        if public_key:
            response_data["PublicKeys"] = [public_key]
        else:
            # SSH Auth Flow - We don't have keys so we can't help
            print("Unable to authenticate user - No public keys found")
            return {}

    return response_data


def get_secret(id):  # type: (str) -> Dict[str,str]
    region = os.environ["SecretsManagerRegion"]
    print("Secrets Manager Region: " + region + " - Secret Name: " + id)

    # Create a Secrets Manager client
    client = boto3.session.Session().client(
        service_name="secretsmanager", region_name=region
    )

    try:
        resp = client.get_secret_value(SecretId="SFTP/" + id)
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary,
        # one of these fields will be populated.
        if "SecretString" in resp:
            print("Found Secret String")
            secret = resp["SecretString"]
        else:
            print("Found Binary Secret")
            secret = base64.b64decode(resp["SecretBinary"])
        secret_dict = json.loads(secret)  # type: Dict[str,str]
        return secret_dict
    except ClientError as err:
        print(
            "Error Talking to SecretsManager: "
            + err.response["Error"]["Code"]
            + ", Message: "
            + err.response["Error"]["Message"]
        )
        return {}
