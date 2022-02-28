# Simple Public SFTP example using AWS Secrets

This example creates a simple public facing AWS Transfer for SFTP service using the API_GATEWAY identity provider using AWS Secrets for the credentials.

A bucket will be created to store the files along with a sample user and an IAM role for the user to access the service. You can change the default user name from `values.auto.tfvars` file.

> After deploying this service, go to the secret manager and replace the secret key `Password` which has a default value of `REPLACE_ME` with a bcrpyt hash of the password. To generate a bcrypt hash, use the command below and replace `PASSWORDHERE` with your own password.

```python
python -c 'import bcrypt; print(bcrypt.hashpw("PASSWORDHERE".encode("utf-8"), bcrypt.gensalt()))'
```



## Usage

    $ terraform init
    $ terraform plan
    $ terraform apply

## Example User Configuration

Once the service has been started, a sample user will be created in the secret manager with the following configuration:


| UserId | HomeDirectoryDetails | Role | Password | _AcceptedIpNetwork*_ |
|--------|----------------------|------|----------|-------------------|
| user1 | `[{\"Entry\": \"/\", \"Target\": \"/s3_bucket/username\"}]` | arn:aws:iam::[account id]:role/transfer-user-iam-role | BCRPYT_HASH | 192.168.1.0/24 |

This will create a user **user1** which is chroot'd to the **/test.devopsgoat/user1** virtual directory in S3.

\* **_AcceptedIpNetwork_** is an optional CIDR for the allowed client source IP address range. You can specify multiple CIDR by separating with comma, e.g.: `192.0.0.0/24, 224.0.0.0/16`.


## Outputs

| Name        | Description                                   |
|-------------|-----------------------------------------------|
| endpoint    | The endpoint of the SFTP service              |
| role        | The IAM Role that must be assigned to users   |
| user-secret | Name of the secret holding user configuration |
| username    | SFTP username                                 |
