# terraform-aws-transfer

This is a Terraform module to create a custom identity provider for the AWS Transfer for SFTP service.

This module aims to set up an identity provider built on:

- API Gateway
- Lambda
- AWS Secrets

This module will output the URL for the API Gateway which should be used as the **_url_** argument for the **_aws_transfer_server_** resource

## Credential Store

The credentials are stored as AWS Secrets.

The infrastructure code is based on the example provided (in the CF template) in the AWS Storage Blog article
https://aws.amazon.com/blogs/storage/enable-password-authentication-for-aws-transfer-family-using-aws-secrets-manager-updated//.

> ⚠️ AWS Secrets Manager costs $0.40 per secret per month. AWS Transfer Family costs $0.30 per HOUR ($216 per month) and additional usage costs.

## Inputs

| Name  | Description                       |  Type  | Default | Required |
| ----- | --------------------------------- | :----: | :-----: | :------: |
| stage | The stage name for the deployment | string |   dev   |   yes    |

## Outputs

| Name                | Description                                                                                                         |
| ------------------- | ------------------------------------------------------------------------------------------------------------------- |
| invoke_url          | The URL which the SFTP service will use to send authentication requests to                                          |
| rest_api_id         | The ARN of the REST service created. <br>This should be used in the IAM role for SFTP to invoke the service         |
| rest_api_stage_name | The stage name of the REST service created. <br> This should be used in the IAM role for SFTP to invoke the service |
| lambda_iam_role     | The IAM role for lambda. If you encrypt secrets with KMS, allow this role to decrypt secrets with the KMS key       |
| lambda_name         | The name of lambda function                                                                                         |

## Usage

```hcl
module "sftp-idp" {
  source                = "github.com/Bubo-AI/terraform-aws-transfer?ref=v0.5.3"
}
```

## Example

- [End-to-end SFTP server example](https://github.com/Bubo-AI/terraform-aws-transfer/tree/master/examples/public-secrets)

## Versions

This module supports Terraform >= v1.0.0 and AWS ~> 4.3.0.
