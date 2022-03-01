resource "aws_iam_role" "iam_for_apigateway_idp" {
  name = "${local.prefix_snake}iam_for_apigateway_idp-${var.stage}"

  assume_role_policy = <<-EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          "Principal": {
            "Service": "apigateway.amazonaws.com"
          },
          "Effect": "Allow",
          "Sid": ""
        }
      ]
    }
  EOF
}


resource "aws_iam_role_policy_attachment" "apigateway-cloudwatchlogs" {
  role       = aws_iam_role.iam_for_apigateway_idp.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

resource "aws_api_gateway_account" "api_gateway_account" {
  cloudwatch_role_arn = aws_iam_role.iam_for_apigateway_idp.arn
}

resource "aws_api_gateway_rest_api" "sftp-idp-secrets" {
  name        = "${local.prefix_kebab}sftp-idp-secrets"
  description = "${var.prefix} - This API provides an IDP for AWS Transfer service"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  body = data.template_file.api-definition.rendered
}

resource "aws_lambda_permission" "allow_apigateway" {
  statement_id  = "AllowExecutionFromApigateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sftp-idp.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.sftp-idp-secrets.execution_arn}/*/*/*"
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.sftp-idp-secrets.id
  triggers = {
    redeployment = sha1(jsonencode([aws_api_gateway_rest_api.sftp-idp-secrets.body]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "stage" {
  stage_name           = "${local.prefix_kebab}${var.stage}"
  rest_api_id          = aws_api_gateway_rest_api.sftp-idp-secrets.id
  deployment_id        = aws_api_gateway_deployment.deployment.id
  xray_tracing_enabled = true
  access_log_settings {
    destination_arn = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/api_gateway/${local.prefix_kebab}${var.stage}"

    format = jsonencode({
      request = {
        requestId         = "$context.requestId"
        requestTime       = "$context.requestTime"
        extendedRequestId = "$context.extendedRequestId"
      }
    })
  }
}

resource "aws_api_gateway_method_settings" "this" {
  rest_api_id = aws_api_gateway_rest_api.sftp-idp-secrets.id
  stage_name  = aws_api_gateway_stage.stage.stage_name
  method_path = "/servers/{serverId}/users/{username}/config/GET"
  settings {
    metrics_enabled      = true
    logging_level        = "INFO"
    cache_data_encrypted = true
  }
}
