output "invoke_url" {
  value = aws_api_gateway_stage.stage.invoke_url
}

output "rest_api_id" {
  value = aws_api_gateway_rest_api.sftp-idp-secrets.id
}

output "rest_api_stage_name" {
  value = aws_api_gateway_stage.stage.stage_name
}

output "lambda_iam_role" {
  value = aws_iam_role.iam_for_lambda_idp.name
}
output "lambda_name" {
  value = aws_lambda_function.sftp-idp.function_name
}
