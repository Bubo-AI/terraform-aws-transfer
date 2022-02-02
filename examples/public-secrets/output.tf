output "endpoint" {
  value = aws_transfer_server.sftp.endpoint
}

output "role" {
  value = aws_iam_role.transfer.arn
}

output "user-secret" {
  value = aws_secretsmanager_secret.user.name
}

output "username" {
  value = var.username
}
