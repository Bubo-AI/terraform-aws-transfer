resource "aws_secretsmanager_secret" "user" {
  name        = "${local.prefix_kebab}SFTP/${var.username}"
  description = "SFTP User - ${var.username} for ${var.prefix}"
  tags = {
    Resource = "SFTP"
    User     = var.username
    Prefix   = var.prefix
  }
}

resource "aws_secretsmanager_secret_version" "user" {
  secret_id     = aws_secretsmanager_secret.user.id
  secret_string = <<-EOF
    {
      "HomeDirectoryDetails": "[{\"Entry\": \"/\", \"Target\": \"/${aws_s3_bucket.sftp.id}/${var.username}\"}]",
      "Password": "REPLACE_ME",
      "Role": "${aws_iam_role.transfer.arn}",
      "UserId": "${var.username}",
      "AcceptedIpNetwork": "0.0.0.0/0"
    }
  EOF
}
