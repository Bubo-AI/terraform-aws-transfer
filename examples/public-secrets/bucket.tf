resource "aws_s3_bucket" "sftp" {
  bucket_prefix = "${local.prefix_kebab}sftpbucket"
  acl           = "private"
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
