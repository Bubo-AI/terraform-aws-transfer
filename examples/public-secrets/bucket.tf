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


resource "aws_s3_bucket_public_access_block" "sftp" {
  bucket                  = aws_s3_bucket.sftp.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

