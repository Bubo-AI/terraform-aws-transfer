resource "aws_s3_bucket" "sftp" {
  bucket_prefix = "${local.prefix_kebab}sftpbucket"
  acl           = "private"
}
