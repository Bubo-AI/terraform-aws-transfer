resource "aws_iam_role" "transfer" {
  name = "${local.prefix_kebab}transfer-user-iam-role-${var.stage}"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Principal": {
            "Service": "transfer.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "transfer" {
  name = "${local.prefix_kebab}transfer-user-iam-policy-${var.stage}"
  role = aws_iam_role.transfer.id

  policy = <<-POLICY
{
  "Version": "2012-10-17",
  "Statement": [
      {
          "Sid": "AllowListingOfUserFolder",
          "Action": [
              "s3:ListBucket"
          ],
          "Effect": "Allow",
          "Resource": [
              "${aws_s3_bucket.sftp.arn}"
          ],
          "Condition": {
              "StringLike": {
                  "s3:prefix": [
                      "${var.username}/*",
                      "${var.username}"
                  ]
              }
          }
      },
      {
          "Sid": "HomeDirObjectAccess",
          "Effect": "Allow",
          "Action": [
              "s3:PutObject",
              "s3:GetObject",
              "s3:DeleteObjectVersion",
              "s3:DeleteObject",
              "s3:GetObjectVersion"
          ],
          "Resource": [
              "${aws_s3_bucket.sftp.arn}/${var.username}",
              "${aws_s3_bucket.sftp.arn}/${var.username}/*"
          ]
       }
  ]
}
  POLICY
}
