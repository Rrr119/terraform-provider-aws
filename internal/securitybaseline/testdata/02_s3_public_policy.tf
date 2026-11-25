# Bucket policy granting access to a wildcard principal.
resource "aws_s3_bucket" "policy_target" {
  bucket = "baseline-public-policy"
}

resource "aws_s3_bucket_policy" "public" {
  bucket = aws_s3_bucket.policy_target.id
  policy = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::baseline-public-policy/*"
        }
      ]
    }
  EOT
}
