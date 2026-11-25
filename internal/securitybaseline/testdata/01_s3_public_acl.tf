# Public canned ACL on an S3 bucket.
resource "aws_s3_bucket" "public_acl" {
  bucket = "baseline-public-acl"
  acl    = "public-read"
}
