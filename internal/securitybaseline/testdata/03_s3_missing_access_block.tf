# Bucket without any public access block configuration.
resource "aws_s3_bucket" "no_block" {
  bucket = "baseline-no-access-block"
}
