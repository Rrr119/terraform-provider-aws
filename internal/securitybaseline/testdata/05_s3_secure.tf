# Baseline-compliant bucket: no public ACL and a full public access block.
resource "aws_s3_bucket" "secure" {
  bucket = "baseline-secure"

  public_access_block {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}
