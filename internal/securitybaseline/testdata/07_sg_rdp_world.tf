# Inline ingress rule exposing RDP through a broad port range.
resource "aws_security_group" "rdp_world" {
  name = "baseline-rdp-world"

  ingress {
    from_port   = 3380
    to_port     = 3390
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
