# VPC managed ingress rule allowing every protocol from the internet.
resource "aws_vpc_security_group_ingress_rule" "all_world" {
  security_group_id = "sg-0123456789abcdef0"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
