locals {
  auth_source_name  = "SecretsManagerRegion"
  auth_source_value = data.aws_region.current.name
  prefix_kebab      = var.prefix == "" ? var.prefix : "${var.prefix}-" # for kebab case resource names
  prefix_snake      = var.prefix == "" ? var.prefix : "${var.prefix}_" # for snake case resource names
}
