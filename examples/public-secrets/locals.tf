locals {
  prefix_kebab = var.prefix == "" ? var.prefix : "${var.prefix}-" # for kebab case resource names
  prefix_snake = var.prefix == "" ? var.prefix : "${var.prefix}_" # for snake case resource names
}
