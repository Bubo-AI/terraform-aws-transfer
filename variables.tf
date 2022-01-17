
variable "prefix" {
  type        = string
  default     = ""
  description = "The prefix of every resource created by this module"

  validation {
    condition     = can(regex("^[a-z0-9]+$", var.prefix))
    error_message = "The prefix must consist of lowercase alphanumeric characters."
  }
}
