variable "stage" {
  description = "The deployment stage"
  default     = "dev"
}

variable "prefix" {
  description = "AWS resource prefix"
  default     = ""
}

variable "username" {
  description = "SFTP Username"
  default     = "transfer-user"
}
variable "region" {
  description = "The aws region"
  default     = "eu-west-1"
}
