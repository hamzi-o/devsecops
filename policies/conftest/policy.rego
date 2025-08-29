package k8s.security

deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.containers[_].securityContext.runAsNonRoot
  msg := "Containers must runAsNonRoot"  # CIS-5.2.5, NIST-AC-6
}

deny[msg] {
  input.kind == "Deployment"
  some c
  not input.spec.template.spec.containers[c].resources.limits
  msg := "Containers must define resource limits"  # CIS-5.1.5, NIST-SA-11
}

deny[msg] {
  input.kind == "Deployment"
  some c
  endswith(input.spec.template.spec.containers[c].image, ":latest")
  msg := "Do not use :latest tag"
}
