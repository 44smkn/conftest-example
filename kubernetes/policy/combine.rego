package main

deny[msg] {
	input[deploy].contents.kind == "Deployment"
	deployment := input[deploy].contents

	input[svc].contents.kind == "Service"
	service := input[svc].contents

	service.spec.selector.app != deployment.spec.template.labels.app
	msg := sprintf("Labels are different! Deployment %v has 'app: %v', Service %v has 'app: %v'", [deployment.metadata.name, deployment.spec.template.labels.app, service.metadata.name, service.spec.selector.app])
}
