package main

# deployment かつ Root以外のユーザで起動していなければ 拒否する
# not -> https://www.openpolicyagent.org/docs/latest/policy-language/#negation
deny[msg] {
	resources := input[_][_]
	resources.kind == "Deployment"
	not resources.spec.template.spec.securityContext.runAsNonRoot

	msg := sprintf("Containers must not run as root in Deployment %s", [resources.metadata.name])
}

# deployment かつ タグ付けされていないコンテナイメージを利用している場合は拒否する
deny[msg] {
	resources := input[_][_]
	resources.kind == "Deployment"
	image := resources.spec.template.spec.containers[_].image
	not contains(image, ":")

	msg := sprintf("You must use tagged container images in Deployment %s", [resources.metadata.name])
}

# serviceのselectorのlabelがDeploymentの.spec.tempalate.metadata.labelsに含まれるかを確認する
deny[msg] {
	input[deployment].contents.kind == "Deployment"
	deployment := input[deployment].contents

	input[service].contents.kind == "Service"
	service := input[service].contents

	service.spec.selector.app != deployment.spec.template.metadata.labels.app
	msg := sprintf("label is different! service: %s <=>  deployment: %s", [service.metadata.name, deployment.metadata.name])
}
