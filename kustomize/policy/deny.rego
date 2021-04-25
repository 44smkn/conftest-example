package main

name := input.metadata.name

# deployment かつ Root以外のユーザで起動していなければ 拒否する
# not -> https://www.openpolicyagent.org/docs/latest/policy-language/#negation
deny[msg] {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot

	msg := sprintf("Containers must not run as root in Deployment %s", [name])
}

# deployment かつ タグ付けされていないコンテナイメージを利用している場合は拒否する
deny[msg] {
	input.kind == "Deployment"
	image := input.spec.template.spec.containers[_].image
	not contains(image, ":")

	msg := sprintf("You must use tagged container images in Deployment %s", [name])
}
