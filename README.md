# conftest-sample

## Kustomize

`kustomize`のコードは[kustomize](https://github.com/kubernetes-sigs/kustomize)の`exapmles/spring-boot`ディレクトリ内のコードを利用させていただきました  

## Command Sample

```sh
cd kustomize
kustomize build overlays/production | conftest test -

cd kubernetes
conftest test  manifests.yaml
```
