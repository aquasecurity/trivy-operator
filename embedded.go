package trivy_operator

import (
	_ "embed"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
)

var (

	//go:embed  deploy/static/04-trivy-operator.policies.yaml
	policies []byte
)

func PoliciesConfigMap() (corev1.ConfigMap, error) {
	var cm corev1.ConfigMap
	_, _, err := scheme.Codecs.UniversalDecoder().Decode(policies, nil, &cm)
	if err != nil {
		return cm, err
	}
	return cm, nil
}
