package starboard

import (
	_ "embed"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
)

var (
	//go:embed deploy/crd/vulnerabilityreports.crd.yaml
	vulnerabilityReportsCRD []byte
	//go:embed deploy/crd/clustervulnerabilityreports.crd.yaml
	clusterVulnerabilityReportsCRD []byte
	//go:embed deploy/crd/configauditreports.crd.yaml
	configAuditReportsCRD []byte
	//go:embed deploy/crd/clusterconfigauditreports.crd.yaml
	clusterConfigAuditReportsCRD []byte
	//go:embed deploy/crd/clustercompliancereports.crd.yaml
	clusterComplianceReportsCRD []byte
	//go:embed deploy/crd/clustercompliancedetailreports.crd.yaml
	clusterComplianceDetailReportsCRD []byte
	//go:embed deploy/crd/ciskubebenchreports.crd.yaml
	kubeBenchReportsCRD []byte
	//go:embed deploy/crd/kubehunterreports.crd.yaml
	kubeHunterReportsCRD []byte
	//go:embed  deploy/static/04-trivy-operator.policies.yaml
	policies []byte

	//go:embed deploy/specs/nsa-1.0.yaml
	nsaSpecV10 []byte
)

func PoliciesConfigMap() (corev1.ConfigMap, error) {
	var cm corev1.ConfigMap
	_, _, err := scheme.Codecs.UniversalDecoder().Decode(policies, nil, &cm)
	if err != nil {
		return cm, err
	}
	return cm, nil
}

func GetVulnerabilityReportsCRD() (apiextensionsv1.CustomResourceDefinition, error) {
	return getCRDFromBytes(vulnerabilityReportsCRD)
}

func GetClusterVulnerabilityReportsCRD() (apiextensionsv1.CustomResourceDefinition, error) {
	return getCRDFromBytes(clusterVulnerabilityReportsCRD)
}

func GetConfigAuditReportsCRD() (apiextensionsv1.CustomResourceDefinition, error) {
	return getCRDFromBytes(configAuditReportsCRD)
}

func GetClusterConfigAuditReportsCRD() (apiextensionsv1.CustomResourceDefinition, error) {
	return getCRDFromBytes(clusterConfigAuditReportsCRD)
}

func GetClusterComplianceReportsCRD() (apiextensionsv1.CustomResourceDefinition, error) {
	return getCRDFromBytes(clusterComplianceReportsCRD)
}

func GetClusterComplianceDetailReportsCRD() (apiextensionsv1.CustomResourceDefinition, error) {
	return getCRDFromBytes(clusterComplianceDetailReportsCRD)
}

func GetCISKubeBenchReportsCRD() (apiextensionsv1.CustomResourceDefinition, error) {
	return getCRDFromBytes(kubeBenchReportsCRD)
}

func GetKubeHunterReportsCRD() (apiextensionsv1.CustomResourceDefinition, error) {
	return getCRDFromBytes(kubeHunterReportsCRD)
}

func GetNSASpecV10() (v1alpha1.ClusterComplianceReport, error) {
	return getComplianceSpec(nsaSpecV10)
}

func getCRDFromBytes(bytes []byte) (apiextensionsv1.CustomResourceDefinition, error) {
	var crd apiextensionsv1.CustomResourceDefinition
	_, _, err := scheme.Codecs.UniversalDecoder().Decode(bytes, nil, &crd)
	if err != nil {
		return apiextensionsv1.CustomResourceDefinition{}, err
	}
	return crd, nil
}

func getComplianceSpec(bytes []byte) (v1alpha1.ClusterComplianceReport, error) {
	var complianceReport v1alpha1.ClusterComplianceReport
	_, _, err := scheme.Codecs.UniversalDecoder().Decode(bytes, nil, &complianceReport)
	if err != nil {
		return v1alpha1.ClusterComplianceReport{}, err
	}
	return complianceReport, nil
}
