package v1alpha1

import (
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/conversion"
)

func (src *VulnerabilityReport) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*v1beta1.VulnerabilityReport)
	return Convert_v1alpha1_VulnerabilityReport_To_v1beta1_VulnerabilityReport(src, dst, nil)
}

func (dst *VulnerabilityReport) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*v1beta1.VulnerabilityReport)
	return Convert_v1beta1_VulnerabilityReport_To_v1alpha1_VulnerabilityReport(src, dst, nil)
}

func (src *ClusterVulnerabilityReport) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*v1beta1.ClusterVulnerabilityReport)
	return Convert_v1alpha1_ClusterVulnerabilityReport_To_v1beta1_ClusterVulnerabilityReport(src, dst, nil)
}

func (dst *ClusterVulnerabilityReport) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*v1beta1.ClusterVulnerabilityReport)
	return Convert_v1beta1_ClusterVulnerabilityReport_To_v1alpha1_ClusterVulnerabilityReport(src, dst, nil)
}
