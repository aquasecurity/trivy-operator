package reports

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NameFromController(controller client.Object) string {
	kind := controller.GetObjectKind().GroupVersionKind().Kind
	name := controller.GetName()
	reportName := fmt.Sprintf("%s-%s", strings.ToLower(kind), name)
	if isValidName(reportName) {
		return reportName
	}
	return fmt.Sprintf("%s-%s", strings.ToLower(kind), kube.ComputeHash(name))
}

func NameFromControllerContainer(controller client.Object, container string) string {
	kind := controller.GetObjectKind().GroupVersionKind().Kind
	name := controller.GetName()
	reportName := fmt.Sprintf("%s-%s-%s", strings.ToLower(kind), name, container)
	if isValidName(reportName) {
		return reportName
	}

	return fmt.Sprintf("%s-%s", strings.ToLower(kind), kube.ComputeHash(name+"-"+container))
}

func isValidName(name string) bool {
	// We also use report names as label values, so must validate both valid resource name and label value
	return len(validation.IsDNS1123Subdomain(name)) == 0 && len(validation.IsValidLabelValue(name)) == 0
}
