package kube

// AppendResourceLabels match resource labels by config and append it to report labels
func AppendResourceLabels(configLabelsNames []string, resourceLabels map[string]string, reportLabels map[string]string) {
	for _, labelToInclude := range configLabelsNames {
		if value, ok := resourceLabels[labelToInclude]; ok {
			reportLabels[labelToInclude] = value
		}
	}
}

// AppendCustomLabels append custom labels to report
func AppendCustomLabels(configCustomLabels map[string]string, reportLabels map[string]string) {
	for key, value := range configCustomLabels {
		reportLabels[key] = value
	}
}
