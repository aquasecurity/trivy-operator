package kube

// AppendResourceAnnotations match resource annotations by config and append it to report annotations
func AppendResourceAnnotations(configAnnotationsNames []string, resourceAnnotations, reportAnnotations map[string]string) {
	for _, labelToInclude := range configAnnotationsNames {
		if value, ok := resourceAnnotations[labelToInclude]; ok {
			reportAnnotations[labelToInclude] = value
		}
	}
}

// AppendCustomAnnotations append custom annotations to report
func AppendCustomAnnotations(configCustomAnnotations, reportAnnotations map[string]string) {
	for key, value := range configCustomAnnotations {
		reportAnnotations[key] = value
	}
}
