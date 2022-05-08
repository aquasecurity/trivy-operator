package ext

// SliceContainsString returns true if the specified slice of strings
// contains the give value, false otherwise.
func SliceContainsString(slice []string, value string) bool {
	exists := false
	for _, targetNamespace := range slice {
		if targetNamespace == value {
			exists = true
		}
	}
	return exists
}
