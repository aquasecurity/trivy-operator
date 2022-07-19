package jobs

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

func IsComplete(job *batchv1.Job) bool {
	return isStatusConditionPresentAndEqual(job.Status.Conditions, batchv1.JobComplete, corev1.ConditionTrue)
}

func IsFailed(job *batchv1.Job) bool {
	return isStatusConditionPresentAndEqual(job.Status.Conditions, batchv1.JobFailed, corev1.ConditionTrue)
}

func IsFinished(job *batchv1.Job) bool {
	return IsComplete(job) || IsFailed(job)
}

// isStatusConditionPresentAndEqual returns true when conditionType is present and equal to status.
func isStatusConditionPresentAndEqual(conditions []batchv1.JobCondition, conditionType batchv1.JobConditionType, status corev1.ConditionStatus) bool {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status == status
		}
	}
	return false
}
