package jobs

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestIsComplete(t *testing.T) {
	type args struct {
		conditionType   batchv1.JobConditionType
		conditionStatus corev1.ConditionStatus
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "suspended true", args: args{conditionType: batchv1.JobSuspended, conditionStatus: corev1.ConditionTrue}, want: false},
		{name: "suspended false", args: args{conditionType: batchv1.JobSuspended, conditionStatus: corev1.ConditionFalse}, want: false},
		{name: "failed true", args: args{conditionType: batchv1.JobFailed, conditionStatus: corev1.ConditionTrue}, want: false},
		{name: "failed false", args: args{conditionType: batchv1.JobFailed, conditionStatus: corev1.ConditionFalse}, want: false},
		{name: "complete true", args: args{conditionType: batchv1.JobComplete, conditionStatus: corev1.ConditionTrue}, want: true},
		{name: "complete false", args: args{conditionType: batchv1.JobComplete, conditionStatus: corev1.ConditionFalse}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := newJobWithCondition(tt.args.conditionType, tt.args.conditionStatus)
			if got := IsComplete(job); got != tt.want {
				t.Errorf("IsComplete() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsFailed(t *testing.T) {
	type args struct {
		conditionType   batchv1.JobConditionType
		conditionStatus corev1.ConditionStatus
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "suspended true", args: args{conditionType: batchv1.JobSuspended, conditionStatus: corev1.ConditionTrue}, want: false},
		{name: "suspended false", args: args{conditionType: batchv1.JobSuspended, conditionStatus: corev1.ConditionFalse}, want: false},
		{name: "failed true", args: args{conditionType: batchv1.JobFailed, conditionStatus: corev1.ConditionTrue}, want: true},
		{name: "failed false", args: args{conditionType: batchv1.JobFailed, conditionStatus: corev1.ConditionFalse}, want: false},
		{name: "complete true", args: args{conditionType: batchv1.JobComplete, conditionStatus: corev1.ConditionTrue}, want: false},
		{name: "complete false", args: args{conditionType: batchv1.JobComplete, conditionStatus: corev1.ConditionFalse}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := newJobWithCondition(tt.args.conditionType, tt.args.conditionStatus)
			if got := IsFailed(job); got != tt.want {
				t.Errorf("IsFailed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsFinished(t *testing.T) {
	type args struct {
		conditionType   batchv1.JobConditionType
		conditionStatus corev1.ConditionStatus
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "suspended true", args: args{conditionType: batchv1.JobSuspended, conditionStatus: corev1.ConditionTrue}, want: false},
		{name: "suspended false", args: args{conditionType: batchv1.JobSuspended, conditionStatus: corev1.ConditionFalse}, want: false},
		{name: "failed true", args: args{conditionType: batchv1.JobFailed, conditionStatus: corev1.ConditionTrue}, want: true},
		{name: "failed false", args: args{conditionType: batchv1.JobFailed, conditionStatus: corev1.ConditionFalse}, want: false},
		{name: "complete true", args: args{conditionType: batchv1.JobComplete, conditionStatus: corev1.ConditionTrue}, want: true},
		{name: "complete false", args: args{conditionType: batchv1.JobComplete, conditionStatus: corev1.ConditionFalse}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := newJobWithCondition(tt.args.conditionType, tt.args.conditionStatus)
			if got := IsFinished(job); got != tt.want {
				t.Errorf("IsFinished() = %v, want %v", got, tt.want)
			}
		})
	}
}

func newJobWithCondition(conditionType batchv1.JobConditionType, conditionStatus corev1.ConditionStatus) *batchv1.Job {
	return &batchv1.Job{Status: batchv1.JobStatus{
		Conditions: []batchv1.JobCondition{{Type: conditionType, Status: conditionStatus}},
	}}
}
