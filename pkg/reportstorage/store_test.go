package reportstorage_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/reportstorage"
)

func TestNew_RejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  etc.Config
		wantErr string
	}{
		{
			name:    "filesystem without directory",
			config:  etc.Config{AltReportStorageType: etc.AltReportStorageFilesystem},
			wantErr: "alternate report storage directory must be set",
		},
		{
			name:    "s3 without bucket",
			config:  etc.Config{AltReportStorageType: etc.AltReportStorageS3},
			wantErr: "alternate report storage S3 bucket must be set",
		},
		{
			name:    "unknown type",
			config:  etc.Config{AltReportStorageType: "gcs"},
			wantErr: `unsupported alternate report storage type "gcs"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := reportstorage.New(context.Background(), tt.config)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestKey(t *testing.T) {
	deployment := kube.ObjectRef{Kind: kube.KindReplicaSet, Name: "nginx-6d9676f5c4", Namespace: "default"}
	clusterRole := kube.ObjectRef{Kind: kube.KindClusterRole, Name: "admin"}

	assert.Equal(t, "vulnerability_reports/default/ReplicaSet-nginx-6d9676f5c4-nginx.json",
		reportstorage.Key("vulnerability_reports", deployment, "nginx"))
	assert.Equal(t, "config_audit_reports/ClusterRole-admin.json",
		reportstorage.Key("config_audit_reports", clusterRole, ""))
}
