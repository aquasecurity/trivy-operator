package operator_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/operator"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

const (
	vreport = "vreport"
	ns      = "default"
)

func TestRegenerateReportIfExpired(t *testing.T) {
	// clock
	clock := ext.NewSystemClock()

	// scheme
	scheme := trivyoperator.NewScheme()

	// set the ScannerReportTTL
	config, err := etc.GetOperatorConfig()
	require.NoError(t, err)
	hours, err := time.ParseDuration("24h")
	require.NoError(t, err)
	config.ScannerReportTTL = &hours

	// logger object
	logger := log.Log.WithName("testing")

	// create TTLReport controller
	instance := operator.TTLReportReconciler{Logger: logger, Config: config, Clock: clock}

	// vuln report data
	vulnReport := v1alpha1.VulnerabilityReport{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "aquasecurity.github.io/v1alpha1",
			Kind:       "VulnerabilityReport",
		},
	}
	vulnReport.Name = vreport
	vulnReport.Namespace = ns

	tests := []struct {
		name                  string
		reportUpdateTimestamp time.Duration
		wantError             bool
		wantReportDeleted     bool
		ttlStr                string
		invalidReportName     bool
		reportType            client.Object
	}{
		/*{
			name:                  "Report timestamp < TTL",
			reportUpdateTimestamp: -15 * time.Hour, // < 24h TTL
			ttlStr:                "24h",
			reportType:            &v1alpha1.VulnerabilityReport{},
		},*/
		{
			name:                  "Report timestamp exceeds TTL",
			reportUpdateTimestamp: -25 * time.Hour, // > 24 TTL
			wantReportDeleted:     true,            // = time.Duration(0)
			ttlStr:                "24h",
			reportType:            &v1alpha1.VulnerabilityReport{},
		},
		/*
			{
				name:       "missing TTL annotation in the report",
				wantError:  false, // Ignoring report without TTL set
				ttlStr:     "24h",
				reportType: &v1alpha1.VulnerabilityReport{},
			},
			{
				name:       "invalid TTL in the annotation",
				ttlStr:     "badtime",
				wantError:  true,
				reportType: &v1alpha1.VulnerabilityReport{},
			},
			{
				name:              "non-existent report name",
				invalidReportName: true,  // sets the report name to empty string
				wantError:         false, // missing/invalid report ignored
				ttlStr:            "24h",
				reportType:        &v1alpha1.VulnerabilityReport{},
			},*/
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.invalidReportName {
				vulnReport.Name = ""
			}
			vulnReport.Annotations = map[string]string{
				"trivy-operator.aquasecurity.github.io/report-ttl": tt.ttlStr,
			}
			vulnReport.CreationTimestamp.Time = clock.Now().Add(tt.reportUpdateTimestamp)

			// generate client with vulnReport
			instance.Client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(&vulnReport).Build()

			nsName := types.NamespacedName{Namespace: ns, Name: vulnReport.Name}

			// Check if TTL expired for the vulnerability report
			_, err := instance.DeleteReportIfExpired(context.TODO(), nsName, &v1alpha1.VulnerabilityReport{})
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			vr := v1alpha1.VulnerabilityReport{}
			err = instance.Client.Get(context.TODO(), nsName, &vr)

			if tt.wantReportDeleted {
				require.Error(t, err)
				require.True(t, apierrors.IsNotFound(err))
				return
			}
			require.NoError(t, err)
		})
	}
}
