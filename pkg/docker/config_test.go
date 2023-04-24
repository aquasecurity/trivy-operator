package docker_test

import (
	"errors"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBasicAuth(t *testing.T) {
	assert.Equal(t, docker.BasicAuth("Zm9vOmJhcg=="), docker.NewBasicAuth("foo", "bar"))
}

func TestConfig_Read(t *testing.T) {
	testCases := []struct {
		name string

		givenJSON string

		expectedAuth  map[string]docker.Auth
		expectedError error

		isLegacy bool
	}{
		{
			name:         "Should return empty credentials when content is empty JSON object",
			givenJSON:    "{}",
			expectedAuth: map[string]docker.Auth{},
		},
		{
			name:         "Should return empty credentials when content is null JSON",
			givenJSON:    "null",
			expectedAuth: map[string]docker.Auth{},
		},
		{
			name:          "Should return error when content is blank",
			givenJSON:     "",
			expectedError: errors.New("unexpected end of JSON input"),
		},
		{
			name: "Should return server credentials stored as username and password encoded in the auth property",
			givenJSON: `{
							"auths": {
								"https://index.docker.io/v1/": {
									"auth": "ZG9ja2VyOmh1Yg=="
								},
								"harbor.domain": {
									"auth": "YWRtaW46SGFyYm9yMTIzNDU="
								}
							}
						}`,
			expectedAuth: map[string]docker.Auth{
				"https://index.docker.io/v1/": {
					Auth:     "ZG9ja2VyOmh1Yg==",
					Username: "docker",
					Password: "hub",
				},
				"harbor.domain": {
					Auth:     "YWRtaW46SGFyYm9yMTIzNDU=",
					Username: "admin",
					Password: "Harbor12345",
				},
			},
		},
		{
			name: "Should return server credentials stored in username and password properties",
			givenJSON: `{
							"auths": {
								"https://index.docker.io/v1/": {
									"auth": "ZG9ja2VyOmh1Yg=="
								},
								"harbor.domain": {
									"username": "admin",
									"password": "Harbor12345"
								}
							}
						}`,
			expectedAuth: map[string]docker.Auth{
				"https://index.docker.io/v1/": {
					Auth:     "ZG9ja2VyOmh1Yg==",
					Username: "docker",
					Password: "hub",
				},
				"harbor.domain": {
					Username: "admin",
					Password: "Harbor12345",
				},
			},
		},
		{
			name: "Should skip empty server entries",
			givenJSON: `{
						"auths": {
						"https://index.docker.io/v1/": {

						},
						"harbor.domain": {
							"auth": "YWRtaW46SGFyYm9yMTIzNDU="
						}
						}
					}`,
			expectedAuth: map[string]docker.Auth{
				"harbor.domain": {
					Auth:     "YWRtaW46SGFyYm9yMTIzNDU=",
					Username: "admin",
					Password: "Harbor12345",
				},
			},
		},
		{
			name: "Should return error when auth is not username and password concatenated with a colon",
			givenJSON: `{
							"auths": {
								"my-registry.domain.io": {
									"auth": "b25seXVzZXJuYW1l"
								}
							}
						}`,
			expectedError: errors.New("expected username and password concatenated with a colon (:)"),
		},
		{
			name:     "Should process legacy .dockercfg json",
			isLegacy: true,
			givenJSON: `{
							"https://index.docker.io/v1/": {
								"auth": "ZG9ja2VyOmh1Yg=="
							},
							"harbor.domain": {
								"auth": "YWRtaW46SGFyYm9yMTIzNDU="
							}
						}`,
			expectedAuth: map[string]docker.Auth{
				"https://index.docker.io/v1/": {
					Auth:     "ZG9ja2VyOmh1Yg==",
					Username: "docker",
					Password: "hub",
				},
				"harbor.domain": {
					Auth:     "YWRtaW46SGFyYm9yMTIzNDU=",
					Username: "admin",
					Password: "Harbor12345",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dockerConfig := &docker.Config{}
			err := dockerConfig.Read([]byte(tc.givenJSON), tc.isLegacy)
			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error())
			default:
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedAuth, dockerConfig.Auths)
			}
		})

	}
}

func TestGetServerFromDockerAuthKey(t *testing.T) {
	testCases := []struct {
		authKey        string
		expectedServer string
	}{
		{
			authKey:        "34.86.43.13:80",
			expectedServer: "34.86.43.13:80",
		},
		{
			authKey:        "core.harbor.domain:8080",
			expectedServer: "core.harbor.domain:8080",
		},
		{
			authKey:        "rg.pl-waw.scw.cloud/trivyoperator",
			expectedServer: "rg.pl-waw.scw.cloud",
		},
		{
			authKey:        "rg.pl-waw.scw.cloud:7777/private",
			expectedServer: "rg.pl-waw.scw.cloud:7777",
		},
		{
			authKey:        "registry.aquasec.com",
			expectedServer: "registry.aquasec.com",
		},
		{
			authKey:        "https://index.docker.io/v1/",
			expectedServer: "index.docker.io",
		},
		{
			authKey:        "https://registry:3780/",
			expectedServer: "registry:3780",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.authKey, func(t *testing.T) {
			server, err := docker.GetServerFromDockerAuthKey(tc.authKey)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedServer, server)
		})
	}
}

func TestGetServerFromImageRef(t *testing.T) {
	testCases := []struct {
		imageRef       string
		expectedServer string
	}{
		{
			imageRef:       "nginx:1.16",
			expectedServer: "index.docker.io",
		},
		{
			imageRef:       "aquasec/trivy:0.10.0",
			expectedServer: "index.docker.io",
		},
		{
			imageRef:       "docker.io/aquasec/harbor-scanner-trivy:0.10.0",
			expectedServer: "index.docker.io",
		},
		{
			imageRef:       "index.docker.io/aquasec/harbor-scanner-trivy:0.10.0",
			expectedServer: "index.docker.io",
		},
		{
			imageRef:       "gcr.io/google-samples/hello-app:1.0",
			expectedServer: "gcr.io",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.imageRef, func(t *testing.T) {
			server, err := docker.GetServerFromImageRef(tc.imageRef)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedServer, server)
		})
	}
}

func TestBasicAuth_Decode(t *testing.T) {
	testCases := []struct {
		name  string
		v     docker.BasicAuth
		want  string
		want1 string
	}{
		{
			name: "Decode GCR",
			v:    docker.BasicAuth("X2pzb25fa2V5OnsKICAidHlwZSI6ICJzZXJ2aWNlX2FjY291bnQiLAogICJwcm9qZWN0X2lkIjogInRlc3QiLAogICJwcml2YXRlX2tleV9pZCI6ICIzYWRhczM0YXNkYXMzNHdhZGFkIiwKICAicHJpdmF0ZV9rZXkiOiAiLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXG4tLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tXG4iLAogICJjbGllbnRfZW1haWwiOiAidGVzdEB0ZXN0LmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKICAiY2xpZW50X2lkIjogIjM0MzI0MjM0MzI0MzI0IiwKICAiYXV0aF91cmkiOiAiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tL28vb2F1dGgyL2F1dGgiLAogICJ0b2tlbl91cmkiOiAiaHR0cHM6Ly9vYXV0aDIuZ29vZ2xlYXBpcy5jb20vdG9rZW4iLAogICJhdXRoX3Byb3ZpZGVyX3g1MDlfY2VydF91cmwiOiAiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vb2F1dGgyL3YxL2NlcnRzIiwKICAiY2xpZW50X3g1MDlfY2VydF91cmwiOiAiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vcm9ib3QvdjEvbWV0YWRhdGEveDUwOS90ZXN0LWdjci1mNWRoM2g1ZyU0MHRlc3QuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iCn0="),
			want: "_json_key",
			want1: `{
  "type": "service_account",
  "project_id": "test",
  "private_key_id": "3adas34asdas34wadad",
  "private_key": "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
  "client_email": "test@test.iam.gserviceaccount.com",
  "client_id": "34324234324324",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test-gcr-f5dh3h5g%40test.iam.gserviceaccount.com"
}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, got1, err := tc.v.Decode()
			require.NoError(t, err)
			assert.Equalf(t, tc.want, got, "Decode()")
			assert.Equalf(t, tc.want1, got1, "Decode()")
		})
	}
}
