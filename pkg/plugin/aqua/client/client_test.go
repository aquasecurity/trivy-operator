package client_test

import (
	"net/http"

	"github.com/aquasecurity/trivy-operator/pkg/plugin/aqua/client"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/ghttp"
)

var _ = Describe("The Aqua API client", func() {

	var server *Server
	var aquaClient client.Clientset

	BeforeEach(func() {
		server = NewServer()
		server.AppendHandlers(
			CombineHandlers(
				VerifyRequest("GET", "/api"),
				RespondWith(http.StatusOK, `{"authorization_header":"Authorization"}`),
			),
		)
		aquaClient, _ = client.NewClient(server.URL(), client.Authorization{
			Basic: &client.UsernameAndPassword{
				Username: "administrator",
				Password: "bdclz",
			},
		})
	})

	Describe("get auth header", func() {
		var server *Server
		BeforeEach(func() {
			server = NewServer()
			server.AppendHandlers(CombineHandlers(
				VerifyRequest("GET", "/api"),
				RespondWith(http.StatusOK, `{"authorization_header":"Authorization"}`),
			),
			)
		})
		Context("when the request succeeds", func() {
			It("should make a request to fetch registries", func() {
				_, err := client.NewClient(server.URL(), client.Authorization{
					Basic: &client.UsernameAndPassword{
						Username: "administrator",
						Password: "bdclz",
					},
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(server.ReceivedRequests()).To(HaveLen(1))
			})
		})
	})

	Describe("fetching registries", func() {
		var returnedRegistries []client.RegistryResponse
		var statusCode int

		BeforeEach(func() {
			returnedRegistries = []client.RegistryResponse{
				{Name: "Docker Hub", Type: "HUB", URL: "https://docker.io"},
				{Name: "Harbor", Type: "HARBOR", Prefixes: []string{"core.harbor.domain"}},
			}
			server.AppendHandlers(
				CombineHandlers(
					VerifyRequest("GET", "/api/v1/registries"),
					VerifyBasicAuth("administrator", "bdclz"),
					VerifyMimeType("application/json"),
					VerifyHeader(http.Header{
						"User-Agent": []string{"TrivySecurityOperator"},
					}),
					RespondWithJSONEncodedPtr(&statusCode, &returnedRegistries),
				),
			)
		})

		Context("when the request succeeds", func() {
			BeforeEach(func() {
				statusCode = http.StatusOK
			})

			It("should make a request to fetch registries", func() {
				registries, err := aquaClient.Registries().List()
				Expect(err).ToNot(HaveOccurred())
				Expect(registries).To(Equal(returnedRegistries))
				Expect(server.ReceivedRequests()).To(HaveLen(2))
			})
		})

		Context("when the response is unauthorized", func() {
			BeforeEach(func() {
				statusCode = http.StatusUnauthorized
			})

			It("should return error", func() {
				_, err := aquaClient.Registries().List()
				Expect(err).To(MatchError(client.ErrUnauthorized))
				Expect(server.ReceivedRequests()).To(HaveLen(2))
			})
		})
	})

	Describe("fetching vulnerabilities", func() {
		var returnedVulnerabilities client.VulnerabilitiesResponse
		var statusCode int

		BeforeEach(func() {
			returnedVulnerabilities = client.VulnerabilitiesResponse{
				Count: 2,
				Results: []client.VulnerabilitiesResponseResult{
					{
						Registry:            "Harbor",
						ImageRepositoryName: "library/nginx",
						Resource: client.Resource{
							Type:    "package",
							Format:  "deb",
							Path:    "",
							Name:    "libxml2",
							Version: "2.9.4+dfsg1-7+b3",
						},
						Name:              "CVE-2020-3909",
						AquaSeverity:      "high",
						AquaVectors:       "AV:N/AC:L/Au:N/C:P/I:P/A:P",
						AquaScoringSystem: "CVSS V2",
						FixVersion:        "",
					},
					{
						Registry:            "Harbor",
						ImageRepositoryName: "library/nginx",
						Resource: client.Resource{
							Type:    "package",
							Format:  "deb",
							Path:    "",
							Name:    "libxml2",
							Version: "2.9.4+dfsg1-7+b3",
						},
						Name:              "CVE-2020-3910",
						AquaSeverity:      "high",
						AquaVectors:       "AV:N/AC:L/Au:N/C:P/I:P/A:P",
						AquaScoringSystem: "CVSS V2",
						FixVersion:        "",
					},
				},
			}
			server.AppendHandlers(
				CombineHandlers(
					VerifyRequest("GET", "/api/v2/images/Harbor/library/nginx/1.17/vulnerabilities"),
					VerifyBasicAuth("administrator", "bdclz"),
					VerifyMimeType("application/json"),
					VerifyHeader(http.Header{
						"User-Agent": []string{"TrivySecurityOperator"},
					}),
					RespondWithJSONEncodedPtr(&statusCode, &returnedVulnerabilities),
				),
			)
		})

		Context("when the request succeeds", func() {
			BeforeEach(func() {
				statusCode = http.StatusOK
			})

			It("should make a request to fetch vulnerabilities", func() {
				vulnerabilities, err := aquaClient.Images().Vulnerabilities("Harbor", "library/nginx", "1.17")
				Expect(err).ToNot(HaveOccurred())
				Expect(vulnerabilities).To(Equal(returnedVulnerabilities))
				Expect(server.ReceivedRequests()).To(HaveLen(2))
			})
		})

		Context("when the request is unauthorized", func() {
			BeforeEach(func() {
				statusCode = http.StatusUnauthorized
			})

			It("should return error", func() {
				_, err := aquaClient.Images().Vulnerabilities("Harbor", "library/nginx", "1.17")
				Expect(err).To(MatchError(client.ErrUnauthorized))
				Expect(server.ReceivedRequests()).To(HaveLen(2))
			})
		})
	})

	AfterEach(func() {
		// shut down the server between tests
		server.Close()
	})

})
