package client

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	defaultTimeout = 30 * time.Second
	userAgent      = "TrivySecurityOperator"
)

var ErrNotFound = errors.New("not found")
var ErrUnauthorized = errors.New("unauthorized")

type client struct {
	baseURL       string
	authHeader    string
	authorization Authorization
	httpClient    *http.Client
}

func (c *client) newGetRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("User-Agent", userAgent)
	if auth := c.authorization.Basic; auth != nil {
		req.Header.Add(c.authHeader, fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", auth.Username, auth.Password)))))
	}
	return req, nil
}

// Aqua api has custom auth header, auth header can be get using /api endpoint
func (c *client) getAuthHeader() error {
	url := fmt.Sprintf("%s/api", c.baseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json; charset=UTF-8")
	req.Header.Add("User-Agent", userAgent)
	resp, err := c.httpClient.Do(req)
	if err != nil || resp == nil {
		return err
	}
	var apiInfo map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&apiInfo)
	if err != nil {
		return err
	}
	if header, ok := apiInfo["authorization_header"].(string); ok {
		c.authHeader = header
	} else {
		// Default fallback
		c.authHeader = "Authorization"
	}
	return nil
}

// Clientset defines methods of the Aqua API client.
type Clientset interface {
	Registries() RegistriesInterface
	Images() ImagesInterface
}

type ImagesInterface interface {
	Vulnerabilities(registry, repo, tag string) (VulnerabilitiesResponse, error)
}

type RegistriesInterface interface {
	List() ([]RegistryResponse, error)
}

// Client represents Aqua API client.
//
// Currently it is not possible to generate API clientset from Swagger / Open API specs,
// but if that was possible this implementations would be deprecated.
type Client struct {
	registries *Registries
	images     *Images
}

// NewClient constructs a new API client with the specified base URL and authorization details.
func NewClient(baseURL string, authorization Authorization) (*Client, error) {
	httpClient := &http.Client{
		Timeout: defaultTimeout,
	}
	client := &client{
		baseURL:       baseURL,
		authorization: authorization,
		httpClient:    httpClient,
	}
	err := client.getAuthHeader()
	if err != nil {
		return &Client{}, fmt.Errorf("failed to get authorization header %w", err)
	}

	return &Client{
		images: &Images{
			client: client,
		},
		registries: &Registries{
			client: client,
		},
	}, nil
}

func (c *Client) Images() ImagesInterface {
	return c.images
}

func (c *Client) Registries() RegistriesInterface {
	return c.registries
}

type Images struct {
	client *client
}

func (i *Images) Vulnerabilities(registry, repo, tag string) (VulnerabilitiesResponse, error) {
	url := fmt.Sprintf("%s/api/v2/images/%s/%s/%s/vulnerabilities", i.client.baseURL, registry, repo, tag)

	req, err := i.client.newGetRequest(url)
	if err != nil {
		return VulnerabilitiesResponse{}, err
	}

	resp, err := i.client.httpClient.Do(req)
	if err != nil {
		return VulnerabilitiesResponse{}, err
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return VulnerabilitiesResponse{}, ErrUnauthorized
	case http.StatusNotFound:
		return VulnerabilitiesResponse{}, ErrNotFound
	case http.StatusOK:
		var vulnerabilitiesResponse VulnerabilitiesResponse
		err = json.NewDecoder(resp.Body).Decode(&vulnerabilitiesResponse)
		if err != nil {
			return VulnerabilitiesResponse{}, err
		}
		return vulnerabilitiesResponse, nil
	default:
		return VulnerabilitiesResponse{}, fmt.Errorf("unexpected response status: %s", resp.Status)
	}
}

type Registries struct {
	client *client
}

func (r *Registries) List() ([]RegistryResponse, error) {
	url := fmt.Sprintf("%s/api/v1/registries", r.client.baseURL)
	req, err := r.client.newGetRequest(url)
	if err != nil {
		return nil, err
	}

	resp, err := r.client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	case http.StatusOK:
		var listRegistriesResponse []RegistryResponse
		err = json.NewDecoder(resp.Body).Decode(&listRegistriesResponse)
		if err != nil {
			return nil, err
		}
		return listRegistriesResponse, nil
	default:
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

}
