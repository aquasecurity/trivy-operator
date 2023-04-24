package docker

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	containerimage "github.com/google/go-containerregistry/pkg/name"
)

type BasicAuth string

func NewBasicAuth(username, password string) BasicAuth {
	var v = new(BasicAuth)
	v.Encode(username, password)
	return *v
}

func (v *BasicAuth) Encode(username, password string) {
	*v = BasicAuth(base64.StdEncoding.EncodeToString(
		[]byte(fmt.Sprintf("%s:%s", username, password))))
}

func (v *BasicAuth) Decode() (string, string, error) {
	bytes, err := base64.StdEncoding.DecodeString(string(*v))
	if err != nil {
		return "", "", err
	}
	split := strings.SplitN(string(bytes), ":", 2)
	if len(split) != 2 {
		return "", "", fmt.Errorf("expected username and password concatenated with a colon (:)")
	}
	return split[0], split[1], nil
}

func (v BasicAuth) String() string {
	return "[REDACTED]"
}

// Auth represent credentials used to login to a Docker registry.
type Auth struct {
	Auth     BasicAuth `json:"auth,omitempty"`
	Username string    `json:"username,omitempty"`
	Password string    `json:"password,omitempty"`
}

func (v Auth) String() string {
	return "[REDACTED]"
}

// Config represents Docker configuration which is typically saved as `~/.docker/config.json`.
type Config struct {
	Auths map[string]Auth `json:"auths"`
}

func (c *Config) Read(contents []byte, isLegacy bool) error {
	if isLegacy {
		// Because ~/.dockercfg contents is "auths" field in ~/.docker/config.json
		// we can simply pass it to "Auths" field of Config
		auths := make(map[string]Auth)
		if err := json.Unmarshal(contents, &auths); err != nil {
			return err
		}
		*c = Config{
			Auths: auths,
		}
	} else {
		if err := json.Unmarshal(contents, c); err != nil {
			return err
		}
	}
	var err error
	c.Auths, err = decodeAuths(c.Auths)
	return err
}

func decodeAuths(auths map[string]Auth) (map[string]Auth, error) {
	decodedAuths := make(map[string]Auth)
	for server, entry := range auths {
		if entry == (Auth{}) {
			continue
		}

		if strings.TrimSpace(string(entry.Auth)) == "" {
			decodedAuths[server] = Auth{
				Username: entry.Username,
				Password: entry.Password,
			}
			continue
		}

		username, password, err := entry.Auth.Decode()
		if err != nil {
			return nil, err
		}

		decodedAuths[server] = Auth{
			Auth:     entry.Auth,
			Username: username,
			Password: password,
		}

	}
	return decodedAuths, nil
}

func (c Config) Write() ([]byte, error) {
	bytes, err := json.Marshal(&c)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// GetServerFromImageRef returns registry server from the specified imageRef.
func GetServerFromImageRef(imageRef string) (string, error) {
	ref, err := containerimage.ParseReference(imageRef)
	if err != nil {
		return "", err
	}
	return ref.Context().RegistryStr(), nil
}

// GetServerFromDockerAuthKey returns the registry server for the specified Docker auth key.
//
// In ~/.docker/config.json auth keys can be specified as URLs or host names.
// For the sake of comparison we need to normalize the registry identifier.
func GetServerFromDockerAuthKey(key string) (string, error) {

	if !(strings.HasPrefix(key, "http://") || strings.HasPrefix(key, "https://")) {
		key = fmt.Sprintf("https://%s", key)
	}

	parsed, err := url.Parse(key)
	if err != nil {
		return "", err
	}

	return parsed.Host, nil
}
