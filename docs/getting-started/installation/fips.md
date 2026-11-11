# FIPS 140-3

Trivy Operator provides a FIPS image tagged `<version>-ubi9-fips` for `linux/amd64` and `linux/arm64`:

```
mirror.gcr.io/aquasec/trivy-operator:<version>-ubi9-fips
public.ecr.aws/aquasecurity/trivy-operator:<version>-ubi9-fips
```

The operator binary in this image uses a FIPS 140-3 validated cryptographic module: the native
[Go Cryptographic Module][go-fips] v1.0.0, covered by [CMVP certificate #5247][cmvp-5247]. It is selected at build time
with `GOFIPS140=certified`. The binary is statically linked and does not depend on the cryptographic libraries of the
base image or the host.

!!! note
    The certificate covers the cryptographic module, not Trivy Operator as a whole. See the security policy attached to
    the certificate for the approved algorithms and tested operational environments.

## Modes

FIPS mode is controlled by the `fips140` setting of the `GODEBUG` environment variable:

| `GODEBUG`      | Behavior                                                                                                                                                                                                   |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `fips140=on`   | Default for the FIPS image. Approved algorithms are served by the FIPS 140-3 module, and `crypto/tls` negotiates only FIPS-approved protocol versions, cipher suites, signature algorithms and key exchanges. |
| `fips140=only` | Same as `on`, and additionally non-approved algorithms return an error or panic. Use it only after verifying that your environment (registries, Kubernetes API server, cloud providers) works with it.       |

When FIPS mode is enabled, the operator logs it at startup:

```
INFO main FIPS 140-3 mode enabled {"moduleVersion": "v1.0.0", "enforced": false}
```

## Installing with Helm

```bash
helm install trivy-operator aqua/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --set image.tag=<version>-ubi9-fips
```

To enforce the strict mode, add the `GODEBUG` variable:

```yaml
image:
  tag: <version>-ubi9-fips
extraEnv:
  - name: GODEBUG
    value: fips140=only
```

## Limitations

The FIPS image covers only the operator itself. Scan jobs run other images, such as Trivy (`trivy.image`) and the node
collector (`nodeCollector`), which must be configured separately if your compliance requirements cover them as well.

[go-fips]: https://go.dev/doc/security/fips140
[cmvp-5247]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247
