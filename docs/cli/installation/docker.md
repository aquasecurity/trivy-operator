# Docker

We also release Docker images `aquasec/starboard:{{ git.tag[1:] }}` and
`public.ecr.aws/aquasecurity/starboard:{{ git.tag[1:] }}` to run Starboard as a Docker container or to manually
schedule Kubernetes scan Jobs in your cluster.

```console
$ docker container run --rm public.ecr.aws/aquasecurity/starboard:{{ git.tag[1:] }} version
Starboard Version: {Version:{{ git.tag[1:] }} Commit:{{ git.commit }} Date:{{ git.date.isoformat() }}}
```
