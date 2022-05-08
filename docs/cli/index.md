# Overview

Starboard CLI is a single executable binary which can be used to find risks, such as vulnerabilities or insecure pod
descriptors, in Kubernetes workloads. By default, the risk assessment reports are stored as instances of
[Custom Resource Definitions].

!!! note
    Even though manual scanning through the command-line is useful, the fact that it's not automated makes it less
    suitable with a large number of Kubernetes resources. Therefore, the [Starboard Operator] provides a better option
    for these scenarios, constantly monitoring built-in Kubernetes resources, such as Deployments and Nodes, and running
    appropriate scanners.

To learn more about the available Starboard CLI commands, run `starboard help` or type a command followed by the
`--help` flag:

```
starboard scan kubehunterreports --help
```

## What's Next?

* Install the command and follow the [Getting Started] guide.

[Custom Resource Definitions]: ./../crds/index.md
[Starboard Operator]: ./../operator/index.md
[Getting Started]: ./getting-started.md

