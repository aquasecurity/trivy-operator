# Releasing

1. Checkout your fork and make sure it's up-to-date with the `upstream`
   ```console
   $ git remote -v
   origin     git@github.com:<your account>/trivy-operator.git (fetch)
   origin     git@github.com:<your account>/trivy-operator.git (push)
   upstream   git@github.com:aquasecurity/trivy-operator.git (fetch)
   upstream   git@github.com:aquasecurity/trivy-operator.git (push)
   ```
   ```
   git pull -r
   git fetch upstream
   git merge upstream/main
   git push
   ```
2. Prepare release by creating the PR with the following changes
   1. In [`deploy/helm/Chart.yaml`]
      1. Update the `version` property
      2. Update the `appVersion` property
   2. Update the `app.kubernetes.io/version` labels in the following files:
      1. [`deploy/compliance/aquasecurity.github.io_clustercompliancedetailreports.yaml`]
      2. [`deploy/compliance/aquasecurity.github.io_clustercompliancereports.yaml`]
      3. [`deploy/crd/aquasecurity.github.io_clusterconfigauditreports.yaml`]
      4. [`deploy/crd/aquasecurity.github.io_configauditreports.yaml`]
      5. [`deploy/crd/aquasecurity.github.io_vulnerabilityreports.yaml`]
      6. [`deploy/crd/aquasecurity.github.io_exposedsecretreports.yaml`]
      7. [`deploy/crd/aquasecurity.github.io_rbacassessmentreports.yaml`]
      8. [`deploy/crd/aquasecurity.github.io_clusterrbacassessmentreports.yaml`]
      9. [`deploy/static/01-trivy-operator.ns.yaml`]
      10. [`deploy/specs/nsa-1.0.yaml`]
   3. Update static resources from Helm chart by running the make target:
      ```
      make manifests
      ```
   4. In [`mkdocs.yml`]
      1. Update the `extra.var.prev_git_tag` property
      2. Update the `extra.var.chart_version` property
3. Review and merge the PR (make sure all tests are passing)
4. Update your fork again
   ```
   git pull -r
   git fetch upstream
   git merge upstream/main
   git push
   ```
5. Create an annotated git tag and push it to the `upstream`. This will trigger the [`.github/workflows/release.yaml`] workflow
   ```
   git tag -v0.13.1 -m 'Release v0.13.1'
   git push upstream v0.13.1
   ```
6. Verify that the `release` workflow has built and published the following artifacts
   1. Trivy-operator container images published to DockerHub
       `docker.io/aquasec/trivy-operator:0.13.1`
   2. Trivy-operator container images published to Amazon ECR Public Gallery
       `public.ecr.aws/aquasecurity/trivy-operator:0.13.1`
 7. Publish the Helm chart by manually triggering the [`.github/workflows/publish-helm-chart.yaml`] workflow
8. Publish docs on https://aquasecurity.github.io/trivy-operator/ by manually triggering the [`.github/workflows/publish-docs.yaml`] workflow
9. Submit trivy-operator Operator to OperatorHub and ArtifactHUB by opening the PR to the https://github.com/k8s-operatorhub/community-operators repository.

[`deploy/helm/Chart.yaml`]: ./deploy/helm/Chart.yaml
[`deploy/compliance/aquasecurity.github.io_clustercompliancedetailreports.yaml`]: ./deploy/compliance/clustercompliancedetailreports.crd.yaml
[`deploy/compliance/aquasecurity.github.io_clustercompliancereports.yaml`]: ./deploy/compliance/clustercompliancereports.crd.yaml
[`deploy/crd/aquasecurity.github.io_clusterconfigauditreports.yaml`]: ./deploy/crd/clusterconfigauditreports.crd.yaml
[`deploy/crd/aquasecurity.github.io_configauditreports.yaml`]: ./deploy/crd/configauditreports.crd.yaml
[`deploy/crd/aquasecurity.github.io_vulnerabilityreports.yaml`]: ./deploy/crd/vulnerabilityreports.crd.yaml
[`deploy/crd/aquasecurity.github.io_exposedsecretreports.yaml`]: ./deploy/crd/exposedsecretreports.crd.yaml
[`deploy/crd/aquasecurity.github.io_rbacassessmentreports.yaml`]: ./deploy/crd/rbacassessmentreports.crd.yaml
[`deploy/crd/aquasecurity.github.io_clusterrbacassessmentreports.yaml`]: ./deploy/crd/clusterrbacassessmentreports.crd.yaml
[`deploy/static/01-trivy-operator.ns.yaml`]: ./deploy/static/01-trivy-operator.ns.yaml
[`deploy/specs/nsa-1.0.yaml`]: ./deploy/specs/nsa-1.0.yaml
[`deploy/static/trivy-operator.yaml`]: ./deploy/static/trivy-operator.yaml
[`mkdocs.yml`]: ./mkdocs.yml
[`.github/workflows/release.yaml`]: ./.github/workflows/release.yaml
[`.github/workflows/publish-helm-chart.yaml`]: ./.github/workflows/publish-helm-chart.yaml
[`.github/workflows/publish-docs.yaml`]: ./.github/workflows/publish-docs.yaml
