# Releasing

1. Checkout your fork and make sure it's up-to-date with the `upstream`

   ```console
   $ git remote -v
   origin     git@github.com:<your account>/trivy-operator.git (fetch)
   origin     git@github.com:<your account>/trivy-operator.git (push)
   upstream   git@github.com:aquasecurity/trivy-operator.git (fetch)
   upstream   git@github.com:aquasecurity/trivy-operator.git (push)
   ```

   ```sh
   git pull -r
   git fetch upstream
   git merge upstream/main
   git push
   ```

2. Prepare release by creating the PR with the following changes
   1. In [`deploy/helm/Chart.yaml`]
      1. Update the `version` property (if change automatically will release a new chart)
      2. Update the `appVersion` property
   2. Update the `app.kubernetes.io/version` labels in the following files:
      1. [`deploy/static/namespace.yaml`]
      2. [`deploy/helm/templates/specs/nsa-1.0.yaml`]
   3. Update static resources from Helm chart by running the mage target:

      ```sh
      mage generate:manifests
      ```

   4. In [`mkdocs.yml`]
      1. Update the `extra.var.prev_git_tag` property
      2. Update the `extra.var.chart_version` property
3. Review and merge the PR (make sure all tests are passing)
4. Update your fork again

   ```sh
   git pull -r
   git fetch upstream
   git merge upstream/main
   git push
   ```

5. Create an annotated git tag and push it to the `upstream`. This will trigger the [`.github/workflows/release.yaml`] workflow

   ```sh
   git tag -v0.17.0 -m 'Release v0.17.0'
   git push upstream v0.17.0
   ```

6. Verify that the `release` workflow has built and published the following artifacts
   1. Trivy-operator container images published to DockerHub
       `docker.io/aquasec/trivy-operator:0.17.0`
   2. Trivy-operator container images published to Amazon ECR Public Gallery
       `public.ecr.aws/aquasecurity/trivy-operator:0.17.0`
   3. Trivy-operator container images published to GitHub Container Registry
       `ghcr.io/aquasecurity/trivy-operator:0.17.0`

7. Submit trivy-operator Operator to OperatorHub and ArtifactHUB by opening the PR to the <https://github.com/k8s-operatorhub/community-operators> repository.

[`deploy/helm/Chart.yaml`]: ./deploy/helm/Chart.yaml
[`deploy/static/namespace.yaml`]: ./deploy/static/namespace.yaml
[`deploy/helm/templates/specs/nsa-1.0.yaml`]: ./deploy/helm/templates/specs/nsa-1.0.yaml
[`mkdocs.yml`]: ./mkdocs.yml
[`.github/workflows/release.yaml`]: ./.github/workflows/release.yaml
