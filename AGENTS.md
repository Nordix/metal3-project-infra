# Metal3 project infrastructure

CI for all Metal3 repositories: Prow configuration and jobs, the Prow
cluster itself, Jenkins pipelines for the heavier E2E jobs, and CI
images. Overview: [README.md](README.md), [prow/README.md](prow/README.md),
[jenkins/README.md](jenkins/README.md). Contribution rules: the
[Metal3 community guide](https://github.com/metal3-io/community/blob/main/CONTRIBUTING.md).

This file holds only what you cannot cheaply infer from the code. Where it
disagrees with the code or the configs, trust those and report the
mismatch.

## AI-assisted contributions

Metal3 follows the CNCF and
[Linux Foundation generative AI policy](https://www.linuxfoundation.org/legal/generative-ai).

- AI is a tool. The human who opens a PR is its author and is responsible
  for every line of it, including licensing and third-party content.
- Review is a conversation between humans. A PR where an agent or bot
  answers reviewers will be closed. Agents may draft changes; the
  contributor reads them, understands them, and replies personally.

- Keep changes surgical. The smallest complete change that solves the
  stated problem wins. Every added file, function, flag, dependency or
  test helper must trace to that problem; anything that does not is
  bloat and gets removed. Prefer reusing existing code over new code.
  Report unrelated findings instead of fixing them in the same PR.

## Repository map

- `prow/config/`: Prow `config.yaml`, `plugins.yaml`, `labels.yaml`, and
  jobs under `jobs/<org>/<repo>.yaml`, with one extra file per release
  branch (`<repo>-release-<x.y>.yaml`).
- Other `prow/` directories: the Prow cluster (CAPO cluster, bootstrap,
  CAPI, add-ons, Prow manifests, Flux), described in
  [prow/README.md](prow/README.md). `prow/container-images/` builds the
  shared `basic-checks` image that most repositories' Go lint and unit
  jobs run in.
- `jenkins/jobs/`: Jenkins declarative pipelines (Groovy). The Jenkins
  job definitions (JJB) are not here; they live in the Nordix Gerrit
  `infra/cicd` repository under `jjb/metal3/`.
- `jenkins/scripts/`, `jenkins/image_building/`: what the pipelines run,
  and the node and CI image builds.

## Testing

- Checks: the presubmits in
  `prow/config/jobs/metal3-io/project-infra.yaml` and
  `.github/workflows/`. Most lint presubmits have a matching `hack/*.sh`
  script, which runs in a container (`CONTAINER_RUNTIME`, default
  `podman`). `cd prow && make validate` runs the same
  `checkconfig --strict` as the `check-prow-config` job.
- Conventions are whatever the existing configs, pipelines and scripts
  do. Read neighboring files before writing new ones. New words that
  spellcheck rejects go in `.cspell-config.json`.
- Before finishing, run `cd prow && make validate` for any `prow/config/`
  change and the `hack/` checks for the file types you touched. All must
  pass.
- Jenkins pipelines and their scripts can only be exercised in CI. On a
  project-infra PR the pipelines check out the PR commit, so trigger the
  affected Jenkins job with `/test <job>`.
- Do not run anything against real infrastructure unless the user asks:
  `kubectl`, `clusterctl`, `openstack` or `s3cmd` against the Prow
  cluster or clouds, `jenkins/scripts/`, `jenkins/image_building/`, or
  `hack/clean_artifactory.sh`. They need production credentials and
  change shared infrastructure. `hack/ipa_debug_tools.sh` runs `sudo` on
  the host.

## Invariants

These apply to writing and to reviewing changes.

- **Merge is deploy.** On merge to `main`, `config-updater` pushes
  `config.yaml`, `plugins.yaml`, `labels.yaml` and `jobs/**` into the
  live Prow ConfigMaps, and Flux syncs `prow/flux` (which includes
  `prow/capi`) from `main`. Jenkins pipelines check out project-infra
  `main` for every repository except project-infra PRs. Other
  `prow/` manifests are applied by hand by maintainers.
- **Blast radius.** One change here can break CI or merging for every
  repository under `prow/config/jobs/`. Presubmits without
  `optional: true` are required merge checks once they run. When changing
  a job on `main`, check whether the release-branch files need the same
  change.
- **Security.** Never weaken security to make something work: no secrets
  in git, no secrets printed in logs (watch `set -x`), no disabled TLS
  verification, no broadened token scopes or workflow `permissions:`.
  Secrets reach the cluster only through External Secrets
  (`*externalsecret*.yaml`). Call out any change to triggers, OWNERS,
  tokens, Secrets, workflow permissions or `pull_request_target` in the
  PR description.
- **Trust and isolation.** Review these areas with extra care:
   - Untrusted code. Presubmits and pull request workflows run PR code,
     from outside contributors after `/ok-to-test`. Never mount Secrets
     into Prow presubmits; today only `jobs/periodics.yaml` does.
     Jenkins pipelines bind credentials with `withCredentials`, and in a
     job that PRs trigger, the PR code can read them. Do not add
     credentials to such jobs.
   - Shared namespace. Job pods run in `test-pods`, Prow components in
     `prow`. A Secret in `test-pods` is available to any job definition
     that mounts it.
   - Merge rights. `/lgtm` and `/approve` come from each repository's
     `OWNERS`; Prow plugins and Tide merge rules come from `plugins.yaml`
     and `config.yaml`. Changes there change who can merge or run CI.
- **Pinning.** Pin new container images by digest and GitHub Actions by
  commit SHA. Exception: images under the prefixes in
  `prow/config/generic-autobumper-config.yaml` stay tag-pinned so the
  `autobump-prow-images` periodic can bump them.

## External references

- [Metal3 Prow dashboard](https://prow.apps.test.metal3.io)
- [Metal3 Jenkins view](https://jenkins.nordix.org/view/Metal3/)
- [Nordix Gerrit infra/cicd (JJB job definitions)](https://gerrit.nordix.org/admin/repos/infra/cicd)
- [Prow job documentation](https://docs.prow.k8s.io/docs/jobs/)
- [Prow config-updater plugin](https://docs.prow.k8s.io/docs/components/plugins/updateconfig/)
