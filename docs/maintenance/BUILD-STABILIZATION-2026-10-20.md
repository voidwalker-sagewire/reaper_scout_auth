# Build stabilization — BUILD-STAB-20261020

Date: 2026-10-20
Status: Prepared on an isolated branch; merge, deployment, and field acceptance are not performed by this change.

## Authorization and baseline

Michael David Miller authorized preparation of the build stabilization changes in the Mobile Development Brief conversation on October 20, 2026.

Repository: `voidwalker-sagewire/reaper_scout_auth`
Target branch: `main`
Inspected source commit: `491e506be1f16b347cce7eb2b79799b160ec1de1`

## Problem and change

GitHub is moving `ubuntu-latest` from Ubuntu 24.04 to Ubuntu 26.04 during October 19–November 19, 2026. Pin 1 job to `ubuntu-24.04` so the workflows do not inherit that major OS change automatically.

- `.github/workflows/test.yml`

This pins the OS release, not an immutable runner image. GitHub still updates the Ubuntu 24.04 image, and existing action tags and dependency constraints keep their existing behavior.

## Scope and validation boundary

Only runner labels and maintenance documentation change. Existing triggers, permissions, commands, dependencies, signing, artifact retention, product versions, and deployment behavior are preserved. This work does not merge the branch, publish an app, deploy a service, flash firmware, or establish field acceptance.

Local validation compares parsed workflow structure before and after: only `jobs.*.runs-on` may differ, and every changed label must be `ubuntu-24.04`. Remote source is read back after writing. Existing GitHub event rules determine whether CI runs; the pull request checks/run history are the authority for compiler and test results. A runner-label pin alone is not a claim of passing CI.

Deployment, release-signing, and automatic version-bump workflows are not manually dispatched for validation. Any workflow limited to pushes on its target branch cannot be runtime-verified from this preparation branch without a separate approved trigger change or test dispatch.

## Resume point

Review this maintenance-only diff and available CI results before merging into `main`. Prepare a separate Ubuntu 26.04 compatibility test when migration is desired; do not remove this pin merely because the label migration completes. Existing product work orders and release/field acceptance states retain their authority.

Source: https://github.blog/changelog/2026-09-17-ubuntu-26-generally-available-and-latest-migration/
