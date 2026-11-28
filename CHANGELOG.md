# Changelog

## Unreleased

- Introduce the native KyMessages server with direct messages, channels, threaded
  replies, attachments, Web Push, voice and video calls, and guest meetings.
- Add KyIdentity sign-in and directory sync, SCIM provisioning, and an operator
  console for workspace settings, agents, audit logs, and backups.
- Support single-instance SQLite deployments with sealed KyRecovery backup
  capsules and an encrypted attachment mirror. See the [restore guide](docs/RESTORE.md).
- Publish native container images to `ghcr.io/busnes-app/kymessages` after the
  first release. Follow the [setup guide](README.md#container-image-and-docker-compose)
  for local previews and the [product definition](docs/PRODUCT.md) for encryption
  and hosted tenancy release gates.
