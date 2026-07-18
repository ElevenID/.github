# ElevenID GitHub defaults

Organization-wide community health files, reusable workflows, and public
repository policy checks for the Marty open-source projects.

The files in this repository are inherited by ElevenID repositories that do
not provide a repository-specific override.

The workflow policy requires Node 24 for JavaScript tooling and rejects known
Node-20-based Action revisions. Repositories containing code manifests also
provide `dependency-health.yml`; temporary dependency exceptions expire and
must link to their owner, upstream project, decision, and public tracking work.
