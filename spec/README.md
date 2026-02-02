# OVRSE Specification

This directory contains the evolving specification for the OVRSE Project.

OVRSE has three core pieces:

1. **OVRS Templates**  
   Reusable remediation patterns that describe *how* to fix issues on a given surface (operating systems, packages, cloud resources, services).

2. **Knowledge Base Entities**  
   Data structures that connect templates to real world vulnerabilities and releases such as CVEs and package versions.

3. **Plans and Execution**  
   The runtime shape of an instantiated remediation plan derived from templates, mappings, and inventory. Plans are what execution engines actually run.

For v1 the focus is on:

- Linux workloads (Debian, Ubuntu, RHEL and related families)
- Package level vulnerabilities (kernel, OS packages, server software)
- A small set of cloud configuration fixes (storage buckets and security groups)

The goal of this specification is to give:

- A repeatable shape for how remediation is described
- Enough structure for planners and engines to reason about safety, validation and rollback
- A clean boundary between *what is vulnerable* (upstream data such as OSV and CSAF) and *how to fix it in a given environment* (OVRS)

## Documents

- [`SPEC.md`](./SPEC.md)
  Overview of OVRSE with architecture diagrams and entry points.

- [`template-spec-v1.md`](./template-spec-v1.md)
  Defines the structure of an OVRS remediation template.

- [`kb-spec-v1.md`](./kb-spec-v1.md)
  Defines the structures used in the knowledge base: CveMapping (with extensions) and PackageRelease (with dependencies).

- [`extensions-spec-v1.md`](./extensions-spec-v1.md)
  Defines extension namespaces including `intel.emphere.dev/v1` for CVE intelligence.

## Architecture

OVRSE follows a three-layer architecture:

1. **Spec Layer (Static)** - Document schemas (CveMapping, PackageRelease, RemediationTemplate)
2. **Intelligence Layer (Dynamic)** - Analysis data attached via extensions (e.g., `intel.emphere.dev/v1`)
3. **Planning Layer (Computed)** - Remediation plans computed at runtime from spec + intelligence

See [SPEC.md](./SPEC.md) for details.
