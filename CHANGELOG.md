# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `ovrse scan` command for vulnerability scanning with ecosystem plugins
- `ovrse mcp` command for MCP server (AI assistant integration)
- Ecosystem plugins: npm, pip, golang
- Daily advisory sync from Emphere Intel API
- Release automation with goreleaser
- Container image (Dockerfile)
- Makefile for common development tasks
- EditorConfig for consistent coding style

## [0.1.0] - 2025-01-28

### Added
- Core OVRS specification (templates, KB, extensions)
- CLI commands: validate, plan, plan-host
- Comprehensive documentation (README, CLI reference, specs)

### Known Issues
- v0.x API may change without notice
- Limited template library (community contributions welcome)
