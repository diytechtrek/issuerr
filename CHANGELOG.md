# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet

### Changed
- Nothing yet

### Fixed
- Nothing yet

## [1.0.0] - 2024-XX-XX

### Added
- Initial release
- Automatic issue processing for Overseerr webhooks
- Support for both TV shows (Sonarr) and movies (Radarr)
- Web-based configuration dashboard
- Secure authentication with bcrypt password hashing
- Password strength validation using zxcvbn
- Rate limiting on sensitive endpoints
- Real-time log viewing
- Queue-based webhook processing
- Health check endpoint for monitoring
- Docker support with PUID/PGID configuration
- Reverse proxy documentation for nginx and Traefik

### Security
- bcrypt password hashing with 12 rounds
- Timing-safe credential comparison
- HTTPOnly, SameSite session cookies
- Dynamic Secure flag based on HTTPS detection
- Non-root container execution
- Rate limiting to prevent brute force attacks
- API key masking in responses

---

## Version History

### Versioning Scheme

- **MAJOR**: Incompatible API changes or breaking config changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Upgrade Notes

When upgrading between versions, check this section for any required actions.

#### Upgrading to 1.x

No special upgrade steps required - this is the initial release.

---

[Unreleased]: https://github.com/diytecktrek/issuerr/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/diytecktrek/issuerr/releases/tag/v1.0.0
