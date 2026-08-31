# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/chrj/rust-spamhaus-submission/compare/v0.1.0...v0.1.1) - 2026-08-31

### Fixed

- use threat type codes the API accepts ([#11](https://github.com/chrj/rust-spamhaus-submission/pull/11))

## [0.1.0](https://github.com/chrj/rust-spamhaus-submission/releases/tag/v0.1.0) - 2026-08-31

### Added

- add async client for the Spamhaus Submission Portal API

### Changed

- move response handling out of the client impl

### Documentation

- add readme and a live example

### Fixed

- keep an email subject that is not a string ([#7](https://github.com/chrj/rust-spamhaus-submission/pull/7))
- stop next_page from overflowing the page number ([#5](https://github.com/chrj/rust-spamhaus-submission/pull/5))
- keep email source out of Debug on responses ([#6](https://github.com/chrj/rust-spamhaus-submission/pull/6))
- keep a threat scope this crate does not know ([#4](https://github.com/chrj/rust-spamhaus-submission/pull/4))
