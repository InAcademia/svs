# Changelog
All notable changes to InAcademia SVS will be documented in this file.

## [Unreleased]

## [Released]
## 2.6.0
## 2020-12-03
- Change IdP attributes logline to INFO

## 2020-11-27
- Add logline for received IdP attributes to backend

## 2020-11-25
### Added
- Error handling when a user requests 'persistent' scope but SVS is unable to construct/retrieve persistent user id for that user due to insufficient information from IdP. 

## 2020-11-18
### Changed
- Fixed the position of transaction logging code 500
### Added
- New transaction logging code 600 (Logged when there is an authentication error from IdP)

## 2020-11-13
### Added
- Error handling against authentication error from IdP 

## 2020-11-24
- Updated translations

## 2020-11-03
- Fixed Consent handler endpoint

## 2020-10-20
### Added
- Added pull request template to the repository

## 2.5.0
## 2020-09-24
### Added
- Attribute override micro_service, see attribute_override.yaml.example how to use
