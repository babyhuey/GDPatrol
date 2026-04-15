# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Integration with AWS Bedrock Claude Sonnet for enhanced Slack message processing
- Comprehensive test suite using pytest for lambda function
- Mock AWS services using moto for testing
- Test fixtures for AWS services and environment variables
- Test cases for various message scenarios including:
  - Basic message processing
  - IP address validation
  - AWS resource detection
  - Error handling
  - Message formatting

### Changed
- Updated lambda function to use AWS Bedrock for message enhancement
- Improved message formatting with better structure and readability
- Enhanced error handling and logging

### Fixed
- IP address validation logic
- Environment variable handling in tests
- Import issues with moto library
- Configuration file handling in tests 

### Security & Reliability Improvements
- Aggressive NACL cleanup: when NACL deny rules approach the AWS limit, automatically delete all but the 10 most recent deny rules before adding a new one
- Rule number wraparound: when rule numbers reach the lower bound, start over at 32700 and delete any existing rule at that number
- Improved reliability for blacklisting IPs even when NACLs are near their entry limits
- Enhanced logging for NACL cleanup and blacklisting actions 