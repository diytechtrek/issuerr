# Contributing to Issuerr

First off, thank you for considering contributing to Issuerr! It's people like you that make Issuerr such a great tool for the self-hosted media community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Style Guidelines](#style-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

This project and everyone participating in it is governed by our commitment to creating a welcoming environment. By participating, you are expected to uphold this commitment. Please be respectful and constructive in all interactions.

## Getting Started

### Issues

- **Bug Reports**: Use the bug report template and include as much detail as possible
- **Feature Requests**: Use the feature request template and explain the use case
- **Questions**: Use GitHub Discussions instead of issues

### Before Contributing

1. Check existing issues to avoid duplicates
2. For major changes, open an issue first to discuss the approach
3. Fork the repository and create your branch from `main`

## How Can I Contribute?

### Reporting Bugs

A good bug report includes:

- Clear, descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Screenshots (if applicable)
- Environment details:
  - Docker version
  - Host OS
  - Browser (if UI-related)
  - Overseerr/Sonarr/Radarr versions

### Suggesting Features

A good feature request includes:

- Clear description of the feature
- Use case / problem it solves
- Potential implementation approach (optional)
- Whether you're willing to implement it

### Code Contributions

Great areas to contribute:

- Bug fixes
- Documentation improvements
- New features (discuss first)
- Test coverage
- Performance improvements
- Security enhancements

## Development Setup

### Prerequisites

- Python 3.11+
- Docker (for testing)
- Git

### Local Development

```bash
# Clone your fork
git clone https://github.com/dicktechtrek/issuerr.git
cd issuerr

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Create config directory
mkdir -p config

# Run the development server
python app.py
```

### Docker Development

```bash
# Build the image
docker build -t issuerr:dev .

# Run with mounted source for live changes
docker run -it --rm \
  -p 5000:5000 \
  -v $(pwd)/config:/config \
  -v $(pwd)/app.py:/app/app.py \
  -v $(pwd)/templates:/app/templates \
  -v $(pwd)/static:/app/static \
  -e PUID=$(id -u) \
  -e PGID=$(id -g) \
  issuerr:dev python app.py
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html
```

## Style Guidelines

### Python Code Style

We follow PEP 8 with some modifications:

- Line length: 120 characters max
- Use 4 spaces for indentation
- Use descriptive variable names
- Add docstrings to functions and classes

```python
def process_webhook(data, config):
    """
    Process an incoming webhook from Overseerr.
    
    Args:
        data: Webhook payload dictionary
        config: Application configuration dictionary
    
    Returns:
        dict: Processing result with 'status' and 'message' keys
    
    Raises:
        ValueError: If required fields are missing
    """
    # Implementation
```

### HTML/CSS/JavaScript

- Use 4 spaces for indentation
- Keep inline JavaScript minimal
- Follow existing patterns in the codebase

### Commits

- Use meaningful commit messages
- Reference issues when applicable
- Keep commits focused and atomic

## Commit Messages

Follow the conventional commits specification:

```
type(scope): description

[optional body]

[optional footer]
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code changes that neither fix bugs nor add features
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples

```
feat(webhook): add support for custom issue types

fix(auth): correct session timeout handling

docs(readme): add reverse proxy examples

chore(deps): update Flask to 3.0.1
```

## Pull Request Process

### Before Submitting

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md (if applicable)
5. Rebase on latest `main`

### PR Title

Use the same format as commit messages:

```
feat(webhook): add retry logic for failed requests
```

### PR Description

Include:

- Summary of changes
- Related issue(s)
- Testing performed
- Screenshots (if UI changes)
- Breaking changes (if any)

### Review Process

1. Automated checks must pass
2. At least one maintainer review required
3. Address feedback promptly
4. Squash commits if requested

### After Merge

- Delete your branch
- Close related issues
- Celebrate! 🎉

## Questions?

Feel free to reach out:

- **GitHub Discussions**: For general questions
- **Issues**: For bugs and features
- **Pull Request**: For code-related discussions

---

Thank you for contributing to Issuerr! Your efforts help make self-hosted media management better for everyone.
