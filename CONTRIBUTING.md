# Contributing to Demogorgon

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/Akheel-Org/Organism.git
cd Organism/bugbounty-tool
bash setup.sh
source venv/bin/activate
pip install -r requirements-dev.txt
```

## Running Tests

```bash
pytest demogorgon/auth/authcore/tests/ -v
```

## Code Style

- Follow existing patterns in the codebase
- Use `ruff` for linting: `ruff check demogorgon/`
- Type hints encouraged but not required
- Keep functions focused and under 100 lines

## Adding a New Detector

1. Add detection logic in `demogorgon/detectors.py`
2. Add corresponding executor in `demogorgon/executors/`
3. Wire it into `researcher.py` act methods
4. Test against DVWA or Juice Shop

## Adding a New Auth Test

1. Add test logic in `demogorgon/auth/authcore/`
2. Follow existing patterns (see `idor_tester.py` for reference)
3. Wire through `demogorgon/auth/bridge.py`

## Reporting Issues

- Use GitHub Issues
- Include: Python version, OS, error output, steps to reproduce
- For security issues, email privately (see README)

## Pull Requests

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes and test
4. Submit PR with clear description of what changed and why

## What NOT to Commit

- `.env` files with API keys
- `recon/` data (target-specific)
- `.private/` credentials
- `venv/` or `node_modules/`
- `hunt_output/` (generated per run)

## License

By contributing, you agree your code will be licensed under MIT.
