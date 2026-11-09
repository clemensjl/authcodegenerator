# Contributing

Bug reports and pull requests are welcome. The library is deliberately small: deterministic, standard library only, no dependencies. Changes that add a dependency or change the output for existing inputs need a good reason, because the same secret and identifier must keep giving the same code.

## Setup

1. Fork the repository and clone your fork.
2. Install it with the dev extras (Python 3.9 or newer):

       pip install -e ".[dev]"

3. Run the tests:

       python -m pytest

## Pull requests

1. Create a branch from `main`.
2. Add or update tests in `tests/` for the behavior you change.
3. Keep the change focused: one fix or feature per pull request.
4. Open the pull request and fill in the template. CI runs the tests on Python 3.9 to 3.13 and must be green.

By contributing you agree that your contribution is licensed under the MIT License, see [LICENSE](LICENSE).
