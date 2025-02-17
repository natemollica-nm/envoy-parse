# Envoy Parse CLI

## Overview
The `lib.envoy` module is designed to analyze and parse Envoy proxy logs, admin API responses, and related data to extract meaningful insights. It supports parsing logs, extracting cluster relationships, and filtering data for easier debugging and analysis.

## Features
- Fetch and parse responses from Envoy Admin API endpoints (`/clusters`, `/config_dump?include_eds`, `/stats`).
- Parse JSON and text-formatted Envoy proxy logs.
- Extract relationships between listeners, clusters, and endpoints.
- Filter logs by time range, error type, or specific service names.
- Generate structured reports in JSON, CSV, or table formats.

## Installation
```sh
# Ensure directory contains `lib/envoy.py`

# Clone the repository
git clone <repo-url>
cd envoy-parse

# Create a virtual environment (optional but recommended)
python3 -m venv .venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`

# Install dependencies
pip install -r requirements.txt
```

## Usage
### Basic Commands
```sh
# Parse logs from a file or directory
python -m lib.envoy --parse /path/to/logs

# Parse using a configuration file (if supported)
python -m lib.envoy --config config.yaml

# Fetch data from Envoy Admin API
python -m lib.envoy --fetch /clusters --fetch /stats

# Filter parsed data
python -m lib.envoy --parse /path/to/logs --filter error_type

# Output results in a specific format
python -m lib.envoy --parse /path/to/logs --output csv
```

### CLI Arguments for `lib.envoy`
| Argument      | Description                                                                          |
|---------------|--------------------------------------------------------------------------------------|
| `--fetch`     | Fetch data from Envoy Admin API (`/clusters`, `/config_dump?include_eds`, `/stats`). |
| `--parse`     | Parse log files or directories.                                                      |
| `--filter`    | Apply predefined filter (e.g., `error_type`).                                        |
| `--output`    | Output format (`json`, `csv`, `table`). Default is `json`.                           |
| `--log-level` | Set logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). Default is `INFO`.          |

## Examples
### Fetch and Parse Data
```sh
python -m lib.envoy --fetch /clusters --fetch /config_dump?include_eds
```

### Parse and Filter Logs
```sh
python -m lib.envoy --parse envoy_logs/ --filter error_type
```

### Generate CSV Output
```sh
python -m lib.envoy --parse logs.json --output csv
```

## Development
### Running Tests
```sh
pytest tests/
```

### Code Linting and Formatting
For `lib.envoy`, this project enforces consistent formatting and linting standards using the following tools:

```sh
# Lint Python code with flake8
flake8 envoy_parse.py

# Format Python code with black
black .

# Sort imports with isort
isort .
```

## Contributing
Contributions are welcome! Please follow these guidelines for `lib.envoy`:

- **Branching strategy**: Use `main` for production-ready code. Create feature branches (`feature/your-feature`) for changes.
- **Testing**: Ensure all tests pass before submitting a PR. Add new tests for any changes or new functionality in `lib/envoy`.
- **Linting and Formatting**: Verify that the code adheres to the project's linting and formatting standards (`flake8`, `isort`, `black`).
- **Pull Requests**: Submit detailed PR descriptions specifying the changes, purpose, and any related issues.

## License
This project is licensed under the MIT License.

