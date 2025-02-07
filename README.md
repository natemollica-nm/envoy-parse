# Envoy Parse CLI

## Overview
The `envoy-parse` CLI tool is designed to analyze and parse Envoy proxy logs, admin API responses, and related data to extract meaningful insights. It supports parsing logs, extracting cluster relationships, and filtering data for easier debugging and analysis.

## Features
- Fetch and parse responses from Envoy Admin API endpoints (`/clusters`, `/config_dump?include_eds`, `/stats`).
- Parse JSON and text-formatted Envoy proxy logs.
- Extract relationships between listeners, clusters, and endpoints.
- Filter logs by time range, error type, or specific service names.
- Generate structured reports in JSON, CSV, or table formats.

## Installation
```sh
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
python envoy_parse.py --parse /path/to/logs

# Fetch data from Envoy Admin API
python envoy_parse.py --fetch /clusters --fetch /stats

# Filter parsed data
python envoy_parse.py --parse /path/to/logs --filter error_type

# Output results in a specific format
python envoy_parse.py --parse /path/to/logs --output csv
```

### CLI Arguments
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
python envoy_parse.py --fetch /clusters --fetch /config_dump?include_eds
```

### Parse and Filter Logs
```sh
python envoy_parse.py --parse envoy_logs/ --filter error_type
```

### Generate CSV Output
```sh
python envoy_parse.py --parse logs.json --output csv
```

## Development
### Running Tests
```sh
pytest tests/
```

### Linting and Formatting
```sh
flake8 envoy_parse.py
black .
```

## Frontend

```shell
npx @shadcn/ui add
```

## Contributing
Contributions are welcome! Please submit a pull request with detailed explanations of your changes.

## License
This project is licensed under the MIT License.

