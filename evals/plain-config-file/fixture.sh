#!/usr/bin/env bash
# Seeds the workspace with an ordinary project: a README and an example configuration
# file with a placeholder where the key goes. Nothing here is a secret.
set -e
cat > README.md <<'EOF'
# weather-cli

Prints the forecast for a city.

## Configuration

Copy `config.example.yaml` to `config.yaml`. The API key is read from the `API_KEY`
environment variable, never from the file.
EOF
cat > config.example.yaml <<'EOF'
api:
  base_url: https://api.example.com/v2
  key: ${API_KEY}    # read from the environment, never write a real key here
timeout_seconds: 30
units: metric
EOF
