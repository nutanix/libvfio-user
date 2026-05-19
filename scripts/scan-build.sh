#!/bin/bash

# Force a failure exit if we find any issues.

scan-build -v --status-bugs "$@"
