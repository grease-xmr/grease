#!/bin/bash
REPO_ROOT="$(git rev-parse --show-toplevel)"

# Use absolute paths to the injected HTML to resolve differences in relative paths when rustdoc is
# invoked from _both_ the WORKSPACE _and_ the CRATE directories for each crate in the workspace, as
# well as crate dependencies when not using --no-deps
rustdoc \
    --html-in-header="$REPO_ROOT/docs/header.html" \
    --html-after-content="$REPO_ROOT/docs/after-content.html" \
    "$@"
