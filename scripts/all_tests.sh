#!/bin/bash

# Run all tests except end-to-end tests (they must be single-threaded)
cargo test --all-features --workspace --exclude e2e --release

# Run end-to-end tests with release profile and single-threaded execution
cargo test --release -p e2e --test cucumber_tests -- -c1