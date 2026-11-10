#!/usr/bin/env bash
# Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
# SPDX-License-Identifier: MIT
# id: er-fee52fa9
# PagoKit — test-validators.sh
#
# Runs the validator test suite. Exits 0 on all pass, non-zero on any failure.

set -e

cd "$(dirname "$0")/.."

echo "==> Running validator tests..."
node hooks/checks/__tests__/run-tests.js
