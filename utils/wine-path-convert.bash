#!/bin/bash

set -e

# Invoke wine with the given arguments, but convert any arguments beginning with a / to begin with
# z:/ which is what wine programs need to pick up on absolute paths.
#
# This is used to invoke (via wine) protobuf during the build which invokes protoc.exe with (local
# system) absolute paths.
#
# E.g.
#     ./wine-path-convert.sh a b /path/c d /some/path/e
# will execute
#     wine a b z:/path/c d z:/some/path/e

args=()

for a in "$@"; do
    args+=("${a/#\//z:\/}")
done

exec wine "${args[@]}"
