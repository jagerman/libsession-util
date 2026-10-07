# Sourced by the packaging scripts.

# Prints the archive name $1 with any TAG in it replaced by the release tag being built, or else by
# the build's time and commit -- the CI build's when there is one, so that every archive from one
# build agrees, and the current ones otherwise.
archive_name() {
    local tag
    if [ -n "$DRONE_TAG" ]; then
        tag="$DRONE_TAG"
    elif [ -n "$DRONE_COMMIT" ]; then
        tag="$(date --date=@$DRONE_BUILD_CREATED +%Y%m%dT%H%M%SZ)-${DRONE_COMMIT:0:9}"
    else
        tag="$(date +%Y%m%dT%H%M%SZ)-$(git rev-parse --short=9 HEAD)"
    fi
    echo "${1/TAG/$tag}"
}
