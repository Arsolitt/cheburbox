# Release image for cheburbox, built by GoReleaser (dockers_v2).
# The binary is already compiled per platform, so the build context contains
# <os>/<arch>/cheburbox plus the license files listed in extra_files — the source
# tree is NOT part of the context.
FROM gcr.io/distroless/static-debian12:nonroot

# TARGETPLATFORM is a buildx predefined ARG. It must be re-declared inside the
# stage: a global ARG (before FROM) is not in scope for instructions after FROM,
# and without this the COPY below expands to an empty platform path.
ARG TARGETPLATFORM

COPY $TARGETPLATFORM/cheburbox /cheburbox
COPY NOTICE LICENSE /usr/share/doc/cheburbox/
COPY licenses /usr/share/doc/cheburbox/licenses/

ENTRYPOINT ["/cheburbox"]
