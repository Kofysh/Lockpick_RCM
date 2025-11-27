# syntax=docker/dockerfile:1
FROM devkitpro/devkitarm:latest AS root

# Use Bash (explicitly) as the default shell.
SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

# Obviously, please keep these package names alphabetized.
RUN apt-get -y update && apt-get -y upgrade && \
    apt-get -y install \
        gcc \
        ;

# Compile source code.
WORKDIR /workspace

ENTRYPOINT ["make"]
