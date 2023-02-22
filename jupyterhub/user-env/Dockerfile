# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
ARG OWNER=jupyter
ARG BASE_CONTAINER=$OWNER/base-notebook
FROM $BASE_CONTAINER

# Fix: https://github.com/hadolint/hadolint/wiki/DL4006
# Fix: https://github.com/koalaman/shellcheck/wiki/SC3014
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

USER root

# Install all OS dependencies for fully functional notebook server
RUN apt-get update --yes && \
    apt-get install --yes --no-install-recommends \
    # Common useful utilities
    git \
    nano-tiny \
    tzdata \
    unzip \
    vim-tiny \
    # git-over-ssh
    openssh-client \
    # less is needed to run help in R
    # see: https://github.com/jupyter/docker-stacks/issues/1588
    less \
    # nbconvert dependencies
    # https://nbconvert.readthedocs.io/en/latest/install.html#installing-tex
    texlive-xetex \
    texlive-fonts-recommended \
    texlive-plain-generic \
    # Enable clipboard on Linux host systems
    xclip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create alternative for nano -> nano-tiny
RUN update-alternatives --install /usr/bin/nano nano /bin/nano-tiny 10

RUN pip install nbgitpuller

# Switch back to jovyan to avoid accidental container runs as root
USER ${NB_UID}

# Install ARM Kernel
RUN pip install arm-jupyter-kernel
RUN /opt/conda/bin/python -m arm_kernel.install --user
# Hacky way to have the right python executive in the kernel json.
# Tried many other ways but it was impossible to make it work
COPY kernel.json /opt/conda/share/jupyter/kernels/arm

# Add R mimetype option to specify how the plot returns from R to the browser
# COPY --chown=${NB_UID}:${NB_GID} Rprofile.site /opt/conda/lib/R/etc/