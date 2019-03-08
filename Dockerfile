#
# Copyright 2017 XLAB d.o.o.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FROM golang:1.11

LABEL maintainer="XLAB d.o.o" \
      description="This image starts the core Emmy server"

# Create appropriate directory structure
RUN mkdir -p $HOME/emmy $HOME/.emmy

# Run subsequent commands from the project root
WORKDIR $HOME/emmy

# Copy project from host to project directory in container
COPY ./ ./

# Install dependencies and compile the project
RUN go install

# Number of parameters for the CL scheme
ENV N_ATTRS_KNOWN 0
ENV N_ATTRS_REVEALED 0
ENV N_ATTRS_HIDDEN 0

# Creates keys for the organization
RUN emmy server cl \
    --known ${N_ATTRS_KNOWN} \
    --revealed ${N_ATTRS_REVEALED} \
    --hidden ${N_ATTRS_HIDDEN}

# Start emmy server
ENTRYPOINT ["emmy", "server", "cl"]

# Set default arguments for entrypoint command
CMD ["--loglevel", "debug", "--db", "redis:6379"]

EXPOSE 7007
