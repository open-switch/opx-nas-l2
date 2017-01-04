# opx-nas-l2
This repository contains the Layer 2 (L2) component of the network abstraction service (NAS). This handles media access control (MAC) learning, programming spanning-tree protocol (STP) state, mirroring, sFlow, and other switch configurations. 

## Build
See [opx-nas-manifest](https://github.com/open-switch/opx-nas-manifest) for more information on common build tools.

###  Build requirements

- `opx-model-dev`
- `opx-common-dev`
- `opx-nas-common-dev`
- `opx-object-library-dev`
- `opx-logging-dev`
- `opx-nas-ndi-dev`
- `opx-nas-ndi-api-dev`
- `opx-nas-linux-dev`

Copy the Debian files to the parent folder (default location of debian files) and run the `opx_build` command.

### Build dependencies
None

(c) Dell 2017
