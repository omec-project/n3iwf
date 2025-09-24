<!--
SPDX-FileCopyrightText: 2025 Intel Corporation

SPDX-License-Identifier: Apache-2.0
-->
[![Go Report Card](https://goreportcard.com/badge/github.com/omec-project/n3iwf)](https://goreportcard.com/report/github.com/omec-project/n3iwf)

# N3IWF

## Overview
N3IWF (Non-3GPP Interworking Function) is a component of the 5G core network that enables secure interworking between 5G core and non-3GPP access networks (such as Wi-Fi). This codebase implements the N3IWF node, handling control and user plane signaling, security associations, and communication with the 5G core (AMF, UPF).

## Architecture
The N3IWF consists of several main components and services, each responsible for a specific aspect of the system. The relationships and interactions between these components are illustrated in the PlantUML component diagram:

![N3IWF Architecture](docs/images/n3iwf-architecture.svg)

**Description:**
- UE connects to N3IWF via a secure IPsec tunnel over WiFi.
- N3IWF acts as a gateway between non-3GPP access (WiFi) and the 5G Core (AMF, UPF).
- Control plane traffic is sent to AMF (N2 interface).
- User plane traffic is sent to UPF (N3 interface).
- UPF forwards user data to the Internet.

## Main Components
- **Main Application**: Entry point (`n3iwf.go`), initializes configuration and starts all services.
- **Context**: Global state and object pools for AMF, UE, security associations, and connections (`context/context.go`, `context/amf.go`, `context/ue.go`).
- **Factory**: Loads and parses configuration files (`factory/config.go`).
- **Logger**: Centralized logging for all components (`logger/logger.go`).
- **NGAP Service**: Handles SCTP connections to AMF, NGAP message processing (`ngap/service/service.go`, `ngap/handler/handler.go`, `ngap/message/build.go`).
- **NWuCP Service**: Handles NAS signaling over TCP from UEs (`nwucp/service/service.go`).
- **NWuUP Service**: Handles user plane data forwarding (`nwuup/service/service.go`).
- **IKE Service**: Manages IKEv2/IPSec negotiation and security associations (`ike/service/service.go`, `ike/message/build.go`).
- **GTP Service**: Forwards user plane packets to the UPF (`gtp/service/service.go`).
- **Utility**: Context initialization and helpers (`util/initContext.go`).

## Service Startup Flow
1. **Initialization**: The main application loads configuration and initializes the context.
2. **Service Start**: The following services are started in parallel:
   - NGAP (SCTP to AMF)
   - NWuCP (NAS TCP server)
   - NWuUP (User plane listener)
   - IKE (IKEv2/IPSec negotiation)
3. **Context Management**: All services share and update the global context for AMF, UE, and security associations.
4. **Message Handling**: NGAP and IKE messages are dispatched to handlers for protocol-specific processing.

## Configuration
- The main configuration file is typically located at `config/n3iwf.yaml`.
- Example configuration options include network interfaces, AMF addresses, security parameters, and logging levels.
- See `factory/config.go` for supported parameters and structure.

## Deployment
- N3IWF can be run as a standalone binary or in a containerized environment (Docker).
- Ensure required network interfaces and routes are configured for SCTP, TCP, and UDP communication.
- For production, review and adjust security settings in the configuration file.

## Troubleshooting
- Logs are written to stdout and can be configured for verbosity in the config file.
- Common issues:
  - SCTP connection failures: Check AMF address and network reachability.
  - IKE/IPSec negotiation errors: Verify security parameters and certificates.
  - User plane forwarding: Ensure GTP and NWuUP interfaces are correctly set up.
- For more details, consult logs and refer to the relevant service source files.

## Key Files
- `n3iwf.go`: Main entry point.
- `service/init.go`: Service initialization and startup logic.
- `context/context.go`, `context/amf.go`, `context/ue.go`: Core context and object management.
- `factory/config.go`: Configuration loading and parsing.
- `logger/logger.go`: Logging setup.
- `ngap/service/service.go`, `ngap/handler/handler.go`, `ngap/message/build.go`: NGAP protocol handling.
- `nwucp/service/service.go`: NWuCP (NAS signaling) service.
- `nwuup/service/service.go`: NWuUP (user plane) service.
- `ike/service/service.go`, `ike/message/build.go`: IKE/IPSec handling.
- `gtp/service/service.go`: GTP user plane forwarding.
- `util/initContext.go`: Context initialization from config.

## Build and Run
To build and run the N3IWF service:

```sh
make all
./bin/n3iwf -cfg <path_to_config_file>
```

Or use the provided Dockerfile to build and run in a containerized environment:

```sh
docker build -t n3iwf .
docker run --rm -it n3iwf
```

To run unit tests:

```sh
make test
```

## License and Notice
- See [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt) for license details.
- See [`NOTICE.txt`](NOTICE.txt) for attribution and notices.

## References
- [3GPP TS 23.501](https://www.3gpp.org/ftp/Specs/archive/23_series/23.501/)
- [3GPP TS 23.502](https://www.3gpp.org/ftp/Specs/archive/23_series/23.502/)
- [3GPP TS 33.501](https://www.3gpp.org/ftp/Specs/archive/33_series/33.501/)
