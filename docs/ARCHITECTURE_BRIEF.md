# TrapNinja Architecture Brief

**Version:** 0.7.13 (Beta)  
**Last Updated:** January 2, 2026  
**Document Type:** Architecture Brief

---

## Table of Contents

- [Overview](#overview)
- [Problem Definitions & Business Context](#problem-definitions--business-context)
- [C4 System Context Diagram](#c4-system-context-diagram)
- [System Overview](#system-overview)
  - [C4 Container Diagram](#c4-container-diagram)
  - [C4 Container Diagram Explanation](#c4-container-diagram-explanation)
  - [Request Flow Sequence](#request-flow-sequence)
  - [Technology Stack](#technology-stack)
- [System Data Models](#system-data-models)
  - [Data Model ER Diagram](#data-model-er-diagram)
- [API Endpoints](#api-endpoints)
  - [Core API Routes](#core-api-routes)
- [Deployment Architecture](#deployment-architecture)

---

## Overview

TrapNinja is a high-performance SNMP trap forwarding system designed for telecommunications environments requiring 99.999% availability. The system captures SNMP traps from multi-vendor network equipment and intelligently routes them to specialized Network Operations Centers (NOCs) based on configurable rules.

**Primary Users:** Network Operations Teams (Voice NOC, Broadband NOC, Transmission NOC, Core Network Team)

**Key Capabilities:**
- High-throughput packet processing (10,000+ traps/second sustained, 100,000+ burst)
- Primary/Secondary high-availability with sub-3-second automatic failover
- Service-based routing to specialized NOCs by IP or OID patterns
- Zero trap loss during monitoring system outages via Redis-based caching and replay
- SNMPv3 decryption and conversion to SNMPv2c
- Prometheus-compatible metrics for comprehensive monitoring

---

## Problem Definitions & Business Context

### Problem Statement

Telecommunications networks generate thousands of SNMP traps per second from diverse equipment including Cisco ASR/NCS routers and Nokia 7750SR/7950XRS systems. Traditional trap forwarding solutions lack the performance, resilience, and intelligent routing capabilities needed for modern carrier-grade operations. Specifically:

1. **Performance bottlenecks** during network events like fiber cuts cause trap floods of 10,000-100,000+ traps that overwhelm traditional forwarders
2. **Single points of failure** in trap forwarding paths result in missed alarms during critical network events
3. **Lack of intelligent routing** forces all NOC teams to receive all traps, creating alert fatigue
4. **Monitoring outages** cause permanent trap loss with no ability to backfill historical data
5. **SNMPv3 encrypted traps** cannot be processed by legacy monitoring systems

### Business Context

- **Primary Users:** Voice NOC, Broadband NOC, Transmission Team, Core Network Operations
- **Use Cases:**
  - Real-time forwarding of SNMP traps to multiple monitoring destinations
  - Service-based routing of traps to specialized NOC teams
  - Blocking noisy or irrelevant trap sources at the forwarder level
  - Replaying cached traps during monitoring system outages
  - Decrypting SNMPv3 traps for legacy monitoring system compatibility
- **Non-Functional Requirements:**
  - **Availability:** 99.999% uptime (5 nines) with automatic failover
  - **Performance:** 10,000+ traps/second sustained, 100,000+ burst handling
  - **Latency:** Sub-millisecond forwarding latency
  - **Scalability:** Horizontal scaling via additional HA pairs
  - **Security:** SNMPv3 decryption, credential management, no trap data persistence beyond cache window
- **Integration Points:** Network Elements (Cisco, Nokia, etc.), NOC Monitoring Systems, Prometheus/Grafana, Redis Cache

---

## C4 System Context Diagram

```mermaid
graph TD
    subgraph Users ["👥 Operations Teams"]
        VoiceNOC["🎧 Voice NOC<br/>Voice Network Team"]
        BroadbandNOC["🌐 Broadband NOC<br/>Internet Services Team"]
        TransNOC["📡 Transmission NOC<br/>Fiber/Transport Team"]
        CoreNOC["🔧 Core NOC<br/>Core Network Team"]
    end

    subgraph NetworkElements ["🖧 Network Elements"]
        CiscoASR["📦 Cisco ASR/NCS<br/>Aggregation Routers"]
        Nokia["📦 Nokia 7750SR/7950XRS<br/>Core Routers"]
        OtherNE["📦 Other SNMP Devices<br/>Switches, Firewalls, etc."]
    end

    subgraph TrapNinjaSystem ["🥷 TrapNinja HA Cluster"]
        Primary["🟢 Primary Node<br/>Active Forwarding"]
        Secondary["🟡 Secondary Node<br/>Standby + Cache"]
    end

    subgraph ExternalSystems ["⚙️ External Systems"]
        Redis[("💾 Redis Cache<br/>Trap Buffering")]
        Prometheus["📊 Prometheus<br/>Metrics Collection"]
        Grafana["📈 Grafana<br/>Dashboards"]
    end

    CiscoASR -->|"UDP 162<br/>SNMP Traps"| Primary
    Nokia -->|"UDP 162<br/>SNMP Traps"| Primary
    OtherNE -->|"UDP 162<br/>SNMP Traps"| Primary
    
    CiscoASR -.->|"UDP 162<br/>SNMP Traps"| Secondary
    Nokia -.->|"UDP 162<br/>SNMP Traps"| Secondary
    OtherNE -.->|"UDP 162<br/>SNMP Traps"| Secondary

    Primary <-->|"TCP 5000<br/>HA Heartbeat"| Secondary
    Primary -->|"Redis Streams<br/>Trap Caching"| Redis
    Secondary -->|"Redis Streams<br/>Trap Caching"| Redis

    Primary -->|"UDP 162<br/>Forwarded Traps"| VoiceNOC
    Primary -->|"UDP 162<br/>Forwarded Traps"| BroadbandNOC
    Primary -->|"UDP 162<br/>Forwarded Traps"| TransNOC
    Primary -->|"UDP 162<br/>Forwarded Traps"| CoreNOC

    Primary -->|"HTTP /metrics<br/>Prometheus Format"| Prometheus
    Secondary -->|"HTTP /metrics<br/>Prometheus Format"| Prometheus
    Prometheus -->|"PromQL Queries"| Grafana

    classDef user fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    classDef network fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    classDef trapninja fill:#e8f5e9,stroke:#2e7d32,stroke-width:3px
    classDef external fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px

    class VoiceNOC,BroadbandNOC,TransNOC,CoreNOC user
    class CiscoASR,Nokia,OtherNE network
    class Primary,Secondary trapninja
    class Redis,Prometheus,Grafana external
```

---

## System Overview

### C4 Container Diagram

```mermaid
graph TD
    subgraph TrapNinjaNode ["🥷 TrapNinja Node - Python 3.9"]
        
        subgraph CaptureLayer ["Capture Layer"]
            eBPF["⚡ eBPF Capture<br/>ebpf.py<br/>Kernel-space filtering"]
            SocketCapture["🔌 Socket Capture<br/>network.py<br/>UDP listeners"]
            SniffCapture["📡 Scapy Sniff<br/>network.py<br/>libpcap fallback"]
        end
        
        subgraph ProcessingLayer ["Processing Layer"]
            PacketQueue[("📥 Packet Queue<br/>200K capacity<br/>queue.Queue")]
            Workers["⚙️ Packet Workers<br/>worker.py<br/>2x CPU threads"]
            Parser["🔍 SNMP Parser<br/>parser.py + snmp.py<br/>Fast-path + slow-path"]
            Forwarder["📤 Forwarder<br/>forwarder.py<br/>Socket pooling"]
        end
        
        subgraph FilteringLayer ["Filtering & Routing"]
            IPFilter["🚫 IP Filter<br/>config.py<br/>blocked_ips.json"]
            OIDFilter["🚫 OID Filter<br/>config.py<br/>blocked_traps.json"]
            Redirection["🔀 Redirection<br/>redirection.py<br/>IP/OID routing"]
        end
        
        subgraph HALayer ["High Availability"]
            HACluster["🔄 HA Cluster<br/>cluster.py<br/>State management"]
            ConfigSync["📋 Config Sync<br/>sync/manager.py<br/>Shared configs"]
            StateManager["📊 State Manager<br/>state.py<br/>PRIMARY/SECONDARY"]
        end
        
        subgraph CacheLayer ["Cache Layer"]
            TrapCache["💾 Trap Cache<br/>redis_backend.py<br/>Rolling retention"]
            ReplayEngine["⏪ Replay Engine<br/>replay.py<br/>Rate-limited replay"]
            FailoverReplay["🔄 Failover Replay<br/>failover/manager.py<br/>Gap detection"]
        end
        
        subgraph StatsLayer ["Statistics & Metrics"]
            GranularStats["📊 Granular Stats<br/>stats/collector.py<br/>Per-IP/OID tracking"]
            PrometheusMetrics["📈 Prometheus<br/>metrics.py<br/>Counter/Gauge export"]
        end
        
        subgraph CLILayer ["CLI & Control"]
            CLIParser["⌨️ CLI Parser<br/>cli/parser.py<br/>Argument handling"]
            ControlSocket["🔌 Control Socket<br/>control.py<br/>Unix socket IPC"]
        end
        
        subgraph SNMPv3Layer ["SNMPv3 Processing"]
            Decryptor["🔐 SNMPv3 Decryptor<br/>snmpv3_decryption.py<br/>AES/DES decryption"]
            CredStore["🔑 Credential Store<br/>snmpv3_credentials.py<br/>Engine ID mapping"]
        end
    end

    subgraph ExternalDeps ["External Dependencies"]
        Redis[("💾 Redis 5.0+<br/>Streams API")]
        Destinations["📡 NOC Destinations<br/>UDP 162"]
        PeerNode["🔄 HA Peer Node<br/>TCP 5000"]
    end

    eBPF --> PacketQueue
    SocketCapture --> PacketQueue
    SniffCapture --> PacketQueue
    
    PacketQueue --> Workers
    Workers --> Parser
    Parser --> IPFilter
    IPFilter --> OIDFilter
    OIDFilter --> Redirection
    Redirection --> Forwarder
    
    Workers --> HACluster
    HACluster --> StateManager
    HACluster <--> ConfigSync
    
    Workers --> TrapCache
    TrapCache --> Redis
    FailoverReplay --> TrapCache
    ReplayEngine --> Forwarder
    
    Workers --> GranularStats
    GranularStats --> PrometheusMetrics
    
    Forwarder --> Destinations
    HACluster <--> PeerNode
    ConfigSync <--> PeerNode

    classDef capture fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    classDef processing fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    classDef filtering fill:#ffebee,stroke:#c62828,stroke-width:2px
    classDef ha fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    classDef cache fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef stats fill:#e0f2f1,stroke:#00695c,stroke-width:2px
    classDef external fill:#fce4ec,stroke:#880e4f,stroke-width:2px

    class eBPF,SocketCapture,SniffCapture capture
    class PacketQueue,Workers,Parser,Forwarder processing
    class IPFilter,OIDFilter,Redirection filtering
    class HACluster,ConfigSync,StateManager ha
    class TrapCache,ReplayEngine,FailoverReplay cache
    class GranularStats,PrometheusMetrics stats
    class Redis,Destinations,PeerNode external
```

### C4 Container Diagram Explanation

TrapNinja is implemented as a Python 3.9 application with modular architecture for maintainability and performance. The system is organized into distinct layers:

**Capture Layer:** Three capture methods with automatic fallback hierarchy. eBPF provides kernel-space filtering for maximum performance (30k+ traps/sec), Socket capture uses UDP listeners for standard operation (10k+ traps/sec), and Scapy Sniff provides libpcap-based fallback for compatibility (5k+ traps/sec). Only ONE capture method runs at a time to prevent packet duplication.

**Processing Layer:** A thread-safe queue with 200,000 packet capacity buffers incoming traps for processing by worker threads (2x CPU cores, up to 32). The SNMP parser implements a fast-path for SNMPv2c (direct byte scanning) and slow-path for SNMPv1/complex packets. The forwarder uses socket pooling for efficient connection reuse.

**Filtering & Routing Layer:** Configuration-driven filtering blocks unwanted IPs and OIDs. The redirection engine routes traps to specialized destinations based on source IP or trap OID patterns, enabling service-based routing to different NOC teams.

**High Availability Layer:** The HA Cluster manages PRIMARY/SECONDARY state with automatic failover. Config Sync ensures shared configurations remain synchronized between nodes. The state machine handles transitions with split-brain detection and resolution.

**Cache Layer:** Redis Streams-based trap caching with configurable retention (default 2 hours) enables replay during monitoring outages. The Failover Replay system automatically detects gaps during HA transitions and replays missed traps.

**Statistics & Metrics Layer:** Granular statistics track per-IP, per-OID, and per-destination metrics. Prometheus-format metrics are exported for integration with monitoring dashboards.

**SNMPv3 Layer:** Decryption engine handles AES/DES encrypted SNMPv3 traps, converting them to SNMPv2c for legacy system compatibility. Credential store manages engine ID to user mappings.

#### Request Flow Sequence

The following sequence diagram illustrates the critical use case of trap reception and forwarding:

```mermaid
sequenceDiagram
    autonumber
    participant NE as Network Element
    participant Capture as Capture Layer
    participant Queue as Packet Queue
    participant Worker as Packet Worker
    participant HA as HA Cluster
    participant Filter as IP/OID Filter
    participant Parser as SNMP Parser
    participant Cache as Redis Cache
    participant Fwd as Forwarder
    participant NOC as NOC Destination

    NE->>+Capture: UDP 162 SNMP Trap
    Capture->>Queue: Enqueue PacketData
    Note over Queue: 200K capacity<br/>Thread-safe

    Queue->>+Worker: Dequeue batch
    Worker->>HA: is_forwarding_enabled?
    
    alt SECONDARY Mode
        HA-->>Worker: False
        Worker->>Cache: Store trap
        Worker-->>Worker: Increment ha_blocked
        Note over Worker: Drop packet
    else PRIMARY Mode
        HA-->>Worker: True
        Worker->>Filter: Check blocked_ips
        alt IP Blocked
            Filter-->>Worker: BLOCKED
            Worker-->>Worker: Increment blocked
        else IP Allowed
            Filter-->>Worker: ALLOWED
            Worker->>Parser: Parse SNMP payload
            Parser-->>Worker: trap_oid, varbinds
            Worker->>Filter: Check blocked_traps
            alt OID Blocked
                Filter-->>Worker: BLOCKED
            else OID Allowed
                Worker->>Cache: Store trap async
                Cache-->>Redis: XADD stream
                Worker->>Fwd: forward_packet
                Fwd->>NOC: UDP 162 Forwarded Trap
                NOC-->>Fwd: ACK implicit
                Fwd-->>Worker: ForwardingResult
                Worker-->>Worker: Increment forwarded
            end
        end
    end
    
    deactivate Worker
    deactivate Capture
```

### Technology Stack

**Runtime & Languages:**
- Python 3.9 (with `-O` optimization flag for production)
- Scapy 2.5+ (packet capture and parsing)
- BCC/eBPF (kernel-space packet acceleration on Linux 4.4+)

**Data Storage:**
- Redis 5.0.3+ (Streams API for trap caching)
- JSON files (configuration persistence)

**Infrastructure:**
- RHEL 8.x / CentOS 8 / Rocky Linux 8 (production OS)
- systemd (service management)
- Ansible (deployment automation)

**Networking:**
- Raw sockets (high-performance forwarding)
- UDP port 162 (SNMP trap reception)
- TCP port 5000 (HA heartbeat)

**Monitoring & Security:**
- Prometheus (metrics export)
- HMAC-SHA256 (HA message authentication)
- SNMPv3 AES/DES decryption (pysnmp, cryptography)

---

## System Data Models

### Data Model ER Diagram

```mermaid
erDiagram
    PACKET_DATA {
        string src_ip PK
        int dst_port
        bytes payload
        float timestamp
    }
    
    PARSED_TRAP {
        string version
        string source_ip FK
        string trap_oid
        string enterprise_oid
        json varbinds
        string community
        string security_name
    }
    
    DESTINATION {
        string ip PK
        int port PK
        string tag
        boolean enabled
    }
    
    BLOCKED_IP {
        string ip PK
        datetime added_at
    }
    
    BLOCKED_OID {
        string oid PK
        datetime added_at
    }
    
    REDIRECTION_RULE {
        string pattern PK
        string rule_type
        string tag FK
        boolean enabled
    }
    
    CACHE_ENTRY {
        string entry_id PK
        string destination FK
        datetime timestamp
        string source_ip
        string trap_oid
        string pdu_base64
    }
    
    HA_STATE {
        string instance_id PK
        string state
        boolean is_forwarding
        float uptime
        int priority
        string peer_host
        float peer_last_seen
    }
    
    IP_STATS {
        string ip PK
        int trap_count
        float rate_per_second
        datetime first_seen
        datetime last_seen
        json top_oids
    }
    
    OID_STATS {
        string oid PK
        int trap_count
        float rate_per_second
        int unique_sources
        datetime first_seen
        datetime last_seen
    }
    
    SNMPV3_CREDENTIAL {
        string engine_id PK
        string username PK
        string auth_protocol
        string auth_key
        string priv_protocol
        string priv_key
    }

    PACKET_DATA ||--o{ PARSED_TRAP : parses_to
    PARSED_TRAP }o--|| DESTINATION : forwards_to
    DESTINATION ||--o{ CACHE_ENTRY : stores
    PARSED_TRAP }o--o| BLOCKED_IP : filtered_by
    PARSED_TRAP }o--o| BLOCKED_OID : filtered_by
    REDIRECTION_RULE }o--|| DESTINATION : routes_to
    PARSED_TRAP }o--o{ REDIRECTION_RULE : matched_by
    PACKET_DATA ||--|| IP_STATS : updates
    PARSED_TRAP ||--|| OID_STATS : updates
    PARSED_TRAP }o--o| SNMPV3_CREDENTIAL : decrypted_by
```

**Data Flow Explanation:**

1. **PACKET_DATA** represents raw captured packets queued for processing
2. **PARSED_TRAP** contains extracted SNMP information after parsing
3. **DESTINATION** defines forwarding targets, loaded from `destinations.json`
4. **BLOCKED_IP/BLOCKED_OID** filter unwanted traffic at processing time
5. **REDIRECTION_RULE** maps IP/OID patterns to destination tags for service-based routing
6. **CACHE_ENTRY** stores traps in Redis Streams for replay capability
7. **HA_STATE** tracks cluster state for coordinated failover
8. **IP_STATS/OID_STATS** collect granular metrics for monitoring dashboards
9. **SNMPV3_CREDENTIAL** stores decryption credentials per engine ID

---

## API Endpoints

### Core API Routes

TrapNinja exposes functionality through a command-line interface (CLI) and Unix socket control interface for programmatic access.

**Daemon Control:**
- `--start` - Start TrapNinja service (daemonized)
- `--stop` - Stop TrapNinja service gracefully
- `--restart` - Restart TrapNinja service
- `--status` - Show service status, uptime, and basic metrics

**Filtering Commands:**
- `--block-ip <IP>` - Block source IP address
- `--unblock-ip <IP>` - Remove IP from block list
- `--list-blocked-ips` - Show all blocked IPs
- `--block-oid <OID>` - Block trap OID
- `--unblock-oid <OID>` - Remove OID from block list
- `--list-blocked-oids` - Show all blocked OIDs

**Statistics Commands:**
- `--stats-summary` - Show processing statistics summary
- `--stats-top-ips [N]` - Show top N source IPs by trap count
- `--stats-top-oids [N]` - Show top N OIDs by trap count
- `--stats-details <IP|OID>` - Show detailed stats for specific IP or OID

**High Availability Commands:**
- `--ha-status` - Show HA cluster status
- `--promote` - Manually promote to PRIMARY
- `--demote` - Manually demote to SECONDARY
- `--force-failover` - Force immediate failover
- `--config-sync-status` - Show configuration sync status
- `--config-sync` - Trigger manual config synchronization

**Cache Commands:**
- `--cache-status` - Show cache connection and statistics
- `--cache-query <destination> --start <time> --end <time>` - Query cached traps
- `--cache-replay <destination> --start <time> --end <time>` - Replay cached traps
- `--cache-clear [destination]` - Clear cache entries

**SNMPv3 Commands:**
- `--snmpv3-add-user` - Add SNMPv3 credentials
- `--snmpv3-list-users` - List configured SNMPv3 users
- `--snmpv3-remove-user <engine_id> <username>` - Remove SNMPv3 credentials

**Prometheus Metrics Endpoint:**
- `GET /metrics` - Prometheus-format metrics export (HTTP)

Key metrics exposed:
| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_traps_received_total` | Counter | Total traps received |
| `trapninja_traps_forwarded_total` | Counter | Total traps forwarded |
| `trapninja_traps_blocked_total` | Counter | Total traps blocked |
| `trapninja_traps_redirected_total` | Counter | Total traps redirected |
| `trapninja_queue_depth` | Gauge | Current packet queue depth |
| `trapninja_ha_state` | Gauge | HA state (1=PRIMARY, 2=SECONDARY) |
| `trapninja_ha_forwarding` | Gauge | Forwarding enabled (1=yes, 0=no) |

---

## Deployment Architecture

```mermaid
graph TD
    subgraph ProductionCluster ["Production HA Cluster"]
        subgraph PrimaryServer ["Primary Server - 10.234.83.133"]
            Primary["🟢 TrapNinja Primary<br/>State: PRIMARY<br/>Forwarding: ENABLED"]
            PrimaryRedis[("Redis Primary<br/>Port 6379")]
        end
        
        subgraph SecondaryServer ["Secondary Server - 10.234.83.134"]
            Secondary["🟡 TrapNinja Secondary<br/>State: SECONDARY<br/>Forwarding: DISABLED"]
            SecondaryRedis[("Redis Secondary<br/>Port 6379")]
        end
    end
    
    subgraph NetworkInfra ["Network Infrastructure"]
        VIP["🌐 Virtual IP<br/>Trap Reception"]
        NE["🖧 Network Elements<br/>SNMP Sources"]
    end
    
    subgraph MonitoringTargets ["Monitoring Destinations"]
        VoiceNOC["🎧 Voice NOC<br/>UDP 162"]
        BroadbandNOC["🌐 Broadband NOC<br/>UDP 162"]
        TransNOC["📡 Transmission NOC<br/>UDP 162"]
    end
    
    subgraph MonitoringStack ["Monitoring Stack"]
        Prometheus["📊 Prometheus<br/>Metrics Collection"]
        Grafana["📈 Grafana<br/>Dashboards"]
    end

    NE -->|"SNMP Traps"| VIP
    VIP -->|"UDP 162"| Primary
    VIP -.->|"UDP 162"| Secondary
    
    Primary <-->|"TCP 5000<br/>Heartbeat"| Secondary
    Primary --> PrimaryRedis
    Secondary --> SecondaryRedis
    
    Primary -->|"Forwarded Traps"| VoiceNOC
    Primary -->|"Forwarded Traps"| BroadbandNOC
    Primary -->|"Forwarded Traps"| TransNOC
    
    Primary -->|"/metrics"| Prometheus
    Secondary -->|"/metrics"| Prometheus
    Prometheus --> Grafana

    classDef primary fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
    classDef secondary fill:#fff9c4,stroke:#f9a825,stroke-width:2px
    classDef external fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    classDef monitoring fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px

    class Primary,PrimaryRedis primary
    class Secondary,SecondaryRedis secondary
    class VIP,NE,VoiceNOC,BroadbandNOC,TransNOC external
    class Prometheus,Grafana monitoring
```

**Deployment Specifications:**

| Component | Primary Server | Secondary Server |
|-----------|---------------|------------------|
| IP Address | 10.234.83.133 | 10.234.83.134 |
| HA Priority | 150 (higher) | 100 (lower) |
| HA Mode | primary | secondary |
| Redis | localhost:6379 | localhost:6379 |
| Cache Retention | 2 hours | 2 hours |

**System Requirements:**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| Memory | 2 GB | 4+ GB |
| Disk | 10 GB | 50+ GB (for cache) |
| Network | 1 Gbps | 10 Gbps |
| OS | RHEL 8.x | RHEL 8.10 |
| Python | 3.9+ | 3.9 with -O flag |

**Performance Characteristics:**

| Metric | Target | Achieved |
|--------|--------|----------|
| Throughput (eBPF) | 30,000/s | 30,000+/s |
| Throughput (Socket) | 10,000/s | 10,000+/s |
| Queue Capacity | 200,000 | 200,000 |
| Failover Time | <5s | 3-4s typical |
| Memory (steady) | <500 MB | 100-300 MB |
| CPU (at 10k/s) | <50% | 20-40% |

---

**Document Revision History:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.7.13 | 2026-01-02 | TrapNinja Team | Initial architecture brief |
