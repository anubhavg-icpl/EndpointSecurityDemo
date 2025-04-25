# Architecture Overview

EndpointSecurityDemo is built on Apple's EndpointSecurity framework, providing a comprehensive system for monitoring and controlling system events on macOS.

## High-Level Architecture

```mermaid
graph TB
    Kernel[macOS Kernel] -- Events --> ESF[EndpointSecurity Framework]
    ESF -- Notifications --> App[EndpointSecurityDemo App]
    App -- Authorization Response --> ESF
    App -- Logs --> Console[System Console]
    App -- Notifications --> NotifCenter[Notification Center]

    subgraph "EndpointSecurityDemo Components"
        Handler[Event Handler]
        GK[Gatekeeper Module]
        XP[XProtect Module]
        Logger[Logging System]
        Rules[Security Rules]
    end

    App --> Handler
    Handler --> GK
    Handler --> XP
    Handler --> Logger
    GK --> Rules
    XP --> Rules
```

## Event Flow Sequence

```mermaid
sequenceDiagram
    participant Kernel as macOS Kernel
    participant ESF as EndpointSecurity Framework
    participant Client as ES Client
    participant Handler as Event Handler
    participant Security as Security Modules

    Kernel->>ESF: Generate system event
    ESF->>Client: Deliver event message
    Client->>Handler: Process message (serial/async)

    alt Auth Event
        Handler->>Security: Evaluate against security policies
        Security->>Handler: Return decision (allow/deny)
        Handler->>ESF: Respond with authorization
        ESF->>Kernel: Apply authorization decision
    else Notify Event
        Handler->>Security: Record event information
        Security->>Handler: Update internal state
    end
```

## Component Architecture

The application is structured into several key components:

### 1. Event Handling System

Two modes of operation are supported:
- **Serial Message Handler**: Processes events one at a time in the order received
- **Asynchronous Message Handler**: Processes events concurrently for improved performance

### 2. Security Modules

```mermaid
classDiagram
    class EndpointSecurityDemo {
        +init()
        +setup_endpoint_security()
        +main()
    }

    class EventHandler {
        +serial_message_handler()
        +asynchronous_message_handler()
        +auth_event_handler()
        +respond_to_auth_event()
    }

    class GatekeeperModule {
        +gatekeeper_auth_handler()
        +is_validly_signed()
        +is_notarized()
    }

    class XProtectModule {
        +xprotect_auth_handler()
        +analyze_file_threat_level()
        +record_suspicious_behavior()
    }

    class SecurityUtils {
        +calculate_file_hash()
        +is_file_quarantined()
        +get_quarantine_data()
    }

    EndpointSecurityDemo --> EventHandler
    EventHandler --> GatekeeperModule
    EventHandler --> XProtectModule
    GatekeeperModule --> SecurityUtils
    XProtectModule --> SecurityUtils
```

### 3. Data Flow

```mermaid
flowchart LR
    Event[System Event] --> Processing[Event Processing]
    Processing --> Analysis[Security Analysis]
    Analysis --> Decision{Decision}
    Decision -- Allow --> AllowAction[Allow Action]
    Decision -- Deny --> DenyAction[Deny Action]
    Decision -- Log --> LoggingSystem[Logging System]
    Decision -- Notify --> NotificationSystem[Notification System]
```

## Technical Implementation

The application is implemented in Objective-C, leveraging the following key frameworks:

- **EndpointSecurity.framework**: Core framework for system event monitoring
- **libbsm.tbd**: For Audit Token functions
- **UniformTypeIdentifiers.framework**: For file type identification
- **Security.framework**: For cryptographic operations

Communication with the EndpointSecurity framework happens through a client connection established with `es_new_client()` and subscription to specific event types with `es_subscribe()`.
