# Architecture Overview

EndpointSecurityDemo is built on Apple's EndpointSecurity framework, providing a comprehensive system for monitoring and controlling system events on macOS.

## High-Level Architecture

```mermaid
graph TB
    Kernel[macOS Kernel] -- Events --> ESF[EndpointSecurity Framework]
    ESF -- Notifications --> App[ESMonitor Class]
    App -- Logs --> LogFile[Event Log File]

    subgraph "EndpointSecurityDemo Components"
        Handler[Event Handler]
        Logger[Logging System]
        SignalHandler[Signal Handler]
    end

    App --> Handler
    App --> Logger
    App --> SignalHandler
```

## Event Flow Sequence

```mermaid
sequenceDiagram
    participant Kernel as macOS Kernel
    participant ESF as EndpointSecurity Framework
    participant Client as ES Client
    participant ESMonitor as ESMonitor Class
    participant LogFile as Log File

    Kernel->>ESF: Generate system event
    ESF->>Client: Deliver event message
    Client->>ESMonitor: Process message
    ESMonitor->>ESMonitor: Format log entry
    ESMonitor->>LogFile: Write log entry
```

## Component Architecture

The application is structured into several key components:

### 1. Core ESMonitor Class

The ESMonitor class serves as the central component that:
- Initializes the EndpointSecurity client
- Sets up the logging system
- Handles incoming events
- Manages cleanup on termination

### 2. Event Handling System

The application monitors four critical event types:
- **EXEC**: Process execution events
- **WRITE**: File write operations
- **UNLINK**: File deletion operations
- **RENAME**: File rename operations

```mermaid
classDiagram
    class ESMonitor {
        -es_client_t *_client
        -NSFileHandle *_logFile
        +init()
        +setupLogger()
        +initializeESClient()
        +setupSignalHandling()
        +handleESMessage(es_message_t*)
        +writeLogEntry(NSString*)
        +currentTimestamp()
        +cleanup()
    }

    class EndpointSecurityFramework {
        +es_new_client()
        +es_subscribe()
        +es_unsubscribe_all()
        +es_delete_client()
    }

    class EventHandler {
        +handleExecEvent()
        +handleWriteEvent()
        +handleUnlinkEvent()
        +handleRenameEvent()
    }

    class LoggingSystem {
        +setupLogger()
        +writeLogEntry()
        +formatTimestamp()
    }

    ESMonitor --> EndpointSecurityFramework : uses
    ESMonitor --> EventHandler : contains
    ESMonitor --> LoggingSystem : contains
```

### 3. Logging System

EndpointSecurityDemo implements a robust file-based logging system that:
- Creates a log file if it doesn't exist
- Formats entries with timestamps and process information
- Appends entries to the log file

### 4. Signal Handling

The application implements proper signal handling to ensure graceful termination:
- Intercepts SIGINT (Ctrl+C) signals
- Performs cleanup operations before termination
- Ensures all resources are properly released

## Data Flow

```mermaid
flowchart LR
    Event[System Event] --> ESFramework[EndpointSecurity Framework]
    ESFramework --> ESMonitor[ESMonitor]
    ESMonitor --> EventProcessing[Event Processing]
    EventProcessing --> LogFormatting[Log Formatting]
    LogFormatting --> LogFile[Log File]
```

## Technical Implementation

The application is implemented in Objective-C, leveraging the following key frameworks:

- **EndpointSecurity.framework**: Core framework for system event monitoring
- **libbsm.tbd**: For Audit Token functions
- **Foundation.framework**: For core Objective-C functionality

Communication with the EndpointSecurity framework happens through a client connection established with `es_new_client()` and subscription to specific event types with `es_subscribe()`.
