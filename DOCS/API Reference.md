# API Reference

This document provides detailed information about the key functions, data structures, and APIs used in EndpointSecurityDemo's ESMonitor implementation.

## ESMonitor Class Reference

### Class Definition

```objectivec
@interface ESMonitor : NSObject {
@private
    es_client_t *_client;
    NSFileHandle *_logFile;
}

- (void)setupLogger;
- (void)initializeESClient;
- (void)setupSignalHandling;
- (void)handleESMessage:(const es_message_t *)message;
- (void)writeLogEntry:(NSString *)entry;
- (void)cleanup;
- (NSString *)currentTimestamp;
@end
```

### Initialization

```objectivec
- (instancetype)init
```

Creates and initializes an ESMonitor object, setting up the logger, EndpointSecurity client, and signal handling.

**Return Value:**
- A fully initialized ESMonitor instance

### Logging Setup

```objectivec
- (void)setupLogger
```

Sets up the file-based logging system:
- Creates the log file at `/var/log/es_monitor.log` if it doesn't exist
- Sets appropriate permissions (644)
- Opens the file for writing
- Positions the file pointer at the end for appending

**Error Handling:**
- Logs an error and exits if the log file cannot be created or opened

### EndpointSecurity Client Initialization

```objectivec
- (void)initializeESClient
```

Creates and configures the EndpointSecurity client:
- Creates a new client with the handleESMessage: callback
- Subscribes to EXEC, WRITE, UNLINK, and RENAME events
- Validates successful client creation and event subscription

**Error Handling:**
- Logs an error and exits if client creation or subscription fails

### Signal Handling

```objectivec
- (void)setupSignalHandling
```

Sets up handling for termination signals:
- Ignores direct SIGINT and SIGTERM signals
- Creates a dispatch source for SIGINT
- Configures cleanup on signal reception
- Ensures proper resource release on termination

### Event Handling

```objectivec
- (void)handleESMessage:(const es_message_t *)message
```

Processes EndpointSecurity event messages:
- Extracts the process ID using audit_token_to_pid
- Formats event-specific log entries based on event type
- Handles path extraction for different event types
- Calls writeLogEntry: for formatted log entries

**Parameters:**
- `message`: Pointer to an es_message_t structure containing event details

### Log Entry Writing

```objectivec
- (void)writeLogEntry:(NSString *)entry
```

Writes a formatted entry to the log file:
- Appends a newline to the entry
- Converts to UTF-8 encoded data
- Writes to the log file
- Handles exceptions that may occur during writing

**Parameters:**
- `entry`: An NSString containing the formatted log entry

**Error Handling:**
- Logs any exceptions that occur during writing

### Timestamp Formatting

```objectivec
- (NSString *)currentTimestamp
```

Generates a formatted timestamp for log entries:
- Uses NSDateFormatter with "yyyy-MM-dd HH:mm:ss.SSS" format
- Ensures thread-safe single initialization of the formatter
- Uses en_US_POSIX locale for consistent formatting

**Return Value:**
- An NSString containing the formatted timestamp

### Cleanup

```objectivec
- (void)cleanup
```

Performs cleanup operations:
- Unsubscribes from all EndpointSecurity events
- Deletes the EndpointSecurity client
- Closes the log file

## EndpointSecurity Framework Integration

### Client Creation

```objectivec
es_new_client_result_t es_new_client(es_client_t **client, const es_handler_block_t handler);
```

Creates a new EndpointSecurity client.

**Parameters:**
- `client`: Pointer to an es_client_t pointer that will be set to the new client
- `handler`: Block to be called when events are received

**Return Values:**
- `ES_NEW_CLIENT_RESULT_SUCCESS`: Client created successfully
- `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`: Application lacks required entitlement
- `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`: Application lacks TCC approval
- `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`: Application not running as root

### Event Subscription

```objectivec
es_return_t es_subscribe(es_client_t *client, const es_event_type_t *events, uint32_t event_count);
```

Subscribes the client to the specified event types.

**Parameters:**
- `client`: The client to subscribe
- `events`: Array of event types to subscribe to
- `event_count`: Number of events in the array

**Return Values:**
- `ES_RETURN_SUCCESS`: Subscription successful
- `ES_RETURN_ERROR`: Subscription failed

### Cleanup Functions

```objectivec
es_return_t es_unsubscribe_all(es_client_t *client);
```

Unsubscribes the client from all event types.

```objectivec
es_return_t es_delete_client(es_client_t *client);
```

Deletes an EndpointSecurity client and releases associated resources.

## Data Structures

### EndpointSecurity Message Structure

The `es_message_t` structure contains information about security events:

```c
typedef struct {
    uint32_t version;
    uint64_t time;
    uint64_t mach_time;
    uint64_t deadline;
    es_process_t *process;
    es_event_type_t event_type;
    es_action_type_t action_type;
    union {
        es_event_exec_t exec;
        es_event_write_t write;
        es_event_unlink_t unlink;
        es_event_rename_t rename;
        // Other event types...
    } event;
} es_message_t;
```

### Process Information

The `es_process_t` structure contains information about a process:

```c
typedef struct {
    audit_token_t audit_token;
    pid_t ppid;
    pid_t original_ppid;
    pid_t group_id;
    pid_t session_id;
    uint32_t codesigning_flags;
    bool is_platform_binary;
    es_file_t *executable;
    char *cwd; // Current working directory
    // Other fields...
} es_process_t;
```

### File Information

The `es_file_t` structure contains information about files:

```c
typedef struct {
    es_string_token_t path;
    uint64_t path_truncated; // Indicates if path was truncated
    // Other fields...
} es_file_t;
```

## Constants and Types

### Event Types

```c
typedef enum {
    ES_EVENT_TYPE_NOTIFY_EXEC,     // Process execution
    ES_EVENT_TYPE_NOTIFY_WRITE,    // File write
    ES_EVENT_TYPE_NOTIFY_UNLINK,   // File deletion
    ES_EVENT_TYPE_NOTIFY_RENAME,   // File rename
    // Many other event types...
} es_event_type_t;
```

### Rename Destination Types

```c
typedef enum {
    ES_DESTINATION_TYPE_EXISTING_FILE, // Destination is an existing file
    ES_DESTINATION_TYPE_NEW_PATH       // Destination is a new path
} es_destination_type_t;
```
