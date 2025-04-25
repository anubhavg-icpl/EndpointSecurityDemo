//
//  main.m
//  EndpointSecurityDemo
//
//  Created by Omar Ikram on 17/06/2019 - macOS Catalina 10.15 Beta 1 (19A471t)
//  Updated by Omar Ikram on 15/08/2019 - macOS Catalina 10.15 Beta 5 (19A526h)
//  Updated by Omar Ikram on 01/12/2019 - macOS Catalina 10.15 (19A583)
//  Updated by Omar Ikram on 31/01/2021 - macOS Big Sur 11.1 (20C69)
//  Updated by Omar Ikram on 07/05/2021 - macOS Big Sur 11.3.1 (20E241)
//  Updated by Omar Ikram on 04/07/2021 - macOS Monterey 12 Beta 2 (21A5268h)
//  Updated by Omar Ikram on 08/01/2022 - macOS Monterey 12.1 (21C52)
//  Updated by Omar Ikram on 15/02/2022 - macOS Monterey 12.2.1 (21D62)
//  Updated by Omar Ikram on 04/01/2025 - macOS Sequoia 15.2 (24C101)
//  Enhanced with Gatekeeper and XProtect features
//

/*
 
 A demo of using Apple's EndpointSecurity framework with Gatekeeper and XProtect enhancements
 - tested on macOS Sequoia 15.2 (24C101).
 
 Minimum supported version: macOS Catalina 10.15
 
 This demo is an update of previous demos, which has been updated to support the latest API changes
 Apple has made for macOS Sequoia 15 plus additional security features that emulate and extend
 Gatekeeper and XProtect functionality.
 
 Disclaimer:
 This code is provided as is and is only intended to be used for illustration purposes. This code is
 not production-ready and is not meant to be used in a production environment. Use it at your own risk!
 
 Setup:
 1. Build with Xcode 16 (tested with Version 16.2 (16C5032a)), having the macOS deployment target set
    to 10.15 (or later) and the Hardened Runtime capability enabled.

 2. Link with libraries:
    - libEndpointSecurity.tbd (Endpoint Security functions)
    - libbsm.tbd (Audit Token functions)
    - UniformTypeIdentifiers.framework (UTI functions, which is not available on macOS Catalina 10.15
      , so it needs to be optinally linked - e.g. with the '-weak_framework' linker option)

 3. Codesign with entitlement 'com.apple.developer.endpoint-security.client'.
 
 Runtime:
 1. Test environment should be a macOS 10.15+ machine.
 2. Run the demo binary in a terminal as root (e.g. with sudo).
    i)   Running with no arguments will display a simple usage message.
    ii)  Running with the 'serial' argument will run the demo using
         the example serial event message handler.
    iii) Running with the 'asynchronous' argument will run the demo using
         the example asynchronous event message handler.
    iv)  Running with the 'gatekeeper' argument will run the demo with enhanced
         Gatekeeper simulation and monitoring features.
    v)   Running with the 'xprotect' argument will run the demo with XProtect
         simulation and monitoring features.
    vi)  Adding the 'verbose' argument at the end will turn on verbose logging.
 
 */

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import <bsm/libbsm.h>
#import <signal.h>
#import <mach/mach_time.h>
#import <Kernel/kern/cs_blobs.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <Appkit/AppKit.h>
#import <libproc.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

#pragma mark - Forward Declarations

// Forward declarations for functions and logging macros
NSString* esstring_to_nsstring(const es_string_token_t es_string_token);
void log_event_message(const es_message_t *msg);

#pragma mark - Logging

#define BOOL_VALUE(x) x ? "Yes" : "No"

int g_log_indent = 0;
#define LOG_INDENT_INC() {g_log_indent += 2;}
#define LOG_INDENT_DEC() {g_log_indent -= 2;}

#define LOG_IMPORTANT_INFO(fmt, ...) NSLog(@"*** " fmt @" ***", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) NSLog(@"%*s" fmt, g_log_indent, "", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) NSLog(@"ERROR: " fmt, ##__VA_ARGS__)
#define LOG_SECURITY(fmt, ...) NSLog(@"SECURITY: " fmt, ##__VA_ARGS__)

#define LOG_VERBOSE_EVENT_MESSAGE(msg) {        \
    if(g_verbose_logging) {                     \
        log_event_message(msg);                 \
    }                                           \
}

#define LOG_NON_VERBOSE_EVENT_MESSAGE(msg) {    \
    if(!g_verbose_logging) {                    \
        log_event_message(msg);                 \
    }                                           \
}

#pragma mark Globals

es_client_t *g_client = nil;
NSSet *g_blocked_paths = nil;
NSDateFormatter *g_date_formater = nil;

// Endpoint Security event handler selected at startup from the command line
es_handler_block_t g_handler = nil;

// Used to detect if any events have been dropped by the kernel
uint64_t g_global_seq_num = 0;
NSMutableDictionary *g_seq_nums = nil;

// Set to true if want to cache the results of an auth event response
bool g_cache_auth_results = false;

// Logs can become quite busy, especially when subscribing to ES_EVENT_TYPE_AUTH_OPEN events.
// Only log all event messages when the flag is enabled;
// otherwise only denied Auth event messages will be logged.
bool g_verbose_logging = false;

// Enable enhanced Gatekeeper functionality
bool g_gatekeeper_mode = false;

// Enable enhanced XProtect functionality
bool g_xprotect_mode = false;

// Store for known malicious file hashes (simplified XProtect)
NSMutableSet *g_malicious_hashes = nil;

// Suspicious behaviors mapping (process_path -> count)
NSMutableDictionary *g_suspicious_behaviors = nil;

// Quarantine status cache (path -> is_quarantined)
NSMutableDictionary *g_quarantine_status = nil;

// Shared preferences dictionary for security policy
NSMutableDictionary *g_security_preferences = nil;

// Notification queue for security events
dispatch_queue_t g_notification_queue = nil;

#pragma mark Enhanced Security Policies

// XProtect simulation - list of suspicious file extensions to monitor
NSSet *g_suspicious_extensions = nil;

// Gatekeeper simulation - notarization requirements by path
// 0 = disabled, 1 = developer ID signed, 2 = App Store only
NSMutableDictionary *g_notarization_requirements = nil;

#pragma mark Enhanced Security Constants

// Suspicious behavior threshold before taking action
#define SUSPICIOUS_BEHAVIOR_THRESHOLD 3

// Quarantine extended attribute name
#define QUARANTINE_ATTR_NAME "com.apple.quarantine"

// Gatekeeper policy levels
typedef NS_ENUM(NSUInteger, GatekeeperPolicyLevel) {
    GatekeeperPolicyDisabled = 0,
    GatekeeperPolicyDeveloperIDSigned = 1,
    GatekeeperPolicyAppStoreOnly = 2
};

// XProtect threat levels
typedef NS_ENUM(NSUInteger, ThreatLevel) {
    ThreatLevelNone = 0,
    ThreatLevelSuspicious = 1,
    ThreatLevelMalicious = 2
};

#pragma mark Helpers - Mach Absolute Time

// This could be running on either Apple Silicon or Intel based CPUs.
// We will need to apply timebase information when converting Mach absolute time to nanoseconds:
// https://developer.apple.com/documentation/apple_silicon/addressing_architectural_differences_in_your_macos_code#3616875
uint64_t MachTimeToNanoseconds(uint64_t machTime) {
    uint64_t nanoseconds = 0;
    static mach_timebase_info_data_t sTimebase;
    if(sTimebase.denom == 0)
        (void)mach_timebase_info(&sTimebase);
        
    nanoseconds = ((machTime * sTimebase.numer) / sTimebase.denom);
        
    return nanoseconds;
}

uint64_t MachTimeToSeconds(uint64_t machTime) {
    return MachTimeToNanoseconds(machTime) / NSEC_PER_SEC;
}

#pragma mark Helpers - Code Signing

typedef struct {
    const NSString* name;
    int value;
} CSFlag;

#define CSFLAG(flag) {@#flag, flag}

// Code signing flags defined in cs_blobs.h
const CSFlag g_csFlags[] = {
    CSFLAG(CS_VALID),               CSFLAG(CS_ADHOC),           CSFLAG(CS_GET_TASK_ALLOW),
    CSFLAG(CS_INSTALLER),           CSFLAG(CS_FORCED_LV),       CSFLAG(CS_INVALID_ALLOWED),
    CSFLAG(CS_HARD),                CSFLAG(CS_KILL),            CSFLAG(CS_CHECK_EXPIRATION),
    CSFLAG(CS_RESTRICT),            CSFLAG(CS_ENFORCEMENT),     CSFLAG(CS_REQUIRE_LV),
    CSFLAG(CS_ENTITLEMENTS_VALIDATED),                          CSFLAG(CS_NVRAM_UNRESTRICTED),
    CSFLAG(CS_RUNTIME),             CSFLAG(CS_LINKER_SIGNED),   CSFLAG(CS_ALLOWED_MACHO),
    CSFLAG(CS_EXEC_SET_HARD),       CSFLAG(CS_EXEC_SET_KILL),   CSFLAG(CS_EXEC_SET_ENFORCEMENT),
    CSFLAG(CS_EXEC_INHERIT_SIP),    CSFLAG(CS_KILLED),          CSFLAG(CS_DYLD_PLATFORM),
    CSFLAG(CS_PLATFORM_BINARY),     CSFLAG(CS_PLATFORM_PATH),   CSFLAG(CS_DEBUGGED),
    CSFLAG(CS_SIGNED),              CSFLAG(CS_DEV_CODE)
};

NSString* codesigning_flags_str(const uint32_t codesigning_flags) {
    NSMutableArray *match_flags = [NSMutableArray new];
    
    // Test which code signing flags have been set and add the matched ones to an array
    for(uint32_t i = 0; i < (sizeof g_csFlags / sizeof *g_csFlags); i++) {
        if((codesigning_flags & g_csFlags[i].value) == g_csFlags[i].value) {
            [match_flags addObject:g_csFlags[i].name];
        }
    }
    
    return [match_flags componentsJoinedByString:@","];
}

// Check if a process is validly signed according to Gatekeeper policy
bool is_validly_signed(const es_process_t* proc, GatekeeperPolicyLevel policy_level) {
    if (policy_level == GatekeeperPolicyDisabled) {
        return true;
    }
    
    // Check if binary is a platform binary (Apple-signed)
    bool is_apple_binary = (proc->codesigning_flags & CS_PLATFORM_BINARY) == CS_PLATFORM_BINARY;
    
    // Check if binary has a valid signature
    bool is_validly_signed = (proc->codesigning_flags & CS_VALID) == CS_VALID;
    
    // Check if the signature was validated (not ad-hoc)
    bool not_adhoc = (proc->codesigning_flags & CS_ADHOC) != CS_ADHOC;
    
    if (is_apple_binary) {
        // Always allow Apple binaries
        return true;
    }
    
    // Get the team ID (used for Developer ID validation)
    NSString *team_id = esstring_to_nsstring(proc->team_id);
    
    // For App Store only policy, check for specific flags
    if (policy_level == GatekeeperPolicyAppStoreOnly) {
        // App Store apps have specific validation flags
        // This is a simplified check - real implementation would be more robust
        return is_validly_signed && not_adhoc &&
               (proc->codesigning_flags & CS_RESTRICT) == CS_RESTRICT;
    }
    
    // For Developer ID policy, check valid signature and not adhoc
    if (policy_level == GatekeeperPolicyDeveloperIDSigned) {
        return is_validly_signed && not_adhoc && team_id.length > 0;
    }
    
    return false;
}

// Check if an app has been notarized
bool is_notarized(const es_process_t* proc) {
    // In a real implementation, you would check for the hardened runtime flag
    // and validate that the app has been notarized using the Security framework
    // This is a simplified implementation
    return (proc->codesigning_flags & CS_RUNTIME) == CS_RUNTIME;
}

#pragma mark Helpers - Security Features

// Calculate SHA256 hash of a file
NSString* calculate_file_hash(const char* path) {
    NSData *data = [NSData dataWithContentsOfFile:@(path) options:NSDataReadingMappedIfSafe error:nil];
    if (!data) {
        return nil;
    }
    
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
    
    NSMutableString *hashString = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hashString appendFormat:@"%02x", hash[i]];
    }
    
    return [hashString copy];
}

// Check if file is quarantined
bool is_file_quarantined(const char* path) {
    NSString *nsPath = @(path);
    
    // Check cache first
    if (g_quarantine_status[nsPath] != nil) {
        return [g_quarantine_status[nsPath] boolValue];
    }
    
    // Read extended attribute
    const char *name = QUARANTINE_ATTR_NAME;
    ssize_t size = getxattr(path, name, NULL, 0, 0, 0);
    bool isQuarantined = (size > 0);
    
    // Cache the result
    g_quarantine_status[nsPath] = @(isQuarantined);
    
    return isQuarantined;
}

// Get quarantine data
NSDictionary* get_quarantine_data(const char* path) {
    const char *name = QUARANTINE_ATTR_NAME;
    ssize_t size = getxattr(path, name, NULL, 0, 0, 0);
    
    if (size <= 0) {
        return nil;
    }
    
    char *buffer = malloc(size);
    if (!buffer) {
        return nil;
    }
    
    getxattr(path, name, buffer, size, 0, 0);
    NSString *qdata = [[NSString alloc] initWithBytes:buffer length:size encoding:NSUTF8StringEncoding];
    free(buffer);
    
    if (!qdata) {
        return nil;
    }
    
    // Parse quarantine data - format is typically:
    // 0083;5f5e196e;Safari;6489CA8E-FC5E-4C0C-9F22-609C7C7D9F6F
    NSArray *components = [qdata componentsSeparatedByString:@";"];
    if (components.count < 4) {
        return nil;
    }
    
    return @{
        @"flag": components[0],
        @"timestamp": components[1],
        @"agent": components[2],
        @"uuid": components[3]
    };
}

// Record suspicious behavior
void record_suspicious_behavior(const es_process_t* proc) {
    NSString *path = esstring_to_nsstring(proc->executable->path);
    NSNumber *count = g_suspicious_behaviors[path];
    
    if (count == nil) {
        count = @(1);
    } else {
        count = @([count intValue] + 1);
    }
    
    g_suspicious_behaviors[path] = count;
    
    if ([count intValue] >= SUSPICIOUS_BEHAVIOR_THRESHOLD) {
        LOG_IMPORTANT_INFO("Process has triggered multiple suspicious behavior alerts: %@", path);
    }
}

// Check if file has a suspicious extension
bool has_suspicious_extension(const NSString* path) {
    NSString *extension = [path pathExtension].lowercaseString;
    return [g_suspicious_extensions containsObject:extension];
}

// Get executable file access permissions
bool can_execute(const es_file_t* file) {
    mode_t mode = file->stat.st_mode;
    uid_t uid = getuid();
    gid_t gid = getgid();
    
    if (uid == 0) {
        // Root can execute anything
        return true;
    }
    
    if (uid == file->stat.st_uid) {
        // User is owner
        return (mode & S_IXUSR) != 0;
    } else if (gid == file->stat.st_gid) {
        // User is in the file's group
        return (mode & S_IXGRP) != 0;
    } else {
        // Other
        return (mode & S_IXOTH) != 0;
    }
}

// Check if a file might be malware based on content analysis
ThreatLevel analyze_file_threat_level(const char* path) {
    // In a real implementation, this would use XProtect's signatures and analysis
    // For this demo, we'll use a simple hash lookup and extension check
    
    // Check file hash against known malicious hashes
    NSString *fileHash = calculate_file_hash(path);
    if (fileHash && [g_malicious_hashes containsObject:fileHash]) {
        return ThreatLevelMalicious;
    }
    
    // Check file extension
    NSString *filePath = @(path);
    if (has_suspicious_extension(filePath)) {
        return ThreatLevelSuspicious;
    }
    
    return ThreatLevelNone;
}

// Send a security notification
void send_security_notification(NSString *title, NSString *message, bool is_critical) {
    dispatch_async(g_notification_queue, ^{
        NSUserNotification *notification = [[NSUserNotification alloc] init];
        notification.title = title;
        notification.informativeText = message;
        notification.soundName = is_critical ? NSUserNotificationDefaultSoundName : nil;
        
        [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:notification];
        
        // Log the notification as well
        LOG_IMPORTANT_INFO("SECURITY ALERT: %@ - %@", title, message);
    });
}

#pragma mark Helpers - Endpoint Security

NSString* esstring_to_nsstring(const es_string_token_t es_string_token) {
    if(es_string_token.data && es_string_token.length > 0) {
        // es_string_token.data is a pointer to a null-terminated string
        return [NSString stringWithUTF8String:es_string_token.data];
    } else {
        return @"";
    }
}

const NSString* event_type_str(const es_event_type_t event_type) {
    static const NSString *names[] = {
        // The following events are available beginning in macOS 10.15
        @"ES_EVENT_TYPE_AUTH_EXEC", @"ES_EVENT_TYPE_AUTH_OPEN", @"ES_EVENT_TYPE_AUTH_KEXTLOAD",
        @"ES_EVENT_TYPE_AUTH_MMAP", @"ES_EVENT_TYPE_AUTH_MPROTECT", @"ES_EVENT_TYPE_AUTH_MOUNT",
        @"ES_EVENT_TYPE_AUTH_RENAME", @"ES_EVENT_TYPE_AUTH_SIGNAL", @"ES_EVENT_TYPE_AUTH_UNLINK",
        @"ES_EVENT_TYPE_NOTIFY_EXEC", @"ES_EVENT_TYPE_NOTIFY_OPEN", @"ES_EVENT_TYPE_NOTIFY_FORK",
        @"ES_EVENT_TYPE_NOTIFY_CLOSE", @"ES_EVENT_TYPE_NOTIFY_CREATE", @"ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA",
        @"ES_EVENT_TYPE_NOTIFY_EXIT", @"ES_EVENT_TYPE_NOTIFY_GET_TASK", @"ES_EVENT_TYPE_NOTIFY_KEXTLOAD",
        @"ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD", @"ES_EVENT_TYPE_NOTIFY_LINK", @"ES_EVENT_TYPE_NOTIFY_MMAP",
        @"ES_EVENT_TYPE_NOTIFY_MPROTECT", @"ES_EVENT_TYPE_NOTIFY_MOUNT", @"ES_EVENT_TYPE_NOTIFY_UNMOUNT",
        @"ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN", @"ES_EVENT_TYPE_NOTIFY_RENAME", @"ES_EVENT_TYPE_NOTIFY_SETATTRLIST",
        @"ES_EVENT_TYPE_NOTIFY_SETEXTATTR", @"ES_EVENT_TYPE_NOTIFY_SETFLAGS", @"ES_EVENT_TYPE_NOTIFY_SETMODE",
        @"ES_EVENT_TYPE_NOTIFY_SETOWNER", @"ES_EVENT_TYPE_NOTIFY_SIGNAL", @"ES_EVENT_TYPE_NOTIFY_UNLINK",
        @"ES_EVENT_TYPE_NOTIFY_WRITE", @"ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE",
        @"ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE", @"ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE",
        @"ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE", @"ES_EVENT_TYPE_AUTH_READLINK", @"ES_EVENT_TYPE_NOTIFY_READLINK",
        @"ES_EVENT_TYPE_AUTH_TRUNCATE", @"ES_EVENT_TYPE_NOTIFY_TRUNCATE", @"ES_EVENT_TYPE_AUTH_LINK",
        @"ES_EVENT_TYPE_NOTIFY_LOOKUP", @"ES_EVENT_TYPE_AUTH_CREATE", @"ES_EVENT_TYPE_AUTH_SETATTRLIST",
        @"ES_EVENT_TYPE_AUTH_SETEXTATTR", @"ES_EVENT_TYPE_AUTH_SETFLAGS", @"ES_EVENT_TYPE_AUTH_SETMODE",
        @"ES_EVENT_TYPE_AUTH_SETOWNER",
        
        // The following events are available beginning in macOS 10.15.1
        @"ES_EVENT_TYPE_AUTH_CHDIR", @"ES_EVENT_TYPE_NOTIFY_CHDIR", @"ES_EVENT_TYPE_AUTH_GETATTRLIST",
        @"ES_EVENT_TYPE_NOTIFY_GETATTRLIST", @"ES_EVENT_TYPE_NOTIFY_STAT", @"ES_EVENT_TYPE_NOTIFY_ACCESS",
        @"ES_EVENT_TYPE_AUTH_CHROOT", @"ES_EVENT_TYPE_NOTIFY_CHROOT", @"ES_EVENT_TYPE_AUTH_UTIMES",
        @"ES_EVENT_TYPE_NOTIFY_UTIMES", @"ES_EVENT_TYPE_AUTH_CLONE", @"ES_EVENT_TYPE_NOTIFY_CLONE",
        @"ES_EVENT_TYPE_NOTIFY_FCNTL", @"ES_EVENT_TYPE_AUTH_GETEXTATTR", @"ES_EVENT_TYPE_NOTIFY_GETEXTATTR",
        @"ES_EVENT_TYPE_AUTH_LISTEXTATTR", @"ES_EVENT_TYPE_NOTIFY_LISTEXTATTR", @"ES_EVENT_TYPE_AUTH_READDIR",
        @"ES_EVENT_TYPE_NOTIFY_READDIR", @"ES_EVENT_TYPE_AUTH_DELETEEXTATTR", @"ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR",
        @"ES_EVENT_TYPE_AUTH_FSGETPATH", @"ES_EVENT_TYPE_NOTIFY_FSGETPATH", @"ES_EVENT_TYPE_NOTIFY_DUP",
        @"ES_EVENT_TYPE_AUTH_SETTIME", @"ES_EVENT_TYPE_NOTIFY_SETTIME", @"ES_EVENT_TYPE_NOTIFY_UIPC_BIND",
        @"ES_EVENT_TYPE_AUTH_UIPC_BIND", @"ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT", @"ES_EVENT_TYPE_AUTH_UIPC_CONNECT",
        @"ES_EVENT_TYPE_AUTH_EXCHANGEDATA", @"ES_EVENT_TYPE_AUTH_SETACL", @"ES_EVENT_TYPE_NOTIFY_SETACL",
        
        // The following events are available beginning in macOS 10.15.4
        @"ES_EVENT_TYPE_NOTIFY_PTY_GRANT", @"ES_EVENT_TYPE_NOTIFY_PTY_CLOSE", @"ES_EVENT_TYPE_AUTH_PROC_CHECK",
        @"ES_EVENT_TYPE_NOTIFY_PROC_CHECK", @"ES_EVENT_TYPE_AUTH_GET_TASK",
        
        // The following events are available beginning in macOS 11.0
        @"ES_EVENT_TYPE_AUTH_SEARCHFS", @"ES_EVENT_TYPE_NOTIFY_SEARCHFS", @"ES_EVENT_TYPE_AUTH_FCNTL",
        @"ES_EVENT_TYPE_AUTH_IOKIT_OPEN", @"ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME",
        @"ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME", @"ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED",
        @"ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME", @"ES_EVENT_TYPE_NOTIFY_TRACE",
        @"ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE", @"ES_EVENT_TYPE_AUTH_REMOUNT", @"ES_EVENT_TYPE_NOTIFY_REMOUNT",
        
        // The following events are available beginning in macOS 11.3
        @"ES_EVENT_TYPE_AUTH_GET_TASK_READ", @"ES_EVENT_TYPE_NOTIFY_GET_TASK_READ",
        @"ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT",

        // The following events are available beginning in macOS 12.0
        @"ES_EVENT_TYPE_NOTIFY_SETUID", @"ES_EVENT_TYPE_NOTIFY_SETGID", @"ES_EVENT_TYPE_NOTIFY_SETEUID",
        @"ES_EVENT_TYPE_NOTIFY_SETEGID", @"ES_EVENT_TYPE_NOTIFY_SETREUID",
        @"ES_EVENT_TYPE_NOTIFY_SETREGID", @"ES_EVENT_TYPE_AUTH_COPYFILE", @"ES_EVENT_TYPE_NOTIFY_COPYFILE",

        // The following events are available beginning in macOS 13.0
        @"ES_EVENT_TYPE_NOTIFY_AUTHENTICATION", @"ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED",
        @"ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED", @"ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN",
        @"ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT", @"ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK",
        @"ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK", @"ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH",
        @"ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH", @"ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN",
        @"ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT", @"ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN",
        @"ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT", @"ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD",
        @"ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE",

        // The following events are available beginning in macOS 14.0
        @"ES_EVENT_TYPE_NOTIFY_PROFILE_ADD", @"ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE", @"ES_EVENT_TYPE_NOTIFY_SU",
        @"ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION", @"ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT",
        @"ES_EVENT_TYPE_NOTIFY_SUDO", @"ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD", @"ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE",
        @"ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET", @"ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD",
        @"ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER", @"ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER",
        @"ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD", @"ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE",
        @"ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET", @"ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER",
        @"ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP", @"ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER",
        @"ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP", @"ES_EVENT_TYPE_NOTIFY_XPC_CONNECT",

        // The following events are available beginning in macOS 15.0
        @"ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE"
    };
    
    if(event_type >= ES_EVENT_TYPE_LAST) {
        return [NSString stringWithFormat:@"Unknown/Unsupported event type: %d", event_type];
    }
    
    return names[event_type];
}

NSString* events_str(size_t count, const es_event_type_t* events) {
    NSMutableArray *arr = [NSMutableArray new];
    
    for(size_t i = 0; i < count; i++) {
        [arr addObject:event_type_str(events[i])];
    }
    
    return [arr componentsJoinedByString:@", "];
}

// On macOS Big Sur 11, Apple have deprecated es_copy_message in favour of es_retain_message
es_message_t * copy_message(const es_message_t * msg) {
    if(@available(macOS 11.0, *)) {
        es_retain_message(msg);
        // simulate a copy
        return (es_message_t*) msg;
    } else {
        return es_copy_message(msg);
    }
}

// On macOS Big Sur 11, Apple have deprecated es_free_message in favour of es_release_message
void free_message(es_message_t * _Nonnull msg) {
    if(@available(macOS 11.0, *)) {
        es_release_message(msg);
    } else {
        es_free_message(msg);
    }
}

#pragma mark Helpers - Misc

NSString* fdtype_str(const uint32_t fdtype) {
    switch(fdtype) {
        case PROX_FDTYPE_ATALK: return @"ATALK";
        case PROX_FDTYPE_VNODE: return @"VNODE";
        case PROX_FDTYPE_SOCKET: return @"SOCKET";
        case PROX_FDTYPE_PSHM: return @"PSHM";
        case PROX_FDTYPE_PSEM: return @"PSEM";
        case PROX_FDTYPE_KQUEUE: return @"KQUEUE";
        case PROX_FDTYPE_PIPE: return @"PIPE";
        case PROX_FDTYPE_FSEVENTS: return @"FSEVENTS";
        case PROX_FDTYPE_NETPOLICY: return @"NETPOLICY";
        default: return [NSString stringWithFormat:@"Unknown/Unsupported fdtype: %d",
                         fdtype];
    }
}

void init_date_formater(void) {
    // Display dates in RFC 3339 date and time format: https://www.ietf.org/rfc/rfc3339.txt
    g_date_formater = [NSDateFormatter new];
    g_date_formater.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    g_date_formater.dateFormat = @"yyyy-MM-dd'T'HH:mm:ssZZZZZ";
    g_date_formater.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
}

NSString* formatted_date_str(__darwin_time_t secs_since_1970) {
    NSDate *date = [NSDate dateWithTimeIntervalSince1970:secs_since_1970];
    return [g_date_formater stringFromDate:date];
}

bool is_system_file(const NSString* path) {
    // For the purpose of this demo. A system file is a file that is under these directories:
    for(NSString* prefix in @[@"/System/", @"/usr/share/"]) {
        if([path hasPrefix:prefix]) {
            return true;
        }
    }
    
    return false;
}

bool is_plain_text_file(const NSString* path) {
    if(@available(macOS 11.0, *)) {
        UTType* utt = [UTType typeWithFilenameExtension:[path pathExtension]];
        return [utt conformsToType:UTTypePlainText];
    } else {
        return [[NSWorkspace sharedWorkspace]
                filenameExtension:[path pathExtension]
                isValidForType:@"public.plain-text"];
    }
}

char* filetype_str(const mode_t st_mode) {
    switch(((st_mode) & S_IFMT)) {
        case S_IFBLK: return "BLK";
        case S_IFCHR: return "CHR";
        case S_IFDIR: return "DIR";
        case S_IFIFO: return "FIFO";
        case S_IFREG: return "REG";
        case S_IFLNK: return "LINK";
        case S_IFSOCK: return "SOCK";
        default: return "";
    }
}

void log_audit_token(const NSString* header, const audit_token_t audit_token) {
    LOG_INFO("%@:", header);
    LOG_INDENT_INC();
    LOG_INFO("pid: %d", audit_token_to_pid(audit_token));
    LOG_INFO("ruid: %d", audit_token_to_ruid(audit_token));
    LOG_INFO("euid: %d", audit_token_to_euid(audit_token));
    LOG_INFO("rgid: %d", audit_token_to_rgid(audit_token));
    LOG_INFO("egid: %d", audit_token_to_egid(audit_token));
    LOG_INDENT_DEC();
}

API_AVAILABLE(macos(12.0))
bool log_muted_paths_events(void) {
    es_muted_paths_t *muted_paths = NULL;
    es_return_t result = es_muted_paths_events(g_client, &muted_paths);
    
    if(ES_RETURN_SUCCESS != result) {
        LOG_ERROR("es_muted_paths_events: ES_RETURN_ERROR");
        return false;
    }
    
    if(NULL == muted_paths) {
        // There are no muted paths
        return true;
    }
    
    LOG_IMPORTANT_INFO("Muted Paths");
    for(size_t i = 0; i < muted_paths->count; i++) {
        es_muted_path_t muted_path = muted_paths->paths[i];
        LOG_INFO("muted_path[%ld]: %@", i, esstring_to_nsstring(muted_path.path));
        
        if(g_verbose_logging) {
            LOG_INDENT_INC();
            LOG_INFO("type: %s", (muted_path.type == ES_MUTE_PATH_TYPE_PREFIX) ? "Prefix" : "Literal");
            LOG_INFO("event_count: %ld", muted_path.event_count);
            LOG_INFO("events: %@", events_str(muted_path.event_count, muted_path.events));
            LOG_INDENT_DEC();
        }
    }
    
    es_release_muted_paths(muted_paths);
    return true;
}

bool log_subscribed_events(void) {
    // Log the subscribed events
    size_t count = 0;
    es_event_type_t *events = NULL;
    es_return_t result = es_subscriptions(g_client, &count, &events);
    
    if(ES_RETURN_SUCCESS != result) {
        LOG_ERROR("es_subscriptions: ES_RETURN_ERROR");
        return false;
    }
    
    LOG_IMPORTANT_INFO("Subscribed Events: %@", events_str(count, events));
    
    free(events);
    return true;
}

void log_file(const NSString* header, const es_file_t* file) {
    if(!file) {
        LOG_INFO("%@: (null)", header);
        return;
    }
    
    LOG_INFO("%@:", header);
    LOG_INDENT_INC();
    LOG_INFO("path: %@", esstring_to_nsstring(file->path));
    LOG_INFO("path_truncated: %s", BOOL_VALUE(file->path_truncated));
    
    LOG_INFO("stat.st_dev: %d", file->stat.st_dev);
    LOG_INFO("stat.st_ino: %llu", file->stat.st_ino);
    LOG_INFO("stat.st_mode: %u (%s)", file->stat.st_mode, filetype_str(file->stat.st_mode));
    LOG_INFO("stat.st_nlink: %u", file->stat.st_nlink);
    
    LOG_INFO("stat.st_uid: %u", file->stat.st_uid);
    LOG_INFO("stat.st_gid: %u", file->stat.st_gid);
    
    LOG_INFO("stat.st_atime: %@", formatted_date_str(file->stat.st_atime));
    LOG_INFO("stat.st_mtime: %@", formatted_date_str(file->stat.st_mtime));
    LOG_INFO("stat.st_ctime: %@", formatted_date_str(file->stat.st_ctime));
    LOG_INFO("stat.st_birthtime: %@", formatted_date_str(file->stat.st_birthtime));
    
    LOG_INFO("stat.st_size: %lld", file->stat.st_size);
    LOG_INFO("stat.st_blocks: %lld", file->stat.st_blocks);
    LOG_INFO("stat.st_blksize: %d", file->stat.st_blksize);
    LOG_INFO("stat.st_flags: %u", file->stat.st_flags);
    LOG_INFO("stat.st_gen: %u", file->stat.st_gen);
    LOG_INDENT_DEC();
}

void log_proc(uint32_t msg_version, const NSString* header, const es_process_t* proc) {
    if(!proc) {
        LOG_INFO("%@: (null)", header);
        return;
    }
    
    LOG_INFO("%@:", header);
    LOG_INDENT_INC();
    log_audit_token(@"proc.audit_token", proc->audit_token);
    LOG_INFO("proc.ppid: %d", proc->ppid);
    LOG_INFO("proc.original_ppid: %d", proc->original_ppid);
    
    if(msg_version >= 4) {
        log_audit_token(@"proc.responsible_audit_token", proc->responsible_audit_token);
        log_audit_token(@"proc.parent_audit_token", proc->parent_audit_token);
    }
    
    LOG_INFO("proc.group_id: %d", proc->group_id);
    LOG_INFO("proc.session_id: %d", proc->session_id);
    LOG_INFO("proc.is_platform_binary: %s", BOOL_VALUE(proc->is_platform_binary));
    LOG_INFO("proc.is_es_client: %s", BOOL_VALUE(proc->is_es_client));
    LOG_INFO("proc.signing_id: %@", esstring_to_nsstring(proc->signing_id));
    LOG_INFO("proc.team_id: %@", esstring_to_nsstring(proc->team_id));
    
    if(msg_version >= 3) {
        LOG_INFO("proc.start_time: %@", formatted_date_str(proc->start_time.tv_sec));
    }
    
    LOG_INFO("proc.codesigning_flags: %x (%@)",
             proc->codesigning_flags, codesigning_flags_str(proc->codesigning_flags));
    
    // proc.cdhash
    NSMutableString *hash = [NSMutableString string];
    for(uint32_t i = 0; i < CS_CDHASH_LEN; i++) {
        [hash appendFormat:@"%02x", proc->cdhash[i]];
    }
    LOG_INFO("proc.cdhash: %@", hash);
    
    log_file(@"proc.executable", proc->executable);
    
    if(msg_version >= 2 && proc->tty) {
        log_file(@"proc.tty", proc->tty);
    }
    
    LOG_INDENT_DEC();
}

void log_command_line_arguments(const es_event_exec_t* exec) {
    uint32_t arg_count = es_exec_arg_count(exec);
    LOG_INFO("event.exec.arg_count: %u", arg_count);
    LOG_INDENT_INC();
    
    // Extract each argument and log it out
    for(uint32_t i = 0; i < arg_count; i++) {
        es_string_token_t arg = es_exec_arg(exec, i);
        LOG_INFO("arg[%d]: %@", i, esstring_to_nsstring(arg));
    }
    
    LOG_INDENT_DEC();
}

void log_environment_variable(const es_event_exec_t* exec) {
    uint32_t env_count = es_exec_env_count(exec);
    LOG_INFO("event.exec.env_count: %u", env_count);
    LOG_INDENT_INC();
    
    // Extract each env and log it out
    for(uint32_t i = 0; i < env_count; i++) {
        es_string_token_t arg = es_exec_env(exec, i);
        LOG_INFO("env[%d]: %@", i, esstring_to_nsstring(arg));
    }
    
    LOG_INDENT_DEC();
}

void log_file_descriptors(const es_event_exec_t* exec) {
    if(@available(macOS 11.0, *)) {
        uint32_t fd_count = es_exec_fd_count(exec);
        LOG_INFO("event.exec.fd_count: %u", fd_count);
        LOG_INDENT_INC();
        
        // Extract each fd and log it out
        for(uint32_t i = 0; i < fd_count; i++) {
            // Pointer must not outlive event
            const es_fd_t *arg = es_exec_fd(exec, i);
            
            LOG_INFO("fd[%d].fd: %d", i, arg->fd);
            LOG_INFO("fd[%d].fdtype: %@", i, fdtype_str(arg->fdtype));
            
            if(PROX_FDTYPE_PIPE == arg->fdtype) {
                LOG_INFO("fd[%d].fd: %llu", i, arg->pipe.pipe_id);
            }
        }
        
        LOG_INDENT_DEC();
    }
}

void log_event_exec(uint32_t msg_version, const es_event_exec_t* exec) {
    log_proc(msg_version, @"event.exec.target", exec->target);
    log_command_line_arguments(exec);
    log_environment_variable(exec);
    log_file_descriptors(exec);
    
    if(msg_version >= 2 && exec->script) {
        log_file(@"event.exec.script", exec->script);
    }
    
    if(msg_version >= 3) {
        log_file(@"event.exec.cwd", exec->cwd);
    }
    
    if(msg_version >= 4) {
        LOG_INFO("event.exec.last_fd: %d", exec->last_fd);
    }
}

void log_event_open(const es_event_open_t* open) {
    NSMutableArray *match_flags = [NSMutableArray new];
    
    if((open->fflag & FREAD) == FREAD) {
        [match_flags addObject:@"FREAD"];
    }
    
    if((open->fflag & FWRITE) == FWRITE) {
        [match_flags addObject:@"FWRITE"];
    }
    
    LOG_INFO("event.open.fflag: %d (%@)",
             open->fflag, [match_flags componentsJoinedByString:@", "]);
    log_file(@"event.open.file", open->file);
}

// Logs the top level datatype sent by Endpoint Security subsystem to its clients
void log_event_message(const es_message_t *msg) {
    LOG_INFO("--- EVENT MESSAGE ----");
    LOG_INFO("event_type: %@ (%d)", event_type_str(msg->event_type), msg->event_type);
    
    // Note: Apple have designed the Endpoint Security structures to support additional fields
    // in the future. Always check the version of the message before using a field, in the message
    // or sub-structure, which has been added to a later version of Endpoint Security.
    // Only new fields are added. Existing fields should be available in future revisions.
    uint32_t version = msg->version;
    LOG_INFO("version: %u", version);
    
    LOG_INFO("time: %@", formatted_date_str(msg->time.tv_sec));
    LOG_INFO("mach_time: %lld", msg->mach_time);
   
    // Note: It's very important that an auth event is processed within the deadline:
    // https://developer.apple.com/documentation/endpointsecurity/es_message_t/3334985-deadline
    LOG_INFO("deadline: %llu", msg->deadline);
    
    uint64_t deadlineInterval = msg->deadline;
    
    if(deadlineInterval > 0) {
        deadlineInterval -= msg->mach_time;
    }
    
    LOG_INFO("deadline interval: %llu (%llu seconds)",
             deadlineInterval, MachTimeToSeconds(deadlineInterval));
    
    // Note: You can use the seq_num field to detect if the kernel had to drop any event messages,
    // for an event type, to the client.
    if(version >= 2) {
        LOG_INFO("seq_num: %lld", msg->seq_num);
    }
    
    // Note: You can use the global_seq_num field to detect if the kernel had to drop any event
    // messages to the client.
    if(version >= 4) {
        LOG_INFO("global_seq_num: %lld", msg->global_seq_num);
    }
    
    if(version >= 4 && msg->thread) {
        LOG_INFO("thread_id: %lld", msg->thread->thread_id);
    }
    
    LOG_INFO("action_type: %s", (msg->action_type == ES_ACTION_TYPE_AUTH) ? "Auth" : "Notify");
    log_proc(version, @"process", msg->process);
    
    // Event specific logging
    switch(msg->event_type) {
        case ES_EVENT_TYPE_AUTH_EXEC: {
            log_event_exec(version, &msg->event.exec);
        }
            break;
            
        case ES_EVENT_TYPE_AUTH_OPEN: {
            log_event_open(&msg->event.open);
        }
            break;
            
        case ES_EVENT_TYPE_NOTIFY_FORK: {
            log_proc(version, @"event.fork.child", msg->event.fork.child);
        }
            break;
            
        case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE: {
            // Available in macOS 15+ - monitor user overrides of Gatekeeper decisions
            if (@available(macOS 15.0, *)) {
                // The exact structure format depends on the Apple SDK
                // This is a simplified version
                LOG_SECURITY("Gatekeeper override detected");
                
                // Log when a user overrides Gatekeeper to allow an unsigned app
                send_security_notification(@"Gatekeeper Override",
                                         @"User overrode Gatekeeper protection",
                                         true);
            }
        }
            break;
            
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED: {
            // Available in macOS 13+ - monitor XProtect malware detections
            if (@available(macOS 13.0, *)) {
                // The exact structure format depends on the Apple SDK
                // This is a simplified version
                LOG_SECURITY("XProtect detected malware");
                
                // Alert on XProtect detections
                send_security_notification(@"Malware Detected",
                                         @"XProtect detected malware",
                                         true);
            }
        }
            break;
            
        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED: {
            // Available in macOS 13+ - monitor XProtect malware remediations
            if (@available(macOS 13.0, *)) {
                // The exact structure format depends on the Apple SDK
                // This is a simplified version
                LOG_SECURITY("XProtect remediated malware");
                
                // Alert on XProtect remediations
                send_security_notification(@"Malware Remediated",
                                         @"XProtect remediated malware",
                                         false);
            }
        }
            break;
            
        case ES_EVENT_TYPE_LAST:
        default: {
            // Not interested
        }
    }
    
    LOG_INFO("");
}

// Demonstrates detecting dropped event messages from the kernel, by either
// using the using the seq_num or global_seq_num fields in an event message
void detect_and_log_dropped_events(const es_message_t *msg) {
    uint32_t version = msg->version;
    
    // Note: You can use the seq_num field to detect if the kernel had to
    // drop any event messages, for an event type, to the client.
    if(version >= 2) {
        uint64_t seq_num = msg->seq_num;
        
        const NSString *type = event_type_str(msg->event_type);
        NSNumber *last_seq_num = [g_seq_nums objectForKey:type];
        
        if(last_seq_num != nil) {
            uint64_t expected_seq_num = [last_seq_num unsignedLongLongValue] + 1;
            
            if(seq_num > expected_seq_num) {
                LOG_ERROR("EVENTS DROPPED! seq_num is ahead by: %llu",
                          (seq_num - expected_seq_num));
            }
        }
        
        [g_seq_nums setObject:[NSNumber numberWithUnsignedLong:seq_num] forKey:type];
    }
    
    // Note: You can use the global_seq_num field to detect if the kernel had to
    // drop any event messages to the client.
    if(version >= 4) {
        uint64_t global_seq_num = msg->global_seq_num;
        
        if(global_seq_num > ++g_global_seq_num) {
            LOG_ERROR("EVENTS DROPPED! global_seq_num is ahead by: %llu",
                      (global_seq_num - g_global_seq_num));
            g_global_seq_num = global_seq_num;
        }
    }
}

#pragma mark - Security Handlers

// Enhanced handler for Gatekeeper-style checks
es_auth_result_t gatekeeper_auth_handler(const es_message_t *msg) {
    // We're only interested in execution events for Gatekeeper functionality
    if (ES_EVENT_TYPE_AUTH_EXEC != msg->event_type) {
        return ES_AUTH_RESULT_ALLOW;
    }
    
    // Get the path of the file being executed
    NSString *path = esstring_to_nsstring(msg->event.exec.target->executable->path);
    
    // Check if we have a specific notarization requirement for this path
    NSNumber *requirementLevel = [g_notarization_requirements objectForKey:path];
    
    // If no specific requirement, use default (developer ID signed)
    GatekeeperPolicyLevel policyLevel = requirementLevel ?
                                      [requirementLevel intValue] :
                                      GatekeeperPolicyDeveloperIDSigned;
    
    // Skip checking system binaries
    if (msg->event.exec.target->is_platform_binary) {
        return ES_AUTH_RESULT_ALLOW;
    }
    
    // Check for quarantine flag
    bool quarantined = is_file_quarantined(msg->event.exec.target->executable->path.data);
    
    // If file is quarantined, apply stricter checks
    if (quarantined) {
        LOG_SECURITY("Quarantined file execution attempt: %@", path);
        
        // Check if validly signed according to policy
        bool validly_signed = is_validly_signed(msg->event.exec.target, policyLevel);
        
        // Check if notarized (for apps requiring it)
        bool notarized = is_notarized(msg->event.exec.target);
        
        // For quarantined files, we want both valid signature and notarization
        if (!validly_signed || (policyLevel >= GatekeeperPolicyDeveloperIDSigned && !notarized)) {
            LOG_SECURITY("BLOCKING EXEC (Gatekeeper): Quarantined file lacks proper signing/notarization: %@", path);
            
            // Send notification
            send_security_notification(@"Execution Blocked",
                                     [NSString stringWithFormat:@"Blocked execution of unsigned/unnotarized app: %@", path],
                                     true);
            
            return ES_AUTH_RESULT_DENY;
        }
        
        // Log successful validation
        LOG_SECURITY("Allowed quarantined file execution (validated): %@", path);
    } else {
        // For non-quarantined files, perform basic signature validation
        if (policyLevel > GatekeeperPolicyDisabled && !is_validly_signed(msg->event.exec.target, policyLevel)) {
            LOG_SECURITY("BLOCKING EXEC (Gatekeeper): Non-quarantined file lacks proper signing: %@", path);
            
            // Send notification
            send_security_notification(@"Execution Blocked",
                                     [NSString stringWithFormat:@"Blocked execution of unsigned app: %@", path],
                                     true);
            
            return ES_AUTH_RESULT_DENY;
        }
    }
    
    return ES_AUTH_RESULT_ALLOW;
}

// Enhanced handler for XProtect-style malware detection
es_auth_result_t xprotect_auth_handler(const es_message_t *msg) {
    if (ES_EVENT_TYPE_AUTH_EXEC == msg->event_type) {
        NSString *path = esstring_to_nsstring(msg->event.exec.target->executable->path);
        
        // Analyze file for potential threats
        ThreatLevel threatLevel = analyze_file_threat_level(msg->event.exec.target->executable->path.data);
        
        if (threatLevel == ThreatLevelMalicious) {
            LOG_SECURITY("BLOCKING EXEC (XProtect): Malicious file detected: %@", path);
            
            // Send notification
            send_security_notification(@"Malware Blocked",
                                     [NSString stringWithFormat:@"Blocked execution of malicious file: %@", path],
                                     true);
            
            return ES_AUTH_RESULT_DENY;
        }
        
        if (threatLevel == ThreatLevelSuspicious) {
            LOG_SECURITY("WARNING (XProtect): Suspicious file execution: %@", path);
            
            // Record suspicious behavior
            record_suspicious_behavior(msg->process);
            
            // Send notification but allow execution
            send_security_notification(@"Suspicious File",
                                     [NSString stringWithFormat:@"Suspicious file executed: %@", path],
                                     false);
        }
    } else if (ES_EVENT_TYPE_AUTH_OPEN == msg->event_type) {
        NSString *filePath = esstring_to_nsstring(msg->event.open.file->path);
        
        // Look for suspicious access patterns to sensitive files
        if ([filePath containsString:@"/Library/Keychains/"] ||
            [filePath containsString:@"/Library/Preferences/"] ||
            [filePath containsString:@"/.ssh/"]) {
            
            LOG_SECURITY("WARNING (XProtect): Sensitive file access: %@ by %@",
                        filePath,
                        esstring_to_nsstring(msg->process->executable->path));
            
            // Record suspicious behavior
            record_suspicious_behavior(msg->process);
            
            // Get number of suspicious behaviors for this process
            NSString *processPath = esstring_to_nsstring(msg->process->executable->path);
            NSNumber *count = g_suspicious_behaviors[processPath];
            
            // If this process has multiple suspicious behaviors, block sensitive file access
            if (count && [count intValue] >= SUSPICIOUS_BEHAVIOR_THRESHOLD) {
                LOG_SECURITY("BLOCKING ACCESS (XProtect): Process has multiple suspicious behaviors: %@", processPath);
                
                // Send notification
                send_security_notification(@"Suspicious Access Blocked",
                                         [NSString stringWithFormat:@"Blocked suspicious access to %@ by %@",
                                         filePath, processPath],
                                         true);
                
                return ES_AUTH_RESULT_DENY;
            }
        }
    }
    
    return ES_AUTH_RESULT_ALLOW;
}

// An example handler to make auth (allow or block) decisions.
// Returns either an ES_AUTH_RESULT_ALLOW or ES_AUTH_RESULT_DENY.
es_auth_result_t auth_event_handler(const es_message_t *msg) {
    // NOTE: You should ignore events from other ES Clients;
    // otherwise you may trigger more events causing a potentially infinite cycle.
    if(msg->process->is_es_client) {
        return ES_AUTH_RESULT_ALLOW;
    }
    
    // Ignore events from root processes unless in Gatekeeper/XProtect mode
    if(0 == audit_token_to_ruid(msg->process->audit_token) &&
       !g_gatekeeper_mode && !g_xprotect_mode) {
        return ES_AUTH_RESULT_ALLOW;
    }
    
    // Run enhanced Gatekeeper checks if enabled
    if (g_gatekeeper_mode) {
        es_auth_result_t gatekeeper_result = gatekeeper_auth_handler(msg);
        if (gatekeeper_result == ES_AUTH_RESULT_DENY) {
            return ES_AUTH_RESULT_DENY;
        }
    }
    
    // Run enhanced XProtect checks if enabled
    if (g_xprotect_mode) {
        es_auth_result_t xprotect_result = xprotect_auth_handler(msg);
        if (xprotect_result == ES_AUTH_RESULT_DENY) {
            return ES_AUTH_RESULT_DENY;
        }
    }
    
    // Block exec if path of process is in our blocked paths list
    if(ES_EVENT_TYPE_AUTH_EXEC == msg->event_type) {
        NSString *path = esstring_to_nsstring(msg->event.exec.target->executable->path);
        
        if(![g_blocked_paths containsObject:path]) {
            return ES_AUTH_RESULT_ALLOW;
        }
        
        // Process is in our blocked list
        LOG_IMPORTANT_INFO("BLOCKING EXEC: %@", path);
        return ES_AUTH_RESULT_DENY;
    }
    
    // Block vim from accessing plain text files
    if(ES_EVENT_TYPE_AUTH_OPEN == msg->event_type) {
        NSString *processPath = esstring_to_nsstring(msg->process->executable->path);
        
        if(![processPath isEqualToString:@"/usr/bin/vim"]) {
            // Not vim
            return ES_AUTH_RESULT_ALLOW;
        }
        
        NSString *filePath = esstring_to_nsstring(msg->event.open.file->path);
        
        if(is_system_file(filePath)) {
            // Ignore System files
            return ES_AUTH_RESULT_ALLOW;
        }
        
        if(!is_plain_text_file(filePath)) {
            // Not a text file
            return ES_AUTH_RESULT_ALLOW;
        }
        
        // Process is vim trying to access a text file
        LOG_IMPORTANT_INFO("BLOCKING OPEN: %@", filePath);
        return ES_AUTH_RESULT_DENY;
    }
    
    // All good
    return ES_AUTH_RESULT_ALLOW;
}

// Sends a response back to Endpoint Security for an auth event
// Note: You must always send a response back before the deadline expires.
void respond_to_auth_event(es_client_t *clt, const es_message_t *msg, es_auth_result_t result) {
    // Only log ES_AUTH_RESULT_DENY results when verbose logging is disabled
    if(ES_AUTH_RESULT_DENY == result) {
        LOG_NON_VERBOSE_EVENT_MESSAGE(msg);
    }
    
    // Note: You use es_respond_auth_result() to respond to auth events,
    // except for ES_EVENT_TYPE_AUTH_OPEN events, which require a response
    // using es_respond_flags_result() instead.
    if(ES_EVENT_TYPE_AUTH_OPEN == msg->event_type) {
        uint32_t authorized_flags = 0;
        
        if(ES_AUTH_RESULT_ALLOW == result) {
            authorized_flags = msg->event.open.fflag;
        }
        
        es_respond_result_t res =
            es_respond_flags_result(clt, msg, authorized_flags, g_cache_auth_results);
        
        if(ES_RESPOND_RESULT_SUCCESS != res) {
            LOG_ERROR("es_respond_flags_result: %d", res);
        }
        
    } else {
        es_respond_result_t res =
            es_respond_auth_result(clt, msg, result, g_cache_auth_results);
        
        if(ES_RESPOND_RESULT_SUCCESS != res) {
            LOG_ERROR("es_respond_auth_result: %d", res);
        }
    }
}

#pragma mark - Endpoint Secuirty Demo

// Clean-up before exiting
void sig_handler(int sig) {
    LOG_IMPORTANT_INFO("Tidying Up");
    
    if(g_client) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
    }
    
    LOG_IMPORTANT_INFO("Exiting");
    exit(EXIT_SUCCESS);
}

void print_usage(const char *name) {
    printf("Usage: %s (serial | asynchronous | gatekeeper | xprotect) [verbose]\n", name);
    printf("Arguments:\n");
    printf("\tserial\t\tUse serial message handler\n");
    printf("\tasynchronous\tUse asynchronous message handler\n");
    printf("\tgatekeeper\tEnable Gatekeeper-like protections\n");
    printf("\txprotect\tEnable XProtect-like protections\n");
    printf("\tverbose\t\tTurns on verbose logging\n");
}

// Initialize security preferences and malware signatures
void init_security_features(void) {
    // Initialize suspicious extensions to monitor
    g_suspicious_extensions = [NSSet setWithObjects:
                              @"app", @"dylib", @"kext", @"pkg",
                              @"dmg", @"sh", @"py", @"js", @"command", nil];
    
    // Initialize malicious hash database (simplified)
    // In a real implementation, this would be loaded from an XProtect signature database
    g_malicious_hashes = [NSMutableSet setWithObjects:
                         @"e1112134b6dcc8bed54e0e34d8ac272795e73d74fc1bed74f5c716480d1bd60b", // Example hash
                         @"74865fb5bca5f883169ea308cc441137d36fb1663dd7749db3cc9e0880a8c51a", // Example hash
                         nil];
    
    // Initialize notarization requirements (path -> requirement level)
    // 0 = disabled, 1 = developer ID signed, 2 = App Store only
    g_notarization_requirements = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                 @(GatekeeperPolicyAppStoreOnly), @"/Applications/Banking.app/Contents/MacOS/Banking",
                                 @(GatekeeperPolicyDeveloperIDSigned), @"/Applications/Developer.app/Contents/MacOS/Developer",
                                 nil];
    
    // Initialize the quarantine status cache
    g_quarantine_status = [NSMutableDictionary new];
    
    // Initialize the suspicious behaviors tracking
    g_suspicious_behaviors = [NSMutableDictionary new];
    
    // Initialize the security preferences
    g_security_preferences = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                            @(YES), @"BlockSuspiciousProcesses",
                            @(YES), @"MonitorSensitiveDirectories",
                            @(YES), @"EnforceCodeSigning",
                            @(YES), @"CheckQuarantineFlag",
                            nil];
    
    // Initialize notification queue
    g_notification_queue = dispatch_queue_create("com.security.notifications", DISPATCH_QUEUE_SERIAL);
    
    LOG_IMPORTANT_INFO("Security features initialized");
}

// Example of an event message handler to process event messages serially from Endpoint Security.
es_handler_block_t serial_message_handler = ^(es_client_t *clt, const es_message_t *msg) {
    // Endpoint Security, by default, calls a event message handler serially for each message.
    
    LOG_VERBOSE_EVENT_MESSAGE(msg);
    
    // NOTE: It is important to process events in a timely manner.
    // The kernel will start to drop events for the client if they are not responded to in time.
    detect_and_log_dropped_events(msg);
    
    // Auth events require a response sent back before the deadline expires
    if(ES_ACTION_TYPE_AUTH == msg->action_type) {
        respond_to_auth_event(clt, msg, auth_event_handler(msg));
    }
};

// Example of an event message handler to process event messages asynchronously from Endpoint Security
es_handler_block_t asynchronous_message_handler = ^(es_client_t *clt, const es_message_t *msg) {
    // Endpoint Security, by default, calls a event message handler serially for each message.
    // We copy/retain the message so that we can process and respond to auth events asynchronously.
    
    LOG_VERBOSE_EVENT_MESSAGE(msg);
    
    // NOTE: It is important to process events in a timely manner.
    // The kernel will start to drop events for the client if they are not responded to in time.
    detect_and_log_dropped_events(msg);
    
    // Copy/Retain the event message so that we process the event asynchronously
    es_message_t *copied_msg = copy_message(msg);
    
    if(!copied_msg) {
        LOG_ERROR("Failed to copy message");
        return;
    }
    
    // Demonstrates handling events out of order, by processing 'ES_ACTION_TYPE_AUTH' events on
    // a separate thread.
    if(ES_ACTION_TYPE_AUTH == copied_msg->action_type) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^(void){
            es_auth_result_t result = auth_event_handler(copied_msg);
            
            // Auth events require a response sent back before the deadline expires
            respond_to_auth_event(clt, copied_msg, result);
            free_message(copied_msg);
        });
        
        return;
    }
    
    // Free/release the message
    free_message(copied_msg);
};

es_handler_block_t get_message_handler_from_commandline_args(int argc, const char * argv[]) {
    if(argc < 2) {
        // No command line argument was given
        return nil;
    }
    
    // check if verbose logging argument was given
    for (int i = 1; i < argc; i++) {
        NSString *arg = [[NSString stringWithUTF8String:argv[i]] lowercaseString];
        
        if ([arg isEqualToString:@"verbose"]) {
            g_verbose_logging = true;
        } else if ([arg isEqualToString:@"gatekeeper"]) {
            g_gatekeeper_mode = true;
        } else if ([arg isEqualToString:@"xprotect"]) {
            g_xprotect_mode = true;
        }
    }
    
    // Try and find an event message handler that matches the first command line argument
    NSString *arg = [[NSString stringWithUTF8String:argv[1]] lowercaseString];
    
    if ([arg isEqualToString:@"gatekeeper"] || [arg isEqualToString:@"xprotect"]) {
        return serial_message_handler;
    }
    
    NSDictionary *handlers = @{
        @"serial" : serial_message_handler,
        @"asynchronous" : asynchronous_message_handler
    };
    
    return [handlers objectForKey:arg];
}

// On macOS Monterey 12, Apple have deprecated es_mute_path_literal in favour of es_mute_path
bool mute_path(const char* path)
{
    es_return_t result = ES_RETURN_ERROR;
    
    if(@available(macOS 12.0, *)) {
        result = es_mute_path(g_client, path, ES_MUTE_PATH_TYPE_LITERAL);
    } else {
        result = es_mute_path_literal(g_client, path);
    }
    
    if(ES_RETURN_SUCCESS != result) {
        LOG_ERROR("mute_path: ES_RETURN_ERROR");
        return false;
    }
    
    return true;
}

// Note: This function shows the boilerplate code required to setup a connection to Endpoint Security
// and subscribe to events.
bool setup_endpoint_security(void) {
    // Create a new client with an associated event message handler.
    // Requires 'com.apple.developer.endpoint-security.client' entitlement.
    es_new_client_result_t res = es_new_client(&g_client, g_handler);
    
    if(ES_NEW_CLIENT_RESULT_SUCCESS != res) {
        switch(res) {
            case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
                LOG_ERROR("Application requires 'com.apple.developer.endpoint-security.client' entitlement");
                break;

            case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
                LOG_ERROR("Application lacks Transparency, Consent, and Control (TCC) approval "
                          "from the user. This can be resolved by granting 'Full Disk Access' from "
                          "the 'Security & Privacy' tab of System Preferences.");
                break;

            case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
                LOG_ERROR("Application needs to be run as root");
                break;

            default:
                LOG_ERROR("es_new_client: %d", res);
        }
        
        return false;
    }
    
    // Explicitly clear the cache of previous cached results from this demo or other ES Clients
    es_clear_cache_result_t resCache = es_clear_cache(g_client);
    if(ES_CLEAR_CACHE_RESULT_SUCCESS != resCache) {
        LOG_ERROR("es_clear_cache: %d", resCache);
        return false;
    }
    
    // Build a list of events to subscribe to
    NSMutableArray *eventsList = [NSMutableArray arrayWithObjects:
                               @(ES_EVENT_TYPE_AUTH_EXEC),
                               @(ES_EVENT_TYPE_AUTH_OPEN),
                               @(ES_EVENT_TYPE_NOTIFY_FORK),
                               nil];
    
    // Add XProtect and Gatekeeper specific events if enabled
    if (g_xprotect_mode) {
        // XProtect needs to monitor write and create events
        [eventsList addObject:@(ES_EVENT_TYPE_NOTIFY_CREATE)];
        [eventsList addObject:@(ES_EVENT_TYPE_NOTIFY_WRITE)];
        
        if (@available(macOS 13.0, *)) {
            [eventsList addObject:@(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED)];
            [eventsList addObject:@(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED)];
        }
    }
    
    if (g_gatekeeper_mode) {
        if (@available(macOS 15.0, *)) {
            [eventsList addObject:@(ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE)];
        }
    }
    
    // Convert NSArray to C array
    es_event_type_t events[eventsList.count];
    for (NSUInteger i = 0; i < eventsList.count; i++) {
        events[i] = (es_event_type_t)[[eventsList objectAtIndex:i] intValue];
    }
    
    // Subscribe to the events we're interested in
    es_return_t subscribed = es_subscribe(g_client, events, sizeof events / sizeof *events);
    
    if(ES_RETURN_ERROR == subscribed) {
        LOG_ERROR("es_subscribe: ES_RETURN_ERROR");
        return false;
    }
    
    // All good
    return log_subscribed_events();
}

int main(int argc, const char * argv[]) {
    signal(SIGINT, &sig_handler);
    
    @autoreleasepool {
        // Init global vars
        g_handler = get_message_handler_from_commandline_args(argc, argv);
        
        if(!g_handler) {
            print_usage(argv[0]);
            return 1;
        }
        
        // Initialize date formatter and other tracking collections
        init_date_formater();
        g_seq_nums = [NSMutableDictionary new];
        
        // Initialize security features if we're in security mode
        if (g_gatekeeper_mode || g_xprotect_mode) {
            init_security_features();
        }
        
        // List of paths to be blocked.
        // For this demo we will block the top binary and Calculator app bundle.
        g_blocked_paths = [NSSet setWithObjects:
                          @"/usr/bin/top",
                          @"/System/Applications/Calculator.app/Contents/MacOS/Calculator",
                          nil];
        
        if(!setup_endpoint_security()) {
            return 1;
        }
        
        if(@available(macOS 12.0, *)) {
            // Note: Endpoint Security for performance reasons will automatically mute a set of paths
            // on creation of new clients ('es_new_client').
            // macOS Monterey 12 now has the 'es_muted_paths_events' function, which can be used to
            // inspect the muted paths.
            log_muted_paths_events();
        } else {
            // ES on macOS Monterey 12 implicitly mutes events from cfprefsd. We need to explicitly do
            // this on older versions of macOS to prevent deadlocks in this program.
            mute_path("/usr/sbin/cfprefsd");
        }
        
        // Log operating mode
        if (g_gatekeeper_mode) {
            LOG_IMPORTANT_INFO("Running in Gatekeeper emulation mode");
        }
        
        if (g_xprotect_mode) {
            LOG_IMPORTANT_INFO("Running in XProtect emulation mode");
        }
        
        // Start handling events from Endpoint Security
        dispatch_main();
    }
    
    return 0;
}
