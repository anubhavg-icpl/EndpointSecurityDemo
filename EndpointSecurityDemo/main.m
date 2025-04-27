//
//  ESMonitor.m
//  EndpointSecurityMonitor
//
//  Updated to support file-based logging of EXEC, WRITE, UNLINK, and RENAME events.
//  Ensure you codesign with the com.apple.developer.endpoint-security.client entitlement
//  and run as root so you can write to /var/log/es_monitor.log
//

#import <bsm/libbsm.h>                  // for audit_token_to_pid()
#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import <dispatch/dispatch.h>
#import <signal.h>

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

@implementation ESMonitor

- (instancetype)init {
    self = [super init];
    if (self) {
        [self setupLogger];
        [self initializeESClient];
        [self setupSignalHandling];
    }
    return self;
}

- (void)setupLogger {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *logPath = @"/var/log/es_monitor.log";
    
    if (![fm fileExistsAtPath:logPath]) {
        BOOL ok = [fm createFileAtPath:logPath
                              contents:nil
                            attributes:@{ NSFilePosixPermissions:@0644 }];
        if (!ok) {
            NSLog(@"[ERROR] Could not create %@", logPath);
            exit(EXIT_FAILURE);
        }
    }
    
    NSError *err = nil;
    _logFile = [NSFileHandle fileHandleForWritingToURL:[NSURL fileURLWithPath:logPath]
                                                error:&err];
    if (!_logFile) {
        NSLog(@"[ERROR] Opening log file: %@", err);
        exit(EXIT_FAILURE);
    }
    [_logFile seekToEndOfFile];
}

- (void)initializeESClient {
    es_new_client_result_t res = es_new_client(&_client, ^(es_client_t *client, const es_message_t *msg) {
        [self handleESMessage:msg];
    });
    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        NSLog(@"[ERROR] es_new_client: %d", res);
        exit(EXIT_FAILURE);
    }
    
    es_event_type_t evts[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_RENAME
    };
    es_return_t sub = es_subscribe(_client, evts, sizeof(evts)/sizeof(evts[0]));
    if (sub != ES_RETURN_SUCCESS) {
        NSLog(@"[ERROR] es_subscribe: %d", sub);
        es_delete_client(_client);
        exit(EXIT_FAILURE);
    }
}

- (void)handleESMessage:(const es_message_t *)message {
    pid_t pid = audit_token_to_pid(message->process->audit_token);
    NSString *entry = nil;
    
    switch (message->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC: {
            const char *p = message->process->executable->path.data;
            entry = [NSString stringWithFormat:@"%@ [PID %d] EXEC → %s",
                     [self currentTimestamp], pid, p];
        } break;
        
        case ES_EVENT_TYPE_NOTIFY_WRITE: {
            const char *t = message->event.write.target->path.data;
            entry = [NSString stringWithFormat:@"%@ [PID %d] WRITE → %s",
                     [self currentTimestamp], pid, t];
        } break;
        
        case ES_EVENT_TYPE_NOTIFY_UNLINK: {
            const char *t = message->event.unlink.target->path.data;
            entry = [NSString stringWithFormat:@"%@ [PID %d] UNLINK → %s",
                     [self currentTimestamp], pid, t];
        } break;
        
        case ES_EVENT_TYPE_NOTIFY_RENAME: {
            const char *src = message->event.rename.source->path.data;
            // Determine which union member to use
            if (message->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                const char *dst = message->event.rename.destination.existing_file->path.data;
                entry = [NSString stringWithFormat:@"%@ [PID %d] RENAME → %s  →  %s",
                         [self currentTimestamp], pid, src, dst];
            } else { // ES_DESTINATION_TYPE_NEW_PATH
                const char *dir  = message->event.rename.destination.new_path.dir->path.data;
                const char *file = message->event.rename.destination.new_path.filename.data;
                entry = [NSString stringWithFormat:@"%@ [PID %d] RENAME → %s  →  %s/%s",
                         [self currentTimestamp], pid, src, dir, file];
            }
        } break;
        
        default:
            return;
    }
    
    if (entry) {
        [self writeLogEntry:entry];
    }
}

- (NSString *)currentTimestamp {
    static NSDateFormatter *fmt;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fmt = [[NSDateFormatter alloc] init];
        fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
        fmt.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    });
    return [fmt stringFromDate:[NSDate date]];
}

- (void)writeLogEntry:(NSString *)entry {
    NSData *d = [[entry stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    @try {
        [_logFile writeData:d];
    } @catch (NSException *ex) {
        NSLog(@"[ERROR] Log write failed: %@", ex.reason);
    }
}

- (void)setupSignalHandling {
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    dispatch_source_t src = dispatch_source_create(
      DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler(src, ^{
        [self cleanup];
        exit(EXIT_SUCCESS);
    });
    dispatch_resume(src);
}

- (void)cleanup {
    if (_client) {
        es_unsubscribe_all(_client);
        es_delete_client(_client);
        _client = NULL;
    }
    [_logFile closeFile];
}

@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSLog(@"[INFO] Starting EndpointSecurity monitor…");
        __unused ESMonitor *mon = [[ESMonitor alloc] init];
        dispatch_main();
    }
    return EXIT_SUCCESS;
}
