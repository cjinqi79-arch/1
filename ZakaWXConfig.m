//
//  ZakaWXConfig.m
//  ZakaWX - 微信防撤回（签名证书注入版 / 无需越狱）
//

#import "ZakaWXConfig.h"

static dispatch_queue_t g_logQueue(void) {
    static dispatch_queue_t q;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        q = dispatch_queue_create("com.zaka.wx.log", DISPATCH_QUEUE_SERIAL);
    });
    return q;
}

@implementation ZakaWXConfig

+ (instancetype)shared {
    static ZakaWXConfig *inst = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        inst = [[ZakaWXConfig alloc] init];
        [inst reload];
    });
    return inst;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        // 默认值：只拦对方，弹提示，不写日志
        _antiRevoke     = YES;
        _alsoSelfRevoke = NO;
        _showToast      = YES;
        _keepLog        = NO;
        _shakePanel     = YES;
        _deepScan       = YES;
    }
    return self;
}

#pragma mark - 路径

+ (NSString *)sandboxFilePath:(NSString *)name {
    NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ZakaWX"];
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:dir isDirectory:&isDir] || !isDir) {
        [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
    }
    return [dir stringByAppendingPathComponent:name];
}

+ (NSString *)configPath {
    return [self sandboxFilePath:@"config.plist"];
}

+ (NSString *)logPath {
    return [self sandboxFilePath:@"ZakaWX.log"];
}

#pragma mark - 读写

- (NSArray<NSString *> *)allKeys {
    return @[ @"antiRevoke", @"alsoSelfRevoke", @"showToast", @"keepLog", @"shakePanel", @"deepScan" ];
}

- (void)reload {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:[ZakaWXConfig configPath]];
    if (![d isKindOfClass:[NSDictionary class]]) {
        // 第一次运行：把默认配置写出去，方便用户自己改
        [self persist];
        return;
    }
    for (NSString *key in [self allKeys]) {
        id v = d[key];
        if (!v) continue;
        @try {
            [self setValue:@([v boolValue]) forKey:key];
        } @catch (__unused NSException *e) { }
    }
}

- (void)persist {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    for (NSString *key in [self allKeys]) {
        @try {
            d[key] = @([[self valueForKey:key] boolValue]);
        } @catch (__unused NSException *e) { }
    }
    [d writeToFile:[ZakaWXConfig configPath] atomically:YES];
}

- (BOOL)boolForKey:(NSString *)key {
    @try {
        return [[self valueForKey:key] boolValue];
    } @catch (__unused NSException *e) {
        return NO;
    }
}

- (void)toggleKey:(NSString *)key {
    @try {
        BOOL now = [[self valueForKey:key] boolValue];
        [self setValue:@(!now) forKey:key];
        [self persist];
    } @catch (__unused NSException *e) { }
}

#pragma mark - 日志

+ (void)log:(NSString *)format, ... {
    if (![[ZakaWXConfig shared] boolForKey:@"keepLog"]) return;

    va_list ap;
    va_start(ap, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:ap];
    va_end(ap);
    if (msg.length == 0) return;

    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.dateFormat = @"MM-dd HH:mm:ss";
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [df stringFromDate:[NSDate date]], msg];

    dispatch_async(g_logQueue(), ^{
        NSString *path = [ZakaWXConfig logPath];
        NSFileManager *fm = [NSFileManager defaultManager];

        // 超过 512KB 直接清掉重来，别把用户空间撑爆
        NSDictionary *attr = [fm attributesOfItemAtPath:path error:NULL];
        if ([attr[NSFileSize] unsignedLongLongValue] > 512 * 1024) {
            [fm removeItemAtPath:path error:NULL];
        }

        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) {
            [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
            return;
        }
        @try {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        } @catch (__unused NSException *e) { }
    });
}

@end
