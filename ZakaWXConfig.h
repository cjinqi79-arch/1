//
//  ZakaWXConfig.h
//  ZakaWX - 微信防撤回（签名证书注入版 / 无需越狱）
//
//  配置读写全部落在 App 沙箱内，避免越狱路径写入失败。
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZakaWXConfig : NSObject

@property (nonatomic, assign) BOOL antiRevoke;      // 防撤回总开关
@property (nonatomic, assign) BOOL alsoSelfRevoke;  // 连自己的撤回也拦（默认关）
@property (nonatomic, assign) BOOL showToast;       // 撤回时弹一条轻提示
@property (nonatomic, assign) BOOL keepLog;         // 记录日志（排查漏拦用）
@property (nonatomic, assign) BOOL shakePanel;      // 摇一摇呼出设置面板
@property (nonatomic, assign) BOOL deepScan;        // 深度扫描（更全，稍慢一点）

+ (instancetype)shared;

- (void)reload;
- (void)persist;

- (BOOL)boolForKey:(NSString *)key;
- (void)toggleKey:(NSString *)key;

// 沙箱内路径：<AppHome>/Documents/ZakaWX/<name>
+ (NSString *)sandboxFilePath:(NSString *)name;

// 仅在 keepLog 打开时真正落盘
+ (void)log:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);

@end

NS_ASSUME_NONNULL_END
