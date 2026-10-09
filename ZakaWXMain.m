//
//  ZakaWXMain.m
//  ZakaWX - 微信防撤回（签名证书注入版 / 无需越狱）
//
//  注入方式：dylib 被 dyld 在主二进制启动时一并加载，
//  所以这里用 constructor 作为入口，再叠几层延迟补扫，
//  避免微信某些类晚于我们加载而漏挂。
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>
#import <unistd.h>

#import "ZakaWXHook.h"
#import "ZakaWXConfig.h"

#pragma mark - 摇一摇呼出面板

typedef void (*ZakaMotionFn)(id, SEL, UIEventSubtype, UIEvent *);
static ZakaMotionFn g_origMotion = NULL;

static void zaka_motionEnded(id self, SEL _cmd, UIEventSubtype motion, UIEvent *event) {
    @try {
        if (motion == UIEventSubtypeMotionShake && [[ZakaWXConfig shared] boolForKey:@"shakePanel"]) {
            static NSTimeInterval lastFire = 0;
            NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
            if (now - lastFire > 1.5) {
                lastFire = now;
                ZakaWXShowPanel();
            }
        }
    } @catch (__unused NSException *e) { }

    if (g_origMotion) {
        g_origMotion(self, _cmd, motion, event);
    }
}

static void ZakaHookShake(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        @try {
            Class cls = [UIWindow class];
            SEL sel = NSSelectorFromString(@"motionEnded:withEvent:");
            Method m = class_getInstanceMethod(cls, sel);
            if (!m) return;
            g_origMotion = (ZakaMotionFn)method_getImplementation(m);
            method_setImplementation(m, (IMP)zaka_motionEnded);
            [ZakaWXConfig log:@"摇一摇入口已挂载"];
        } @catch (__unused NSException *e) { }
    });
}

#pragma mark - 入口

static void ZakaBootstrap(void) {
    ZakaHookShake();
    ZakaWXStart();
}

__attribute__((constructor)) static void ZakaWXInit(void) {
    @autoreleasepool {
        // 触发一次配置初始化（同时把默认 config.plist 写到沙箱里）
        [ZakaWXConfig shared];

        dispatch_async(dispatch_get_main_queue(), ^{
            ZakaBootstrap();
        });

        // 微信部分类加载较晚，这里多补几轮扫描，纯兜底
        NSArray<NSNumber *> *delays = @[ @2.0, @5.0, @12.0 ];
        for (NSNumber *d in delays) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(d.doubleValue * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                ZakaBootstrap();
            });
        }

        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                          object:nil
                                                           queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(__unused NSNotification *note) {
            ZakaBootstrap();
        }];

        [ZakaWXConfig log:@"dylib 已加载 pid=%d", (int)getpid()];
    }
}
