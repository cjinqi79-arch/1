//
//  ZakaWXHook.m
//  ZakaWX - 微信防撤回（签名证书注入版 / 无需越狱）
//
//  设计要点：
//  1. 不依赖 CydiaSubstrate / libsubstrate —— 只用系统自带的 Objective-C 运行时，
//     这样重签名注入后没有任何额外依赖，不会被 dyld 因找不到框架而拒载。
//  2. 不做「写死方法名」的单点挂载。微信每个大版本撤回入口都在换名字，
//     所以这里做两层：白名单类精确挂 + 全类名扫描兜底挂。
//  3. 只挂「名字含 revoke/recall 且参数全是对象/指针」的方法，最大限度避免误挂。
//  4. 所有挂载点外面都包异常保护，任何一个出问题都不影响微信本身。
//

#import "ZakaWXHook.h"
#import "ZakaWXConfig.h"

#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>

#pragma mark - 全局表

static NSMutableDictionary<NSString *, NSValue *> *g_origIMPs;
static NSMutableSet<NSString *>            *g_hooked;
static dispatch_queue_t                     g_scanQueue;

#pragma mark - 原始 IMP 存取

static NSString *ZakaKeyWithClass(Class cls, SEL sel) {
    return [NSString stringWithFormat:@"%s|%s", class_getName(cls), sel_getName(sel)];
}

static void ZakaStoreOrig(Class cls, SEL sel, IMP imp) {
    if (!imp) return;
    g_origIMPs[ZakaKeyWithClass(cls, sel)] = [NSValue valueWithPointer:(void *)imp];
}

// 沿继承链往上找：被替换的方法一定在链上某个类里，
// 这样既不会取到别的类同名的实现，也能覆盖"子类继承父类"的情况。
static IMP ZakaOrigIMP(Class cls, SEL sel) {
    Class c = cls;
    while (c) {
        NSValue *v = g_origIMPs[ZakaKeyWithClass(c, sel)];
        if (v) return (IMP)v.pointerValue;
        c = class_getSuperclass(c);
    }
    return NULL;
}

#pragma mark - 当前登录账号

static NSString *ZakaMyWXID(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        @try {
            NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
            NSArray *candidates = @[ @"m_nsUsrName", @"m_nsUserName", @"m_nsLastUserName", @"userName" ];
            for (NSString *k in candidates) {
                NSString *v = [d stringForKey:k];
                if (v.length > 0) { cached = v; break; }
            }

            if (cached.length == 0) {
                Class centerCls = NSClassFromString(@"MMServiceCenter");
                Class contactCls = NSClassFromString(@"WCContactMgr");
                if (centerCls && contactCls) {
                    id center = ((id (*)(id, SEL))objc_msgSend)(centerCls, NSSelectorFromString(@"defaultCenter"));
                    if (center) {
                        id mgr = ((id (*)(id, SEL, id))objc_msgSend)(center, NSSelectorFromString(@"getService:"), contactCls);
                        if (mgr) {
                            SEL s = NSSelectorFromString(@"getMyUserName");
                            if ([mgr respondsToSelector:s]) {
                                cached = ((id (*)(id, SEL))objc_msgSend)(mgr, s);
                            }
                        }
                    }
                }
            }
        } @catch (__unused NSException *e) { }
    });
    return cached;
}

#pragma mark - 从参数里识别发送者

// 只认对象类型的 ivar，避免 object_getIvar 打在非对象成员上出事
static BOOL ZakaIsObjectIvar(Ivar iv) {
    const char *enc = ivar_getTypeEncoding(iv);
    if (!enc) return NO;
    return enc[0] == '@';
}

static BOOL ZakaLooksLikeWXID(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || s.length < 5) return NO;
    if ([s containsString:@"wxid_"]) return YES;
    if ([s containsString:@"@"]) return YES;      // 微信号形式的登录名
    if ([s rangeOfString:@"^[A-Za-z][A-Za-z0-9_-]{5,}$" options:NSRegularExpressionSearch].location != NSNotFound) return YES;
    return NO;
}

static NSString *ZakaFindSenderInObject(id obj, int depth) {
    if (!obj || depth > 2) return nil;
    if (![obj isKindOfClass:[NSObject class]]) return nil;
    if ([obj isKindOfClass:[NSString class]] ||
        [obj isKindOfClass:[NSNumber class]] ||
        [obj isKindOfClass:[NSData class]] ||
        [obj isKindOfClass:[NSArray class]] ||
        [obj isKindOfClass:[NSDictionary class]]) {
        return nil;
    }
    if ([obj isKindOfClass:[UIView class]] || [obj isKindOfClass:[UIViewController class]]) return nil;

    @try {
        unsigned int count = 0;
        Ivar *ivars = class_copyIvarList(object_getClass(obj), &count);
        if (!ivars || count == 0) {
            if (ivars) free(ivars);
            return nil;
        }

        // 第一轮：名字像发送者的字符串字段，优先级最高
        for (unsigned int i = 0; i < count; i++) {
            if (!ZakaIsObjectIvar(ivars[i])) continue;
            const char *cname = ivar_getName(ivars[i]);
            if (!cname) continue;
            NSString *lname = [@(cname) lowercaseString];
            BOOL nameHit = ([lname containsString:@"from"] ||
                            [lname containsString:@"sender"] ||
                            [lname containsString:@"realchat"] ||
                            [lname containsString:@"usr"] ||
                            [lname containsString:@"creat"]);
            if (!nameHit) continue;

            id val = nil;
            @try { val = object_getIvar(obj, ivars[i]); } @catch (__unused NSException *e) { continue; }
            if ([val isKindOfClass:[NSString class]] && ZakaLooksLikeWXID(val)) {
                free(ivars);
                return val;
            }
        }

        // 第二轮：钻进子对象里再找一层
        for (unsigned int i = 0; i < count; i++) {
            if (!ZakaIsObjectIvar(ivars[i])) continue;
            const char *cname = ivar_getName(ivars[i]);
            if (!cname) continue;
            NSString *lname = [@(cname) lowercaseString];
            if ([lname hasPrefix:@"m_"]) {
                // 微信的成员大多带 m_ 前缀，优先钻这些
                id val = nil;
                @try { val = object_getIvar(obj, ivars[i]); } @catch (__unused NSException *e) { continue; }
                NSString *found = ZakaFindSenderInObject(val, depth + 1);
                if (found.length) {
                    free(ivars);
                    return found;
                }
            }
        }
        free(ivars);
    } @catch (__unused NSException *e) { }
    return nil;
}

static NSString *ZakaFindSender(NSArray *args) {
    for (id a in args) {
        NSString *found = ZakaFindSenderInObject(a, 0);
        if (found.length) return found;
    }
    return nil;
}

#pragma mark - 判定是否拦截

static void ZakaNoteBlocked(id self, SEL sel, NSArray *args) {
    (void)args;
    NSString *cls = NSStringFromClass(object_getClass(self));
    NSString *line = [NSString stringWithFormat:@"拦截 %@ -[%@ %@]", cls, cls, NSStringFromSelector(sel)];
    [ZakaWXConfig log:@"%@", line];

    if (![[ZakaWXConfig shared] boolForKey:@"showToast"]) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        ZakaWXToast(@"拦住了一条撤回，消息还在");
    });
}

static BOOL ZakaShouldBlock(id self, SEL sel, NSArray *args) {
    ZakaWXConfig *cfg = [ZakaWXConfig shared];
    if (!cfg.antiRevoke) return NO;
    if (cfg.alsoSelfRevoke) return YES;

    NSString *me = ZakaMyWXID();
    if (me.length == 0) return YES;   // 认不出自己，按对方处理（防撤回优先）

    NSString *sender = ZakaFindSender(args);
    if (sender.length > 0 && [sender isEqualToString:me]) return NO;  // 自己撤回，放行

    [ZakaWXConfig log:@"sender=%@ me=%@", sender ?: @"?", me];
    return YES;
}

#pragma mark - 挂载桩函数（按参数个数分派，保证安全转发）

typedef void (*ZakaFn0)(id, SEL);
typedef void (*ZakaFn1)(id, SEL, id);
typedef void (*ZakaFn2)(id, SEL, id, id);
typedef void (*ZakaFn3)(id, SEL, id, id, id);
typedef void (*ZakaFn4)(id, SEL, id, id, id, id);

#define ZAKA_PRELUDE(ARGS_ARRAY_VALUE)                                          \
    IMP zaka_orig = ZakaOrigIMP(object_getClass(self), _cmd);                   \
    if (!zaka_orig) return;                                                     \
    @try {                                                                      \
        if (ZakaShouldBlock(self, _cmd, (ARGS_ARRAY_VALUE))) {                  \
            ZakaNoteBlocked(self, _cmd, (ARGS_ARRAY_VALUE));                    \
            return;                                                             \
        }                                                                       \
    } @catch (__unused NSException *e) { }

static void zaka_hook_0(id self, SEL _cmd) {
    ZAKA_PRELUDE(@[])
    ((ZakaFn0)zaka_orig)(self, _cmd);
}

static void zaka_hook_1(id self, SEL _cmd, id a1) {
    ZAKA_PRELUDE(@[ (a1 ?: [NSNull null]) ])
    ((ZakaFn1)zaka_orig)(self, _cmd, a1);
}

static void zaka_hook_2(id self, SEL _cmd, id a1, id a2) {
    ZAKA_PRELUDE(@[ (a1 ?: [NSNull null]), (a2 ?: [NSNull null]) ])
    ((ZakaFn2)zaka_orig)(self, _cmd, a1, a2);
}

static void zaka_hook_3(id self, SEL _cmd, id a1, id a2, id a3) {
    ZAKA_PRELUDE(@[ (a1 ?: [NSNull null]), (a2 ?: [NSNull null]), (a3 ?: [NSNull null]) ])
    ((ZakaFn3)zaka_orig)(self, _cmd, a1, a2, a3);
}

static void zaka_hook_4(id self, SEL _cmd, id a1, id a2, id a3, id a4) {
    ZAKA_PRELUDE(@[ (a1 ?: [NSNull null]), (a2 ?: [NSNull null]), (a3 ?: [NSNull null]), (a4 ?: [NSNull null]) ])
    ((ZakaFn4)zaka_orig)(self, _cmd, a1, a2, a3, a4);
}

#pragma mark - 筛选目标方法

static BOOL ZakaNameLooksRevoke(NSString *selName) {
    NSString *l = [selName lowercaseString];

    // 账号、登录、证书类的 revoke 跟消息撤回无关，拦了只会搞坏微信正常功能
    NSArray<NSString *> *deny = @[ @"token", @"auth", @"login", @"logout", @"cert",
                                   @"device", @"oauth", @"sessionkey", @"rsa", @"license" ];
    for (NSString *d in deny) {
        if ([l containsString:d]) return NO;
    }

    if ([l containsString:@"revoke"]) return YES;
    if ([l containsString:@"recall"]) return YES;
    return NO;
}

// 参数必须全是对象 / 指针类型，才允许挂（避免寄存器与栈布局不一致）
static BOOL ZakaArgsAreSafe(Method m) {
    const char *enc = method_getTypeEncoding(m);
    if (!enc) return NO;
    @try {
        NSMethodSignature *sig = [NSMethodSignature signatureWithObjCTypes:enc];
        NSUInteger total = sig.numberOfArguments;
        if (total < 3) return NO;                 // 只有 self / _cmd 的没意义
        for (NSUInteger i = 2; i < total; i++) {
            const char *t = [sig getArgumentTypeAtIndex:i];
            if (!t) return NO;
            if (t[0] != '@' && t[0] != '^' && t[0] != ':' && t[0] != '?') return NO;
        }
        return YES;
    } @catch (__unused NSException *e) {
        return NO;
    }
}

static NSUInteger ZakaArgCount(Method m) {
    NSUInteger n = method_getNumberOfArguments(m);
    return n >= 2 ? n - 2 : 0;
}

static IMP ZakaStubForCount(NSUInteger n) {
    switch (n) {
        case 0:  return (IMP)zaka_hook_0;
        case 1:  return (IMP)zaka_hook_1;
        case 2:  return (IMP)zaka_hook_2;
        case 3:  return (IMP)zaka_hook_3;
        case 4:  return (IMP)zaka_hook_4;
        default: return NULL;
    }
}

#pragma mark - 挂载

static BOOL ZakaHookMethod(Class cls, Method m) {
    SEL sel = method_getName(m);
    NSString *key = ZakaKeyWithClass(cls, sel);
    if ([g_hooked containsObject:key]) return NO;
    if (!ZakaArgsAreSafe(m)) return NO;

    IMP stub = ZakaStubForCount(ZakaArgCount(m));
    if (!stub) return NO;

    IMP old = method_getImplementation(m);
    if (old == stub) { [g_hooked addObject:key]; return NO; }

    ZakaStoreOrig(cls, sel, old);
    method_setImplementation(m, stub);
    [g_hooked addObject:key];

    [ZakaWXConfig log:@"挂载 -[%@ %@]", NSStringFromClass(cls), NSStringFromSelector(sel)];
    return YES;
}

static NSUInteger ZakaHookClass(Class cls) {
    if (!cls) return 0;
    NSUInteger hit = 0;
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    if (!methods) return 0;
    for (unsigned int i = 0; i < count; i++) {
        NSString *selName = NSStringFromSelector(method_getName(methods[i]));
        if (!ZakaNameLooksRevoke(selName)) continue;
        if (ZakaHookMethod(cls, methods[i])) hit++;
    }
    free(methods);
    return hit;
}

// 白名单：社区里历年来出现过的撤回入口所在类
static NSArray<NSString *> *ZakaWhitelistClasses(void) {
    return @[
        @"CMessageMgr",
        @"CMessageMgrExt",
        @"MessageService",
        @"MessageServiceExt",
        @"MMSessionInfo",
        @"MMMsgLogicMgr",
        @"MMMessageLogic",
        @"WCMessageService",
        @"MessageLogicController",
        @"MMChatViewController",
    ];
}

static BOOL ZakaClassLooksInteresting(NSString *name) {
    if (name.length < 3) return NO;
    // 系统类一律不碰
    NSArray *prefixes = @[ @"NS", @"UI", @"CA", @"CF", @"WK", @"AV", @"MK", @"SK", @"PK", @"_", @"Swift" ];
    for (NSString *p in prefixes) {
        if ([name hasPrefix:p]) return NO;
    }
    NSString *l = [name lowercaseString];
    if ([l containsString:@"msg"]) return YES;
    if ([l containsString:@"message"]) return YES;
    if ([l containsString:@"chat"]) return YES;
    if ([l containsString:@"session"]) return YES;
    return NO;
}

#pragma mark - 启动

void ZakaWXStart(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_origIMPs  = [NSMutableDictionary dictionary];
        g_hooked    = [NSMutableSet set];
        g_scanQueue = dispatch_queue_create("com.zaka.wx.scan", DISPATCH_QUEUE_SERIAL);
    });

    if (![ZakaWXConfig shared].antiRevoke) {
        [ZakaWXConfig log:@"防撤回开关关闭，跳过挂载"];
        return;
    }

    NSUInteger hits = 0;

    // 第一层：白名单类，精确挂
    for (NSString *name in ZakaWhitelistClasses()) {
        Class cls = NSClassFromString(name);
        if (!cls) continue;
        NSUInteger n = ZakaHookClass(cls);
        if (n > 0) {
            hits += n;
            [ZakaWXConfig log:@"白名单命中 %@ +%lu", name, (unsigned long)n];
        }
    }

    // 第二层：全类扫描兜底
    if ([ZakaWXConfig shared].deepScan) {
        int numClasses = objc_getClassList(NULL, 0);
        if (numClasses > 0) {
            Class *classes = (Class *)malloc(sizeof(Class) * (size_t)numClasses);
            if (classes) {
                numClasses = objc_getClassList(classes, numClasses);
                for (int i = 0; i < numClasses; i++) {
                    @try {
                        Class c = classes[i];
                        NSString *cname = NSStringFromClass(c);
                        if (!ZakaClassLooksInteresting(cname)) continue;
                        hits += ZakaHookClass(c);
                    } @catch (__unused NSException *e) { }
                }
                free(classes);
            }
        }
    }

    [ZakaWXConfig log:@"本轮挂载完成，命中 %lu 个方法", (unsigned long)hits];
}

#pragma mark - 设置面板

static UIViewController *ZakaTopViewController(void) {
    UIWindow *keyWin = nil;
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        if (w.isKeyWindow) { keyWin = w; break; }
    }
    if (!keyWin) keyWin = [UIApplication sharedApplication].windows.firstObject;

    UIViewController *vc = keyWin.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

static NSArray<NSArray<NSString *> *> *ZakaPanelRows(void) {
    return @[
        @[ @"antiRevoke",     @"防撤回" ],
        @[ @"alsoSelfRevoke", @"自己的撤回也拦" ],
        @[ @"showToast",      @"撤回时弹提示" ],
        @[ @"keepLog",        @"记录日志" ],
        @[ @"shakePanel",     @"摇一摇呼出本面板" ],
        @[ @"deepScan",       @"深度扫描(更全)" ],
    ];
}

void ZakaWXShowPanel(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *top = ZakaTopViewController();
        if (!top) return;

        ZakaWXConfig *cfg = [ZakaWXConfig shared];
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"ZakaWX 设置"
                                                                  message:@"点一项切换开关，改完立刻生效"
                                                           preferredStyle:UIAlertControllerStyleActionSheet];

        for (NSArray<NSString *> *row in ZakaPanelRows()) {
            NSString *key = row[0];
            NSString *title = row[1];
            NSString *mark = [cfg boolForKey:key] ? @"[开]" : @"[关]";
            NSString *line = [NSString stringWithFormat:@"%@ %@", mark, title];

            [ac addAction:[UIAlertAction actionWithTitle:line
                                                  style:UIAlertActionStyleDefault
                                                handler:^(__unused UIAlertAction *action) {
                [cfg toggleKey:key];
                if (![cfg boolForKey:@"antiRevoke"] && ![key isEqualToString:@"antiRevoke"]) {
                    // 关掉总开关之后其余项无意义，这里不额外处理
                }
                ZakaWXShowPanel();   // 重开刷新状态
            }]];
        }

        [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];

        // iPad 上 ActionSheet 必须有锚点，否则直接崩
        if (ac.popoverPresentationController) {
            ac.popoverPresentationController.sourceView = top.view;
            ac.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(top.view.bounds),
                                                                     CGRectGetMidY(top.view.bounds), 1, 1);
            ac.popoverPresentationController.permittedArrowDirections = 0;
        }

        [top presentViewController:ac animated:YES completion:nil];
    });
}

#pragma mark - 轻提示

void ZakaWXToast(NSString *text) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *win = nil;
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w.isKeyWindow) { win = w; break; }
        }
        if (!win) win = [UIApplication sharedApplication].windows.firstObject;
        if (!win) return;

        UILabel *label = [[UILabel alloc] init];
        label.text = text;
        label.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
        label.textColor = [UIColor whiteColor];
        label.backgroundColor = [UIColor colorWithWhite:0 alpha:0.82];
        label.textAlignment = NSTextAlignmentCenter;
        label.numberOfLines = 1;
        [label sizeToFit];
        label.layer.cornerRadius = 14;
        label.layer.masksToBounds = YES;

        CGFloat w = label.bounds.size.width + 28;
        CGFloat h = 32;
        label.frame = CGRectMake(0, 0, w, h);
        label.center = CGPointMake(win.bounds.size.width / 2, 90);
        label.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin |
                                 UIViewAutoresizingFlexibleRightMargin |
                                 UIViewAutoresizingFlexibleBottomMargin;

        [win addSubview:label];
        [win bringSubviewToFront:label];

        [UIView animateWithDuration:0.3 delay:2.0 options:UIViewAnimationOptionCurveEaseInOut animations:^{
            label.alpha = 0;
        } completion:^(__unused BOOL finished) {
            [label removeFromSuperview];
        }];
    });
}
