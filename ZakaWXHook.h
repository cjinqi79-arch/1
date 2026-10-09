//
//  ZakaWXHook.h
//  ZakaWX - 微信防撤回（签名证书注入版 / 无需越狱）
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// 启动挂载（幂等，可以重复调用）
void ZakaWXStart(void);

// 呼出设置面板
void ZakaWXShowPanel(void);

// 轻提示
void ZakaWXToast(NSString *text);

NS_ASSUME_NONNULL_END
