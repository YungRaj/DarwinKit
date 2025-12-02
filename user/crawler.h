/*
 * Copyright (c) YungRaj
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <objc/message.h>
#include <objc/objc.h>
#include <objc/runtime.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <SpriteKit/SpriteKit.h>
#include <UIKit/UIKit.h>

/* iOS App Crawler */

extern NSString *kNSDarwinAppCrawlerCrawledViews;

namespace NSDarwin {
namespace AppCrawler {
class CrawlManager;
}
} // namespace NSDarwin

using namespace NSDarwin::AppCrawler;

@interface NSViewCrawlData : NSObject

@property(strong, nonatomic) NSString *name;

@property(strong, nonatomic) NSString *parent;

@property(assign, nonatomic) CGRect frame;
@property(assign, nonatomic) CGPoint position; // position in window
@property(assign, nonatomic) CGPoint center;

@property(assign, nonatomic) CGPoint anchorPoint;

@end

@interface NSDarwinAppCrawler : NSObject

@property(atomic) CrawlManager *crawlManager;

@property(strong, atomic) NSTimer *crawlingTimer;
@property(strong, atomic) NSTimer *idleTimer;

@property(strong, atomic) NSMutableDictionary *crawlData;

@property(strong, atomic) NSMutableArray *viewControllerStack;

@property(assign, atomic) CFAbsoluteTime timeSinceLastUserInteraction;

@property(assign, atomic) BOOL spriteKitCrawlCondition;
@property(assign, atomic) BOOL crawlerTimerDidFire;

- (instancetype)initWithCrawlingManager:(CrawlManager *)crawlManager;

- (NSMutableDictionary *)crawlData;

- (NSViewCrawlData *)setupCrawlDataForView:(UIView *)view;

- (UIViewController *)topViewController;
- (UIViewController *)topViewControllerWithRootViewController:
    (UIViewController *)rootViewController;

- (BOOL)hasViewBeenCrawled:(UIView *)view
          inViewController:(UIViewController *)vc;

- (void)crawlingTimerDidFire:(NSTimer *)timer;
- (void)idlingTimerDidFire:(NSTimer *)timer;

- (void)simulateTouchEventAtPoint:(CGPoint)point;
- (void)simulateTouchesOnSpriteKitView:(SKView *)view;

- (bool)bypassInterstitialAds:(UIViewController *)vc;

- (void)pushViewControllerToStack:(UIViewController *)vc;

- (BOOL)simulatedTouchesHasHadNoEffect;

@end

namespace NSDarwin {
namespace AppCrawler {
class CrawlManager {
public:
  explicit CrawlManager(UIApplication *application,
                        id<UIApplicationDelegate> delegate)
      : application(application), delegate(delegate) {
    SetupAppCrawler();
  }

  ~CrawlManager() = default;

  NSDarwinAppCrawler *GetCrawler() { return crawler; }

  NSTimer *GetCrawlingTimer() { return crawler.crawlingTimer; }

  NSTimer *GetIdleTimer() { return crawler.idleTimer; }

  NSString *GetBundleID() { return bundleIdentifier; }

  UIApplication *GetApplication() { return application; }

  id<UIApplicationDelegate> GetAppDelegate() { return delegate; }

  UIViewController *GetCurrentViewController() { return currentViewController; }

  NSArray *GetViews() { return [currentViewController.view subviews]; }

  void SetCurrentViewController(UIViewController *viewController) {
    currentViewController = viewController;
  }

  void SetupAppCrawler();

  inline void SetupCrawlingTimer() {
    InvalidateCrawlingTimer();

    crawler.crawlingTimer =
        [NSTimer scheduledTimerWithTimeInterval:1.25f
                                         target:crawler
                                       selector:@selector(crawlingTimerDidFire:)
                                       userInfo:nil
                                        repeats:NO];
  }

  inline void SetupIdleTimer() {
    InvalidateIdleTimer();

    crawler.idleTimer =
        [NSTimer scheduledTimerWithTimeInterval:3.5f
                                         target:crawler
                                       selector:@selector(idlingTimerDidFire:)
                                       userInfo:nil
                                        repeats:NO];
  }

  void InvalidateCrawlingTimer() {
    if (crawler.crawlingTimer && [crawler.crawlingTimer isValid]) {
      [crawler.crawlingTimer invalidate];
      crawler.crawlingTimer = nullptr;
    }
  }

  void InvalidateIdleTimer() {
    if (crawler.idleTimer && [crawler.idleTimer isValid]) {
      [crawler.idleTimer invalidate];
      crawler.idleTimer = nullptr;
    }
  }

  NSMutableArray *GetViewsForUserInteraction(UIViewController *viewController);
  NSMutableArray *GetViewsForUserInteractionFromRootView(UIView *view);

  NSMutableArray *GetViewsWithKindOfClass(NSMutableArray *views, Class cls);

  void OnViewControllerViewDidAppear(UIViewController *viewController);

private:
  NSDarwinAppCrawler *crawler;
  NSDictionary *crawlData;
  NSString *bundleIdentifier;
  UIApplication *application;
  id<UIApplicationDelegate> delegate;
  UIViewController *currentViewController;
};
} // namespace AppCrawler
} // namespace NSDarwin
