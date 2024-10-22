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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dlfcn.h>

#include <mach/exc.h>
#include <mach/mach.h>

#include <arpa/inet.h>

#include <ifaddrs.h>

#include <AppKit/NSAlert.h>
#include <Foundation/Foundation.h>

#import <os/log.h>

bool try_port(int port) {
  struct sockaddr_in serv_addr;

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0) {
    printf("socket error\n");

    return false;
  }

  bzero((char *)&serv_addr, sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(port);

  if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
    if (errno == EADDRINUSE) {
      NSLog(@"port %d is not available\n", port);
    } else {
      printf("could not bind to process (%d) %s\n", errno, strerror(errno));
    }

    return false;
  }

  if (close(sockfd) < 0) {
    printf("did not close fd: %s\n", strerror(errno));

    return false;
  }

  return true;
}

#define MAX_PORT 2000

int get_unused_port() {
  bool found = false;

  int port = 1337;

  while (!found) {
    if (port == MAX_PORT) {
      return -1;
    }

    if (try_port(port) == true) {
      break;
    }

    ++port;
  }

  return port;
}

NSString *get_ip_address() {
  NSString *ip_address;

  char *ip;

  struct ifaddrs *ifaddrs;
  struct ifaddrs *ifaddr;

  struct in_addr inaddr;

  ifaddrs = nullptr;
  ip_address = nullptr;

  if (!getifaddrs(&ifaddrs)) {
    for (ifaddr = ifaddrs; ifaddr; ifaddr = ifaddr->ifa_next) {
      if (ifaddr->ifa_addr->sa_family == 2) {
        if (strcmp(ifaddr->ifa_name, "en0") == 0) {
          inaddr.s_addr = *(uint32_t *)&ifaddr->ifa_addr->sa_data;

          ip = inet_ntoa(inaddr);

          ip_address = [NSString stringWithUTF8String:ip];
        }
      }
    }
  }

  free(ifaddrs);

  return ip_address;
}

void run_cycript_server() {
  mach_vm_address_t CYListenServer;

  NSString *ip_address;

  int port;

  ip_address = get_ip_address();

  port = get_unused_port();

  if (port == -1) {
    NSLog(@"Could not find available port!\n");
  }

  CYListenServer = reinterpret_cast<mach_vm_address_t>(
      dlsym((void *)0xFFFFFFFFFFFFFFFE, "CYListenServer"));

  if (CYListenServer && port > 0) {
    typedef void (*_CYListenServer_)(int port);
    void (*_CYListenServer)(int port);

    _CYListenServer = reinterpret_cast<_CYListenServer_>(CYListenServer);

    _CYListenServer(port);

    NSLog(@"CYListenServer = %lld called!\n", CYListenServer);

    // dispatch_async(dispatch_get_main_queue(), ^{
    // });
    NSString *message = [NSString
        stringWithFormat:@"%@ - MacRootKit",
                         [[NSBundle mainBundle]
                             objectForInfoDictionaryKey:@"CFBundleName"]];
    NSString *informativeText = [NSString
        stringWithFormat:@"Cycript is now running on port %d on %@!", port,
                         [[NSBundle mainBundle] bundleIdentifier]];

    os_log_info(OS_LOG_DEFAULT, "%{public}@\n%{public}@", message,
                informativeText);

    /* NSAlert *alert = [[NSAlert alloc] init];

    [alert setAlertStyle:NSAlertStyleInformational];
    [alert setMessageText:message];
    [alert addButtonWithTitle:@"OK"];
    [alert setInformativeText:informativeText];

    [alert beginSheetModalForWindow:[[NSApplication sharedApplication]
    mainWindow] completionHandler:(void (^)(NSModalResponse returnCode)) {
           }];*/

    NSLog(@"Running cycript server on port %d at IP Address %@", port,
          ip_address);
  }
}

extern "C" {
__attribute__((constructor)) static void initializer() {
  printf("[%s] initializer()\n", __FILE__);

  run_cycript_server();
}

__attribute__((destructor)) static void finalizer() {
  printf("[%s] finalizer()\n", __FILE__);
}
}