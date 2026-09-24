// dh_files.h — 宿主 App 沙盒文件浏览 (只读)
//
// 根目录为 NSHomeDirectory(); 仅允许访问 Documents / Library / tmp 子树。

#ifndef DH_FILES_H
#define DH_FILES_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// GET /api/files?path= — 列目录 (path 为空=沙盒根下的三个入口)
NSDictionary * _Nullable dh_files_list_dict(NSString * _Nullable relPath, NSError ** _Nullable err);

// GET /api/files/preview?path=&limit= — 预览: UTF-8 文本或二进制 Hex Dump
NSDictionary * _Nullable dh_files_preview_dict(NSString *relPath, NSUInteger limit, NSError ** _Nullable err);

// 解析相对路径为绝对路径 (须为已存在文件, 供下载); 失败返回 nil
NSString * _Nullable dh_files_resolve_file(NSString *relPath, NSError ** _Nullable err);

NS_ASSUME_NONNULL_END

#endif // DH_FILES_H
