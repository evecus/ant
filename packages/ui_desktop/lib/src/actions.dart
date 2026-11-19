/// 统一动作执行助手：捕获 AppException/ParseException → Toast。
/// 触发 UAC 提权重启（startCore/enableTun 内部可能走到）时，
/// Toast 提示后延迟 1 秒退出进程，避免新旧实例并存。
library;

import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ui_kit/ui_kit.dart';

/// requestElevationAndRestart 成功发起提权时抛出的固定消息。
/// UI 收到该消息必须退出当前实例（新实例已在拉起）。
const String elevationRestartMessage = '正在以管理员身份重启程序…';

/// 判断异常是否为「提权重启」信号。
bool isElevationRestart(AppException e) => e.message == elevationRestartMessage;

/// 统一动作错误处理：
/// - 提权重启消息 → Toast 后延迟 1 秒执行退出（给 Toast 留显示时间）；
/// - AppException/ParseException → `[failurePrefix]: message`；
/// - 其他异常 → `[failurePrefix]: error`。
Future<void> showActionError(
  BuildContext? context,
  Object error, {
  String failurePrefix = '操作失败',
}) async {
  if (error is AppException && isElevationRestart(error)) {
    await _exitForElevation(context, error.message);
    return;
  }
  final String msg;
  if (error is AppException) {
    msg = error.message;
  } else if (error is ParseException) {
    msg = error.message;
  } else {
    msg = '$error';
  }
  _showToast(context, '$failurePrefix: $msg', ToastType.error);
}

/// 提权重启：Toast 后延迟 1 秒退出（给 Toast 留显示时间）。
Future<void> _exitForElevation(BuildContext? context, String message) async {
  _showToast(context, message, ToastType.warning);
  await Future<void>.delayed(const Duration(seconds: 1));
  exit(0);
}

/// Toast 前置检查 mounted（与 async 逻辑隔离，避免跨 async 使用 context）。
void _showToast(BuildContext? context, String message, ToastType type) {
  if (context == null || !context.mounted) return;
  AppToast.show(context, message, type);
}

/// 执行一个后端动作；失败弹 Toast（前缀 [failurePrefix]），成功可选提示。
/// 返回是否成功。触发提权重启时本函数不会返回（进程退出）。
Future<bool> runAction(
  BuildContext context,
  Future<void> Function() fn, {
  String failurePrefix = '操作失败',
  String? successMsg,
}) async {
  try {
    await fn();
    if (context.mounted) {
      if (successMsg != null) {
        AppToast.show(context, successMsg, ToastType.success);
      }
    }
    return true;
  } catch (e) {
    if (context.mounted) {
      await showActionError(context, e, failurePrefix: failurePrefix);
    } else if (e is AppException && isElevationRestart(e)) {
      // 无可用 UI 上下文也要退出，避免新旧实例并存
      await _exitForElevation(null, e.message);
    }
  }
  return false;
}

/// 格式化订阅上次更新时间（unix 秒 → 本地时间字符串）。
String formatLastUpdate(int unixSec) {
  if (unixSec <= 0) return '从未更新';
  final t = DateTime.fromMillisecondsSinceEpoch(unixSec * 1000);
  String two(int v) => v.toString().padLeft(2, '0');
  return '${t.year}-${two(t.month)}-${two(t.day)} ${two(t.hour)}:${two(t.minute)}';
}
