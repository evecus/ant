/// 启动参数解析 — 对齐 Go 版 winutil 的 silentArg（`--silent`）。
///
/// Windows runner 的 main.cpp 把完整命令行参数（去掉程序名）通过
/// `DartProject.set_dart_entrypoint_arguments` 传给 Dart isolate，
/// Dart 侧经 **main(List<String> args)** 的参数读到
/// （不是 `Platform.executableArguments` —— 那是 VM 参数，Flutter
/// Windows 上恒为空，之前静默启动失效就是这里读错了入口）。
/// `--silent` 由自启动项写入（applyAutoStart），程序启动时据此决定
/// 是否显示主窗口（仅托盘）。
library;

/// 静默启动参数（Go: winutil silentArg）。
const String kSilentArg = '--silent';

/// 命令行参数里是否带 `--silent`。
bool hasSilentArg(List<String> args) => args.contains(kSilentArg);
