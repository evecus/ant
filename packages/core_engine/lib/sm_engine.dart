/// ant GUI 引擎层（桌面端）。
library;

export 'src/core_process.dart';
export 'src/engine.dart';
export 'src/sysproxy.dart';
export 'src/winutil.dart'
    show
        isAdmin,
        launchElevated,
        setRegistryRun,
        deleteRegistryRun,
        createScheduledTask,
        deleteScheduledTask,
        WinUtilException;
