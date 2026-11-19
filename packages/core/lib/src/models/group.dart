/// 分组模型 — 移植自 Go: backend/node/store.go 的 Group 类型。
///
/// JSON 字段名与 Go 的 Group struct tag 完全一致
/// （last_update 带 omitempty 语义）。
library;

/// 节点分组。默认分组（id "default"，名称「默认」）为内建分组，
/// 名称/位置不可变（由 NodeStore 保证）。
/// 订阅字段（subUrl/autoUpdate/updateIntervalHours）驱动分组级
/// 「编辑」对话框与后台订阅自动更新循环。
class Group {
  String id;
  String name;
  bool isDefault;

  /// 订阅链接（空 = 普通分组）
  String subUrl;

  /// 是否自动更新订阅
  bool autoUpdate;

  /// 自动更新间隔（小时）
  int updateIntervalHours;

  /// 上次更新时间（unix 秒）
  int lastUpdate;

  Group({
    this.id = '',
    this.name = '',
    this.isDefault = false,
    this.subUrl = '',
    this.autoUpdate = false,
    this.updateIntervalHours = 0,
    this.lastUpdate = 0,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'is_default': isDefault,
        'sub_url': subUrl,
        'auto_update': autoUpdate,
        'update_interval_hours': updateIntervalHours,
        if (lastUpdate != 0) 'last_update': lastUpdate, // omitempty
      };

  static Group fromJson(Map<String, dynamic> j) => Group(
        id: j['id'] as String? ?? '',
        name: j['name'] as String? ?? '',
        isDefault: j['is_default'] as bool? ?? false,
        subUrl: j['sub_url'] as String? ?? '',
        autoUpdate: j['auto_update'] as bool? ?? false,
        updateIntervalHours: (j['update_interval_hours'] as num?)?.toInt() ?? 0,
        lastUpdate: (j['last_update'] as num?)?.toInt() ?? 0,
      );

  /// 深拷贝（对应 Go 的值语义：结构体赋值即拷贝）。
  Group copy() => Group.fromJson(toJson());
}

/// 内建默认分组 ID — Go: DefaultGroupID
const String defaultGroupID = 'default';

/// 内建默认分组名称 — Go: DefaultGroupName
const String defaultGroupName = '默认';
