/// 节点/分组存储 — 移植自 Go: backend/node/store.go。
///
/// 存储后端为内嵌 SQLite（与 Go 版一致，data/nodes.db）：
///   - 建表语句与 Go 版逐字对应（nodes/groups 两表 + 索引 + 列补齐）。
///   - 节点完整结构（含各协议配置与 raw_outbound/raw_clash_proxy）以
///     Node.toJson() 形式存入 data 列；name/protocol/address/port/sub_url/
///     group_id 作为可查询列；group_id 列为权威值。
///   - 所有变更操作（addMany/update/delete/clear/removeByGroup/move、
///     各分组操作）立即写库 — save() 为 no-op（对齐 Go Save）。
///   - 节点归属分组；内建默认分组「默认」始终存在且不可重命名/删除。
///     move() 仅在同组内调整顺序。
///   - 旧版 JSON 存储（nodes.json）在库为空时自动导入，导入后改名保留。
///   - 错误统一抛 [ParseException]（Go 版通过 error 返回值表达）。
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:sqlite3/open.dart';
import 'package:sqlite3/sqlite3.dart';

import '../models/group.dart';
import '../models/node.dart';
import '../parsing/common.dart';

/// Windows 下加载 sqlite3.dll：优先 exe 旁/PATH 里的 sqlite3.dll
/// （sqlite3_flutter_libs 桌面构建会放置），失败回退系统自带的
/// winsqlite3.dll（纯 Dart 测试 / CI 环境没有前者）。
DynamicLibrary _openSqliteWindows() {
  try {
    return DynamicLibrary.open('sqlite3.dll');
  } catch (_) {/* fallthrough */}
  return DynamicLibrary.open('winsqlite3.dll');
}

bool _loaderReady = false;

void _ensureSqliteLoader() {
  if (_loaderReady) return;
  _loaderReady = true;
  if (Platform.isWindows) {
    open.overrideFor(OperatingSystem.windows, _openSqliteWindows);
  }
}

/// 节点 + 分组存储（SQLite 后端，API 语义与 Go 版一致）。
class NodeStore {
  final String path;

  Database? _db;

  NodeStore(this.path);

  // ─── 持久化 ──────────────────────────────────────────────────────────────

  /// 打开数据库并初始化（建表 / 修复旧数据 / 内建默认分组 /
  /// 迁移旧 nodes.json）。失败抛 [ParseException]。
  void load() {
    _ensureSqliteLoader();
    if (_db != null) return;
    final f = File(path);
    final dir = f.parent;
    if (!dir.existsSync()) dir.createSync(recursive: true);
    final Database db;
    try {
      db = sqlite3.open(path);
    } catch (e) {
      throw ParseException('打开数据库失败: $e');
    }
    try {
      db.execute('PRAGMA busy_timeout = 5000');
      db.execute('PRAGMA journal_mode = WAL');
      _init(db);
      _migrateLegacyJsonIfNeeded(db);
      _db = db;
    } on ParseException {
      db.dispose();
      rethrow;
    } catch (e) {
      db.dispose();
      throw ParseException('初始化数据库失败: $e');
    }
  }

  /// 写库已在各操作内即时完成；保留以兼容 API（对齐 Go Save 为 no-op）。
  void save() {}

  /// 释放数据库连接（应用退出时调用）。
  void close() {
    _db?.dispose();
    _db = null;
  }

  Database get _d {
    final db = _db;
    if (db == null) {
      load();
      return _db!;
    }
    return db;
  }

  /// 建表与默认数据（对齐 Go Store.init）。
  void _init(Database db) {
    const stmts = [
      'CREATE TABLE IF NOT EXISTS nodes ('
          ' id       TEXT PRIMARY KEY,'
          ' position INTEGER NOT NULL DEFAULT 0,'
          ' name     TEXT    NOT NULL DEFAULT \'\','
          ' protocol TEXT    NOT NULL DEFAULT \'\','
          ' address  TEXT    NOT NULL DEFAULT \'\','
          ' port     INTEGER NOT NULL DEFAULT 0,'
          ' sub_url  TEXT    NOT NULL DEFAULT \'\','
          ' group_id TEXT    NOT NULL DEFAULT \'default\','
          ' data     TEXT    NOT NULL'
          ')',
      'CREATE TABLE IF NOT EXISTS groups ('
          ' id        TEXT PRIMARY KEY,'
          ' name      TEXT    NOT NULL,'
          ' position  INTEGER NOT NULL DEFAULT 0,'
          ' is_default INTEGER NOT NULL DEFAULT 0'
          ')',
      'CREATE INDEX IF NOT EXISTS idx_nodes_position ON nodes(position)',
      'CREATE INDEX IF NOT EXISTS idx_nodes_sub_url  ON nodes(sub_url)',
      'CREATE INDEX IF NOT EXISTS idx_nodes_group    ON nodes(group_id)',
    ];
    for (final q in stmts) {
      db.execute(q);
    }
    // 旧库补列（对齐 Go 的 addColumnIfMissing；全新库 CREATE 已含这些列，
    // ALTER 仅在列缺失时执行）
    _addColumnIfMissing(db, 'nodes', 'group_id',
        "ALTER TABLE nodes ADD COLUMN group_id TEXT NOT NULL DEFAULT 'default'");
    _addColumnIfMissing(db, 'groups', 'sub_url',
        "ALTER TABLE groups ADD COLUMN sub_url TEXT NOT NULL DEFAULT ''");
    _addColumnIfMissing(db, 'groups', 'auto_update',
        'ALTER TABLE groups ADD COLUMN auto_update INTEGER NOT NULL DEFAULT 0');
    _addColumnIfMissing(db, 'groups', 'update_interval_hours',
        'ALTER TABLE groups ADD COLUMN update_interval_hours INTEGER NOT NULL DEFAULT 0');
    _addColumnIfMissing(db, 'groups', 'last_update',
        'ALTER TABLE groups ADD COLUMN last_update INTEGER NOT NULL DEFAULT 0');
    // group_id 为空的节点归入默认分组
    db.execute("UPDATE nodes SET group_id = ? WHERE group_id = ''",
        [defaultGroupID]);
    // 内建默认分组（始终存在，position 0）
    db.execute(
        'INSERT OR IGNORE INTO groups (id, name, position, is_default) VALUES (?, ?, 0, 1)',
        [defaultGroupID, defaultGroupName]);
  }

  void _addColumnIfMissing(Database db, String table, String column,
      String alterSQL) {
    final rows = db.select('PRAGMA table_info($table)');
    for (final row in rows) {
      if (row['name'] == column) return;
    }
    db.execute(alterSQL);
  }

  /// 旧 JSON 存储（nodes.json，与 db 同目录）迁移：库内无节点且仅默认分组时
  /// 导入全部节点与分组，然后改名 nodes.json → nodes.json.migrated 保留备份。
  void _migrateLegacyJsonIfNeeded(Database db) {
    final legacy = File(
        '${File(path).parent.path}${Platform.pathSeparator}nodes.json');
    if (!legacy.existsSync()) return;
    final nodesCount = db.select('SELECT COUNT(*) AS c FROM nodes').first['c'] as int;
    final groupsCount =
        db.select('SELECT COUNT(*) AS c FROM groups').first['c'] as int;
    if (nodesCount > 0 || groupsCount > 1) return; // 已有数据，不动

    Map<String, dynamic> doc;
    try {
      doc = (jsonDecode(legacy.readAsStringSync()) as Map)
          .cast<String, dynamic>();
    } catch (_) {
      return; // 解析失败：保留原文件，跳过迁移
    }
    try {
      db.execute('BEGIN');
      // 分组（默认分组已存在，仅同步订阅字段与位置）
      final rawGroups = doc['groups'];
      if (rawGroups is List) {
        for (final e in rawGroups) {
          if (e is! Map) continue;
          final g = Group.fromJson((e['group'] as Map? ?? const {})
              .cast<String, dynamic>());
          final pos = (e['position'] as num?)?.toInt() ?? 0;
          if (g.id == defaultGroupID) {
            db.execute(
              'UPDATE groups SET position = ?, sub_url = ?, auto_update = ?, '
              'update_interval_hours = ?, last_update = ? WHERE id = ?',
              [pos, g.subUrl, _b2i(g.autoUpdate), g.updateIntervalHours,
               g.lastUpdate, g.id],
            );
          } else {
            db.execute(
              'INSERT OR REPLACE INTO groups (id, name, position, is_default, '
              'sub_url, auto_update, update_interval_hours, last_update) '
              'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
              [g.id, g.name, pos, _b2i(g.isDefault), g.subUrl,
               _b2i(g.autoUpdate), g.updateIntervalHours, g.lastUpdate],
            );
          }
        }
      }
      // 节点（data 列 = Node JSON；group_id 列权威）
      final rawNodes = doc['nodes'];
      if (rawNodes is List) {
        var maxPos = 0;
        for (final e in rawNodes) {
          if (e is! Map) continue;
          final pos = (e['position'] as num?)?.toInt() ?? 0;
          if (pos > maxPos) maxPos = pos;
        }
        for (final e in rawNodes) {
          if (e is! Map) continue;
          final node = Node.fromJson(
              (e['node'] as Map? ?? const {}).cast<String, dynamic>());
          var gid = (e['group_id'] as String?) ?? '';
          if (gid.isEmpty) gid = defaultGroupID;
          final pos = (e['position'] as num?)?.toInt() ?? 0;
          db.execute(
            'INSERT OR REPLACE INTO nodes '
            '(id, position, name, protocol, address, port, sub_url, group_id, data) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
              node.id,
              pos > 0 ? pos : ++maxPos,
              node.name,
              node.protocol,
              node.address,
              node.port,
              node.subUrl,
              gid,
              jsonEncode(node.toJson()),
            ],
          );
        }
      }
      db.execute('COMMIT');
    } catch (_) {
      try {
        db.execute('ROLLBACK');
      } catch (_) {}
      return; // 迁移失败：保留原 JSON，从空库开始
    }
    try {
      legacy.renameSync('${legacy.path}.migrated');
    } catch (_) {}
  }

  // ─── 内部 helpers ────────────────────────────────────────────────────────

  static int _b2i(bool b) => b ? 1 : 0;

  Node _rowToNode(Map<String, Object?> row) {
    final n = Node.fromJson(
        (jsonDecode(row['data'] as String) as Map).cast<String, dynamic>());
    var gid = row['group_id'] as String? ?? '';
    if (gid.isEmpty) gid = defaultGroupID;
    n.groupId = gid;
    return n;
  }

  Group _rowToGroup(Map<String, Object?> row) => Group(
        id: row['id'] as String? ?? '',
        name: row['name'] as String? ?? '',
        isDefault: (row['is_default'] as int? ?? 0) == 1,
        subUrl: row['sub_url'] as String? ?? '',
        autoUpdate: (row['auto_update'] as int? ?? 0) == 1,
        updateIntervalHours: row['update_interval_hours'] as int? ?? 0,
        lastUpdate: row['last_update'] as int? ?? 0,
      );

  // ─── 节点 API ────────────────────────────────────────────────────────────

  /// 返回全部节点，按 position 排序（对齐 Go GetAll）。
  List<Node> getAll() {
    final rows = _d.select(
        'SELECT data, group_id FROM nodes ORDER BY position');
    return [for (final r in rows) _rowToNode(r)];
  }

  /// 按 ID 查找节点，不存在返回 null（对齐 Go Get）。
  Node? get(String id) {
    final rows = _d.select(
        'SELECT data, group_id FROM nodes WHERE id = ?', [id]);
    if (rows.isEmpty) return null;
    return _rowToNode(rows.first);
  }

  /// 批量新增节点（INSERT OR REPLACE 语义，对齐 Go insertAll）：
  /// 同 ID 覆盖旧记录；group_id 为空归入默认分组；position 从当前最大值递增。
  void addMany(List<Node> nodes) {
    if (nodes.isEmpty) return;
    final db = _d;
    var pos = db.select('SELECT MAX(position) AS m FROM nodes').first['m']
            as int? ??
        0;
    db.execute('BEGIN');
    try {
      for (final n in nodes) {
        pos++;
        var gid = n.groupId;
        if (gid.isEmpty) gid = defaultGroupID;
        db.execute(
          'INSERT OR REPLACE INTO nodes '
          '(id, position, name, protocol, address, port, sub_url, group_id, data) '
          'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
          [
            n.id, pos, n.name, n.protocol, n.address, n.port, n.subUrl,
            gid, jsonEncode(n.toJson()),
          ],
        );
      }
      db.execute('COMMIT');
    } catch (_) {
      try {
        db.execute('ROLLBACK');
      } catch (_) {}
      rethrow;
    }
  }

  /// 更新节点（WHERE id）：position 不变；节点不存在时为 no-op（对齐 Go Update）。
  void update(Node n) {
    _d.execute(
      'UPDATE nodes SET '
      'name = ?, protocol = ?, address = ?, port = ?, sub_url = ?, group_id = ?, data = ? '
      'WHERE id = ?',
      [n.name, n.protocol, n.address, n.port, n.subUrl, n.groupId,
       jsonEncode(n.toJson()), n.id],
    );
  }

  /// 删除节点（不存在时为 no-op）。
  void delete(String id) {
    _d.execute('DELETE FROM nodes WHERE id = ?', [id]);
  }

  /// 在节点所属分组内按 delta（-1 = 上移，+1 = 下移）交换相邻位置。
  /// 返回是否成功（越界/节点不存在时失败，对齐 Go Move）。
  bool move(String id, int delta) {
    if (delta == 0) return false;
    final db = _d;
    final gRows = db.select(
        'SELECT group_id FROM nodes WHERE id = ?', [id]);
    if (gRows.isEmpty) return false;
    final groupId = gRows.first['group_id'] as String;
    final rows = db.select(
        'SELECT id, position FROM nodes WHERE group_id = ? ORDER BY position',
        [groupId]);
    final entries = [
      for (final r in rows)
        (id: r['id'] as String, pos: r['position'] as int),
    ];
    final idx = entries.indexWhere((e) => e.id == id);
    if (idx < 0) return false;
    final j = idx + delta;
    if (j < 0 || j >= entries.length) return false;
    // 同组内交换两条记录的 position（不影响其他分组顺序）
    db.execute('UPDATE nodes SET position = ? WHERE id = ?',
        [entries[j].pos, entries[idx].id]);
    db.execute('UPDATE nodes SET position = ? WHERE id = ?',
        [entries[idx].pos, entries[j].id]);
    return true;
  }

  /// 清空全部节点（分组保留）。
  void clear() {
    _d.execute('DELETE FROM nodes');
  }

  /// 删除指定分组内的全部节点
  /// （分组订阅「更新」用它整体替换组内节点）。
  void removeByGroup(String groupId) {
    _d.execute('DELETE FROM nodes WHERE group_id = ?', [groupId]);
  }

  /// 节点总数。
  int count() =>
      _d.select('SELECT COUNT(*) AS c FROM nodes').first['c'] as int;

  // ─── 分组管理 ────────────────────────────────────────────────────────────

  /// 返回全部分组，按 position 排序（对齐 Go GetGroups）。
  List<Group> getGroups() {
    final rows = _d.select(
        'SELECT id, name, is_default, sub_url, auto_update, '
        'update_interval_hours, last_update FROM groups ORDER BY position');
    return [for (final r in rows) _rowToGroup(r)];
  }

  /// 按 ID 查找分组，不存在返回 null。
  Group? groupByID(String id) {
    final rows = _d.select(
        'SELECT id, name, is_default, sub_url, auto_update, '
        'update_interval_hours, last_update FROM groups WHERE id = ?',
        [id]);
    if (rows.isEmpty) return null;
    return _rowToGroup(rows.first);
  }

  /// 记录订阅上次成功更新时间。
  void setGroupLastUpdate(String id, int unixSec) {
    _d.execute('UPDATE groups SET last_update = ? WHERE id = ?',
        [unixSec, id]);
  }

  /// 指定 ID 的分组是否存在。
  bool groupExists(String id) =>
      _d.select('SELECT 1 FROM groups WHERE id = ?', [id]).isNotEmpty;

  /// 返回可用分组 ID：分组存在则原样返回，否则返回默认分组。
  String groupIDValid(String groupId) {
    if (groupId.isNotEmpty &&
        groupId != defaultGroupID &&
        groupExists(groupId)) {
      return groupId;
    }
    return defaultGroupID;
  }

  /// 新建分组，插入到 afterID 之后（"" = 追加到末尾）。拒绝重名。
  /// 成功返回新建分组（对齐 Go AddGroup）。
  Group addGroup(String name, String afterID) {
    name = name.trim();
    if (name.isEmpty) throw ParseException('分组名称不能为空');
    final db = _d;
    // 重名校验
    if (db.select('SELECT 1 FROM groups WHERE name = ?', [name]).isNotEmpty) {
      throw ParseException('分组名称已存在: $name');
    }
    // 按 position 排序的 id 列表
    final ids = [
      for (final r in db.select('SELECT id FROM groups ORDER BY position'))
        r['id'] as String,
    ];
    var insertAt = ids.length; // 默认追加到末尾
    if (afterID.isNotEmpty) {
      final i = ids.indexOf(afterID);
      if (i >= 0) insertAt = i + 1;
    }
    final newID = newUuid();
    ids.insert(insertAt, newID);

    db.execute('BEGIN');
    try {
      // 全量重编号 position = i+1（新 id 尚未入库，UPDATE 对它无效果）
      for (var i = 0; i < ids.length; i++) {
        db.execute('UPDATE groups SET position = ? WHERE id = ?', [i + 1, ids[i]]);
      }
      db.execute(
        'INSERT INTO groups (id, name, position, is_default) VALUES (?, ?, ?, ?)',
        [newID, name, insertAt + 1, 0],
      );
      db.execute('COMMIT');
    } catch (_) {
      try {
        db.execute('ROLLBACK');
      } catch (_) {}
      rethrow;
    }
    return Group(id: newID, name: name, isDefault: false);
  }

  /// 执行 UPDATE 并返回受影响行数（sqlite3 2.x 无 updatedRows，用 changes()）。
  int _executeChanges(Database db, String sql, List<Object?> args) {
    db.execute(sql, args);
    return db.select('SELECT changes() AS c').first['c'] as int;
  }

  /// 重命名分组。默认分组不可重命名（对齐 Go RenameGroup）。
  void renameGroup(String id, String name) {
    name = name.trim();
    if (name.isEmpty) throw ParseException('分组名称不能为空');
    if (id == defaultGroupID) throw ParseException('默认分组不可重命名');
    final db = _d;
    if (db
        .select('SELECT 1 FROM groups WHERE name = ? AND id != ?', [name, id])
        .isNotEmpty) {
      throw ParseException('分组名称已存在: $name');
    }
    final n = _executeChanges(db,
        'UPDATE groups SET name = ? WHERE id = ? AND is_default = 0', [name, id]);
    if (n == 0) throw ParseException('分组不存在');
  }

  /// 编辑分组：名称 + 订阅设置。默认分组保持名称（忽略改名请求），
  /// 但可像其他分组一样设置订阅（对齐 Go UpdateGroup）。
  void updateGroup(String id, String name, String subUrl, bool autoUpdate,
      int intervalHours) {
    if (id == defaultGroupID) {
      name = defaultGroupName; // 默认分组名称固定
    } else {
      name = name.trim();
      if (name.isEmpty) throw ParseException('分组名称不能为空');
      if (_d
          .select('SELECT 1 FROM groups WHERE name = ? AND id != ?',
              [name, id])
          .isNotEmpty) {
        throw ParseException('分组名称已存在: $name');
      }
    }
    // 订阅链接为空时自动更新设置无效
    subUrl = subUrl.trim();
    if (subUrl.isEmpty) {
      autoUpdate = false;
      intervalHours = 0;
    }
    final n = _executeChanges(_d,
        'UPDATE groups SET name = ?, sub_url = ?, auto_update = ?, '
        'update_interval_hours = ? WHERE id = ?',
        [name, subUrl, _b2i(autoUpdate), intervalHours, id]);
    if (n == 0) throw ParseException('分组不存在');
  }

  /// 与左（delta=-1）或右（delta=+1）邻居分组交换位置。
  /// 默认分组永远在最左：不可移动，任何分组也不能占据它的位置
  /// （这同时禁止了紧随默认分组之后的分组左移，对齐 Go MoveGroup）。
  void moveGroup(String id, int delta) {
    if (delta != -1 && delta != 1) throw ParseException('非法移动方向');
    if (id == defaultGroupID) throw ParseException('默认分组不可移动');
    final db = _d;
    final ids = [
      for (final r in db.select('SELECT id FROM groups ORDER BY position'))
        r['id'] as String,
    ];
    final idx = ids.indexOf(id);
    if (idx < 0) throw ParseException('分组不存在');
    final j = idx + delta;
    if (j < 0 || j >= ids.length) {
      if (delta == -1) throw ParseException('已在最左侧');
      throw ParseException('已在最右侧');
    }
    if (ids[idx] == defaultGroupID || ids[j] == defaultGroupID) {
      throw ParseException('默认分组必须保持在最左侧');
    }
    final posI = db
        .select('SELECT position FROM groups WHERE id = ?', [ids[idx]])
        .first['position'] as int;
    final posJ = db
        .select('SELECT position FROM groups WHERE id = ?', [ids[j]])
        .first['position'] as int;
    db.execute('UPDATE groups SET position = ? WHERE id = ?',
        [posJ, ids[idx]]);
    db.execute('UPDATE groups SET position = ? WHERE id = ?',
        [posI, ids[j]]);
  }

  /// 删除分组，其节点移入默认分组。默认分组不可删除（对齐 Go DeleteGroup）。
  void deleteGroup(String id) {
    if (id == defaultGroupID) throw ParseException('默认分组不可删除');
    final db = _d;
    final n = _executeChanges(db,
        'DELETE FROM groups WHERE id = ? AND is_default = 0', [id]);
    if (n == 0) throw ParseException('分组不存在');
    // 组内节点移入默认分组
    db.execute('UPDATE nodes SET group_id = ? WHERE group_id = ?',
        [defaultGroupID, id]);
    // 压缩 position：按当前顺序重新编号 i+1
    final ordered = [
      for (final r in db.select('SELECT id FROM groups ORDER BY position'))
        r['id'] as String,
    ];
    db.execute('BEGIN');
    try {
      for (var i = 0; i < ordered.length; i++) {
        db.execute('UPDATE groups SET position = ? WHERE id = ?',
            [i + 1, ordered[i]]);
      }
      db.execute('COMMIT');
    } catch (_) {
      try {
        db.execute('ROLLBACK');
      } catch (_) {}
      rethrow;
    }
  }

  /// 存储文件路径（用于展示/调试）。
  String get dbPath => path;
}
