/// store_test.go 的 Dart 移植 — 用例原样照抄，作为移植验收标准。
/// 存储后端由 SQLite 改为 JSON 文件，临时目录用 Directory.systemTemp。
library;

import 'dart:io';

import 'package:ant_core/src/export/clash_write.dart';
import 'package:ant_core/src/models/group.dart';
import 'package:ant_core/src/models/node.dart';
import 'package:ant_core/src/parsing/common.dart';
import 'package:ant_core/src/storage/store.dart';
import 'package:test/test.dart';

Node newTestNode(String id, String name, String protocol, String addr, int port) => Node(
      id: id,
      name: name,
      protocol: protocol,
      address: addr,
      port: port,
      ss: SSConfig(method: 'aes-256-gcm', password: 'pw-$id'),
    );

/// 在系统临时目录下创建本次测试专用目录（对应 Go 的 t.TempDir()）。
Directory _tempDir() => Directory.systemTemp.createTempSync('ant_store_test_');

void main() {
  // clash_write.go 的单节点转换冒烟用例（Go 版该模块测试位于 config 包，
  // 这里验证基本可用性与异常路径）
  group('clash_write', () {
    test('ss node → clash proxy entry', () {
      final n = newTestNode('1', 'SS 节点', 'ss', '1.1.1.1', 443);
      final p = nodeToClashProxy(n);
      expect(p['type'], 'ss');
      expect(p['name'], 'SS 节点');
      expect(p['server'], '1.1.1.1');
      expect(p['port'], 443);
      expect(p['cipher'], 'aes-256-gcm');
      expect(p['password'], 'pw-1');
    });

    test('rawClashProxy round-trip keeps original entry and refreshes name/server/port', () {
      final n = newTestNode('1', '改名', 'ss', '5.5.5.5', 8443)
        ..rawClashProxy = {
          'name': '旧名',
          'type': 'ss',
          'server': '1.2.3.4',
          'port': 8388,
          'cipher': 'aes-128-gcm',
          'password': 'pw',
        };
      final p = nodeToClashProxy(n);
      expect(p['name'], '改名');
      expect(p['server'], '5.5.5.5');
      expect(p['port'], 8443);
      expect(p['cipher'], 'aes-128-gcm');
      // 原始条目不被就地修改
      expect(n.rawClashProxy!['name'], '旧名');
      expect(n.rawClashProxy!['port'], 8388);
    });

    test('unsupported protocol throws ParseException', () {
      final n = newTestNode('1', 'ssh', 'ssh', '1.1.1.1', 22);
      expect(() => nodeToClashProxy(n), throwsA(isA<ParseException>()));
    });
  });

  group('store', () {
    test('TestStoreGroups', () {
      final dir = _tempDir();
      addTearDown(() => dir.deleteSync(recursive: true));
      final dbPath = '${dir.path}${Platform.pathSeparator}nodes.json';

      final s = NodeStore(dbPath);
      s.load();
      addTearDown(s.close);

      // 默认分组在启动时即存在
      var groups = s.getGroups();
      expect(groups.length, 1);
      expect(groups[0].id, 'default');
      expect(groups[0].name, '默认');
      expect(groups[0].isDefault, isTrue);

      // 在「默认」之后创建分组
      final g = s.addGroup('机场A', 'default');
      expect(g.id, isNotEmpty);
      expect(g.isDefault, isFalse);
      // 重名分组被拒绝
      expect(() => s.addGroup('机场A', ''), throwsA(isA<ParseException>()));

      // 节点进入指定分组
      s.addMany([
        newTestNode('n1', 'A组节点1', 'ss', '1.1.1.1', 443),
        newTestNode('n2', 'A组节点2', 'ss', '1.1.1.2', 443),
        newTestNode('d1', '默认节点', 'ss', '2.2.2.2', 443),
      ]);
      s.update(Node(
        id: 'n1',
        name: 'A组节点1',
        protocol: 'ss',
        address: '1.1.1.1',
        port: 443,
        groupId: g.id,
        ss: SSConfig(method: 'aes-256-gcm', password: 'x'),
      ));
      s.update(Node(
        id: 'n2',
        name: 'A组节点2',
        protocol: 'ss',
        address: '1.1.1.2',
        port: 443,
        groupId: g.id,
        ss: SSConfig(method: 'aes-256-gcm', password: 'x'),
      ));

      var all = s.getAll();
      var inA = 0, inDefault = 0;
      for (final n in all) {
        if (n.groupId == g.id) {
          inA++;
        } else if (n.groupId == 'default' || n.groupId == '') {
          inDefault++;
        }
      }
      expect(inA, 2, reason: 'group membership wrong: inA=$inA inDefault=$inDefault');
      expect(inDefault, 1, reason: 'group membership wrong: inA=$inA inDefault=$inDefault');

      // Move 限定在同组内：移动 d1（默认分组）不影响 A组
      // d1 上移 — 它是默认分组的唯一节点 → 失败
      expect(s.move('d1', -1), isFalse, reason: 'move single-node group should fail');
      // 在 A组 内把 n2 上移：顺序 n1,n2 → n2,n1
      expect(s.move('n2', -1), isTrue, reason: 'Move(n2,-1) should succeed');
      // 验证默认分组节点未受影响且 A组 顺序已改变
      final aOrder = [for (final n in s.getAll()) if (n.groupId == g.id) n.id];
      expect(aOrder, ['n2', 'n1'], reason: 'group move wrong: $aOrder');

      // 重命名
      expect(() => s.renameGroup('default', 'X'), throwsA(isA<ParseException>()),
          reason: 'renaming default group should fail');
      s.renameGroup(g.id, '机场B');

      // 删除分组 → 其节点移入默认分组
      expect(() => s.deleteGroup('default'), throwsA(isA<ParseException>()),
          reason: 'deleting default group should fail');
      s.deleteGroup(g.id);
      groups = s.getGroups();
      expect(groups.length, 1, reason: 'groups after delete = ${groups.length}, want 1');
      inDefault = 0;
      for (final n in s.getAll()) {
        if (n.groupId == 'default' || n.groupId == '') inDefault++;
      }
      expect(inDefault, 3,
          reason: 'nodes should move to default after group delete, got $inDefault');

      // afterID 为空追加到末尾；排序上「默认」始终第一
      final g2 = s.addGroup('新分组', '');
      groups = s.getGroups();
      expect(groups.length, 2);
      expect(groups[0].id, 'default');
      expect(groups[1].id, g2.id, reason: 'group order wrong');

      // 重新打开后数据持久化
      s.close();
      final s2 = NodeStore(dbPath);
      addTearDown(s2.close);
      final gs = s2.getGroups();
      expect(gs.length, 2);
      expect(gs[0].name, '默认');
      expect(gs[1].name, '新分组', reason: 'groups after reopen wrong');
      expect(s2.count(), 3, reason: 'nodes after reopen = ${s2.count()}, want 3');
    });

    test('TestStoreCRUDAndOrder', () {
      final dir = _tempDir();
      addTearDown(() => dir.deleteSync(recursive: true));
      final dbPath = '${dir.path}${Platform.pathSeparator}nodes.json';

      final s = NodeStore(dbPath);
      s.load();
      addTearDown(s.close);

      // AddMany
      s.addMany([
        newTestNode('1', '节点一', 'ss', '1.1.1.1', 443),
        newTestNode('2', '节点二', 'vless', '2.2.2.2', 8443),
        newTestNode('3', '节点三', 'trojan', '3.3.3.3', 443),
      ]);

      expect(s.getAll().length, 3, reason: 'want 3 nodes');
      // 顺序检查
      var all = s.getAll();
      expect([all[0].id, all[1].id, all[2].id], ['1', '2', '3'], reason: 'unexpected order');

      // Get
      var n = s.get('2');
      expect(n, isNotNull);
      expect(n!.protocol, 'vless');

      // 下移：2 → 第 3 位
      expect(s.move('2', 1), isTrue, reason: 'Move(2, +1) should succeed');
      all = s.getAll();
      expect(all[2].id, '2', reason: 'after move down order wrong');
      // 再下移 → 已在底部，应失败
      expect(s.move('2', 1), isFalse, reason: 'Move at bottom should fail');
      // 上移：2 移回
      expect(s.move('2', -1), isTrue, reason: 'Move(2, -1) should succeed');
      expect(s.move('1', -1), isFalse, reason: 'Move at top should fail');

      // Update
      final updated = newTestNode('1', '改名了', 'ss', '9.9.9.9', 1234);
      s.update(updated);
      n = s.get('1');
      expect(n, isNotNull);
      expect(n!.name, '改名了');
      expect(n.address, '9.9.9.9');
      expect(n.port, 1234);
      expect(n.ss, isNotNull);
      expect(n.ss!.method, 'aes-256-gcm', reason: 'nested config lost after update');

      // Delete
      s.delete('3');
      expect(s.get('3'), isNull, reason: 'Delete failed');
      expect(s.count(), 2, reason: 'count = ${s.count()}, want 2');

      // ─── 重新打开后的持久化 ───
      s.close();
      final s2 = NodeStore(dbPath);
      addTearDown(s2.close);
      s2.load();
      final got = s2.get('1');
      expect(got, isNotNull);
      expect(got!.name, '改名了', reason: 'persistence failed');
      expect(s2.count(), 2, reason: 'count after reopen = ${s2.count()}, want 2'); // 1, 2
      // 顺序已持久化："1" 仍在 "2" 之前
      final ids = [for (final nn in s2.getAll()) nn.id];
      expect([ids[0], ids[1]], ['1', '2'], reason: 'order after reopen wrong: $ids');
    });
  });

  // 保证 Group / clash_write 的引用不被 tree-shake 掉（API 可达性检查）
  test('group model JSON tags align with Go', () {
    final g = Group(
      id: 'g1',
      name: '分组',
      subUrl: 'https://example.com/sub',
      autoUpdate: true,
      updateIntervalHours: 6,
      lastUpdate: 1700000000,
    );
    final j = g.toJson();
    expect(j.keys, containsAll(['id', 'name', 'is_default', 'sub_url', 'auto_update', 'update_interval_hours', 'last_update']));
    expect(Group.fromJson(j).copy().id, 'g1');
    // last_update 的 omitempty 语义
    expect(Group(id: 'g2', name: 'x').toJson().containsKey('last_update'), isFalse);
    expect(defaultGroupID, 'default');
    expect(defaultGroupName, '默认');
  });
}
