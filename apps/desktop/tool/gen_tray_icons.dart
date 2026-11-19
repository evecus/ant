// 生成托盘图标（运行中=绿色圆点 / 停止=灰色圆点）。
// 无第三方依赖，手写最小 PNG（IHDR + 存储型 deflate IDAT + IEND）
// 与最小 ICO（多尺寸，供 Windows 托盘使用）。
//
// 运行：dart tool/gen_tray_icons.dart（在 apps/desktop 目录下）
//
// 背景：Windows 的 Shell_NotifyIcon 在从 PNG 生成 HICON 时，对直通
// （straight）alpha 的小尺寸图标经常合成错误，托盘区域显示为发灰/
// 透明的方块（其它平台用 PNG 没问题）。标准做法是额外提供 .ico
// （内含 16/24/32/48 多尺寸位图，预乘 alpha），并在 Windows 上
// 优先加载 .ico，其余平台仍用 .png。
import 'dart:io';
import 'dart:typed_data';

const int size = 32;
const List<int> _icoSizes = [16, 24, 32, 48];

Future<void> main() async {
  await _write('tray_running', 0x4C, 0xAF, 0x50); // Material green
  await _write('tray_stopped', 0x9E, 0x9E, 0x9E); // Material grey
  stdout.writeln('托盘图标已生成到 assets/');
}

Future<void> _write(String name, int r, int g, int b) async {
  final png = _encodePng(_drawDot(size, r, g, b));
  final pngFile = File('assets/$name.png');
  if (!pngFile.parent.existsSync()) {
    pngFile.parent.createSync(recursive: true);
  }
  await pngFile.writeAsBytes(png);
  stdout.writeln('写入 ${pngFile.path}（${png.length} bytes）');

  final ico = _encodeIco([
    for (final s in _icoSizes) _drawDot(s, r, g, b),
  ]);
  final icoFile = File('assets/$name.ico');
  await icoFile.writeAsBytes(ico);
  stdout.writeln('写入 ${icoFile.path}（${ico.length} bytes）');
}

/// 4x 超采样画一个实心圆，边缘带抗锯齿。半径随画布尺寸等比缩放，
/// 保证 16/24/32/48 各尺寸视觉一致。
Uint8List _drawDot(int s, int r, int g, int b) {
  final radius = s * 10.0 / 32.0;
  final cx = (s - 1) / 2, cy = (s - 1) / 2;
  final rgba = Uint8List(s * s * 4);
  var p = 0;
  for (var y = 0; y < s; y++) {
    for (var x = 0; x < s; x++) {
      var hit = 0;
      for (final dy in const [0.125, 0.375, 0.625, 0.875]) {
        for (final dx in const [0.125, 0.375, 0.625, 0.875]) {
          final ddx = x + dx - cx;
          final ddy = y + dy - cy;
          if (ddx * ddx + ddy * ddy <= radius * radius) hit++;
        }
      }
      rgba[p++] = r;
      rgba[p++] = g;
      rgba[p++] = b;
      rgba[p++] = hit * 255 ~/ 16;
    }
  }
  return rgba;
}

/// 把 RGBA 像素编码为最小 PNG（color type 6, bit depth 8）。
Uint8List _encodePng(Uint8List rgba) {
  // 每行前置 filter byte 0（None）。
  final raw = Uint8List(size * (size * 4 + 1));
  for (var y = 0; y < size; y++) {
    final rowStart = y * (size * 4 + 1);
    raw[rowStart] = 0;
    raw.setRange(rowStart + 1, rowStart + 1 + size * 4,
        rgba.sublist(y * size * 4, (y + 1) * size * 4));
  }

  final out = BytesBuilder();
  out.add(const [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]); // 签名
  out.add(_chunk('IHDR', _ihdr(size)));
  out.add(_chunk('IDAT', _zlibStored(raw)));
  out.add(_chunk('IEND', Uint8List(0)));
  return out.toBytes();
}

Uint8List _ihdr(int s) {
  final b = ByteData(13);
  b.setUint32(0, s); // width
  b.setUint32(4, s); // height
  b.setUint8(8, 8); // bit depth
  b.setUint8(9, 6); // color type: RGBA
  b.setUint8(10, 0); // compression
  b.setUint8(11, 0); // filter
  b.setUint8(12, 0); // interlace
  return b.buffer.asUint8List();
}

/// 把一组不同尺寸的 RGBA 位图编码为 Windows ICO（BMP 内嵌，非 PNG 内嵌，
/// 兼容性最好）。每帧写为 32bpp BGRA「预乘 alpha」DIB + 1bpp AND 掩码，
/// 这是 Shell_NotifyIcon 正确合成半透明图标最保险的格式。
Uint8List _encodeIco(List<Uint8List> framesRgba) {
  final sizes = _icoSizes;
  assert(framesRgba.length == sizes.length);

  final dibs = <Uint8List>[];
  for (var i = 0; i < sizes.length; i++) {
    dibs.add(_encodeDib(sizes[i], framesRgba[i]));
  }

  const headerLen = 6;
  const dirEntryLen = 16;
  var offset = headerLen + dirEntryLen * sizes.length;

  final header = ByteData(headerLen);
  header.setUint16(0, 0, Endian.little); // reserved
  header.setUint16(2, 1, Endian.little); // type: icon
  header.setUint16(4, sizes.length, Endian.little); // count

  final dir = BytesBuilder();
  for (var i = 0; i < sizes.length; i++) {
    final s = sizes[i];
    final dib = dibs[i];
    final entry = ByteData(dirEntryLen);
    entry.setUint8(0, s >= 256 ? 0 : s); // width (0 = 256)
    entry.setUint8(1, s >= 256 ? 0 : s); // height
    entry.setUint8(2, 0); // color count
    entry.setUint8(3, 0); // reserved
    entry.setUint16(4, 1, Endian.little); // color planes
    entry.setUint16(6, 32, Endian.little); // bits per pixel
    entry.setUint32(8, dib.length, Endian.little); // size of bitmap data
    entry.setUint32(12, offset, Endian.little); // offset of bitmap data
    dir.add(entry.buffer.asUint8List());
    offset += dib.length;
  }

  final out = BytesBuilder();
  out.add(header.buffer.asUint8List());
  out.add(dir.toBytes());
  for (final dib in dibs) {
    out.add(dib);
  }
  return out.toBytes();
}

/// 单帧 DIB：BITMAPINFOHEADER（高度写为 2*s，上半 XOR 色彩位图 + 下半 AND
/// 掩码位图）+ 32bpp BGRA 像素（自底向上，alpha 预乘）+ 1bpp AND 掩码
/// （全 0 = 完全依赖 alpha 通道，避免与 alpha 叠加导致边缘发灰/发透明）。
Uint8List _encodeDib(int s, Uint8List rgba) {
  const headerLen = 40;
  final pixelsLen = s * s * 4;
  // AND 掩码：每行按 32bit 对齐，1bpp。
  final maskRowBytes = ((s + 31) ~/ 32) * 4;
  final maskLen = maskRowBytes * s;

  final header = ByteData(headerLen);
  header.setUint32(0, headerLen, Endian.little);
  header.setInt32(4, s, Endian.little); // width
  header.setInt32(8, s * 2, Endian.little); // height：XOR+AND 两部分之和
  header.setUint16(12, 1, Endian.little); // planes
  header.setUint16(14, 32, Endian.little); // bpp
  header.setUint32(16, 0, Endian.little); // BI_RGB
  header.setUint32(20, pixelsLen + maskLen, Endian.little); // image size
  header.setInt32(24, 0, Endian.little);
  header.setInt32(28, 0, Endian.little);
  header.setUint32(32, 0, Endian.little);
  header.setUint32(36, 0, Endian.little);

  // 像素数据自底向上、BGRA、alpha 预乘（premultiplied），
  // 这是 HICON 32bpp 图标在 Windows 下渲染最不容易出错的组合。
  final pixels = Uint8List(pixelsLen);
  var dst = 0;
  for (var y = s - 1; y >= 0; y--) {
    var src = y * s * 4;
    for (var x = 0; x < s; x++) {
      final r = rgba[src];
      final g = rgba[src + 1];
      final b = rgba[src + 2];
      final a = rgba[src + 3];
      pixels[dst] = (b * a) ~/ 255; // B
      pixels[dst + 1] = (g * a) ~/ 255; // G
      pixels[dst + 2] = (r * a) ~/ 255; // R
      pixels[dst + 3] = a; // A
      src += 4;
      dst += 4;
    }
  }

  // AND 掩码全 0：完全不透明区域交给 alpha 通道决定，
  // 避免部分渲染路径把掩码当作硬边缘叠加进而出现灰边/透明块。
  final mask = Uint8List(maskLen);

  final out = BytesBuilder();
  out.add(header.buffer.asUint8List());
  out.add(pixels);
  out.add(mask);
  return out.toBytes();
}

/// zlib 流（0x78 0x01）+ 单个「存储型」deflate 块 + adler32。
Uint8List _zlibStored(Uint8List data) {
  final out = BytesBuilder();
  out.add(const [0x78, 0x01]);
  var offset = 0;
  while (offset < data.length) {
    final n = (data.length - offset) > 65535 ? 65535 : data.length - offset;
    final finalBlock = offset + n >= data.length;
    out.addByte(finalBlock ? 1 : 0);
    final len = ByteData(2)..setUint16(0, n, Endian.little);
    out.add(len.buffer.asUint8List());
    final nlen = ByteData(2)..setUint16(0, n ^ 0xFFFF, Endian.little);
    out.add(nlen.buffer.asUint8List());
    out.add(data.sublist(offset, offset + n));
    offset += n;
  }
  final a = ByteData(4)..setUint32(0, _adler32(data), Endian.big);
  out.add(a.buffer.asUint8List());
  return out.toBytes();
}

Uint8List _chunk(String type, Uint8List data) {
  final b = BytesBuilder();
  final len = ByteData(4)..setUint32(0, data.length, Endian.big);
  b.add(len.buffer.asUint8List());
  final typeBytes = type.codeUnits;
  b.add(typeBytes);
  b.add(data);
  final crc = ByteData(4)
    ..setUint32(0, _crc32([...typeBytes, ...data]), Endian.big);
  b.add(crc.buffer.asUint8List());
  return b.toBytes();
}

final List<int> _crcTable = () {
  final t = List<int>.filled(256, 0);
  for (var n = 0; n < 256; n++) {
    var c = n;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) == 1 ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    t[n] = c;
  }
  return t;
}();

int _crc32(List<int> data) {
  var c = 0xFFFFFFFF;
  for (final byte in data) {
    c = _crcTable[(c ^ byte) & 0xFF] ^ (c >>> 8);
  }
  return (c ^ 0xFFFFFFFF) & 0xFFFFFFFF;
}

int _adler32(Uint8List data) {
  var a = 1, b = 0;
  for (final byte in data) {
    a = (a + byte) % 65521;
    b = (b + a) % 65521;
  }
  return (b << 16) | a;
}
