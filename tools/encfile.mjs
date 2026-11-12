// 本地工具：管理管理区的「加密文件库」
// 仓库布局：
//   private/index.json        公开：指向加密清单及其 salt/iv（不含密码）
//   private/manifest.enc      加密的清单（真实文件名、路径、每文件 IV、大小、MIME）
//   private/<随机id>.enc      加密的文件本体（AES-GCM）
// 密钥模型：密码 + 清单 salt 派生一个密钥；清单和每个文件各自用随机 IV。
// 用法：
//   node tools/encfile.mjs add --password 密码 --name "显示名" 本地文件路径
//   node tools/encfile.mjs list --password 密码
//   node tools/encfile.mjs remove --password 密码 --name "显示名"（或 --path xxx.enc）
//   node tools/encfile.mjs rotate --old 旧密码 --new 新密码   （全库重加密，文件名不变）
// 改完提交推送后，管理区页面解锁即可看到文件列表。
import { webcrypto, randomBytes } from 'node:crypto';
import { readFile, writeFile, unlink, mkdir } from 'node:fs/promises';
import { join, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const subtle = webcrypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();
const ROOT = dirname(dirname(fileURLToPath(import.meta.url))); // 仓库根
const PRIVATE = join(ROOT, 'private');
const ITERATIONS = 310000;

const MIME = {
  '.zip': 'application/zip', '.7z': 'application/x-7z-compressed', '.rar': 'application/vnd.rar',
  '.pdf': 'application/pdf', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8', '.csv': 'text/csv',
  '.json': 'application/json', '.mp4': 'video/mp4', '.mp3': 'audio/mpeg',
  '.apk': 'application/vnd.android.package-archive',
  '.exe': 'application/vnd.microsoft.portable-executable',
  '.doc': 'application/msword', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel', '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
};
const mimeOf = (p) => MIME[extname(p).toLowerCase()] || 'application/octet-stream';

const b64 = (buf) => Buffer.from(buf).toString('base64');
const fromB64 = (s) => Buffer.from(s, 'base64');

async function deriveKey(password, salt) {
  const base = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptWith(key, bytes) {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
  return { iv: b64(iv), ct: Buffer.from(ct) };
}

async function decryptWith(key, ivB64, ctBuf) {
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) }, key, ctBuf);
  return Buffer.from(pt);
}

async function readIndex() {
  try { return JSON.parse(await readFile(join(PRIVATE, 'index.json'), 'utf8')); }
  catch (e) { return null; }
}

async function readManifest(key, index) {
  const raw = await readFile(join(PRIVATE, index.manifest.file));
  const pt = await decryptWith(key, index.manifest.iv, raw);
  return JSON.parse(dec.decode(pt));
}

async function writeManifest2(key, manifest, saltOverride) {
  const m = await encryptWith(key, enc.encode(JSON.stringify(manifest)));
  await writeFile(join(PRIVATE, 'manifest.enc'), m.ct);
  const saltB64 = saltOverride || (CURRENT_SALT ? b64(CURRENT_SALT) : null);
  if (!saltB64) throw new Error('缺少 salt 上下文');
  const index = { v: 1, manifest: { file: 'manifest.enc', salt: saltB64, iv: m.iv, iterations: ITERATIONS } };
  await writeFile(join(PRIVATE, 'index.json'), JSON.stringify(index, null, 2) + '\n');
  return index;
}

// 从已派生的 key 里拿不回 salt——所以在加载库时把现用 salt 存进上下文
let CURRENT_SALT = null;

async function bootstrap(password) {
  await mkdir(PRIVATE, { recursive: true });
  const salt = randomBytes(16);
  CURRENT_SALT = salt;
  const key = await deriveKey(password, salt);
  const manifest = { v: 1, files: [] };
  const m = await encryptWith(key, enc.encode(JSON.stringify(manifest)));
  await writeFile(join(PRIVATE, 'manifest.enc'), m.ct);
  const index = { v: 1, manifest: { file: 'manifest.enc', salt: b64(salt), iv: m.iv, iterations: ITERATIONS } };
  await writeFile(join(PRIVATE, 'index.json'), JSON.stringify(index, null, 2) + '\n');
  return { key, manifest, index };
}

function humanSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(2) + ' MB';
}

function argValue(argv, flag) {
  const i = argv.indexOf(flag);
  if (i >= 0 && i + 1 < argv.length) return argv[i + 1];
  const eq = argv.find(a => a.startsWith(flag + '='));
  return eq ? eq.slice(flag.length + 1) : undefined;
}

// ---------- 命令 ----------

async function cmdAdd(argv) {
  const password = argValue(argv, '--password');
  const name = argValue(argv, '--name');
  const src = argv[argv.length - 1];
  if (!password || !name || !src || src.startsWith('--')) {
    console.error('用法：node tools/encfile.mjs add --password 密码 --name "显示名" 本地文件路径'); process.exit(1);
  }
  const bytes = await readFile(src);
  let key, manifest;
  const index = await readIndex();
  if (index) {
    key = await deriveKey(password, fromB64(index.manifest.salt));
    CURRENT_SALT = fromB64(index.manifest.salt);
    manifest = await readManifest(key, index);
  } else {
    console.log('（还没有加密文件库，正在初始化 private/）');
    const b = await bootstrap(password);
    key = b.key; manifest = b.manifest;
  }
  // 同名 = 更新（替换旧文件体，避免孤儿 .enc）
  const old = manifest.files.find(f => f.name === name);
  if (old) { try { await unlink(join(PRIVATE, old.path)); } catch (e) { } }
  const path = (old ? old.path : randomBytes(4).toString('hex') + '.enc');
  const e = await encryptWith(key, bytes);
  await writeFile(join(PRIVATE, path), e.ct);
  const entry = { name, path, iv: e.iv, size: bytes.length, mime: mimeOf(src) };
  if (old) Object.assign(old, entry); else manifest.files.push(entry);
  await writeManifest2(key, manifest);
  console.log(`已加密入库：${name} → private/${path}（${humanSize(bytes.length)}），共 ${manifest.files.length} 个文件`);
  console.log('提交推送 private/ 目录后，管理区解锁即可下载。');
}

async function cmdList(argv) {
  const password = argValue(argv, '--password');
  if (!password) { console.error('用法：node tools/encfile.mjs list --password 密码'); process.exit(1); }
  const index = await readIndex();
  if (!index) { console.log('还没有加密文件库。'); return; }
  const key = await deriveKey(password, fromB64(index.manifest.salt));
  const manifest = await readManifest(key, index);
  if (!manifest.files.length) { console.log('文件库是空的。'); return; }
  manifest.files.forEach(f => console.log(`${f.name}  ${humanSize(f.size)}  private/${f.path}`));
}

async function cmdRemove(argv) {
  const password = argValue(argv, '--password');
  const name = argValue(argv, '--name');
  const path = argValue(argv, '--path');
  if (!password || (!name && !path)) { console.error('用法：node tools/encfile.mjs remove --password 密码 --name "显示名"（或 --path xxx.enc）'); process.exit(1); }
  const index = await readIndex();
  if (!index) { console.log('还没有加密文件库。'); return; }
  const key = await deriveKey(password, fromB64(index.manifest.salt));
  CURRENT_SALT = fromB64(index.manifest.salt);
  const manifest = await readManifest(key, index);
  const entry = manifest.files.find(f => (name && f.name === name) || (path && f.path === path));
  if (!entry) { console.error('没找到这个文件。用 list 查看现有条目。'); process.exit(1); }
  try { await unlink(join(PRIVATE, entry.path)); } catch (e) { }
  manifest.files = manifest.files.filter(f => f !== entry);
  await writeManifest2(key, manifest);
  console.log(`已移除：${entry.name}（${entry.path}），剩 ${manifest.files.length} 个文件`);
}

async function cmdRotate(argv) {
  const oldPwd = argValue(argv, '--old');
  const newPwd = argValue(argv, '--new');
  if (!oldPwd || !newPwd) { console.error('用法：node tools/encfile.mjs rotate --old 旧密码 --new 新密码'); process.exit(1); }
  const index = await readIndex();
  if (!index) { console.log('还没有加密文件库，无需轮换。'); return; }
  const oldKey = await deriveKey(oldPwd, fromB64(index.manifest.salt));
  const manifest = await readManifest(oldKey, index); // 密码错在这里直接抛
  const newSalt = randomBytes(16);
  CURRENT_SALT = newSalt;
  const newKey = await deriveKey(newPwd, newSalt);
  // 逐个文件重加密（同名 .enc 原地替换，路径不变）
  for (const f of manifest.files) {
    const raw = await readFile(join(PRIVATE, f.path));
    const pt = await decryptWith(oldKey, f.iv, raw);
    const e = await encryptWith(newKey, pt);
    await writeFile(join(PRIVATE, f.path), e.ct);
    f.iv = e.iv;
  }
  await writeManifest2(newKey, manifest, b64(newSalt));
  console.log(`全库已用新密码重加密（${manifest.files.length} 个文件）。页面上的密码也记得换成新的。`);
}

// ---------- 入口 ----------
const [cmd, ...rest] = process.argv.slice(2);
const commands = { add: cmdAdd, list: cmdList, remove: cmdRemove, rotate: cmdRotate };
if (!commands[cmd]) {
  console.error('用法：node tools/encfile.mjs <add|list|remove|rotate> ...（见文件头注释）');
  process.exit(1);
}
try {
  await commands[cmd](rest);
} catch (e) {
  if (e.name === 'OperationError') {
    console.error('密码不对（或 manifest.enc 已损坏），解密失败。');
  } else {
    console.error('出错了：' + (e && e.message ? e.message : e));
  }
  process.exit(1);
}
