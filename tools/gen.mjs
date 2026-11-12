// 本地工具：生成/轮换管理区密码与加密内容（本目录与密文不涉密，密码只经 stdout 给你）
// 用法：
//   node gen.mjs "要加密的管理内容"                  → 随机生成新密码（旧密码作废）
//   node gen.mjs --password 你的密码 "要加密的内容"   → 沿用指定密码换内容
// 输出：密文写入 tools/admin_data.json，并自动把 SALT/IV/CIPHER/ITERATIONS
//       四个常量同步进仓库根目录的 admin.html（改完提交推送即可上线）
// 注意：private/ 下的加密文件库用的是同一个密码。若换密码，除了换管理区密文，
//       还要用 node tools/encfile.mjs rotate --old 旧密码 --new 新密码 把文件库迁移过去。
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';

// ---- 参数解析：--password 或 --password=xxx；其余参数拼成内容 ----
const argv = process.argv.slice(2);
let password = null;
const contentParts = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--password') password = argv[++i] ?? null;
  else if (argv[i].startsWith('--password=')) password = argv[i].slice('--password='.length);
  else contentParts.push(argv[i]);
}
if (password !== null && password === '') { console.error('--password 不能为空'); process.exit(1); }
const content = (contentParts.join(' ') || '欢迎进入管理区。\n这里是加密内容，只有输入正确密码才能看到。').replaceAll('\\n', '\n');

// ---- 生成密码（未指定时随机 16 位，只打印这一次） ----
let generated = false;
if (password === null) {
  generated = true;
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const rand = randomBytes(16);
  password = '';
  for (let i = 0; i < rand.length; i++) password += charset[rand[i] % charset.length];
}

const salt = randomBytes(16);
const iv = randomBytes(12);
const iterations = 310000;

const enc = new TextEncoder();
const pt = enc.encode(content);

// 派生密钥
const baseKey = await webcrypto.subtle.importKey(
  'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
);
const key = await webcrypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
  baseKey,
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt', 'decrypt']
);

const ct = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);

const data = {
  salt: Buffer.from(salt).toString('base64'),
  iv: Buffer.from(iv).toString('base64'),
  ct: Buffer.from(ct).toString('base64'),
  iterations,
};

// 自测解密
const dk2 = await webcrypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
  baseKey,
  { name: 'AES-GCM', length: 256 },
  false,
  ['decrypt']
);
const dec = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, dk2, ct);
const decText = new TextDecoder().decode(dec);
if (decText !== content) { console.error('自测失败'); process.exit(1); }

// ---- 写 admin_data.json（工具侧记录，与线上同源） ----
writeFileSync(new URL('./admin_data.json', import.meta.url), JSON.stringify(data, null, 2));
console.log('=== 密文已写入 tools/admin_data.json ===');

// ---- 同步进 admin.html 的四个常量行 ----
const htmlPath = new URL('../admin.html', import.meta.url);
let html = readFileSync(htmlPath, 'utf8');
const before = html;
html = html
  .replace(/const SALT = fromBase64\('[^']*'\);/, `const SALT = fromBase64('${data.salt}');`)
  .replace(/const IV = fromBase64\('[^']*'\);/, `const IV = fromBase64('${data.iv}');`)
  .replace(/const CIPHER = fromBase64\('[^']*'\);/, `const CIPHER = fromBase64('${data.ct}');`)
  .replace(/const ITERATIONS = \d+;/, `const ITERATIONS = ${data.iterations};`);
if (html !== before && html.includes(`fromBase64('${data.salt}')`)) {
  writeFileSync(htmlPath, html);
  console.log('=== 已同步 admin.html 的密文常量 ===');
} else {
  console.error('警告：admin.html 常量未替换成功，请手动把 SALT/IV/CIPHER/ITERATIONS 抄进去');
}

if (generated) {
  console.log('=== 密码（只显示这一次，请保存好）===');
  console.log(password);
} else {
  console.log('=== 密码：沿用你通过 --password 指定的那个 ===');
}
