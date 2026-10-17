// 本地工具：生成管理区密码与加密内容（不推送到线上）
// 用法：node gen.mjs "要加密的管理内容"
// 输出：密码（stdout）+ 密文 JSON（写入 admin_data.json）
import { randomBytes, createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';

const content = (process.argv[2] || '欢迎进入管理区。\n这里是加密内容，只有输入正确密码才能看到。').replaceAll('\\n', '\n');

// 生成随机密码（16 位，含大小写字母数字）
const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const rand = randomBytes(16);
let password = '';
for (let i = 0; i < rand.length; i++) password += charset[rand[i] % charset.length];

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

writeFileSync(new URL('./admin_data.json', import.meta.url), JSON.stringify(data, null, 2));
console.log('=== 密码（只显示这一次，请保存好）===');
console.log(password);
console.log('=== 密文已写入 admin_data.json ===');