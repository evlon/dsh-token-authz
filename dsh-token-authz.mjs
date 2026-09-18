/**
 * dsh-token-authz - 数字分身临时 Token 授权服务
 *
 * 场景：数字分身需要代表主人调用企业 MCP/API（经 higress 网关统一入口）。
 * 流程：
 *   1. 分身请求授权（scope = 要访问的资源 + 读写）
 *   2. 主人（经 Matrix 或直接）同意后，本服务签发短时 JWT
 *   3. 分身带 JWT 调 higress 网关 → jwt-auth 插件验签（HS256 共享 secret）
 *   4. 网关把 sub/scope 注入 header 转发后端，后端按 scope 放行
 *
 * 【回滚说明】2026-09-10：曾尝试"服务端强制 owner 批准码"(v2, OWNER_SECRETS +
 * /owner/approve)，方向被否（主人 secret 若下发会使每个同事都能生成 token）。
 * 已回滚到 v1（无条件签发，owner 同意由调用方保证——Matrix 请示闭环在
 * dsh-matrix-agent 侧）。新方向 = Keycloak 标准授权服务器（见
 * iteration/方案-Keycloak统一授权与Matrix主人同意.md），本服务仅作过渡/降级。
 *
 * JWT claims:
 *   iss: "dsh-token-authz"        (网关 consumer 校验)
 *   sub: 分身 twinId               (身份)
 *   aud: "ai-gateway"             (受众，纯标识)
 *   scope: "roster:read roster:write" (OAuth2 风格 scope 声明)
 *   iat/exp: 短时 (默认 30min)
 *   jti: 随机唯一 id (防重放)
 *
 * 运行: node dsh-token-authz.mjs [--port 8766] [--secret <HS256 secret>]
 *   secret 缺省自动生成并打印（生产应从环境/文件读取并注入网关 jwks）
 *
 * 接口:
 *   GET  /health
 *   POST /issue   {twinId, owner, scope: "a:read b:write", ttlSeconds?} -> {token}
 *       —— v1：owner 同意由调用方保证（Matrix 请示闭环在 dsh-matrix-agent 侧）。
 *   GET  /verify?token=...  (可选调试)
 */
import { createHmac, randomBytes } from 'node:crypto'

const PORT = Number(process.env.AUTHZ_PORT || 8766)
// SECRET 语义: 原始字节的 base64url 表示。签发 HMAC 时解码回字节作 key，
// JWK k 字段用同一 base64url —— 与网关 jwt-auth(HS256) 的解码语义一致。
const SECRET_B64 = process.env.AUTHZ_SECRET || randomBytes(32).toString('base64url')
const SECRET = Buffer.from(SECRET_B64, 'base64url')
const ISS = 'dsh-token-authz'
const DEFAULT_TTL = 30 * 60 // 30min

// JWT `aud`（受众）：固定为纯标识 "ai-gateway"，不做环境分档、不写成域名。
//
// ⚠️ 语义（2026-09 确认）：
//   aud 是「受众标识」而非「可访问域名」。此前写成形似域名的值，易被误当成
//   真实入口，且全局搜索时因带域名后缀难以唯一定位、易漏改，故收敛为单一纯标识。
//
// 关于「是否需要与网关同步改」：Higress 标准 jwt-auth 插件只校验 iss + 签名，
// 不校验 aud（官方 consumer 配置无 aud/audiences 字段），故本字段为信息性
// 标识，不存在「改这里必须同步改网关」的约束。若将来要用 aud 做防串用校验，
// 需走 ext-auth 或自定义 Wasm，届时再另行评估。
const AUDIENCE = 'ai-gateway'

const DEFAULT_AUDIENCE = AUDIENCE

console.log(`[authz] JWT aud = ${DEFAULT_AUDIENCE}`)

if (!process.env.AUTHZ_SECRET) {
  console.log(`[authz] generated ephemeral secret (base64url of raw bytes): ${SECRET_B64}`)
  console.log('[authz] put this secret into gateway jwt-auth consumer jwks k (kty:oct)')
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64url')
}

/** Sign a HS256 JWT with compact serialization. */
function signJwt(payload) {
  const header = { alg: 'HS256', typ: 'JWT', kid: 'authz-1' }
  const h = b64url(JSON.stringify(header))
  const p = b64url(JSON.stringify(payload))
  const sig = createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64url')
  return `${h}.${p}.${sig}`
}

/** Minimal HS256 JWT verify (for /verify debug only; gateway does real auth). */
function verifyJwt(token) {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const expect = createHmac('sha256', SECRET).update(`${parts[0]}.${parts[1]}`).digest('base64url')
  const a = Buffer.from(parts[2])
  const b = Buffer.from(expect)
  if (a.length !== b.length || !a.equals(b)) return null
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
  if (payload.exp && Date.now() / 1000 > payload.exp) return { ...payload, expired: true }
  return payload
}

function json(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' })
  res.end(JSON.stringify(obj))
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = ''
    req.on('data', (c) => (data += c))
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}) } catch { resolve(null) }
    })
  })
}

import { createServer } from 'node:http'
const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`)
  try {
    if (req.method === 'GET' && url.pathname === '/health') {
      return json(res, 200, { ok: true, service: 'dsh-token-authz', issuer: ISS })
    }
    if (req.method === 'GET' && url.pathname === '/jwks') {
      // 网关 consumer 配置用的对称 JWK（k = SECRET_B64，与签名解码语义一致）
      return json(res, 200, { keys: [{ kty: 'oct', kid: 'authz-1', alg: 'HS256', k: SECRET_B64 }] })
    }
    if (req.method === 'POST' && url.pathname === '/issue') {
      const body = await readBody(req)
      if (!body || !body.twinId || !body.scope) {
        return json(res, 400, { ok: false, error: 'twinId and scope are required' })
      }
      const now = Math.floor(Date.now() / 1000)
      const ttl = body.ttlSeconds && Number(body.ttlSeconds) > 0 ? Number(body.ttlSeconds) : DEFAULT_TTL
      const payload = {
        iss: ISS,
        sub: String(body.twinId),
        owner: body.owner || undefined,
        scope: String(body.scope),
        aud: body.aud || DEFAULT_AUDIENCE,
        iat: now,
        exp: now + ttl,
        jti: randomBytes(12).toString('hex'),
      }
      const token = signJwt(payload)
      console.log(`[authz] issued token sub=${payload.sub} scope="${payload.scope}" ttl=${ttl}s`)
      return json(res, 200, { ok: true, token, expiresAt: payload.exp, claims: payload })
    }
    if (req.method === 'GET' && url.pathname === '/verify') {
      const t = url.searchParams.get('token')
      if (!t) return json(res, 400, { ok: false, error: 'token param required' })
      const payload = verifyJwt(t)
      if (!payload) return json(res, 401, { ok: false, error: 'invalid signature' })
      if (payload.expired) return json(res, 401, { ok: false, error: 'expired', claims: payload })
      return json(res, 200, { ok: true, claims: payload })
    }
    return json(res, 404, { ok: false, error: 'no route' })
  } catch (e) {
    return json(res, 500, { ok: false, error: String(e && e.message || e) })
  }
})

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[authz] dsh-token-authz listening on http://0.0.0.0:${PORT}`)
  console.log(`[authz] issuer=${ISS} defaultTtl=${DEFAULT_TTL}s`)
})
