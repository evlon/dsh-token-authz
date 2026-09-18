// echo-headers.mjs - 受保护业务模拟端点（验证网关 claims_to_headers 注入 + scope 放行）
//
// 模拟一个「需要主人授权才可读的企业业务数据」服务，经 Higress 网关暴露。
// 网关 jwt-auth 验签通过后注入 X-Twin-Id / X-Twin-Owner / X-Twin-Scope header；
// 本服务按 scope 决策：
//   GET /secret-data  -> 仅当 X-Twin-Scope 含 "secret:read" 时返回业务数据，否则 403
//   GET /echo         -> 回显 headers（调试用，不做 scope 校验）
//   GET /health       -> ok
import { createServer } from 'node:http'
const PORT = Number(process.env.PORT || 8790)

// 模拟的业务数据：告警明细（测试用，与 ai-test-data 呼应）
const SECRET_PAYLOAD = {
  service: 'order-service',
  secretKey: 'order-db-readonly',
  alerts: [
    { id: 'A-1001', level: 'P1', title: 'order-service 接口 P99 超时', rootCause: '数据库连接池打满', suggestion: '扩容连接池 + 限流', owner: '交易组' },
    { id: 'A-1002', level: 'P2', title: '消息积压超过阈值', rootCause: '消费端批量处理过慢', suggestion: '拆分批次 + 增加消费者', owner: '消息组' },
  ],
  note: '该数据需要主人授权 scope=secret:read 才能读取（模拟企业受保护业务数据）。',
}

createServer((req, res) => {
  const url = req.url ?? '/'
  const write = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify(obj, null, 2))
  }
  try {
    if (req.method === 'GET' && url.startsWith('/health')) {
      return write(200, { ok: true, service: 'secret-data-demo' })
    }
    // 受保护数据：校验 X-Twin-Scope（网关注入）
    if (req.method === 'GET' && url.startsWith('/secret-data')) {
      const scope = String(req.headers['x-twin-scope'] ?? '')
      const twinId = String(req.headers['x-twin-id'] ?? '')
      const owner = String(req.headers['x-twin-owner'] ?? '')
      if (!scope.split(/\s+/).includes('secret:read')) {
        return write(403, { ok: false, error: `scope 不足：需要 secret:read，当前 scope="${scope}"` })
      }
      return write(200, { ok: true, data: SECRET_PAYLOAD, grantedBy: owner, twin: twinId })
    }
    // 调试：回显 headers
    if (req.method === 'GET' && url.startsWith('/echo')) {
      return write(200, { method: req.method, url, headers: req.headers })
    }
    return write(404, { error: 'no route' })
  } catch (e) {
    return write(500, { error: String(e && e.message || e) })
  }
}).listen(PORT, '0.0.0.0', () => console.log(`secret-data-demo on :${PORT}`))
