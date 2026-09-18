// pm2 ecosystem for dsh-token-authz (授权服务)
// 用法: pm2 start ecosystem.config.cjs
// secret 需与 higress jwt-auth consumer jwks 的 k 一致 (HS256 对称)
// 【回滚说明】2026-09-10：移除 AUTHZ_OWNER_SECRETS/AUTHZ_APPROVE_TTL（v2 批准码方向被否）。
// 新方向 = Keycloak 标准授权（见方案文档），本服务仅作过渡/降级通道。
module.exports = {
  apps: [
    {
      name: 'dsh-token-authz',
      script: 'E:/ai-works/dsh-token-authz/dsh-token-authz.mjs',
      interpreter: 'C:/nvm4w/nodejs/node.exe',
      env: {
        AUTHZ_PORT: '8766',
        AUTHZ_SECRET: 'R0EwY3dLX1NlY3JldEtleTIwMjZBaUdhdGV3YXlUZXN0T25seTEyMzQ1Ng',
      },
    },
  ],
}
