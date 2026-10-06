// =============================================================
// Cloudflare Workers —— Trae API 代理
// 免费 serverless，全球边缘节点，避开 GitHub Actions IP 限流
//
// 部署步骤（2 分钟）：
// 1. 注册 https://dash.cloudflare.com （免费）
// 2. Workers & Pages -> Create -> Create Worker -> 命名 trae-proxy
// 3. 把这个代码粘进去 -> Deploy
// 4. 拿到 URL 比如 https://trae-proxy.yourname.workers.dev
// 5. 在 GitHub Secrets 里加 TRAE_PROXY = https://trae-proxy.yourname.workers.dev
// =============================================================

// 允许转发到的目标 host（白名单，防止被滥用）
const ALLOWED_HOSTS = [
  "api.trae.cn",
  "trae-api.com",
];

// Worker 入口
export default {
  async fetch(request, env, ctx) {
    // CORS（浏览器调的话需要）
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Cloudide-Token, x-uid, x-app-id, x-device-id, x-machine-id, x-request-id, x-ide-version, x-ide-version-code, x-device-type, x-os-version",
        },
      });
    }

    // 只接受 /proxy 路径
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/proxy")) {
      return new Response(
        JSON.stringify({ ok: true, msg: "Trae API proxy is ready", usage: "POST /proxy with {url, method, headers, body}" }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // 从 body 读转发请求
    let reqJson;
    try {
      reqJson = await request.json();
    } catch (e) {
      return new Response(JSON.stringify({ ok: false, error: "invalid json body" }), { status: 400 });
    }

    const targetUrl = reqJson.url;
    if (!targetUrl) {
      return new Response(JSON.stringify({ ok: false, error: "missing url" }), { status: 400 });
    }

    // 安全检查：只允许 Trae 的 API host
    const parsed = new URL(targetUrl);
    if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
      return new Response(
        JSON.stringify({ ok: false, error: `host ${parsed.hostname} not allowed` }),
        { status: 403 }
      );
    }

    const method = reqJson.method || "POST";
    const headers = reqJson.headers || {};
    const body = reqJson.body !== undefined ? JSON.stringify(reqJson.body) : undefined;

    // 转发请求
    let resp;
    try {
      resp = await fetch(targetUrl, { method, headers, body, cf: { minTLSVersion: "TLSv1.2" } });
    } catch (e) {
      return new Response(JSON.stringify({ ok: false, error: String(e) }), { status: 502 });
    }

    // 返回结果
    const text = await resp.text();
    return new Response(text, {
      status: resp.status,
      headers: {
        "Content-Type": resp.headers.get("Content-Type") || "application/json",
        "Access-Control-Allow-Origin": "*",
        "X-Proxy-By": "Cloudflare-Workers",
      },
    });
  },
};
