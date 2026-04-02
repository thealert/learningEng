/**
 * Cloudflare Pages Function: GET /api/tts-sign
 *
 * 在 Cloudflare 控制台配置以下环境变量（Settings → Environment variables）：
 *   XF_APPID      讯飞 APPID
 *   XF_APIKEY     讯飞 APIKey
 *   XF_APISECRET  讯飞 APISecret（建议设为 Secret）
 */
export async function onRequestGet(context) {
  const { env } = context;

  const APPID     = env.XF_APPID;
  const APIKey    = env.XF_APIKEY;
  const APISecret = env.XF_APISECRET;

  if (!APPID || !APIKey || !APISecret) {
    return jsonResponse({ error: '服务端未配置讯飞 key' }, 500);
  }

  const host = 'tts-api.xfyun.cn';
  const path = '/v2/tts';
  const date = new Date().toUTCString(); // RFC1123, UTC

  // 签名原始字段（格式固定，不可改动）
  const signOrigin = `host: ${host}\ndate: ${date}\nGET ${path} HTTP/1.1`;
  const signature  = await hmacSha256(APISecret, signOrigin);
  const authOrigin = `api_key="${APIKey}", algorithm="hmac-sha256", headers="host date request-line", signature="${signature}"`;
  const authorization = btoa(authOrigin);

  const wsUrl = `wss://${host}${path}`
    + `?authorization=${encodeURIComponent(authorization)}`
    + `&date=${encodeURIComponent(date)}`
    + `&host=${host}`;

  return jsonResponse({ wsUrl, appId: APPID });
}

// Workers 运行时可直接使用 crypto.subtle（无需 HTTPS 限制）
async function hmacSha256(key, data) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}
