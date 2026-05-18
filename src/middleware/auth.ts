src/middleware/auth.ts
import type { PagesFunction, PagesFunctionContext } from '@cloudflare/pages-functions-types';
import { jwtVerify } from 'jose';

// Cache for JWKS to avoid fetching on every request
let jwksCache: { keys: any[]; expiry: number } | null = null;
const JWKS_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

async function fetchJwks(issuer: string): Promise<any[]> {
  const now = Date.now();
  if (jwksCache && now < jwksCache.expiry) {
    return jwksCache.keys;
  }
  const res = await fetch(`${issuer}cdn-cgi/access/certs`);
  if (!res.ok) {
    throw new Error('Failed to fetch JWKS from Cloudflare Access');
  }
  const data = await res.json();
  jwksCache = { keys: data.keys, expiry: now + JWKS_CACHE_TTL };
  return data.keys;
}

export const onRequest: PagesFunction = async (context, next) => {
  const req = context.request;
  // Cloudflare Access injects the JWT in this header
  const token = req.headers.get('Cf-Access-Jwt-Assertion');
  if (!token) {
    return new Response('Missing Cloudflare Access JWT', { status: 401 });
  }

  let payload;
  try {
    if (process.env.JWT_SECRET) {
      // Local development: verify using HS256 secret
      const secret = new TextEncoder().encode(process.env.JWT_SECRET);
      const { payload: verifiedPayload } = await jwtVerify(token, secret);
      payload = verifiedPayload;
    } else {
      // Production: verify using Cloudflare Access JWKS
      const issuer = process.env.CF_ACCESS_ISSUER;
      if (!issuer) {
        throw new Error('CF_ACCESS_ISSUER environment variable is not set');
      }
      const keys = await fetchJwks(issuer);
      const { payload: verifiedPayload } = await jwtVerify(token, keys);
      payload = verifiedPayload;
    }
  } catch (err) {
    console.error('JWT verification failed:', err);
    return new Response('Invalid or expired token', { status: 401 });
  }

  // Attach user information (e.g., email, name, sub) to the request context
  context.data.user = payload;

  // Proceed to the next middleware or handler
  return await next();
};