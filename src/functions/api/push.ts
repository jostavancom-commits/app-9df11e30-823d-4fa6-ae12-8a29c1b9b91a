import type { Context } from '@cloudflare/workers-types';
import jwt from 'jsonwebtoken';

interface PushSubscription {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
}

/**
 * Verify JWT and return payload or throw.
 */
async function verifyJwt(request: Request, env: Env): Promise<any> {
  const auth = request.headers.get('Authorization');
  if (!auth?.startsWith('Bearer ')) {
    throw new Error('Missing or malformed Authorization header');
  }
  const token = auth.split(' ')[1];
  return jwt.verify(token, env.JWT_SECRET);
}

/**
 * POST /api/push/subscribe
 * Body: { endpoint: string, keys: { p256dh: string, auth: string } }
 */
export const onRequestPost = async (context: Context) => {
  try {
    await verifyJwt(context.request, context.env);
  } catch (e) {
    return new Response('Unauthorized', { status: 401 });
  }

  let body: PushSubscription;
  try {
    body = await context.request.json();
  } catch {
    return new Response('Invalid JSON', { status: 400 });
  }

  if (!body.endpoint || !body.keys?.p256dh || !body.keys?.auth) {
    return new Response('Missing required fields', { status: 400 });
  }

  // Assuming a table push_subscriptions exists with columns:
  // endpoint TEXT PRIMARY KEY, p256dh TEXT NOT NULL, auth TEXT NOT NULL, user_id TEXT
  // We store the user identifier from the JWT (sub claim) if present.
  const payload = await verifyJwt(context.request, context.env);
  const userId = payload.sub ?? payload.userId ?? null;

  await context.env.DB.prepare(
    `
    INSERT INTO push_subscriptions (endpoint, p256dh, auth, user_id)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(endpoint) DO UPDATE SET
      p256dh=excluded.p256dh,
      auth=excluded.auth,
      user_id=excluded.user_id
    `
  )
    .bind(body.endpoint, body.keys.p256dh, body.keys.auth, userId)
    .run();

  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};

/**
 * DELETE /api/push/unsubscribe
 * Body: { endpoint: string }
 */
export const onRequestDelete = async (context: Context) => {
  try {
    await verifyJwt(context.request, context.env);
  } catch (e) {
    return new Response('Unauthorized', { status: 401 });
  }

  let body: { endpoint: string };
  try {
    body = await context.request.json();
  } catch {
    return new Response('Invalid JSON', { status: 400 });
  }

  if (!body.endpoint) {
    return new Response('Missing endpoint', { status: 400 });
  }

  const payload = await verifyJwt(context.request, context.env);
  const userId = payload.sub ?? payload.userId ?? null;

  await context.env.DB.prepare(
    `
    DELETE FROM push_subscriptions
    WHERE endpoint = ? AND (user_id = ? OR ? IS NULL)
    `
  )
    .bind(body.endpoint, userId, userId)
    .run();

  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};