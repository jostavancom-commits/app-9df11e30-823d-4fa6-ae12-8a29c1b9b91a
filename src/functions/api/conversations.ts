import { verify } from 'jsonwebtoken';

export async function onRequest(context) {
  const { request, env } = context;
  const { DB, JWT_SECRET } = env;

  // --- Auth ---
  const authHeader = request.headers.get('Authorization') ?? '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }
  let payload;
  try {
    payload = verify(token, JWT_SECRET.toString());
  } catch (_) {
    return new Response(JSON.stringify({ error: 'Invalid token' }), { status: 401 });
  }
  const userId = payload.sub; // assume subject holds the user id

  // --- GET: list conversations ---
  if (request.method === 'GET') {
    const stmt = DB.prepare(`
      SELECT
        c.id,
        c.type,
        c.name,
        c.created_at,
        (
          SELECT m.content
          FROM messages m
          WHERE m.conversation_id = c.id
          ORDER BY m.created_at DESC
          LIMIT 1
        ) AS last_message,
        (
          SELECT m.created_at
          FROM messages m
          WHERE m.conversation_id = c.id
          ORDER BY m.created_at DESC
          LIMIT 1
        ) AS last_message_at
      FROM conversations c
      JOIN conversation_members cm ON c.id = cm.conversation_id
      WHERE cm.user_id = ?
      ORDER BY c.updated_at DESC
    `);
    const { results } = await stmt.bind(userId).all();
    return new Response(JSON.stringify(results), { status: 200 });
  }

  // --- POST: create conversation ---
  if (request.method === 'POST') {
    let body;
    try {
      body = await request.json();
    } catch (_) {
      return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400 });
    }
    const { type, participantIds, name } = body;
    if (!type || !participantIds || !Array.isArray(participantIds)) {
      return new Response(JSON.stringify({ error: 'Invalid payload' }), { status: 400 });
    }

    // Ensure the requester is part of the conversation
    const allIds = Array.from(new Set([userId, ...participantIds]));

    if (type === 'direct' && allIds.length !== 2) {
      return new Response(JSON.stringify({ error: 'Direct conversation must involve exactly two users' }), { status: 400 });
    }
    if (type === 'group' && (typeof name !== 'string' || name.trim() === '')) {
      return new Response(JSON.stringify({ error: 'Group conversation requires a non‑empty name' }), { status: 400 });
    }

    await DB.exec('BEGIN');
    try {
      // Insert conversation
      const convStmt = DB.prepare(`
        INSERT INTO conversations (type, name, created_at, updated_at)
        VALUES (?, ?, datetime('now'), datetime('now'))
      `);
      const convResult = await convStmt.bind(type, type === 'group' ? name : null).run();
      const conversationId = convResult.meta.last_row_id;

      // Insert memberships
      const memberStmt = DB.prepare(`
        INSERT INTO conversation_members (conversation_id, user_id, joined_at)
        VALUES (?, ?, datetime('now'))
      `);
      for (const uid of allIds) {
        await memberStmt.bind(conversationId, uid).run();
      }

      await DB.exec('COMMIT');
      return new Response(
        JSON.stringify({
          id: conversationId,
          type,
          name: type === 'group' ? name : null,
        }),
        { status: 201 }
      );
    } catch (e) {
      await DB.exec('ROLLBACK');
      return new Response(JSON.stringify({ error: 'Failed to create conversation' }), { status: 500 });
    }
  }

  // --- Fallback ---
  return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405 });
}