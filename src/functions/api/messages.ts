export const onRequest = async (context) => {
  const { request, env, params } = context;
  const { pathname } = new URL(request.url);
  const method = request.method;

  // Helper: verify JWT and return payload
  const verifyJwt = async (token) => {
    if (!env.JWT_SECRET) throw new Error('JWT_SECRET not configured');
    return new Promise((resolve, reject) => {
      require('jsonwebtoken').verify(token, env.JWT_SECRET, (err, payload) => {
        if (err) reject(err);
        else resolve(payload);
      });
    });
  };

  // GET /api/messages/:conversationId
  if (method === 'GET' && pathname.startsWith('/api/messages/')) {
    const conversationId = params.conversationId;
    if (!conversationId) {
      return new Response(JSON.stringify({ error: 'Missing conversationId' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    try {
      const stmt = env.DB.prepare(
        'SELECT id, conversationId, senderId, content, timestamp FROM messages WHERE conversationId = ? ORDER BY timestamp ASC'
      );
      const { results } = await stmt.bind(conversationId).all();
      return new Response(JSON.stringify(results), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Failed to fetch messages', details: e.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  // POST /api/messages
  if (method === 'POST' && pathname === '/api/messages') {
    let payload;
    try {
      payload = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const { conversationId, content } = payload;
    if (!conversationId || typeof conversationId !== 'string') {
      return new Response(JSON.stringify({ error: 'Missing or invalid conversationId' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    if (!content || typeof content !== 'string') {
      return new Response(JSON.stringify({ error: 'Missing or invalid content' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Auth: Expect Authorization: Bearer <token>
    const authHeader = request.headers.get('Authorization');
    let senderId = null;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      try {
        const jwtPayload = await verifyJwt(token);
        // Assuming JWT payload contains sub as user id
        senderId = jwtPayload.sub || null;
      } catch {
        return new Response(JSON.stringify({ error: 'Invalid or expired token' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } else {
      return new Response(JSON.stringify({ error: 'Missing Authorization header' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const timestamp = new Date().toISOString();

    try {
      // Insert message into D1
      const insertStmt = env.DB.prepare(
        'INSERT INTO messages (conversationId, senderId, content, timestamp) VALUES (?, ?, ?, ?)'
      );
      await insertStmt.bind(conversationId, senderId, content, timestamp).run();

      // Retrieve the inserted message to broadcast (including generated id)
      const selectStmt = env.DB.prepare(
        'SELECT id, conversationId, senderId, content, timestamp FROM messages WHERE rowid = last_insert_rowid()'
      );
      const { results } = await selectStmt.first();
      const message = results;

      // Broadcast via Durable Object (binding: CHATHUB)
      // Assume the Durable Object has a method `broadcast(message)`
      const stub = env.CHATHUB.idFromName(conversationId);
      await stub.broadcast(message);

      return new Response(JSON.stringify(message), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Failed to store message', details: e.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  // Fallback for unsupported routes/methods
  return new Response(JSON.stringify({ error: 'Not Found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' },
  });
};