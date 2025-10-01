Project Context: We are building a chatting app like WhatsApp/Telegram. Backend is Node.js (with Express) acting as an API gateway to Supabase. All Supabase interactions (auth, DB queries, realtime, storage) happen here—frontend connects only to this backend. Supabase handles JWT/sessions, so use supabase-js with service role key for secure ops.

Key Rules:
1. Use Express for routing; implement endpoints from this list: [Paste the full endpoint list here or reference it].
2. Supabase Integration: Initialize supabase = createClient(url, service_key); Proxy requests (e.g., for /api/auth/login, call supabase.auth.signInWithPassword, return result).
3. Auth Middleware: For protected routes, verify JWT via supabase.auth.getUser(req.headers.authorization).
4. Real-Time: Use Socket.IO for WebSockets; on connect, auth socket with token, then relay Supabase realtime events (e.g., channel subscriptions for chats).
5. Data Formats: Respond with JSON { data, error }; validate inputs with Joi/Zod.
6. For Each Endpoint: When I ask to develop an endpoint, generate the code, then provide a "frontend integration prompt" for Lovable AI. The prompt should include: API method/path, req params/body example, response example, error cases, and WebSocket ties if real-time.
7. Security: RLS via Supabase; add rate limiting.
8. No Client Exposure: Never return Supabase keys or direct DB access.

Example: If building /api/messages/send, code it, then give prompt like: "Build a React MessageInput component that POSTs to /api/messages/send with { chatId, text }, handles response, and listens for 'new_message' via WebSocket."

Always generate complete, testable code based on this.