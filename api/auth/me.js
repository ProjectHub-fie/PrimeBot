export default async function handler(req, res) {
  // Configure CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-User-Session');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method === 'GET') {
    // Check for user session token in headers (simple stateless auth for Vercel)
    const userSession = req.headers['x-user-session'];
    
    if (userSession) {
      try {
        // Simple decode - in production use proper JWT verification
        const userData = JSON.parse(Buffer.from(userSession, 'base64').toString());
        res.json({ user: userData });
      } catch (error) {
        res.status(401).json({ message: "Invalid session" });
      }
    } else {
      res.status(401).json({ message: "Not authenticated" });
    }
  } else {
    res.status(405).json({ message: "Method not allowed" });
  }
}