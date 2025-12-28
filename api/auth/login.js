export default async function handler(req, res) {
  // Configure CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method === 'POST') {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    // Simple demo validation - in production use proper auth
    if (email && password) {
      const userData = {
        id: 'user-' + Date.now(),
        email: email,
        firstName: email.split('@')[0],
        lastName: 'User'
      };
      
      // Create a simple session token for stateless authentication
      const sessionToken = Buffer.from(JSON.stringify(userData)).toString('base64');
      
      res.setHeader('X-User-Session', sessionToken);
      res.json({
        user: userData,
        sessionToken: sessionToken
      });
    } else {
      res.status(401).json({ message: "Invalid email or password" });
    }
  } else {
    res.status(405).json({ message: "Method not allowed" });
  }
}