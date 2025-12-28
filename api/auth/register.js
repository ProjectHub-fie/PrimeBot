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
    const { email, password, firstName, lastName } = req.body;
    
    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Simple demo registration - in production use proper auth
    const userData = {
      id: 'user-' + Date.now(),
      email: email,
      firstName: firstName,
      lastName: lastName
    };
    
    // Create a simple session token for stateless authentication
    const sessionToken = Buffer.from(JSON.stringify(userData)).toString('base64');
    
    res.setHeader('X-User-Session', sessionToken);
    res.json({
      user: userData,
      sessionToken: sessionToken
    });
  } else {
    res.status(405).json({ message: "Method not allowed" });
  }
}