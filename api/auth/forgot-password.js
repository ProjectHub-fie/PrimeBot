
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
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: "Email is required" });
      }

      // Generate reset token
      const crypto = await import('crypto');
      const resetToken = crypto.randomBytes(32).toString('hex');

      // Send reset email using nodemailer
      const nodemailer = await import('nodemailer');
      
      const transporter = nodemailer.default.createTransporter({
        service: 'gmail',
        auth: {
          user: 'dev.projecthub.fie@gmail.com',
          pass: 'exkf ymlg buup cwrh'
        }
      });

      const mailOptions = {
        from: `"ProjectHub" <dev.projecthub.fie@gmail.com>`,
        to: email,
        subject: 'Password Reset Request',
        html: `
          <h2>Password Reset Request</h2>
          <p>Hello,</p>
          <p>You requested to reset your password. Use the token below to reset your password:</p>
          <p><strong>Reset Token:</strong> <code>${resetToken}</code></p>
          <p>This token will expire in 1 hour.</p>
          <p>If you didn't request this, please ignore this email.</p>
          <hr>
          <p><em>ProjectHub Security Team</em></p>
        `,
        replyTo: 'dev.projecthub.fie@gmail.com'
      };

      await transporter.sendMail(mailOptions);

      // Store the token temporarily (in production, use a database)
      // For demo purposes, we'll just return success
      res.json({ message: "If an account with that email exists, you will receive a reset email" });
    } catch (error) {
      console.error('Forgot password error:', error);
      res.status(500).json({ message: "Failed to process password reset request" });
    }
  } else {
    res.status(405).json({ message: "Method not allowed" });
  }
}
