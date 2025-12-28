
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
      const { name, email, subject, message } = req.body;

      if (!name || !email || !subject || !message) {
        return res.status(400).json({ message: "All fields are required" });
      }

      // Import nodemailer
      const nodemailer = await import('nodemailer');

      // Create transporter using Gmail SMTP
      const transporter = nodemailer.default.createTransporter({
        service: 'gmail',
        auth: {
          user: 'dev.projecthub.fie@gmail.com',
          pass: 'exkf ymlg buup cwrh'
        }
      });

      // Email content
      const mailOptions = {
        from: `"Contact Form" <dev.projecthub.fie@gmail.com>`,
        to: 'dev.projecthub.fie@gmail.com',
        subject: `New Contact Form: ${subject}`,
        html: `
          <h2>New Contact Form Submission</h2>
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Subject:</strong> ${subject}</p>
          <p><strong>Message:</strong></p>
          <p>${message.replace(/\n/g, '<br>')}</p>
          <hr>
          <p><em>Sent from ProjectHub contact form</em></p>
        `,
        replyTo: email
      };

      // Send email
      await transporter.sendMail(mailOptions);

      res.json({ message: "Contact form submitted successfully" });
    } catch (error) {
      console.error('Contact form error:', error);
      res.status(500).json({ message: "Failed to submit contact form" });
    }
  } else {
    res.status(405).json({ message: "Method not allowed" });
  }
}
