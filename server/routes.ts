import type { Express } from "express";
import { createServer, type Server } from "http";
import session from "express-session";
import bcrypt from "bcryptjs";
import { storage } from "./storage";
import passport from "./auth";
import { insertProjectRequestSchema } from "@shared/schema";

// Middleware to check if user is authenticated
function requireAuth(req: any, res: any, next: any) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Authentication required" });
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Session configuration with memory store (for now)
  app.use(session({
    store: undefined, // Use memory store for now
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production', // HTTPS in production
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
  }));

  // Initialize passport
  app.use(passport.initialize());
  app.use(passport.session());

  // Auth routes
  app.post('/api/auth/register', async (req, res) => {
    try {
      const { email, password, firstName, lastName } = req.body;

      // Validate required fields
      if (!email || !password || !firstName || !lastName) {
        return res.status(400).json({ message: "All fields are required" });
      }

      // Check if user already exists
      const existingUser = await storage.getUserByEmail(email);
      if (existingUser) {
        return res.status(400).json({ message: "Email already registered" });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create user
      const { randomUUID } = await import("crypto");
      const user = await storage.upsertUser({
        id: randomUUID(),
        email,
        firstName,
        lastName,
        password: hashedPassword,
      });

      // Log user in
      req.login(user, (err) => {
        if (err) {
          return res.status(500).json({ message: "Registration successful but login failed" });
        }
        res.json({ user: { id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName } });
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ message: "Registration failed" });
    }
  });

  app.post('/api/auth/login', (req, res, next) => {
    passport.authenticate('local', (err: any, user: any, info: any) => {
      if (err) {
        return res.status(500).json({ message: "Login failed" });
      }
      if (!user) {
        return res.status(401).json({ message: info?.message || "Invalid email or password" });
      }

      req.login(user, (loginErr) => {
        if (loginErr) {
          return res.status(500).json({ message: "Login failed" });
        }
        res.json({ user: { id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName } });
      });
    })(req, res, next);
  });

  app.post('/api/auth/logout', (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ message: "Logout failed" });
      }
      res.json({ message: "Logged out successfully" });
    });
  });

  // Forgot password endpoint
  app.post('/api/auth/forgot-password', async (req, res) => {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: "Email is required" });
      }

      // Check if user exists
      const user = await storage.getUserByEmail(email);
      if (!user) {
        // Don't reveal if email exists or not for security
        return res.json({ message: "If an account with that email exists, you will receive a reset email" });
      }

      // Generate reset token
      const { randomBytes } = await import("crypto");
      const resetToken = randomBytes(32).toString('hex');
      const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour from now

      // Save reset token to user
      await storage.updateUserResetToken(user.id, resetToken, resetTokenExpiry);

      // Send reset email
      const { default: nodemailer } = await import('nodemailer');
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'dev.projecthub.fie@gmail.com',
          pass: 'exkf ymlg buup cwrh'
        }
      });

      const resetUrl = `${req.protocol}://${req.get('host')}/reset-password?token=${resetToken}`;
      
      const mailOptions = {
        from: `"ProjectHub" <dev.projecthub.fie@gmail.com>`,
        to: email,
        subject: 'Password Reset Request',
        html: `
          <h2>Password Reset Request</h2>
          <p>Hello ${user.firstName},</p>
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

      res.json({ message: "If an account with that email exists, you will receive a reset email" });
    } catch (error) {
      console.error('Forgot password error:', error);
      res.status(500).json({ message: "Failed to process password reset request" });
    }
  });

  // Reset password endpoint
  app.post('/api/auth/reset-password', async (req, res) => {
    try {
      const { token, newPassword } = req.body;

      if (!token || !newPassword) {
        return res.status(400).json({ message: "Token and new password are required" });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({ message: "Password must be at least 6 characters" });
      }

      // Find user by reset token
      const user = await storage.getUserByResetToken(token);
      if (!user || !user.resetTokenExpiry || new Date() > user.resetTokenExpiry) {
        return res.status(400).json({ message: "Invalid or expired reset token" });
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update user password and clear reset token
      await storage.resetUserPassword(user.id, hashedPassword);

      res.json({ message: "Password reset successfully" });
    } catch (error) {
      console.error('Reset password error:', error);
      res.status(500).json({ message: "Failed to reset password" });
    }
  });

  // Discord OAuth routes - enabled when Discord credentials are available
  if (process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_SECRET) {
    app.get('/api/auth/discord', passport.authenticate('discord'));
    app.get('/api/auth/discord/callback',
      passport.authenticate('discord', { failureRedirect: '/login?error=discord_failed' }),
      (req, res) => {
        res.redirect('/request-project?login=success');
      }
    );
  }

  // Get current user
  app.get('/api/auth/me', (req, res) => {
    if (req.isAuthenticated()) {
      const user = req.user as any;
      res.json({ user: { id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName } });
    } else {
      res.status(401).json({ message: "Not authenticated" });
    }
  });

  // Contact form endpoint
  app.post('/api/contact', async (req, res) => {
    try {
      const { name, email, subject, message } = req.body;

      // Import nodemailer
      const { default: nodemailer } = await import('nodemailer');

      // Create transporter using Gmail SMTP
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'dev.projecthub.fie@gmail.com',
          pass: 'exkf ymlg buup cwrh' // App password, not regular password
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
  });

  // Project request routes
  app.post('/api/project-requests', requireAuth, async (req, res) => {
    try {
      const user = req.user as any;
      const validatedData = insertProjectRequestSchema.parse({
        ...req.body,
        userId: user.id
      });

      const projectRequest = await storage.createProjectRequest(validatedData);
      res.json(projectRequest);
    } catch (error) {
      console.error('Project request creation error:', error);
      res.status(500).json({ message: "Failed to create project request" });
    }
  });

  app.get('/api/project-requests', requireAuth, async (req, res) => {
    try {
      const user = req.user as any;
      const requests = await storage.getProjectRequests(user.id);
      res.json(requests);
    } catch (error) {
      console.error('Project requests fetch error:', error);
      res.status(500).json({ message: "Failed to fetch project requests" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}