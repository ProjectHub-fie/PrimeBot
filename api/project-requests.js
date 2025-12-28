
import bcrypt from "bcryptjs";
import session from "express-session";
import passport from "passport";
import { storage } from "../server/storage.js";
import { insertProjectRequestSchema } from "../shared/schema.js";

// Initialize passport configuration
import "../server/auth.js";

// Middleware to check if user is authenticated
function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Authentication required" });
}

export default async function handler(req, res) {
  // Configure CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method === 'POST') {
    try {
      const validatedData = insertProjectRequestSchema.parse(req.body);
      
      // Add a default user ID for Vercel deployment
      // In production, you would implement proper authentication
      const requestData = {
        ...validatedData,
        userId: req.body.userId || 'vercel-user-' + Date.now()
      };

      const projectRequest = await storage.createProjectRequest(requestData);
      res.json(projectRequest);
    } catch (error) {
      console.error('Project request creation error:', error);
      res.status(500).json({ message: "Failed to create project request" });
    }
  } else if (req.method === 'GET') {
    try {
      const requests = await storage.getAllProjectRequests();
      res.json(requests);
    } catch (error) {
      console.error('Project requests fetch error:', error);
      res.status(500).json({ message: "Failed to fetch project requests" });
    }
  } else {
    res.status(405).json({ message: "Method not allowed" });
  }
}
