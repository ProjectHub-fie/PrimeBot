import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as DiscordStrategy } from "passport-discord";
import bcrypt from "bcryptjs";
import { storage } from "./storage";
import type { User } from "@shared/schema";

// Local strategy (email/password)
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    console.log('Attempting login for email:', email);
    
    if (!email || !password) {
      return done(null, false, { message: 'Email and password are required' });
    }

    const user = await storage.getUserByEmail(email);
    if (!user || !user.password) {
      console.log('User not found or no password:', email);
      return done(null, false, { message: 'Invalid email or password' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      console.log('Invalid password for user:', email);
      return done(null, false, { message: 'Invalid email or password' });
    }

    console.log('Login successful for user:', email);
    return done(null, user);
  } catch (error) {
    console.error('Login error:', error);
    return done(error);
  }
}));


// Discord OAuth strategy - hardcoded credentials
const DISCORD_CLIENT_ID = "1410900086463926308";
const DISCORD_CLIENT_SECRET = "z7Hf45mm7_rzVrNpKUbnY9gaLZ714nle";

const getCallbackURL = () => {
  return "https://projecthub-fie.vercel.app/api/auth/discord/callback";
};

passport.use(new DiscordStrategy({
  clientID: DISCORD_CLIENT_ID,
  clientSecret: DISCORD_CLIENT_SECRET,
  callbackURL: getCallbackURL(),
  scope: ['identify', 'email']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await storage.getUserBySocialId('discord', profile.id);

    if (!user) {
      user = await storage.upsertUser({
        id: profile.id,
        discordId: profile.id,
        email: profile.email || null,
        firstName: profile.username || null,
        lastName: null,
        profileImageUrl: profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : null,
      });
    }

    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));


// Serialize user for session
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await storage.getUser(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

export default passport;