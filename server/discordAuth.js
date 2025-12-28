
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const session = require('express-session');
const { storage } = require('./storage');

function getSession() {
    const sessionTtl = 7 * 24 * 60 * 60 * 1000; // 1 week
    return session({
        secret: process.env.SESSION_SECRET || 'fallback-secret-for-dev',
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: sessionTtl,
        },
    });
}

async function upsertUser(profile) {
    if (storage && typeof storage.upsertUser === 'function') {
        await storage.upsertUser({
            id: profile.id,
            email: profile.email,
            username: profile.username,
            discriminator: profile.discriminator,
            avatar: profile.avatar,
            verified: profile.verified,
        });
    }
}

async function getReplitDiscordAccessToken() {
    const hostname = process.env.REPLIT_CONNECTORS_HOSTNAME;
    const xReplitToken = process.env.REPL_IDENTITY 
        ? 'repl ' + process.env.REPL_IDENTITY 
        : process.env.WEB_REPL_RENEWAL 
        ? 'depl ' + process.env.WEB_REPL_RENEWAL 
        : null;

    if (!xReplitToken) {
        throw new Error('X_REPLIT_TOKEN not found');
    }

    const response = await fetch(
        'https://' + hostname + '/api/v2/connection?include_secrets=true&connector_names=discord',
        {
            headers: {
                'Accept': 'application/json',
                'X_REPLIT_TOKEN': xReplitToken
            }
        }
    );
    const data = await response.json();
    const connection = data.items?.[0];
    
    const clientId = connection?.settings?.oauth?.client_id;
    const clientSecret = connection?.settings?.oauth?.client_secret;

    if (!clientId || !clientSecret) {
        throw new Error('Discord connector credentials not found');
    }

    return { clientId, clientSecret };
}

async function setupDiscordAuth(app) {
    app.set('trust proxy', 1);
    app.use(getSession());
    app.use(passport.initialize());
    app.use(passport.session());

    let clientId = process.env.DISCORD_CLIENT_ID;
    let clientSecret = process.env.DISCORD_CLIENT_SECRET;

    // Try to get credentials from Replit Connector if not in env
    if (!clientId || !clientSecret) {
        try {
            const credentials = await getReplitDiscordAccessToken();
            clientId = credentials.clientId;
            clientSecret = credentials.clientSecret;
            console.log('✅ Using Discord credentials from Replit Connector');
        } catch (error) {
            console.warn('⚠️ Could not fetch Discord credentials from Connector:', error.message);
        }
    }

    // Check if Discord credentials are configured
    if (!clientId || !clientSecret) {
        console.warn('⚠️ Discord OAuth credentials not configured. Authentication will be disabled.');
        
        app.get('/api/login', (req, res) => {
            res.status(503).json({ error: 'Authentication not configured' });
        });
        
        app.get('/api/auth/callback', (req, res) => {
            res.redirect('/?error=auth_not_configured');
        });
        
        app.get('/api/logout', (req, res) => {
            res.redirect('/');
        });
        
        app.get('/api/auth/user', (req, res) => {
            res.status(401).json({ message: 'Authentication not configured' });
        });
        
        return;
    }

    // Configure Discord Strategy
    passport.use(new DiscordStrategy({
        clientID: clientId,
        clientSecret: clientSecret,
        callbackURL: process.env.DISCORD_REDIRECT_URI,
        scope: ['identify', 'email']
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            await upsertUser(profile);
            const user = {
                id: profile.id,
                username: profile.username,
                discriminator: profile.discriminator,
                avatar: profile.avatar,
                email: profile.email,
                verified: profile.verified,
                accessToken: accessToken,
                refreshToken: refreshToken
            };
            return done(null, user);
        } catch (error) {
            return done(error, null);
        }
    }));

    passport.serializeUser((user, done) => {
        done(null, user);
    });

    passport.deserializeUser((user, done) => {
        done(null, user);
    });

    // Routes
    app.get('/api/login', (req, res, next) => {
        const callbackURL = process.env.DISCORD_REDIRECT_URI;
        passport.authenticate('discord', { callbackURL })(req, res, next);
    });

    app.get('/api/auth/callback', (req, res, next) => {
        const callbackURL = process.env.DISCORD_REDIRECT_URI;
        passport.authenticate('discord', { 
            callbackURL,
            failureRedirect: '/' 
        })(req, res, next);
    }, (req, res) => {
        res.redirect('/dashboard');
    });

    app.get('/api/logout', (req, res) => {
        req.logout((err) => {
            if (err) {
                console.error('Logout error:', err);
            }
            res.redirect('/');
        });
    });

    app.get('/api/auth/user', (req, res) => {
        if (req.isAuthenticated()) {
            res.json(req.user);
        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }
    });
}

const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ message: 'Unauthorized' });
};

module.exports = { setupDiscordAuth, isAuthenticated };
