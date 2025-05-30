require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { google } = require('googleapis');
const path = require('path');
const { User, Site, syncDatabase } = require('./database'); // Import DB models

const app = express();
const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(express.json()); // For parsing application/json
app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // Set to false, login will init session
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        maxAge: 24 * 60 * 60 * 1000 * 7 // 7 days
    }
}));
app.use(passport.initialize());
app.use(passport.session());

// --- Passport Configuration ---
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findByPk(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL,
    scope: [
        'profile',
        'email',
        'https://www.googleapis.com/auth/drive.readonly' // Essential scope
    ],
    accessType: 'offline', // Request refresh token
    prompt: 'consent'      // Force prompt for consent to ensure refresh token is issued
},
async (accessToken, refreshToken, profile, done) => {
    try {
        const [user, created] = await User.findOrCreate({
            where: { googleId: profile.id },
            defaults: {
                email: profile.emails[0].value,
                displayName: profile.displayName,
                accessToken: accessToken,
                refreshToken: refreshToken || null, // Store refresh token
            }
        });

        if (!created) { // User exists, update tokens
            user.accessToken = accessToken;
            if (refreshToken) user.refreshToken = refreshToken; // Update refresh token if a new one is provided
            await user.save();
        }
        return done(null, user);
    } catch (err) {
        return done(err, null);
    }
}));

// --- Helper: Authentication Middleware ---
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ message: 'User not authenticated. Please login.' });
}

// --- Helper: Get OAuth2Client with current tokens ---
async function getOAuth2Client(user) {
    const oauth2Client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        process.env.CALLBACK_URL
    );
    oauth2Client.setCredentials({
        access_token: user.accessToken,
        refresh_token: user.refreshToken,
    });

    // Check if access token is expired and refresh if necessary
    if (oauth2Client.isTokenExpiring()) {
        try {
            console.log(`Token for user ${user.email} is expiring, attempting refresh...`);
            const { credentials } = await oauth2Client.refreshAccessToken();
            oauth2Client.setCredentials(credentials);
            user.accessToken = credentials.access_token;
            // If a new refresh token is issued, update it (though rare after first grant)
            if (credentials.refresh_token) {
                user.refreshToken = credentials.refresh_token;
            }
            await user.save();
            console.log(`Token for user ${user.email} refreshed successfully.`);
        } catch (refreshError) {
            console.error(`Failed to refresh token for user ${user.email}:`, refreshError.message);
            // If refresh fails, the user might need to re-authenticate
            // This could happen if the refresh token is revoked or invalid
            throw new Error('Failed to refresh access token. Please re-authenticate.');
        }
    }
    return oauth2Client;
}


// --- Auth Routes ---
app.get('/auth/google',
    passport.authenticate('google'));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login-failed.html' }), // You'll need a login-failed.html
    (req, res) => {
        res.redirect('/dashboard.html'); // Or wherever your main app page is
    }
);

app.get('/auth/logout', (req, res, next) => {
    req.logout(err => {
        if (err) { return next(err); }
        req.session.destroy(() => {
            res.clearCookie('connect.sid'); // Clear the session cookie
            res.json({ message: 'Logged out successfully' });
        });
    });
});

app.get('/api/me', ensureAuthenticated, (req, res) => {
    res.json({
        id: req.user.id,
        displayName: req.user.displayName,
        email: req.user.email
    });
});

// --- API Routes for Drive Interaction & Site Management ---
app.get('/api/drive/folders', ensureAuthenticated, async (req, res) => {
    try {
        const oauth2Client = await getOAuth2Client(req.user);
        const drive = google.drive({ version: 'v3', auth: oauth2Client });

        const response = await drive.files.list({
            q: "mimeType='application/vnd.google-apps.folder' and trashed=false and 'me' in owners", // Only folders owned by user
            fields: 'files(id, name, webViewLink, capabilities)',
            spaces: 'drive',
            pageSize: 100
        });

        // Filter for folders the user can share (important for DriveToWeb functionality)
        const sharableFolders = response.data.files.filter(folder => folder.capabilities.canShare);
        res.json(sharableFolders);

    } catch (error) {
        console.error('Error listing folders:', error.message);
        if (error.message.includes('re-authenticate')) {
            return res.status(401).json({ message: error.message, action: 're-authenticate' });
        }
        res.status(500).json({ message: 'Error fetching folders from Google Drive.' });
    }
});

app.post('/api/sites/publish', ensureAuthenticated, async (req, res) => {
    const { folderId, folderName, siteName } = req.body;
    if (!folderId || !siteName) {
        return res.status(400).json({ message: 'Folder ID and Site Name are required.' });
    }
    if (!/^[a-zA-Z0-9-]+$/.test(siteName)) {
        return res.status(400).json({ message: 'Site name can only contain letters, numbers, and hyphens.' });
    }

    try {
        // Check if siteName (subdomain) already exists
        const existingSite = await Site.findOne({ where: { siteName: siteName.toLowerCase() } });
        if (existingSite) {
            return res.status(409).json({ message: `Site name "${siteName}" is already taken. Please choose another.` });
        }

        // TODO: Add check for "Anyone with the link can view" for the folderId
        // This is complex and involves checking permissions. For now, we'll trust the user.
        // You'd use drive.permissions.list({ fileId: folderId })

        const newSite = await Site.create({
            userId: req.user.id,
            siteName: siteName.toLowerCase(),
            driveFolderId: folderId,
            driveFolderName: folderName,
        });

        // For local testing, the URL will be path-based
        const siteUrl = `http://${process.env.APP_DOMAIN}/site/${newSite.siteName}`;
        // In production, it would be: `https://${newSite.siteName}.${YOUR_PRODUCTION_ROOT_DOMAIN}`

        res.status(201).json({
            message: 'Site published successfully!',
            site: newSite,
            siteUrl: siteUrl
        });
    } catch (error) {
        console.error('Error publishing site:', error);
        if (error.name === 'SequelizeUniqueConstraintError') {
             return res.status(409).json({ message: `Site name "${siteName}" is already taken. Please choose another.` });
        }
        res.status(500).json({ message: 'Failed to publish site.' });
    }
});

app.get('/api/sites', ensureAuthenticated, async (req, res) => {
    try {
        const sites = await Site.findAll({ where: { userId: req.user.id } });
        res.json(sites.map(site => ({
            ...site.toJSON(),
            // Adjust URL based on environment for display
            siteUrl: process.env.NODE_ENV === 'production'
                ? `https://${site.siteName}.o4dhome.odoo.com` // Your actual production domain
                : `http://${process.env.APP_DOMAIN}/site/${site.siteName}`
        })));
    } catch (error) {
        console.error('Error fetching user sites:', error);
        res.status(500).json({ message: 'Failed to fetch sites.' });
    }
});

// --- Public Site Serving Route (Path-based for local, adaptable for subdomains) ---
app.get('/site/:siteName/*', async (req, res, next) => {
    const siteName = req.params.siteName.toLowerCase();
    let filePath = req.params[0] || 'index.html'; // Default to index.html
    if (filePath.endsWith('/')) {
        filePath += 'index.html';
    }

    try {
        const siteConfig = await Site.findOne({ where: { siteName }, include: User });
        if (!siteConfig) {
            return res.status(404).send('Site not found.');
        }

        const siteOwner = siteConfig.User;
        if (!siteOwner) {
            return res.status(500).send('Site owner not found. Configuration error.');
        }
        
        const oauth2Client = await getOAuth2Client(siteOwner);
        const drive = google.drive({ version: 'v3', auth: oauth2Client });

        // Find the file within the specified folder
        const listResponse = await drive.files.list({
            q: `'${siteConfig.driveFolderId}' in parents and name='${path.basename(filePath)}' and trashed=false`,
            fields: 'files(id, name, mimeType, webViewLink, size)',
            corpora: 'user', // Important for files shared with the user
            supportsAllDrives: true,
            includeItemsFromAllDrives: true,
            // path.dirname(filePath) should be handled by Drive API structure if nested,
            // but for simplicity we are looking for basename in root of selected folder.
            // For nested paths, you'd need to recursively find folder IDs or use full path queries.
            // Let's simplify: for now, we assume flat structure or only `index.html` in subdirs.
            // A more robust solution would traverse the path.
        });

        if (!listResponse.data.files || listResponse.data.files.length === 0) {
            // Try to find index.html if filePath was a directory
            if (filePath.endsWith('index.html')) { // Already tried index.html
                 return res.status(404).send(`File not found: ${filePath}`);
            }
            // If path was 'foo/' we try 'foo/index.html', if it was 'foo' we try 'foo/index.html'
            // This logic is simplified here.
            return res.status(404).send(`File not found: ${filePath}`);
        }

        const file = listResponse.data.files[0];

        // Security check for very large files (optional)
        const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
        if (parseInt(file.size) > MAX_FILE_SIZE) {
            return res.status(413).send('File too large to serve.');
        }

        const fileResponse = await drive.files.get(
            { fileId: file.id, alt: 'media' },
            { responseType: 'stream' }
        );

        res.setHeader('Content-Type', file.mimeType || 'application/octet-stream');
        res.setHeader('Cache-Control', 'public, max-age=300'); // Cache for 5 minutes
        fileResponse.data.pipe(res);

    } catch (error) {
        console.error(`Error serving file ${filePath} for site ${siteName}:`, error.message);
        if (error.message.includes('re-authenticate') || (error.response && error.response.status === 401)) {
            res.status(503).send('Service temporarily unavailable (auth issue with site owner).');
        } else if (error.code === 404 || (error.response && error.response.status === 404)) {
            res.status(404).send(`File not found in Drive: ${filePath}`);
        } else {
            res.status(500).send('Error serving file from Google Drive.');
        }
    }
});


// --- Static File Serving for Dashboard UI ---
// Create a 'public' folder and put your dashboard.html, login-failed.html etc. in it
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html')); // Main landing page
});

// --- Start Server ---
async function startServer() {
    await syncDatabase(); // Ensure DB is synced before starting server
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
        console.log(`Ensure your Google OAuth Redirect URI is: http://localhost:${PORT}/auth/google/callback`);
    });
}

startServer();