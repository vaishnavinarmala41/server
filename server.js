const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const path = require('path');
const WebSocket = require('ws');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

// --- PHASE 5: SECURITY HARDENING ---
app.use(helmet());

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many requests' }
});
app.use('/api/', apiLimiter);

const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || process.env.JWT_SECRET;
const ADMIN_TOKEN_TTL = process.env.ADMIN_TOKEN_TTL || '8h';

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many admin requests' }
});
app.use('/admin', adminLimiter);
app.use('/admin', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
});

function isValidEmail(email) {
    return typeof email === 'string' && email.includes('@') && email.length <= 254;
}

function isValidPassword(password) {
    return typeof password === 'string' && password.length >= 6 && password.length <= 128;
}

function sanitizePagination(value, fallback, max) {
    const parsed = Number.parseInt(value, 10);
    if (Number.isNaN(parsed) || parsed <= 0) return fallback;
    return Math.min(parsed, max);
}

function isValidObjectId(id) {
    return mongoose.Types.ObjectId.isValid(id);
}

// --- MONGODB CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB error:', err));

// --- MONGODB MODELS ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user', index: true },
    isBanned: { type: Boolean, default: false, index: true },
    bannedAt: { type: Date, default: null },
    bannedReason: { type: String, default: null },
    lastLoginAt: { type: Date, default: null },
    publicKey: { type: String },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const MessageSchema = new mongoose.Schema(
    {
        from: { type: String, required: true, trim: true },
        to: { type: String, required: true, trim: true },
        message: { type: String, required: true },
        timestamp: { type: Number, required: true }
    },
    { versionKey: false }
);
MessageSchema.index({ from: 1, to: 1, timestamp: 1 });
const Message = mongoose.model('Message', MessageSchema);

// --- AUTH ROUTES ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!isValidEmail(email)) return res.status(400).json({ success: false, message: 'Invalid email' });
        if (!username || username.trim().length < 3) {
            return res.status(400).json({ success: false, message: 'Invalid username' });
        }
        if (!isValidPassword(password)) {
            return res.status(400).json({ success: false, message: 'Password must be 8-128 chars' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ username: username.trim(), email, password: hashedPassword });
        await user.save();
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
        res.status(201).json({
            success: true,
            message: 'User registered',
            token,
            user: { id: user._id, username: user.username, email: user.email, role: user.role }
        });
    } catch (e) {
        res.status(400).json({ success: false, message: 'Username or email already exists' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!isValidEmail(email) || !isValidPassword(password)) {
            return res.status(400).json({ success: false, message: 'Invalid credentials format' });
        }
        const user = await User.findOne({ email });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        if (user.isBanned) {
            return res.status(403).json({ success: false, message: 'Account is banned' });
        }
        user.lastLoginAt = new Date();
        await user.save();
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: { id: user._id, username: user.username, email: user.email, role: user.role }
        });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

function extractBearerToken(req) {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) return null;
    return auth.slice(7).trim();
}

function signAdminToken(adminUser) {
    return jwt.sign(
        { adminId: adminUser._id.toString(), role: adminUser.role, type: 'admin' },
        ADMIN_JWT_SECRET,
        { expiresIn: ADMIN_TOKEN_TTL }
    );
}

async function verifyAdminToken(req, res, next) {
    try {
        const token = extractBearerToken(req);
        if (!token) {
            return res.status(401).json({ success: false, message: 'Missing admin token' });
        }

        const payload = jwt.verify(token, ADMIN_JWT_SECRET);
        if (payload.type !== 'admin' || payload.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Admin access required' });
        }

        const admin = await User.findById(payload.adminId).select('_id role username email isBanned').lean();
        if (!admin || admin.role !== 'admin' || admin.isBanned) {
            return res.status(403).json({ success: false, message: 'Admin account not authorized' });
        }

        req.admin = admin;
        return next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Invalid or expired admin token' });
    }
}

app.post('/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!isValidEmail(email) || !isValidPassword(password)) {
            return res.status(400).json({ success: false, message: 'Invalid credentials format' });
        }

        const admin = await User.findOne({ email, role: 'admin' });
        if (!admin || !await bcrypt.compare(password, admin.password)) {
            return res.status(401).json({ success: false, message: 'Invalid admin credentials' });
        }
        if (admin.isBanned) {
            return res.status(403).json({ success: false, message: 'Admin account is banned' });
        }

        admin.lastLoginAt = new Date();
        await admin.save();

        const token = signAdminToken(admin);
        return res.json({
            success: true,
            token,
            admin: { id: admin._id, username: admin.username, email: admin.email, role: admin.role }
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Admin login failed' });
    }
});

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const clients = new Map();
const socketToUserId = new Map();
const adminMonitors = new Set();
const connectionLogs = [];

function pushConnectionLog(event, userId, extra = {}) {
    connectionLogs.push({
        event,
        userId,
        timestamp: Date.now(),
        ...extra
    });
    if (connectionLogs.length > 500) {
        connectionLogs.splice(0, connectionLogs.length - 500);
    }
}

function broadcastMonitorSnapshot() {
    if (!adminMonitors.size) return;
    const payload = JSON.stringify({
        type: 'monitor_snapshot',
        connectedUsers: Array.from(clients.keys()),
        activeConnections: clients.size,
        connectionLogs: connectionLogs.slice(-50)
    });

    for (const ws of adminMonitors) {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(payload);
        }
    }
}

const getConversationMessages = async (req, res) => {
    try {
        const user1 = (req.query.user1 || '').trim();
        const user2 = (req.query.user2 || '').trim();

        if (!user1 || !user2) {
            return res.status(400).json({
                success: false,
                message: 'user1 and user2 are required query params'
            });
        }

        const messages = await Message.find({
            $or: [
                { from: user1, to: user2 },
                { from: user2, to: user1 }
            ]
        })
            .sort({ timestamp: 1 })
            .select('from to message timestamp -_id')
            .lean();

        return res.json(messages);
    } catch (error) {
        console.error('GET /messages failed:', error.message);
        return res.status(500).json({
            success: false,
            message: 'Failed to fetch messages'
        });
    }
};

const getAllUserMessages = async (req, res) => {
    try {
        const userId = (req.query.userId || '').trim();

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'userId is a required query param'
            });
        }

        const messages = await Message.find({
            $or: [
                { from: userId },
                { to: userId }
            ]
        })
            .sort({ timestamp: 1 })
            .select('from to message timestamp -_id')
            .lean();

        return res.json(messages);
    } catch (error) {
        console.error('GET /messages/all failed:', error.message);
        return res.status(500).json({
            success: false,
            message: 'Failed to fetch all user messages'
        });
    }
};

const saveMessage = async (req, res) => {
    try {
        const from = (req.body.from || '').trim();
        const to = (req.body.to || '').trim();
        const message = typeof req.body.message === 'string' ? req.body.message : '';
        const timestamp = Number(req.body.timestamp);

        if (!from || !to || !message || Number.isNaN(timestamp)) {
            return res.status(400).json({
                success: false,
                message: 'from, to, message and numeric timestamp are required'
            });
        }

        await Message.create({ from, to, message, timestamp });
        return res.status(201).json({ success: true });
    } catch (error) {
        console.error('POST /messages failed:', error.message);
        return res.status(500).json({
            success: false,
            message: 'Failed to store message'
        });
    }
};

app.get('/messages', getConversationMessages);
app.get('/api/messages', getConversationMessages);
app.get('/messages/all', getAllUserMessages);
app.get('/api/messages/all', getAllUserMessages);
app.post('/messages', saveMessage);
app.post('/api/messages', saveMessage);

app.get('/admin/dashboard', verifyAdminToken, async (req, res) => {
    try {
        const [totalUsers, bannedUsers, adminUsers, messagesCount] = await Promise.all([
            User.countDocuments(),
            User.countDocuments({ isBanned: true }),
            User.countDocuments({ role: 'admin' }),
            Message.countDocuments()
        ]);

        const last24h = Date.now() - 24 * 60 * 60 * 1000;
        const messagesLast24h = await Message.countDocuments({ timestamp: { $gte: last24h } });

        return res.json({
            success: true,
            data: {
                totalUsers,
                bannedUsers,
                adminUsers,
                activeUsers: clients.size,
                connectedUsers: Array.from(clients.keys()),
                messagesCount,
                messagesLast24h,
                uptimeSeconds: Math.floor(process.uptime()),
                serverTime: Date.now(),
                status: 'ok'
            }
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Failed to load dashboard' });
    }
});

app.get('/admin/users', verifyAdminToken, async (req, res) => {
    try {
        const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
        const role = typeof req.query.role === 'string' ? req.query.role.trim() : '';
        const banned = typeof req.query.banned === 'string' ? req.query.banned.trim() : '';
        const page = sanitizePagination(req.query.page, 1, 100000);
        const limit = sanitizePagination(req.query.limit, 20, 100);
        const skip = (page - 1) * limit;

        const filter = {};
        if (q) {
            filter.$or = [
                { username: { $regex: q, $options: 'i' } },
                { email: { $regex: q, $options: 'i' } }
            ];
        }
        if (role === 'admin' || role === 'user') {
            filter.role = role;
        }
        if (banned === 'true' || banned === 'false') {
            filter.isBanned = banned === 'true';
        }

        const [users, total] = await Promise.all([
            User.find(filter)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .select('_id username email role isBanned bannedAt bannedReason lastLoginAt createdAt')
                .lean(),
            User.countDocuments(filter)
        ]);

        return res.json({ success: true, data: { users, page, limit, total } });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Failed to load users' });
    }
});

app.patch('/admin/users/:id/ban', verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidObjectId(id)) return res.status(400).json({ success: false, message: 'Invalid user id' });
        const banned = Boolean(req.body.banned);
        const reason = typeof req.body.reason === 'string' ? req.body.reason.trim().slice(0, 200) : null;

        const user = await User.findById(id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        if (user.role === 'admin' && user._id.toString() === req.admin._id.toString()) {
            return res.status(400).json({ success: false, message: 'Cannot ban your own admin account' });
        }

        user.isBanned = banned;
        user.bannedAt = banned ? new Date() : null;
        user.bannedReason = banned ? reason : null;
        await user.save();

        return res.json({ success: true });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Failed to update ban state' });
    }
});

app.post('/admin/users/:id/reset-password', verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidObjectId(id)) return res.status(400).json({ success: false, message: 'Invalid user id' });
        const newPassword = req.body.newPassword;
        if (!isValidPassword(newPassword)) {
            return res.status(400).json({ success: false, message: 'Password must be 8-128 chars' });
        }

        const user = await User.findById(id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        user.password = await bcrypt.hash(newPassword, 12);
        await user.save();
        return res.json({ success: true });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Failed to reset password' });
    }
});

app.delete('/admin/users/:id', verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidObjectId(id)) return res.status(400).json({ success: false, message: 'Invalid user id' });
        const user = await User.findById(id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        if (user.role === 'admin' && user._id.toString() === req.admin._id.toString()) {
            return res.status(400).json({ success: false, message: 'Cannot delete your own admin account' });
        }

        await Promise.all([
            Message.deleteMany({ $or: [{ from: user.username }, { to: user.username }] }),
            User.deleteOne({ _id: id })
        ]);

        const activeSocket = clients.get(user.username);
        if (activeSocket) {
            try { activeSocket.close(4003, 'Account deleted'); } catch (_) {}
            clients.delete(user.username);
        }
        return res.json({ success: true });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Failed to delete user' });
    }
});

app.get('/admin/messages', verifyAdminToken, async (req, res) => {
    try {
        const from = typeof req.query.from === 'string' ? req.query.from.trim() : '';
        const to = typeof req.query.to === 'string' ? req.query.to.trim() : '';
        const page = sanitizePagination(req.query.page, 1, 100000);
        const limit = sanitizePagination(req.query.limit, 50, 200);
        const skip = (page - 1) * limit;

        const filter = {};
        if (from) filter.from = from;
        if (to) filter.to = to;

        const [messages, total] = await Promise.all([
            Message.find(filter)
                .sort({ timestamp: -1 })
                .skip(skip)
                .limit(limit)
                .select('_id from to timestamp')
                .lean(),
            Message.countDocuments(filter)
        ]);

        const metadata = messages.map((m) => ({
            id: m._id,
            from: m.from,
            to: m.to,
            timestamp: m.timestamp
        }));

        return res.json({ success: true, data: { messages: metadata, page, limit, total } });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Failed to load message metadata' });
    }
});

app.delete('/admin/messages/:id', verifyAdminToken, async (req, res) => {
    try {
        if (!isValidObjectId(req.params.id)) {
            return res.status(400).json({ success: false, message: 'Invalid message id' });
        }
        const deleted = await Message.deleteOne({ _id: req.params.id });
        if (!deleted.deletedCount) {
            return res.status(404).json({ success: false, message: 'Message not found' });
        }
        return res.json({ success: true });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Failed to delete message' });
    }
});

app.get('/admin/monitor', verifyAdminToken, async (req, res) => {
    return res.json({
        success: true,
        data: {
            activeUsers: clients.size,
            connectedUsers: Array.from(clients.keys()),
            connectionLogs: connectionLogs.slice(-100)
        }
    });
});

app.get('/admin/panel', (req, res) => {
    return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

function detachSocket(ws) {
    const userId = socketToUserId.get(ws);
    if (userId) {
        clients.delete(userId);
        socketToUserId.delete(ws);
    }
}

function validateMessage(msg) {
    if (!msg || typeof msg !== 'object') return false;
    if (msg.type !== 'message') return false;
    if (typeof msg.from !== 'string' || msg.from.trim() === '') return false;
    if (typeof msg.to !== 'string' || msg.to.trim() === '') return false;
    if (typeof msg.payload !== 'string') return false;
    return true;
}

wss.on('connection', async (ws, req) => {
    const urlParams = new URL(req.url, 'http://localhost').searchParams;
    const token = urlParams.get('token');
    const adminToken = urlParams.get('adminToken');

    if (adminToken) {
        try {
            const payload = jwt.verify(adminToken, ADMIN_JWT_SECRET);
            if (payload.type !== 'admin' || payload.role !== 'admin') throw new Error('Invalid admin token');
            ws.isAdminMonitor = true;
            ws.adminId = payload.adminId;
            adminMonitors.add(ws);
            ws.send(JSON.stringify({
                type: 'monitor_snapshot',
                connectedUsers: Array.from(clients.keys()),
                activeConnections: clients.size,
                connectionLogs: connectionLogs.slice(-50)
            }));
            return;
        } catch (error) {
            ws.close(4001, 'Unauthorized admin monitor');
            return;
        }
    }

    try {
        if (!token) throw new Error('No token');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId).select('username isBanned').lean();
        if (!user || user.isBanned) throw new Error('Banned or missing user');
        ws.tokenUserId = decoded.userId;
        ws.tokenUsername = user.username;
        console.log(`WS connected. tokenUserId=${ws.tokenUserId}`);
    } catch (e) {
        console.warn('Unauthorized WebSocket connection', e.message);
        ws.terminate();
        return;
    }

    ws.on('message', async (data) => {
        try {
            const msg = JSON.parse(data.toString());

            if (msg.type === 'register') {
                const userId = typeof msg.userId === 'string' ? msg.userId.trim() : '';
                if (!userId) {
                    console.warn('Register failed: missing userId');
                    return;
                }
                if (userId !== ws.tokenUsername) {
                    console.warn(`Register failed: userId mismatch token=${ws.tokenUsername} requested=${userId}`);
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ type: 'error', payload: 'Invalid userId for token' }));
                    }
                    return;
                }

                const existingSocket = clients.get(userId);
                if (existingSocket && existingSocket !== ws) {
                    try {
                        existingSocket.close(4001, 'Logged in from another session');
                    } catch (_) {}
                }

                clients.set(userId, ws);
                socketToUserId.set(ws, userId);
                ws.userId = userId;
                console.log(`${userId} connected (active=${clients.size})`);
                pushConnectionLog('connected', userId, { active: clients.size });
                broadcastMonitorSnapshot();
                ws.send(JSON.stringify({ type: 'registered', userId }));
                return;
            }

            if (!validateMessage(msg)) {
                console.warn('Invalid message dropped due to schema mismatch');
                return;
            }

            const registeredUserId = socketToUserId.get(ws);
            if (!registeredUserId) {
                console.warn('Message dropped: socket not registered yet');
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'error', payload: 'Register first' }));
                }
                return;
            }

            const safeFrom = msg.from.trim();
            const safeTo = msg.to.trim();
            const timestamp = Number(msg.timestamp) || Date.now();

            if (safeFrom !== registeredUserId) {
                console.warn(`Message dropped: sender mismatch from=${safeFrom} registered=${registeredUserId}`);
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'error', payload: 'Sender mismatch' }));
                }
                return;
            }

            const dbMessage = new Message({
                from: safeFrom,
                to: safeTo,
                message: msg.payload,
                timestamp
            });
            await dbMessage.save();

            const target = clients.get(safeTo);
            if (target && target.readyState === WebSocket.OPEN) {
                target.send(JSON.stringify({
                    type: 'message',
                    from: safeFrom,
                    to: safeTo,
                    payload: msg.payload,
                    timestamp
                }));
                console.log(`WS route ok from=${safeFrom} to=${safeTo}`);
                pushConnectionLog('message_routed', safeFrom, { to: safeTo });
                broadcastMonitorSnapshot();
            } else {
                console.warn(`WS route miss from=${safeFrom} to=${safeTo}`);
                pushConnectionLog('route_miss', safeFrom, { to: safeTo });
                broadcastMonitorSnapshot();
            }
        } catch (e) {
            console.error("WS Message Error:", e.message);
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'error', payload: 'Message processing failed' }));
            }
        }
    });

    ws.on('close', () => {
        if (ws.isAdminMonitor) {
            adminMonitors.delete(ws);
            return;
        }
        const closedUserId = socketToUserId.get(ws) || ws.userId || 'unregistered';
        detachSocket(ws);
        pushConnectionLog('disconnected', closedUserId, { active: clients.size });
        broadcastMonitorSnapshot();
        console.log(`WS closed for userId=${closedUserId}`);
    });

    ws.on('error', (error) => {
        if (ws.isAdminMonitor) {
            adminMonitors.delete(ws);
            return;
        }
        const erroredUserId = socketToUserId.get(ws) || ws.userId || 'unregistered';
        pushConnectionLog('socket_error', erroredUserId, { message: error.message });
        broadcastMonitorSnapshot();
        console.error(`WS error userId=${erroredUserId}:`, error.message);
    });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
