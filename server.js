const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const WebSocket = require('ws');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.use(express.json());

// --- PHASE 5: SECURITY HARDENING ---
app.use(helmet());

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many requests' }
});
app.use('/api/', apiLimiter);

// --- MONGODB CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB error:', err));

// --- MONGODB MODELS ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
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
        if (!email.includes('@')) return res.status(400).json({ success: false, message: 'Invalid email' });
        if (!username || username.trim().length < 3) {
            return res.status(400).json({ success: false, message: 'Invalid username' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ username: username.trim(), email, password: hashedPassword });
        await user.save();
        res.status(201).json({ success: true, message: 'User registered' });
    } catch (e) {
        res.status(400).json({ success: false, message: 'Username or email already exists' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
        res.json({ success: true, token, user: { id: user._id, username: user.username, email: user.email } });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const clients = new Map();
const socketToUserId = new Map();

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
app.post('/messages', saveMessage);
app.post('/api/messages', saveMessage);

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

wss.on('connection', (ws, req) => {
    const urlParams = new URL(req.url, 'http://localhost').searchParams;
    const token = urlParams.get('token');

    try {
        if (!token) throw new Error('No token');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        ws.tokenUserId = decoded.userId;
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

                const existingSocket = clients.get(userId);
                if (existingSocket && existingSocket !== ws) {
                    try {
                        existingSocket.close(4001, 'Logged in from another session');
                    } catch (_) {}
                }

                clients.set(userId, ws);
                socketToUserId.set(ws, userId);
                ws.userId = userId;
                console.log(`WS register success. userId=${userId}, activeClients=${clients.size}`);
                return;
            }

            if (!validateMessage(msg)) {
                console.warn('Invalid message dropped due to schema mismatch');
                return;
            }

            const safeFrom = msg.from.trim();
            const safeTo = msg.to.trim();
            const timestamp = Number(msg.timestamp) || Date.now();

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
            } else {
                console.warn(`WS route miss from=${safeFrom} to=${safeTo}`);
            }
        } catch (e) {
            console.error("WS Message Error:", e.message);
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'error', payload: 'Message processing failed' }));
            }
        }
    });

    ws.on('close', () => {
        detachSocket(ws);
        console.log(`WS closed for userId=${ws.userId || 'unregistered'}`);
    });

    ws.on('error', (error) => {
        console.error(`WS error userId=${ws.userId || 'unregistered'}:`, error.message);
    });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
