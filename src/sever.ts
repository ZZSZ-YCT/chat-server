import WebSocket, { WebSocketServer } from 'ws';
import express from 'express';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import argon2 from 'argon2';
import { v4 as uuidv4 } from 'uuid';
import http from 'http';
import { PrismaClient } from '@prisma/client';

// 默认配置（可通过环境变量覆盖）
const JWT_SECRET = process.env.JWT_SECRET || 'wIebVIFUSBPjcm5nJ7IjNZddNl04CfIOTZIaBHlSn1mWvPim9l';
const PORT = process.env.PORT || 8080;
// 当项目在 docker 内运行时，数据库连接使用容器名作为 host，这里设默认值，若在本地运行可自行覆盖
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://postgres:postgres@postgres:5432/chatdb?schema=public';

const prisma = new PrismaClient();

// 自动注册管理员（用户名：admin；密码为 10 位随机字符串，存入数据库并使用 argon2 加密）
async function autoRegisterAdmin() {
    const adminUser = await prisma.adminUser.findUnique({ where: { username: 'admin' } });
    if (!adminUser) {
        const randomPassword = generateRandomPassword(10);
        const passwordHash = await argon2.hash(randomPassword);
        await prisma.adminUser.create({
            data: { username: 'admin', passwordHash }
        });
        console.log(`自动注册管理员成功。用户名：admin，密码：${randomPassword}`);
    }
}
function generateRandomPassword(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}
autoRegisterAdmin().catch(err => console.error('自动注册管理员出错：', err));

/**
 * 内存中维护在线房间（所有聊天记录与用户数据均存入 PostgreSQL）
 */
interface ChatClient {
    ws: WebSocket;
    nickname: string;
}
interface ChatRoom {
    clients: Set<ChatClient>;
}
const rooms: Map<string, ChatRoom> = new Map();

// 使用 Express 与 HTTP 服务器统一管理 HTTP 与 WebSocket
const app = express();
app.use(bodyParser.json());
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

/**
 * JWT 鉴权中间件（管理员接口统一使用）
 */
function adminAuthMiddleware(req: express.Request, res: express.Response, next: express.NextFunction) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: '缺少授权头' });
    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: '缺少 token' });
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        (req as any).admin = payload;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'token 无效' });
    }
}

/**
 * 管理员登录接口
 * POST /admin/login
 * 请求体：{ "username": "xxx", "password": "xxx" }
 * 返回：{ "token": "xxx" }
 */
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ error: '必须提供用户名和密码' });
    const adminUser = await prisma.adminUser.findUnique({ where: { username } });
    if (!adminUser)
        return res.status(401).json({ error: '凭据错误' });
    try {
        const valid = await argon2.verify(adminUser.passwordHash, password);
        if (!valid) return res.status(401).json({ error: '凭据错误' });
        const token = jwt.sign({ username }, JWT_SECRET, { algorithm: 'HS256' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: '内部错误' });
    }
});

/**
 * 管理员注册接口
 * POST /admin/register
 * 需要 Bearer 鉴权
 * 请求体：{ "username": "xxx", "password": "xxx" }
 * 若用户存在则更新密码，否则创建新用户。
 */
app.post('/admin/register', adminAuthMiddleware, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ error: '必须提供用户名和密码' });
    try {
        const passwordHash = await argon2.hash(password);
        await prisma.adminUser.upsert({
            where: { username },
            update: { passwordHash },
            create: { username, passwordHash }
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: '内部错误' });
    }
});

/**
 * 管理员接口：踢出用户
 * POST /admin/userControl
 * 请求体：{ "roomId": "xxx", "nickname": [ "user1", "user2" ] } 或 { "roomId": "xxx", "nickname": "all" }
 */
app.post('/admin/userControl', adminAuthMiddleware, async (req, res) => {
    const { roomId, nickname } = req.body;
    if (!roomId || !nickname)
        return res.status(400).json({ error: '必须提供 roomId 和 nickname' });
    const room = rooms.get(roomId);
    if (!room) return res.status(404).json({ error: '房间不存在' });

    let nicknames: string[] = [];
    if (nickname === 'all') {
        nicknames = Array.from(room.clients).map(c => c.nickname);
    } else if (Array.isArray(nickname)) {
        nicknames = nickname;
    } else {
        return res.status(400).json({ error: 'nickname 必须为数组或 "all"' });
    }

    let kicked = false;
    room.clients.forEach(client => {
        if (nicknames.includes(client.nickname)) {
            if (client.ws.readyState === WebSocket.OPEN) {
                client.ws.send(JSON.stringify({ type: 'system', data: 'userListReset' }));
                client.ws.close(4000, '管理员踢出');
                kicked = true;
            }
        }
    });
    if (kicked) res.json({ success: true });
    else res.status(404).json({ error: '未在房间中找到匹配的用户' });
});

/**
 * 管理员接口：删除消息
 * POST /admin/messageManagement
 * 请求体：{ "roomId": "xxx", "messageId": [ "id1", "id2" ] } 或 { "roomId": "xxx", "messageId": "all" }
 */
app.post('/admin/messageManagement', adminAuthMiddleware, async (req, res) => {
    const { roomId, messageId } = req.body;
    if (!roomId || !messageId)
        return res.status(400).json({ error: '必须提供 roomId 和 messageId' });

    if (messageId === 'all') {
        await prisma.chatMessage.deleteMany({ where: { roomId } });
    } else if (Array.isArray(messageId)) {
        await prisma.chatMessage.deleteMany({
            where: { roomId, uuid: { in: messageId } }
        });
    } else {
        return res.status(400).json({ error: 'messageId 必须为数组或 "all"' });
    }
    const room = rooms.get(roomId);
    if (room) {
        room.clients.forEach(client => {
            if (client.ws.readyState === WebSocket.OPEN) {
                client.ws.send(JSON.stringify({ type: 'system', data: 'messageReset' }));
            }
        });
    }
    res.json({ success: true });
});

/**
 * WebSocket 连接处理
 * 客户端通过 ws://<host>/<roomId> 连接（roomId 为房间标识）
 */
wss.on('connection', (ws: WebSocket, request) => {
    const url = request.url || '';
    const roomId = url.split('/')[1];
    if (!roomId) {
        ws.close(1008, '未提供房间 ID');
        return;
    }
    let room = rooms.get(roomId);
    if (!room) {
        room = { clients: new Set<ChatClient>() };
        rooms.set(roomId, room);
    }
    console.log(`新连接进入房间：${roomId}`);
    (ws as any).hasLoggedIn = false;
    (ws as any).clientData = null;

    ws.on('message', async (data: WebSocket.RawData) => {
        try {
            const msg = JSON.parse(data.toString());
            // 登录消息：格式 { type: "login", nickname: "xxx" }
            if (msg.type === 'login') {
                if (!msg.nickname) {
                    ws.send(JSON.stringify({ type: 'error', message: '登录必须提供昵称' }));
                    return;
                }
                if ((ws as any).hasLoggedIn) {
                    ws.send(JSON.stringify({ type: 'error', message: '已登录' }));
                    return;
                }
                const client: ChatClient = { ws, nickname: msg.nickname };
                room!.clients.add(client);
                (ws as any).hasLoggedIn = true;
                (ws as any).clientData = client;
                // 将用户记录入数据库（保证所有曾参与该房间的用户均被保存）
                await prisma.chatUser.upsert({
                    where: { roomId_nickname: { roomId, nickname: msg.nickname } },
                    update: {},
                    create: { roomId, nickname: msg.nickname }
                });
                ws.send(JSON.stringify({ type: 'login', success: true }));
                console.log(`客户端 ${msg.nickname} 登录到房间 ${roomId}`);
                return;
            }

            if (!(ws as any).hasLoggedIn) {
                ws.send(JSON.stringify({ type: 'error', message: '请先登录' }));
                return;
            }

            // 聊天消息：格式 { type: "message", content: "消息内容" }
            if (msg.type === 'message') {
                if (!msg.content) {
                    ws.send(JSON.stringify({ type: 'error', message: '消息内容不能为空' }));
                    return;
                }
                const client = (ws as any).clientData as ChatClient;
                const messageId = uuidv4();
                // 将消息存入数据库（每条消息都有全局唯一 UUID）
                await prisma.chatMessage.create({
                    data: {
                        uuid: messageId,
                        roomId,
                        nickname: client.nickname,
                        content: msg.content
                    }
                });
                // 向房间内所有在线客户端广播消息
                room!.clients.forEach(c => {
                    if (c.ws.readyState === WebSocket.OPEN) {
                        c.ws.send(JSON.stringify({
                            type: 'message',
                            uuid: messageId,
                            nickname: client.nickname,
                            content: msg.content
                        }));
                    }
                });
                return;
            }

            // 命令消息：{ type: "command", command: "online" } 或 { type: "command", command: "history" }
            if (msg.type === 'command') {
                if (msg.command === 'online') {
                    const onlineUsers = Array.from(room!.clients).map(c => c.nickname);
                    ws.send(JSON.stringify({ type: 'online', users: onlineUsers }));
                } else if (msg.command === 'history') {
                    const messages = await prisma.chatMessage.findMany({
                        where: { roomId },
                        orderBy: { timestamp: 'asc' }
                    });
                    ws.send(JSON.stringify({ type: 'history', messages }));
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: '未知的命令' }));
                }
                return;
            }
            ws.send(JSON.stringify({ type: 'error', message: '未知的消息类型' }));
        } catch (err) {
            console.error('处理消息出错：', err);
            ws.send(JSON.stringify({ type: 'error', message: 'JSON 格式错误' }));
        }
    });

    ws.on('close', () => {
        const client = (ws as any).clientData as ChatClient;
        if (client) {
            room!.clients.delete(client);
            console.log(`客户端 ${client.nickname} 从房间 ${roomId} 断开连接`);
        } else {
            console.log(`未登录客户端从房间 ${roomId} 断开`);
        }
    });
});

server.listen(PORT, () => {
    console.log(`服务器正在 ${PORT} 端口上运行`);
});