// [Added] Force Node.js to prefer IPv4 resolution to solve ENETUNREACH issues on some platforms (like Render + Supabase)
require('dns').setDefaultResultOrder('ipv4first');

const express = require('express');
const { Pool } = require('pg'); 
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
// [Added] pg-simple session store
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcrypt');
const { GoogleGenerativeAI } = require("@google/generative-ai");
const rateLimit = require('express-rate-limit');
const csrf = require('csrf');
require('dotenv').config(); 

const app = express();

app.set('trust proxy', 1); 

const PORT = process.env.PORT || 3000;

// [Modified] Initialize PostgreSQL Connection Pool
// SSL 設定：
// - 預設允許自簽憑證（適用於 Render、Heroku 等雲端平台）
// - 可透過 DB_SSL_REJECT_UNAUTHORIZED=true 強制要求有效憑證
// - 可透過 DB_SSL_REJECT_UNAUTHORIZED=false 明確允許自簽憑證
const sslConfig = (() => {
    // 如果明確指定了環境變數，使用該值
    if (process.env.DB_SSL_REJECT_UNAUTHORIZED !== undefined) {
        return { rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED === 'true' };
    }
    // 預設允許自簽憑證（適用於大多數雲端平台）
    return { rejectUnauthorized: false };
})();

// 主應用程式連線池（Supabase 使用 Supavisor/PgBouncer，Session Mode 連線數受限）
// Supabase 免費方案：直接連線 60，Pooler 200，但 Session Mode 的 pool_size 通常較小
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? sslConfig : false,
    max: 2, // Supabase Session Mode 建議使用較小的連線池（2-3 個）
    idleTimeoutMillis: 5000, // 快速釋放未使用的連線（5 秒）
    connectionTimeoutMillis: 2000, // 快速超時，避免等待
    allowExitOnIdle: false,
});

// Session store 使用同一個連線池（避免建立過多連線）
// Supabase Session Mode：每個連線獨佔一個底層連線，pool_size 限制了可用連線數
// 因此共用同一個連線池，總連線數限制在 2 個以內
const sessionPool = pool;

// 資料庫連線錯誤處理
pool.on('error', async (err) => {
    // Supabase 連線錯誤處理
    if (err.message && err.message.includes('MaxClientsInSessionMode')) {
        console.warn('Supabase 連線池已滿，請等待連線釋放或考慮使用 Transaction Mode (port 6543)');
    } else if (err.message && err.message.includes('Connection terminated')) {
        console.warn('資料庫連線終止（可能是暫時的）:', err.message);
    } else {
        console.error('資料庫連線錯誤:', err?.message || err);
        // 避免在連線錯誤時記錄到資料庫（可能造成循環）
        if (!err.message || !err.message.includes('MaxClients')) {
            await logError(err, 'Database connection error', null).catch(() => {});
        }
    }
});

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// [Modified] Session Configuration（必須在路由保護之前，才能使用 req.session）
let sessionStore;
try {
    sessionStore = new pgSession({
        pool: sessionPool, // 使用獨立的 session 連線池
        tableName: 'session',
        createTableIfMissing: true,
        pruneSessionInterval: false // 手動控制清理，避免初始化問題
    });
} catch (storeError) {
    console.warn('Session store initialization warning:', storeError?.message || storeError);
    // 如果 session store 初始化失敗，使用記憶體 store（僅開發環境）
    if (process.env.NODE_ENV !== 'production') {
        console.warn('Falling back to memory store for development');
        sessionStore = undefined;
    }
}

app.use(session({
    store: sessionStore,
    secret: (() => {
        const secret = process.env.SESSION_SECRET;
        const defaultSecret = 'sms-secret-key-pg-final-v3';
        const devSecret = 'sms-secret-key-pg-final-v3-dev-only';
        
        // 生產環境必須設定 SESSION_SECRET
        if (process.env.NODE_ENV === 'production') {
            if (!secret || secret === defaultSecret || secret === devSecret) {
                console.error('===========================================');
                console.error('錯誤: 生產環境必須設定 SESSION_SECRET 環境變數！');
                console.error('請在 .env 檔案中設定一個隨機且複雜的 SESSION_SECRET');
                console.error('可以使用命令產生: openssl rand -base64 32');
                console.error('===========================================');
                throw new Error('SESSION_SECRET environment variable is required in production');
            }
            // 驗證生產環境的 SESSION_SECRET 長度（至少 32 字元）
            if (secret.length < 32) {
                console.error('警告: 生產環境的 SESSION_SECRET 長度建議至少 32 字元');
            }
        } else {
            // 開發環境警告
            if (!secret || secret === defaultSecret || secret === devSecret) {
                console.warn('警告: SESSION_SECRET 環境變數未設定或使用預設值！');
                console.warn('請在 .env 檔案中設定一個隨機且複雜的 SESSION_SECRET');
                console.warn('可以使用命令產生: openssl rand -base64 32');
            }
        }
        return secret || devSecret;
    })(),
    resave: false,
    saveUninitialized: false,
    proxy: true, 
    cookie: { 
        maxAge: 30 * 24 * 60 * 60 * 1000, 
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
    } 
}));

// 路由保護中間件：檢查 HTML 頁面訪問權限（必須在 session 之後）
const protectHtmlPages = (req, res, next) => {
    // 允許 API 路由
    if (req.path.startsWith('/api/')) {
        return next();
    }
    
    // 允許登入頁面
    if (req.path === '/login.html' || req.path === '/login') {
        return next();
    }
    
    // 允許靜態資源（CSS、JS、圖片等）
    if (req.path.match(/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/)) {
        return next();
    }
    
    // 檢查是否需要認證的頁面（HTML 檔案或根路徑）
    if (req.path === '/' || req.path.endsWith('.html')) {
        if (!req.session || !req.session.user) {
            // 未登入，重定向到登入頁
            return res.redirect('/login.html');
        }
    }
    
    next();
};

// 應用路由保護（在靜態檔案服務之前）
app.use(protectHtmlPages);

// 管理頁面模板權限（避免僅靠前端隱藏）
// - 一般帳號：可看查詢/月曆等業務內容
// - 但不可取得「資料管理 / 後台管理」的 view HTML
app.use((req, res, next) => {
    // 只處理 views 下的 html 模板
    if (!(req.path && req.path.startsWith('/views/') && req.path.endsWith('.html'))) {
        return next();
    }

    // 已由 protectHtmlPages 保證登入（.html 需登入）；這裡再做「群組/角色」限制
    (async () => {
        const userId = req.session?.user?.id;
        const role = req.session?.user?.role;
        let isAdmin = false;
        try {
            if (userId) isAdmin = await isAdminUser(userId, pool);
        } catch (e) {
            isAdmin = false;
        }

        const deny = () =>
            res.status(403).send(
                `<div style="padding:24px;font-family:system-ui,'Noto Sans TC',sans-serif;color:#0f172a;">
                    <h3 style="margin:0 0 8px 0;">權限不足</h3>
                    <div style="color:#64748b;font-size:14px;line-height:1.6;">
                        您沒有權限存取此管理頁面。
                    </div>
                </div>`
            );

        // 後台管理：僅「系統管理群組」成員
        if (req.path === '/views/users-view.html') {
            return isAdmin ? next() : deny();
        }
        // 資料管理：系統管理群組 或 角色=manager
        if (req.path === '/views/import-view.html' || req.path === '/views/plans-view.html') {
            return (isAdmin || role === 'manager') ? next() : deny();
        }
        return next();
    })().catch(() => {
        return res.status(403).send(
            `<div style="padding:24px;font-family:system-ui,'Noto Sans TC',sans-serif;color:#0f172a;">
                <h3 style="margin:0 0 8px 0;">權限不足</h3>
                <div style="color:#64748b;font-size:14px;line-height:1.6;">
                    您沒有權限存取此管理頁面。
                </div>
            </div>`
        );
    });
});

// 靜態檔案服務
app.use(express.static(path.join(__dirname, 'public')));

// --- Admin group helpers ---
async function isAdminUser(userId, db = pool) {
    const id = userId != null ? parseInt(userId, 10) : null;
    if (!Number.isFinite(id)) return false;
    const r = await db.query(
        `SELECT 1
         FROM user_groups ug
         JOIN groups g ON g.id = ug.group_id
         WHERE ug.user_id = $1 AND g.is_admin_group = true
         LIMIT 1`,
        [id]
    );
    return (r.rows || []).length > 0;
}

// 權限檢查中間件（admin 由「系統管理群組」決定）
const requireAdmin = async (req, res, next) => {
    try {
        if (!req.session || !req.session.user) return res.status(403).json({ error: 'Denied' });
        const ok = await isAdminUser(req.session.user.id, pool);
        if (!ok) return res.status(403).json({ error: 'Denied' });
        return next();
    } catch (e) {
        return res.status(403).json({ error: 'Denied' });
    }
};

const requireAdminOrManager = async (req, res, next) => {
    try {
        if (!req.session || !req.session.user) return res.status(403).json({ error: 'Denied' });
        const role = req.session.user.role;
        if (role === 'manager') return next();
        const ok = await isAdminUser(req.session.user.id, pool);
        if (!ok) return res.status(403).json({ error: 'Denied' });
        return next();
    } catch (e) {
        return res.status(403).json({ error: 'Denied' });
    }
};

// --- Groups / record-level authorization helpers ---
async function getUserGroupIds(userId, db = pool) {
    const r = await db.query('SELECT group_id FROM user_groups WHERE user_id = $1', [userId]);
    return (r.rows || []).map(x => parseInt(x.group_id, 10)).filter(n => Number.isFinite(n));
}

async function getUserDataGroupIds(userId, db = pool) {
    const r = await db.query(
        `SELECT ug.group_id
         FROM user_groups ug
         JOIN groups g ON g.id = ug.group_id
         WHERE ug.user_id = $1 AND COALESCE(g.is_admin_group, false) = false
         ORDER BY ug.group_id ASC`,
        [userId]
    );
    return (r.rows || []).map(x => parseInt(x.group_id, 10)).filter(n => Number.isFinite(n));
}

async function getPrimaryGroupId(userId, db = pool) {
    // 主要群組：排除「系統管理群組」（避免新資料歸屬到 admin group）
    const r = await db.query(
        `SELECT ug.group_id
         FROM user_groups ug
         JOIN groups g ON g.id = ug.group_id
         WHERE ug.user_id = $1 AND COALESCE(g.is_admin_group, false) = false
         ORDER BY ug.group_id ASC
         LIMIT 1`,
        [userId]
    );
    const gid = r.rows[0]?.group_id;
    const n = gid != null ? parseInt(gid, 10) : null;
    return Number.isFinite(n) ? n : null;
}

async function isIssueEditor(userId, issueId, db = pool) {
    const uid = userId != null ? parseInt(userId, 10) : null;
    const iid = issueId != null ? parseInt(issueId, 10) : null;
    if (!Number.isFinite(uid) || !Number.isFinite(iid)) return false;
    const r = await db.query(
        "SELECT 1 FROM issue_editors WHERE issue_id = $1 AND user_id = $2 LIMIT 1",
        [iid, uid]
    );
    return (r.rows || []).length > 0;
}

async function isPlanEditorByPlanId(userId, planId, db = pool) {
    const uid = userId != null ? parseInt(userId, 10) : null;
    const pid = planId != null ? parseInt(planId, 10) : null;
    if (!Number.isFinite(uid) || !Number.isFinite(pid)) return false;
    const r = await db.query(
        "SELECT 1 FROM plan_editors WHERE plan_id = $1 AND user_id = $2 LIMIT 1",
        [pid, uid]
    );
    return (r.rows || []).length > 0;
}

async function isPlanEditorByPlanNameYear(userId, planName, year, db = pool) {
    const uid = userId != null ? parseInt(userId, 10) : null;
    if (!Number.isFinite(uid)) return false;
    const n = String(planName || '').trim();
    const y = String(year || '').trim();
    if (!n || !y) return false;
    const r = await db.query(
        `SELECT 1
         FROM inspection_plan_schedule h
         JOIN plan_editors pe ON pe.plan_id = h.id
         WHERE h.plan_name = $1 AND h.year = $2 AND h.inspection_seq = '00'
           AND pe.user_id = $3
         LIMIT 1`,
        [n, y, uid]
    );
    return (r.rows || []).length > 0;
}

async function canEditByOwnership(user, record, db = pool) {
    // user: { id, role?, isAdmin? }
    // record: { owner_group_id, owner_user_id, edit_mode }
    if (!user || !user.id) return false;
    // admin 以「系統管理群組」為準（兼容舊 role=admin）
    try {
        if (user.isAdmin === true) return true;
        if (user.role === 'admin') return true; // legacy rescue
        const ok = await isAdminUser(user.id, db);
        if (ok) return true;
    } catch (e) {}

    const ownerUserId = record?.owner_user_id != null ? parseInt(record.owner_user_id, 10) : null;
    const ownerGroupId = record?.owner_group_id != null ? parseInt(record.owner_group_id, 10) : null;
    const mode = String(record?.edit_mode || 'GROUP').toUpperCase();
    const recType = String(record?.__type || '').trim();
    const recId = record?.id != null ? parseInt(record.id, 10) : null;

    if (ownerUserId && user.id === ownerUserId) return true;

    if (mode === 'OWNER_ONLY') {
        return ownerUserId != null && user.id === ownerUserId;
    }

    // 協作編修（跨群組）
    // - 只在非 OWNER_ONLY 模式下生效
    try {
        if (recType === 'issue' && Number.isFinite(recId)) {
            if (await isIssueEditor(user.id, recId, db)) return true;
        }
        if (recType === 'plan_header' && Number.isFinite(recId)) {
            if (await isPlanEditorByPlanId(user.id, recId, db)) return true;
        }
        if (recType === 'schedule') {
            const pn = record?.plan_name;
            const py = record?.year;
            if (await isPlanEditorByPlanNameYear(user.id, pn, py, db)) return true;
        }
    } catch (e) {
        // 若資料表不存在或查詢失敗，走原本的群組/承辦規則
    }

    // legacy (owner_group_id 未設定) → 開發中先不擋，避免舊資料無法操作
    if (!ownerGroupId) return true;

    const gids = await getUserGroupIds(user.id, db);
    return gids.includes(ownerGroupId);
}

// 統一的 API 錯誤處理函數
function handleApiError(e, req, res, context) {
    // 記錄錯誤日誌
    logError(e, context, req).catch(() => {});
    
    // 根據環境決定錯誤訊息
    const errorMessage = process.env.NODE_ENV === 'production' 
        ? '伺服器錯誤，請稍後再試' 
        : (e.detail || e.message || '伺服器錯誤，請稍後再試');
    
    res.status(500).json({ error: errorMessage });
}

// CSRF 保護設定
const csrfProtection = new csrf();
const getCsrfToken = (req, res, next) => {
    if (!req.session.csrfSecret) {
        req.session.csrfSecret = csrfProtection.secretSync();
    }
    req.csrfToken = csrfProtection.create(req.session.csrfSecret);
    next();
};

// CSRF 驗證中間件（僅用於需要保護的路由）
const verifyCsrf = (req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        return next();
    }
    
    try {
        const token = req.headers['x-csrf-token'] || req.body._csrf;
        const secret = req.session.csrfSecret;
        
        if (!secret || !token) {
            return res.status(403).json({ error: 'CSRF token missing' });
        }
        
        if (!csrfProtection.verify(secret, token)) {
            return res.status(403).json({ error: 'Invalid CSRF token' });
        }
        
        next();
    } catch (e) {
        console.error('CSRF verification error:', e);
        logError(e, 'CSRF verification error', req).catch(() => {});
        return res.status(500).json({ error: 'CSRF verification failed' });
    }
};

// 為所有需要認證的路由提供 CSRF token
app.use('/api/', getCsrfToken);

const requireAuth = (req, res, next) => {
    try {
        if (req.session && req.session.user) {
            next();
        } else {
            console.warn('[AUTH] Unauthorized request to:', req.path, 'Session:', !!req.session);
            if (!res.headersSent) {
                res.status(401).json({ error: 'Unauthorized' });
            }
        }
    } catch (e) {
        console.error('[AUTH] Error in requireAuth middleware:', e);
        process.stderr.write(`[AUTH] ERROR: ${e.message}\n`);
        if (!res.headersSent) {
            res.status(500).json({ 
                error: 'Authentication check failed',
                message: e.message,
                code: e.code
            });
        }
    }
};

// 對所有 API 路由套用速率限制（除了已經有特定限制的路由）
// 注意：這個中間件必須放在 session 之後
app.use('/api/', (req, res, next) => {
    // 登入路由使用 loginLimiter，不需要再次限制
    if (req.path === '/auth/login') {
        return next();
    }
    // Gemini API 使用 geminiLimiter
    if (req.path === '/gemini') {
        return next();
    }
    // 其他 API 使用通用限制
    return apiLimiter(req, res, next);
});

// --- Database Initialization ---
async function initDB() {
    let retries = 5;
    while (retries > 0) {
        try {
            const client = await pool.connect();
            try {
                console.log('Connected to PostgreSQL. Checking schema...');

                // Session Table
                await client.query(`
                    CREATE TABLE IF NOT EXISTS session (
                        sid varchar NOT NULL COLLATE "default",
                        sess json NOT NULL,
                        expire timestamp(6) NOT NULL
                    ) WITH (OIDS=FALSE);
                `);
                try {
                    await client.query(`ALTER TABLE session ADD CONSTRAINT session_pkey PRIMARY KEY (sid) NOT DEFERRABLE INITIALLY IMMEDIATE`);
                } catch (e) {}
                try {
                    await client.query(`CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON session (expire)`);
                } catch (e) {}

                // Issues Table
                await client.query(`CREATE TABLE IF NOT EXISTS issues (
                    id SERIAL PRIMARY KEY,
                    number TEXT UNIQUE,
                    year TEXT,
                    unit TEXT,
                    content TEXT,
                    status TEXT,
                    item_kind_code TEXT,
                    division_name TEXT,
                    inspection_category_name TEXT,
                    category TEXT,
                    handling TEXT,
                    review TEXT,
                    plan_name TEXT,
                    issue_date TEXT,
                    owner_group_id INTEGER,
                    owner_user_id INTEGER,
                    edit_mode TEXT DEFAULT 'GROUP',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )`);

                // Users Table
                await client.query(`CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT,
                    name TEXT,
                    role TEXT DEFAULT 'viewer',
                    must_change_password BOOLEAN DEFAULT true,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )`);
                
                // 新增 must_change_password 欄位（如果不存在）
                try {
                    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT true`);
                } catch (e) {}
                
                // 角色整併（方案A）：editor 視為 manager，避免舊帳號失效
                try {
                    await client.query(`UPDATE users SET role = 'manager' WHERE role = 'editor'`);
                } catch (e) {}
                // admin 將改由「系統管理群組」決定（舊 role=admin 會在後面遷移）

                // Groups / User groups (多群組隸屬)
                await client.query(`CREATE TABLE IF NOT EXISTS groups (
                    id SERIAL PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    is_admin_group BOOLEAN DEFAULT false,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )`);
                // 向後兼容：舊資料庫可能沒有 is_admin_group
                try { await client.query(`ALTER TABLE groups ADD COLUMN IF NOT EXISTS is_admin_group BOOLEAN DEFAULT false`); } catch (e) {}
                // 確保「系統管理群組」唯一（只允許一個 true）
                try {
                    await client.query(`
                        CREATE UNIQUE INDEX IF NOT EXISTS uq_groups_admin_group_true
                        ON groups ((is_admin_group))
                        WHERE is_admin_group = true
                    `);
                } catch (e) {
                    // 若既有資料已多個 true，索引會失敗；開發中先忽略
                }
                await client.query(`CREATE TABLE IF NOT EXISTS user_groups (
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_id, group_id)
                )`);

                // 協作編修：開立事項可額外指定可編修人員（跨群組）
                // 注意：OWNER_ONLY 模式仍僅允許 owner_user + 系統管理群組
                await client.query(`CREATE TABLE IF NOT EXISTS issue_editors (
                    issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (issue_id, user_id)
                )`);

                // 檢查計畫單一表（原 inspection_plan_schedule）：月曆排程 + 取號 等，不再使用 inspection_plans
                await client.query(`CREATE TABLE IF NOT EXISTS inspection_plan_schedule (
                    id SERIAL PRIMARY KEY,
                    start_date DATE,
                    end_date DATE,
                    plan_name TEXT NOT NULL,
                    year TEXT NOT NULL,
                    plan_type TEXT,
                    railway TEXT NOT NULL,
                    inspection_type TEXT NOT NULL,
                    business TEXT,
                    inspection_seq TEXT NOT NULL,
                    plan_number TEXT NOT NULL,
                    location TEXT,
                    inspector TEXT,
                    owner_group_id INTEGER,
                    owner_user_id INTEGER,
                    edit_mode TEXT DEFAULT 'GROUP',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )`);

                // 協作編修：檢查計畫（主檔 00）可額外指定可編修人員（跨群組）
                // 注意：OWNER_ONLY 模式仍僅允許 owner_user + 系統管理群組
                await client.query(`CREATE TABLE IF NOT EXISTS plan_editors (
                    plan_id INTEGER NOT NULL REFERENCES inspection_plan_schedule(id) ON DELETE CASCADE,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (plan_id, user_id)
                )`);
                // 修改 start_date 為允許 NULL（如果原本是 NOT NULL）
                try {
                    await client.query(`ALTER TABLE inspection_plan_schedule ALTER COLUMN start_date DROP NOT NULL`);
                } catch (e) {
                    // 如果已經是 NULL 或不存在，忽略錯誤
                }
                // 修改 business 為允許 NULL（因為取號編碼不再使用業務類別）
                try {
                    await client.query(`ALTER TABLE inspection_plan_schedule ALTER COLUMN business DROP NOT NULL`);
                } catch (e) {
                    // 如果已經是 NULL 或不存在，忽略錯誤
                }
                await client.query(`ALTER TABLE inspection_plan_schedule ADD COLUMN IF NOT EXISTS plan_type TEXT`);
                await client.query(`ALTER TABLE inspection_plan_schedule ADD COLUMN IF NOT EXISTS location TEXT`);
                await client.query(`ALTER TABLE inspection_plan_schedule ADD COLUMN IF NOT EXISTS inspector TEXT`);
                // 向後兼容：如果存在 scheduled_date 欄位，遷移到 start_date
                try {
                    await client.query(`ALTER TABLE inspection_plan_schedule ADD COLUMN IF NOT EXISTS start_date DATE`);
                    await client.query(`ALTER TABLE inspection_plan_schedule ADD COLUMN IF NOT EXISTS end_date DATE`);
                    await client.query(`UPDATE inspection_plan_schedule SET start_date = scheduled_date WHERE start_date IS NULL AND scheduled_date IS NOT NULL`);
                } catch (e) {}
                try {
                    await client.query(`ALTER TABLE inspection_plan_schedule DROP COLUMN IF EXISTS scheduled_date`);
                } catch (e) {}
                try {
                    await client.query(`DROP INDEX IF EXISTS idx_schedule_date`);
                } catch (e) {}
                try {
                    await client.query(`CREATE INDEX IF NOT EXISTS idx_schedule_start_date ON inspection_plan_schedule(start_date)`);
                    await client.query(`CREATE INDEX IF NOT EXISTS idx_schedule_year ON inspection_plan_schedule(year)`);
                } catch (e) {}
                // 取號唯一性：同年度+鐵路機構+檢查類別下，inspection_seq（不含 00 主檔）不得重複
                // 注意：若既有資料已重複，建立唯一索引會失敗，但開發中可忽略並於清庫後自動生效
                try {
                    await client.query(`
                        CREATE UNIQUE INDEX IF NOT EXISTS uq_schedule_seq
                        ON inspection_plan_schedule(year, railway, inspection_type, inspection_seq)
                        WHERE inspection_seq <> '00'
                    `);
                } catch (e) {
                    console.warn('Create uq_schedule_seq index warning:', e?.message || e);
                }
                await client.query(`ALTER TABLE inspection_plan_schedule ADD COLUMN IF NOT EXISTS planned_count INTEGER`);

                // 遷移：若曾使用 inspection_plans，將僅存於該表的 (name,year) 補進 schedule 後刪除 inspection_plans
                try {
                    const hasPlans = await client.query(
                        "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='inspection_plans'"
                    );
                    if (hasPlans.rows.length > 0) {
                        const planRows = await client.query(
                            "SELECT name, year, created_at FROM inspection_plans"
                        );
                        for (const r of planRows.rows || []) {
                            const n = (r.name || '').trim();
                            const y = (r.year || '').trim();
                            if (!n) continue;
                            const ex = await client.query(
                                "SELECT 1 FROM inspection_plan_schedule WHERE plan_name = $1 AND year = $2 LIMIT 1",
                                [n, y]
                            );
                            if (ex.rows.length > 0) continue;
                            const sd = r.created_at ? new Date(r.created_at).toISOString().slice(0, 10) : '2000-01-01';
                            await client.query(
                                `INSERT INTO inspection_plan_schedule (start_date, end_date, plan_name, year, railway, inspection_type, business, inspection_seq, plan_number)
                                 VALUES ($1, NULL, $2, $3, '-', '-', '-', '00', '(手動)')`,
                                [sd, n, y]
                            );
                        }
                        await client.query(`DROP TABLE IF EXISTS inspection_plans CASCADE`);
                    }
                } catch (e) {
                    console.warn('inspection_plans migration warning:', e?.message || e);
                }

                // Logs Table
                await client.query(`CREATE TABLE IF NOT EXISTS logs (
                    id SERIAL PRIMARY KEY,
                    username TEXT,
                    action TEXT,
                    details TEXT,
                    ip_address TEXT,
                    login_time TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )`);

                // App Templates / Files (for storing uploaded example xlsx)
                await client.query(`CREATE TABLE IF NOT EXISTS app_files (
                    key TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    mime TEXT NOT NULL,
                    data BYTEA NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )`);

                // Add missing columns if they don't exist
                const newColumns = [];
                // 支持無限次審查，預先創建前 30 次欄位（如果需要更多可以動態創建）
                for (let i = 2; i <= 30; i++) {
                    newColumns.push({ name: `handling${i}`, type: 'TEXT' });
                    newColumns.push({ name: `review${i}`, type: 'TEXT' });
                }
                for (let i = 1; i <= 30; i++) {
                    newColumns.push({ name: `reply_date_r${i}`, type: 'TEXT' });
                    newColumns.push({ name: `response_date_r${i}`, type: 'TEXT' });
                }
                newColumns.push({ name: 'plan_name', type: 'TEXT' });
                newColumns.push({ name: 'issue_date', type: 'TEXT' });

                for (const col of newColumns) {
                    try {
                        await client.query(`ALTER TABLE issues ADD COLUMN IF NOT EXISTS ${col.name} ${col.type}`);
                    } catch (e) { }
                }

                // Issues ownership / edit mode（向後兼容）
                try { await client.query(`ALTER TABLE issues ADD COLUMN IF NOT EXISTS owner_group_id INTEGER`); } catch (e) {}
                try { await client.query(`ALTER TABLE issues ADD COLUMN IF NOT EXISTS owner_user_id INTEGER`); } catch (e) {}
                try { await client.query(`ALTER TABLE issues ADD COLUMN IF NOT EXISTS edit_mode TEXT DEFAULT 'GROUP'`); } catch (e) {}

                // Plan schedule ownership / edit mode（向後兼容）
                try { await client.query(`ALTER TABLE inspection_plan_schedule ADD COLUMN IF NOT EXISTS owner_group_id INTEGER`); } catch (e) {}
                try { await client.query(`ALTER TABLE inspection_plan_schedule ADD COLUMN IF NOT EXISTS owner_user_id INTEGER`); } catch (e) {}
                try { await client.query(`ALTER TABLE inspection_plan_schedule ADD COLUMN IF NOT EXISTS edit_mode TEXT DEFAULT 'GROUP'`); } catch (e) {}

                // Create Default Admin if no users exist
                const userRes = await client.query("SELECT count(*) as count FROM users");
                if (parseInt(userRes.rows[0].count) === 0) {
                    // 使用環境變數提供預設密碼，或在首次登入後強制修改
                    const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 
                        require('crypto').randomBytes(16).toString('hex');
                    const hash = bcrypt.hashSync(defaultPassword, 10);
                    await client.query("INSERT INTO users (username, password, name, role, must_change_password) VALUES ($1, $2, $3, $4, $5)", 
                        ['admin', hash, '系統管理員', 'manager', true]);
                    console.log("===========================================");
                    console.log("警告: 已建立預設管理員帳號");
                    console.log("帳號: admin");
                    console.log("密碼: " + (process.env.DEFAULT_ADMIN_PASSWORD ? "使用環境變數設定" : defaultPassword));
                    console.log("請立即登入並修改密碼！");
                    console.log("===========================================");
                }

                // Ensure default group exists, and admin is assigned (for fresh installs)
                try {
                    // 1) 確保存在「系統管理群組」（is_admin_group=true）
                    let adminGroupId = null;
                    const agRes = await client.query("SELECT id FROM groups WHERE is_admin_group = true ORDER BY id ASC LIMIT 1");
                    adminGroupId = agRes.rows[0]?.id || null;
                    if (!adminGroupId) {
                        const ins = await client.query(
                            "INSERT INTO groups (name, is_admin_group) VALUES ($1, true) ON CONFLICT (name) DO UPDATE SET is_admin_group = true RETURNING id",
                            ['系統管理群組']
                        );
                        adminGroupId = ins.rows[0]?.id || null;
                    }

                    // 2) 確保至少有一個一般群組（用於資料歸屬/預設 owner_group）
                    let defaultGroupId = null;
                    const gRes = await client.query("SELECT id FROM groups WHERE is_admin_group = false ORDER BY id ASC LIMIT 1");
                    defaultGroupId = gRes.rows[0]?.id || null;
                    if (!defaultGroupId) {
                        const ins = await client.query("INSERT INTO groups (name, is_admin_group) VALUES ($1, false) RETURNING id", ['預設群組']);
                        defaultGroupId = ins.rows[0]?.id || null;
                    }

                    // 3) 把 admin 使用者加入「系統管理群組」與「預設群組」（避免鎖死）
                    // 3-1) 遷移：舊 role=admin → 加入系統管理群組，並把 role 降回 manager（admin 改由群組判斷）
                    try {
                        if (adminGroupId) {
                            const legacyAdmins = await client.query("SELECT id FROM users WHERE role = 'admin'");
                            for (const row of (legacyAdmins.rows || [])) {
                                const uid = row?.id;
                                if (!uid) continue;
                                await client.query(
                                    "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                                    [uid, adminGroupId]
                                );
                            }
                        }
                        await client.query("UPDATE users SET role = 'manager' WHERE role = 'admin'");
                    } catch (e) {
                        console.warn('Legacy admin migration warning:', e?.message || e);
                    }

                    const aRes = await client.query("SELECT id FROM users WHERE username = $1 LIMIT 1", ['admin']);
                    const adminId = aRes.rows[0]?.id;
                    if (adminId && adminGroupId) {
                        await client.query(
                            "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                            [adminId, adminGroupId]
                        );
                    }
                    if (adminId && defaultGroupId) {
                        await client.query(
                            "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                            [adminId, defaultGroupId]
                        );
                    }
                } catch (e) {
                    console.warn('Default group/admin mapping warning:', e?.message || e);
                }
                
                console.log('Database initialized successfully.');
                return;

            } catch (err) {
                console.error('Init DB Schema Error:', err);
                throw err;
            } finally {
                client.release();
            }
        } catch (connErr) {
            console.error(`Connection failed, retrying... (${retries} left)`, connErr.message);
            retries--;
            await new Promise(res => setTimeout(res, 2000));
        }
    }
    throw new Error('Could not connect to database after multiple retries.');
}

// Rate Limiting 設定
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 分鐘
    max: 5, // 最多 5 次登入嘗試
    message: { error: '登入嘗試過多，請 15 分鐘後再試' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // 開發環境可以放寬限制
        return process.env.NODE_ENV === 'development';
    }
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 分鐘
    max: 100, // 最多 100 次請求
    message: { error: 'API 調用過於頻繁，請稍後再試' },
    standardHeaders: true,
    legacyHeaders: false,
});

const geminiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 分鐘
    max: 20, // 最多 20 次 AI 分析請求
    message: { error: 'AI 分析請求過於頻繁，請稍後再試' },
    standardHeaders: true,
    legacyHeaders: false,
});

async function logAction(username, action, details, req) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    try {
        // 如果是登入動作，同時寫入 login_time
        if (action === 'LOGIN') {
            await pool.query("INSERT INTO logs (username, action, details, ip_address, login_time, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", 
                [username, action, details, ip]);
        } else {
            await pool.query("INSERT INTO logs (username, action, details, ip_address, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)", 
                [username, action, details, ip]);
        }
    } catch (e) { 
        console.error("Log error:", e);
        // 記錄錯誤到檔案
        writeToLogFile(`Error logging action: ${e.message}`, 'ERROR');
    }
}

// 錯誤日誌記錄函數（記錄到資料庫）
async function logError(error, context, req) {
    try {
        const ip = req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress) : 'system';
        const username = req?.session?.user?.username || 'system';
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorStack = error instanceof Error ? error.stack : '';
        const details = `${context}: ${errorMessage}${errorStack ? `\nStack: ${errorStack.substring(0, 500)}` : ''}`;
        
        // 嘗試記錄到資料庫，如果失敗則只記錄到檔案
        try {
            await pool.query(
                "INSERT INTO logs (username, action, details, ip_address, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)",
                [username, 'ERROR', details, ip]
            );
        } catch (dbError) {
            // 資料庫記錄失敗，只記錄到檔案
            console.error("Failed to log error to database:", dbError);
        }
        
        // 同時寫入檔案日誌
        writeToLogFile(`[ERROR] ${context}: ${errorMessage}`, 'ERROR');
    } catch (e) {
        // 如果整個錯誤記錄過程失敗，至少輸出到 console
        console.error("Failed to log error:", e);
        console.error("Original error:", error);
    }
}

// 寫入日誌檔案
function writeToLogFile(message, level = 'INFO') {
    try {
        const logDir = path.join(__dirname, 'logs');
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir, { recursive: true });
        }
        const today = new Date().toISOString().split('T')[0];
        const logFile = path.join(logDir, `app-${today}.log`);
        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] [${level}] ${message}\n`;
        fs.appendFileSync(logFile, logEntry, 'utf8');
    } catch (e) {
        console.error("Write log file error:", e);
    }
}

// 密碼複雜度驗證函數
function validatePassword(password) {
    if (!password || typeof password !== 'string') {
        return { valid: false, message: '密碼不能為空' };
    }
    
    if (password.length < 8) {
        return { valid: false, message: '密碼至少需要 8 個字元' };
    }
    
    if (!/[A-Z]/.test(password)) {
        return { valid: false, message: '密碼必須包含至少一個大寫字母' };
    }
    
    if (!/[a-z]/.test(password)) {
        return { valid: false, message: '密碼必須包含至少一個小寫字母' };
    }
    
    if (!/[0-9]/.test(password)) {
        return { valid: false, message: '密碼必須包含至少一個數字' };
    }
    
    return { valid: true };
}

// 日誌輪轉機制：清理舊日誌檔案
function cleanupOldLogs() {
    try {
        const logDir = path.join(__dirname, 'logs');
        if (!fs.existsSync(logDir)) {
            return;
        }
        
        const maxAge = 30 * 24 * 60 * 60 * 1000; // 30 天
        const now = Date.now();
        
        fs.readdir(logDir, (err, files) => {
            if (err) {
                console.error('Error reading log directory:', err);
                return;
            }
            
            files.forEach(file => {
                if (!file.startsWith('app-') || !file.endsWith('.log')) {
                    return;
                }
                
                const filePath = path.join(logDir, file);
                fs.stat(filePath, (err, stats) => {
                    if (err) {
                        return;
                    }
                    
                    const fileAge = now - stats.mtime.getTime();
                    if (fileAge > maxAge) {
                        fs.unlink(filePath, (err) => {
                            if (err) {
                                console.error(`Error deleting old log file ${file}:`, err);
                            } else {
                                console.log(`Deleted old log file: ${file}`);
                            }
                        });
                    }
                });
            });
        });
    } catch (e) {
        console.error('Error in cleanupOldLogs:', e);
    }
}

// 啟動時執行一次日誌清理，然後每天執行一次
cleanupOldLogs();
setInterval(cleanupOldLogs, 24 * 60 * 60 * 1000); // 每 24 小時執行一次

// API: 取得 CSRF token
app.get('/api/csrf-token', (req, res) => {
    if (!req.session.csrfSecret) {
        req.session.csrfSecret = csrfProtection.secretSync();
    }
    const token = csrfProtection.create(req.session.csrfSecret);
    res.json({ csrfToken: token });
});

// API: 接收前端日誌
app.post('/api/log', requireAuth, verifyCsrf, (req, res) => {
    try {
        const { message, level = 'INFO' } = req.body;
        if (message) {
            writeToLogFile(message, level);
            res.json({ success: true });
        } else {
            res.status(400).json({ error: 'Message is required' });
        }
    } catch (e) {
        console.error("Log API error:", e);
        logError(e, 'Log API error', req).catch(() => {});
        res.status(500).json({ error: 'Failed to write log' });
    }
});

// --- API Routes ---

app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
        const user = result.rows[0];
        
        if (!user || !user.password) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (bcrypt.compareSync(password, user.password)) {
            const isAdmin = await isAdminUser(user.id, pool);
            req.session.user = { id: user.id, username: user.username, role: user.role, name: user.name, isAdmin };
            req.session.save((err) => {
                if(err) {
                    console.error("Session save error:", err);
                    return res.status(500).json({error: 'Session error'});
                }
                logAction(user.username, 'LOGIN', 'User logged in', req).catch(()=>{});
                // 檢查是否需要更新密碼
                const mustChangePassword = user.must_change_password === true || user.must_change_password === null;
                res.json({ 
                    success: true, 
                    user: req.session.user,
                    mustChangePassword: mustChangePassword
                });
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (e) {
        console.error("Login Error:", e);
        logError(e, 'Login error', req).catch(() => {});
        res.status(500).json({ error: 'System error' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ error: 'Logout failed' });
        res.clearCookie('connect.sid'); 
        res.json({ success: true });
    });
});

app.get('/api/auth/me', async (req, res) => {
    if (req.session && req.session.user) {
        try {
            const result = await pool.query(
                `SELECT u.id, u.username, u.name, u.role,
                        COALESCE(array_agg(ug.group_id) FILTER (WHERE ug.group_id IS NOT NULL), '{}') AS group_ids,
                        COALESCE(BOOL_OR(g.is_admin_group = true), false) AS is_admin
                 FROM users u
                 LEFT JOIN user_groups ug ON ug.user_id = u.id
                 LEFT JOIN groups g ON g.id = ug.group_id
                 WHERE u.id = $1
                 GROUP BY u.id`,
                [req.session.user.id]
            );
            const latestUser = result.rows[0];

            if (!latestUser) {
                req.session.destroy();
                return res.json({ isLogin: false });
            }
            // session 只保留必要欄位
            const isAdmin = latestUser.is_admin === true;
            req.session.user = { id: latestUser.id, username: latestUser.username, role: latestUser.role, name: latestUser.name, isAdmin };
            res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            const groupIds = Array.isArray(latestUser.group_ids)
                ? latestUser.group_ids.map(x => parseInt(x, 10)).filter(n => Number.isFinite(n))
                : [];
            res.json({ isLogin: true, id: latestUser.id, username: latestUser.username, name: latestUser.name, role: latestUser.role, isAdmin, groupIds });
        } catch (e) {
            console.error("Auth check db error:", e);
            res.json({ isLogin: false });
        }
    } else {
        res.json({ isLogin: false });
    }
});

app.put('/api/auth/profile', requireAuth, verifyCsrf, async (req, res) => {
    const { name, password } = req.body;
    const id = req.session.user.id;
    try {
        if (password) {
            // 驗證密碼複雜度
            const passwordValidation = validatePassword(password);
            if (!passwordValidation.valid) {
                return res.status(400).json({ error: passwordValidation.message });
            }
            const hash = bcrypt.hashSync(password, 10);
            await pool.query("UPDATE users SET name = $1, password = $2, must_change_password = $3 WHERE id = $4", [name, hash, false, id]);
            logAction(req.session.user.username, 'UPDATE_PROFILE', `更新個人資料：已更新姓名為「${name}」並變更密碼`, req);
        } else {
            await pool.query("UPDATE users SET name = $1 WHERE id = $2", [name, id]);
            logAction(req.session.user.username, 'UPDATE_PROFILE', `更新個人資料：已更新姓名為「${name}」`, req);
        }
        res.json({ success: true });
    } catch (e) { 
        logError(e, 'Update profile error', req).catch(() => {});
        res.status(500).json({ error: e.message }); 
    }
});

// 首次登入強制更新密碼 API
app.post('/api/auth/change-password', requireAuth, verifyCsrf, async (req, res) => {
    const { password } = req.body;
    const id = req.session.user.id;
    try {
        if (!password) {
            return res.status(400).json({ error: '密碼為必填項目' });
        }
        
        // 驗證密碼複雜度
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
            return res.status(400).json({ error: passwordValidation.message });
        }
        
        // 更新密碼並清除 must_change_password 標記
        const hash = bcrypt.hashSync(password, 10);
        await pool.query("UPDATE users SET password = $1, must_change_password = $2 WHERE id = $3", [hash, false, id]);
        
        logAction(req.session.user.username, 'CHANGE_PASSWORD', 'User changed password (first login)', req).catch(()=>{});
        res.json({ success: true });
    } catch (e) {
        handleApiError(e, req, res, 'Change password error');
    }
});

app.post('/api/gemini', geminiLimiter, async (req, res) => {
    const { content, rounds } = req.body;
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) return res.status(500).json({ error: '後端未設定 GEMINI_API_KEY' });
    try {
        const genAI = new GoogleGenerativeAI(apiKey);
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
        const latestRound = (rounds && rounds.length > 0) ? rounds[rounds.length - 1] : { handling: '無', review: '無' };
        const previousReview = (rounds && rounds.length > 1) ? rounds[rounds.length - 2].review : '無';
        const prompt = `
        你現在是【鐵道監理機關】的專業審查人員，正在審核受檢機構針對缺失事項的改善情形。
        請秉持「中立、客觀、平實」的原則進行審查。
        【待改善事項內容】：${content}
        【上一回合審查意見】：${previousReview}
        【本次機構辦理情形】：${latestRound.handling || '無'}
        【回覆格式要求】：JSON: {"fulfill": "Yes/No", "result": "100字內簡評"}
        `;
        const result = await model.generateContent(prompt);
        const response = await result.response;
        let text = response.text().replace(/```json/g, '').replace(/```/g, '').trim();
        try {
            const json = JSON.parse(text);
            res.json(json);
        } catch (parseError) {
            res.json({ fulfill: text.includes("Yes") ? "Yes" : "No", reason: text.replace(/[{}]/g, '').trim() });
        }
    } catch (e) {
        console.error("Gemini API Error:", e);
        res.status(500).json({ error: 'AI 分析失敗: ' + e.message });
    }
});

app.get('/api/issues', requireAuth, async (req, res) => {
    const { page = 1, pageSize = 20, q, year, unit, status, itemKindCode, division, inspectionCategory, planName, sortField, sortDir } = req.query;
    const limit = parseInt(pageSize);
    const offset = (page - 1) * limit;
    let where = ["1=1"], params = [], idx = 1;

    res.set('Cache-Control', 'no-store');

    if (q) {
        where.push(`(number LIKE $${idx} OR content LIKE $${idx} OR handling LIKE $${idx} OR review LIKE $${idx} OR plan_name LIKE $${idx})`);
        params.push(`%${q}%`); idx++;
    }
    if (year) { where.push(`year = $${idx}`); params.push(year); idx++; }
    if (unit) { where.push(`unit = $${idx}`); params.push(unit); idx++; }
    if (status) { where.push(`status = $${idx}`); params.push(status); idx++; }
    if (itemKindCode) { where.push(`item_kind_code = $${idx}`); params.push(itemKindCode); idx++; }
    if (division) { where.push(`division_name = $${idx}`); params.push(division); idx++; }
    if (inspectionCategory) { where.push(`inspection_category_name = $${idx}`); params.push(inspectionCategory); idx++; }
    // 修正：如果提供了計畫名稱，需要同時考慮年度來精確匹配
    // planName 參數現在可能是 "planName|||year" 格式，或者只有 planName
    if (planName) {
        const planParts = planName.split('|||');
        const actualPlanName = planParts[0];
        const planYear = planParts[1];
        
        if (planYear) {
            // 如果提供了年度，同時匹配計畫名稱和年度
            where.push(`plan_name = $${idx} AND year = $${idx+1}`);
            params.push(actualPlanName, planYear);
            idx += 2;
        } else {
            // 如果沒有提供年度，只匹配計畫名稱（向後兼容）
            where.push(`plan_name = $${idx}`);
            params.push(actualPlanName);
            idx++;
        }
    }

    let orderBy = "created_at DESC";
    const validCols = ['year', 'number', 'unit', 'status', 'created_at'];
    if (sortField && validCols.includes(sortField)) {
        orderBy = `${sortField} ${sortDir === 'asc' ? 'ASC' : 'DESC'}`;
    }

    try {
        const countRes = await pool.query(`SELECT count(*) FROM issues WHERE ${where.join(" AND ")}`, params);
        const total = parseInt(countRes.rows[0].count);
        const dataRes = await pool.query(`SELECT * FROM issues WHERE ${where.join(" AND ")} ORDER BY ${orderBy} LIMIT $${idx} OFFSET $${idx+1}`, [...params, limit, offset]);
        const sRes = await pool.query("SELECT status, count(*) as count FROM issues GROUP BY status");
        const uRes = await pool.query("SELECT unit, count(*) as count FROM issues GROUP BY unit");
        const yRes = await pool.query("SELECT year, count(*) as count FROM issues GROUP BY year");
        const tRes = await pool.query("SELECT max(updated_at) as updated, max(created_at) as latest FROM issues");
        const latestTime = tRes.rows[0] ? (tRes.rows[0].updated || tRes.rows[0].latest) : null;

        res.json({
            data: dataRes.rows,
            total,
            page: parseInt(page),
            pageSize: limit,
            pages: Math.ceil(total / limit),
            latestCreatedAt: latestTime,
            globalStats: { status: sRes.rows, unit: uRes.rows, year: yRes.rows }
        });
    } catch (e) { 
        handleApiError(e, req, res, 'Get issues error');
    }
});

app.put('/api/issues/:id', requireAuth, verifyCsrf, async (req, res) => {
    const { status, round, handling, review, replyDate, responseDate, content, issueDate, 
            number, year, unit, divisionName, inspectionCategoryName, itemKindCode, category, planName } = req.body;
    const id = req.params.id;
    const r = parseInt(round) || 1;
    const hField = r === 1 ? 'handling' : `handling${r}`;
    const rField = r === 1 ? 'review' : `review${r}`;
    const replyField = `reply_date_r${r}`;
    const respField = `response_date_r${r}`;
    try {
        // 角色限制（方案A）：viewer 不可寫入；admin 由「系統管理群組」決定
        const role = req.session?.user?.role;
        const isAdmin = await isAdminUser(req.session.user.id, pool);
        if (!(isAdmin || role === 'manager')) {
            return res.status(403).json({ error: 'Denied' });
        }

        // 讀取歸屬以判斷是否可編輯
        const issueMetaRes = await pool.query(
            "SELECT id, number, status, owner_group_id, owner_user_id, edit_mode FROM issues WHERE id=$1",
            [id]
        );
        if (issueMetaRes.rows.length === 0) return res.status(404).json({ error: 'Issue not found' });
        const issueMeta = issueMetaRes.rows[0];
        const canEdit = await canEditByOwnership({ id: req.session.user.id, role }, { ...issueMeta, __type: 'issue' }, pool);
        if (!canEdit) return res.status(403).json({ error: 'Denied' });

        // 先查詢 issue number
        const issueNumber = issueMeta.number || `ID:${id}`;
        
        // 如果超過預設欄位範圍（30次），動態創建欄位
        if (r > 30) {
            try {
                await pool.query(`ALTER TABLE issues ADD COLUMN IF NOT EXISTS ${hField} TEXT`);
                await pool.query(`ALTER TABLE issues ADD COLUMN IF NOT EXISTS ${rField} TEXT`);
                await pool.query(`ALTER TABLE issues ADD COLUMN IF NOT EXISTS ${replyField} TEXT`);
                await pool.query(`ALTER TABLE issues ADD COLUMN IF NOT EXISTS ${respField} TEXT`);
            } catch (colError) {
                // 忽略欄位已存在的錯誤
                if (!colError.message.includes('already exists')) {
                    console.error('Error creating columns:', colError);
                }
            }
        }

        // 方案A：manager 同時具備審查與資料管理，沿用既有完整更新流程
        
        // 構建更新語句，如果提供了 content 或 issueDate 則包含它們
        // 注意：replyDate 和 responseDate 如果提供空字符串，應該明確更新為空字符串
        // 如果未提供（undefined），則不更新該欄位
        let updateFields = [`status=$1`, `${hField}=$2`, `${rField}=$3`, `updated_at=CURRENT_TIMESTAMP`];
        let params = [status, handling || '', review || ''];
        let paramIdx = 4;
        
        // 處理 replyDate：如果提供了（即使是空字符串），也要更新
        if (replyDate !== undefined) {
            updateFields.splice(updateFields.length - 1, 0, `${replyField}=$${paramIdx}`);
            params.push(replyDate || '');
            paramIdx++;
        }
        
        // 處理 responseDate：如果提供了（即使是空字符串），也要更新
        if (responseDate !== undefined) {
            updateFields.splice(updateFields.length - 1, 0, `${respField}=$${paramIdx}`);
            params.push(responseDate || '');
            paramIdx++;
        }
        
        if (content !== undefined) {
            updateFields.push(`content=$${paramIdx}`);
            params.push(content);
            paramIdx++;
        }
        
        if (issueDate !== undefined) {
            updateFields.push(`issue_date=$${paramIdx}`);
            params.push(issueDate);
            paramIdx++;
        }
        
        // 支持更新更多字段
        if (number !== undefined) {
            updateFields.push(`number=$${paramIdx}`);
            params.push(number);
            paramIdx++;
        }
        
        if (year !== undefined) {
            updateFields.push(`year=$${paramIdx}`);
            params.push(year);
            paramIdx++;
        }
        
        if (unit !== undefined) {
            updateFields.push(`unit=$${paramIdx}`);
            params.push(unit);
            paramIdx++;
        }
        
        if (divisionName !== undefined) {
            updateFields.push(`division_name=$${paramIdx}`);
            params.push(divisionName);
            paramIdx++;
        }
        
        if (inspectionCategoryName !== undefined) {
            updateFields.push(`inspection_category_name=$${paramIdx}`);
            params.push(inspectionCategoryName);
            paramIdx++;
        }
        
        if (itemKindCode !== undefined) {
            updateFields.push(`item_kind_code=$${paramIdx}`);
            params.push(itemKindCode);
            paramIdx++;
        }
        
        if (category !== undefined) {
            updateFields.push(`category=$${paramIdx}`);
            params.push(category);
            paramIdx++;
        }
        
        if (planName !== undefined) {
            updateFields.push(`plan_name=$${paramIdx}`);
            params.push(planName);
            paramIdx++;
        }
        
        params.push(id);
        await pool.query(`UPDATE issues SET ${updateFields.join(', ')} WHERE id=$${paramIdx}`, params);
        const actionDetails = `更新開立事項：編號 ${issueNumber}，第 ${r} 次審查，狀態：${status}${content !== undefined ? '，內容已更新' : ''}${issueDate !== undefined ? '，開立日期已更新' : ''}${number !== undefined ? '，編號已更新' : ''}${year !== undefined ? '，年度已更新' : ''}${unit !== undefined ? '，機構已更新' : ''}${divisionName !== undefined ? '，分組已更新' : ''}${inspectionCategoryName !== undefined ? '，檢查種類已更新' : ''}${itemKindCode !== undefined ? '，類型已更新' : ''}${planName !== undefined ? '，檢查計畫已更新' : ''}`;
        logAction(req.session.user.username, 'UPDATE_ISSUE', actionDetails, req);
        res.json({ success: true });
    } catch (e) { 
        handleApiError(e, req, res, 'Update issue error');
    }
});

// 協作編修（開立事項）：取得/設定可編修人員名單（跨群組）
app.get('/api/issues/:id/editors', requireAuth, requireAdminOrManager, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id' });

        const metaRes = await pool.query(
            "SELECT id, owner_group_id, owner_user_id, edit_mode FROM issues WHERE id=$1",
            [id]
        );
        if (metaRes.rows.length === 0) return res.status(404).json({ error: 'Not found' });
        const canEdit = await canEditByOwnership(
            { id: req.session.user.id, role: req.session.user.role },
            { ...metaRes.rows[0], __type: 'issue' },
            pool
        );
        if (!canEdit) return res.status(403).json({ error: 'Denied' });

        const r = await pool.query(
            `SELECT u.id, u.username, u.name, u.role,
                    COALESCE(BOOL_OR(g.is_admin_group = true), false) AS is_admin
             FROM issue_editors ie
             JOIN users u ON u.id = ie.user_id
             LEFT JOIN user_groups ug ON ug.user_id = u.id
             LEFT JOIN groups g ON g.id = ug.group_id
             WHERE ie.issue_id = $1
             GROUP BY u.id
             ORDER BY COALESCE(BOOL_OR(g.is_admin_group = true), false) DESC, u.role ASC, u.username ASC`,
            [id]
        );
        res.json({
            data: (r.rows || []).map(u => ({
                id: u.id,
                username: u.username,
                name: u.name,
                role: u.role,
                isAdmin: u.is_admin === true
            }))
        });
    } catch (e) {
        handleApiError(e, req, res, 'Get issue editors error');
    }
});

app.put('/api/issues/:id/editors', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const editorUserIdsRaw = req.body?.editorUserIds;
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id' });
    const editorUserIds = Array.isArray(editorUserIdsRaw)
        ? Array.from(new Set(editorUserIdsRaw.map(x => parseInt(x, 10)).filter(n => Number.isFinite(n))))
        : [];
    try {
        const metaRes = await pool.query(
            "SELECT id, number, owner_group_id, owner_user_id, edit_mode FROM issues WHERE id=$1",
            [id]
        );
        if (metaRes.rows.length === 0) return res.status(404).json({ error: 'Not found' });
        const meta = metaRes.rows[0];
        const canEdit = await canEditByOwnership(
            { id: req.session.user.id, role: req.session.user.role },
            { ...meta, __type: 'issue' },
            pool
        );
        if (!canEdit) return res.status(403).json({ error: 'Denied' });

        // 僅允許指派「資料管理者」或「系統管理群組」成員，避免選到 viewer 造成表面可選但實際不可編修
        if (editorUserIds.length > 0) {
            const uRes = await pool.query(
                `SELECT u.id, u.role, COALESCE(BOOL_OR(g.is_admin_group = true), false) AS is_admin
                 FROM users u
                 LEFT JOIN user_groups ug ON ug.user_id = u.id
                 LEFT JOIN groups g ON g.id = ug.group_id
                 WHERE u.id = ANY($1)
                 GROUP BY u.id`,
                [editorUserIds]
            );
            const byId = new Map((uRes.rows || []).map(r => [parseInt(r.id, 10), r]));
            const invalid = editorUserIds.filter(uid => !byId.has(uid));
            if (invalid.length) return res.status(400).json({ error: `找不到使用者：${invalid.join(', ')}` });
            const notAllowed = editorUserIds.filter(uid => {
                const row = byId.get(uid);
                const isAdmin = row?.is_admin === true;
                const role = String(row?.role || '');
                return !(isAdmin || role === 'manager');
            });
            if (notAllowed.length) return res.status(400).json({ error: `僅可指派「資料管理者」或「系統管理員」：${notAllowed.join(', ')}` });
        }

        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query("DELETE FROM issue_editors WHERE issue_id = $1", [id]);
            if (editorUserIds.length > 0) {
                await client.query(
                    "INSERT INTO issue_editors (issue_id, user_id) SELECT $1, x FROM UNNEST($2::int[]) AS x ON CONFLICT DO NOTHING",
                    [id, editorUserIds]
                );
            }
            await client.query('COMMIT');
        } catch (e) {
            try { await client.query('ROLLBACK'); } catch (_) {}
            throw e;
        } finally {
            client.release();
        }
        logAction(req.session.user.username, 'UPDATE_ISSUE_EDITORS', `更新開立事項協作編修：編號 ${meta.number || `ID:${id}`}，共 ${editorUserIds.length} 人`, req).catch(()=>{});
        res.json({ success: true });
    } catch (e) {
        handleApiError(e, req, res, 'Update issue editors error');
    }
});

app.delete('/api/issues/:id', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    try {
        // 先查詢 issue number / 歸屬再刪除
        const issueRes = await pool.query(
            "SELECT id, number, owner_group_id, owner_user_id, edit_mode FROM issues WHERE id=$1",
            [req.params.id]
        );
        if (issueRes.rows.length === 0) return res.status(404).json({ error: 'Not found' });
        const issueNumber = issueRes.rows[0]?.number || `ID:${req.params.id}`;
        const canEdit = await canEditByOwnership(
            { id: req.session.user.id, role: req.session.user.role },
            { ...issueRes.rows[0], __type: 'issue' },
            pool
        );
        if (!canEdit) return res.status(403).json({ error: 'Denied' });
        
        await pool.query("DELETE FROM issues WHERE id=$1", [req.params.id]);
        logAction(req.session.user.username, 'DELETE_ISSUE', `刪除開立事項：編號 ${issueNumber}`, req);
        res.json({success:true});
    } catch (e) { 
        logError(e, 'Delete issue error', req).catch(() => {});
        res.status(500).json({ error: e.message }); 
    }
});

app.post('/api/issues/batch-delete', requireAuth, verifyCsrf, async (req, res) => {
    const isAdmin = await isAdminUser(req.session.user.id, pool);
    if (!(isAdmin || req.session.user.role === 'manager')) return res.status(403).json({error:'Denied'});
    const { ids } = req.body;
    try {
        if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'ids required' });

        // 權限檢查（避免跨組批次刪除）
        if (!isAdmin) {
            const rows = await pool.query(
                "SELECT id, number, owner_group_id, owner_user_id, edit_mode FROM issues WHERE id = ANY($1)",
                [ids]
            );
            const denied = [];
            for (const row of (rows.rows || [])) {
                const ok = await canEditByOwnership(
                    { id: req.session.user.id, role: req.session.user.role },
                    { ...row, __type: 'issue' },
                    pool
                );
                if (!ok) denied.push(row.number || `ID:${row.id}`);
            }
            if (denied.length > 0) {
                return res.status(403).json({ error: `Denied: ${denied.slice(0, 10).join(', ')}${denied.length > 10 ? '...' : ''}` });
            }
        }

        // 先查詢所有要刪除的編號
        const issueRes = await pool.query("SELECT number FROM issues WHERE id = ANY($1)", [ids]);
        const numbers = issueRes.rows.map(r => r.number).filter(Boolean);
        const numberList = numbers.length > 0 ? numbers.join(', ') : `${ids.length} 筆`;
        
        await pool.query("DELETE FROM issues WHERE id = ANY($1)", [ids]);
        logAction(req.session.user.username, 'BATCH_DELETE_ISSUES', `批次刪除開立事項：${numberList} (共 ${ids.length} 筆)`, req);
        res.json({success:true});
    } catch (e) { 
        handleApiError(e, req, res, 'Batch delete issues error');
    }
});

app.post('/api/issues/import', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    const { data, round, reviewDate, replyDate, allowUpdate, ownerGroupId: ownerGroupIdInput } = req.body;
    const r = parseInt(round) || 1;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const duplicateNumbers = [];
        const operationResults = []; // 記錄每個項目的操作類型
        // 建立時的歸屬群組（允許指定；manager 只能選自己群組，admin 由「系統管理群組」決定）
        let ownerGroupId = ownerGroupIdInput != null ? parseInt(ownerGroupIdInput, 10) : null;
        if (!Number.isFinite(ownerGroupId)) ownerGroupId = null;
        const isAdmin = await isAdminUser(req.session.user.id, client);
        if (!isAdmin) {
            const myGids = await getUserDataGroupIds(req.session.user.id, client);
            if (ownerGroupId == null) ownerGroupId = myGids[0] ?? null;
            if (ownerGroupId != null && !myGids.includes(ownerGroupId)) {
                await client.query('ROLLBACK');
                return res.status(403).json({ error: 'Denied' });
            }
        } else {
            if (ownerGroupId != null) {
                const g = await client.query("SELECT 1 FROM groups WHERE id = $1 AND COALESCE(is_admin_group, false) = false LIMIT 1", [ownerGroupId]);
                if (g.rows.length === 0) {
                    await client.query('ROLLBACK');
                    return res.status(400).json({ error: '群組不存在' });
                }
            } else {
                ownerGroupId = await getPrimaryGroupId(req.session.user.id, client);
            }
        }
        if (ownerGroupId == null) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: '請先將帳號加入至少一個資料群組' });
        }
        const ownerUserId = req.session.user.id;
        
        for (const item of data) {
            // 使用精確匹配查詢編號（區分大小寫，去除前後空格）
            const trimmedNumber = (item.number || '').trim();
            const check = await client.query(
                "SELECT id, content, owner_group_id, owner_user_id, edit_mode FROM issues WHERE TRIM(number) = $1",
                [trimmedNumber]
            );
            if (check.rows.length > 0) {
                // 如果是新增事項（round=1）且不允許更新，檢查內容是否相同
                // 只有在編號已存在、內容不同、且現有內容不為空時，才視為重複編號錯誤
                if (r === 1 && !allowUpdate) {
                    const existingContent = (check.rows[0].content || '').trim();
                    const newContent = (item.content || '').trim();
                    // 只有在明確是重複編號且內容不同時才報錯
                    // 如果現有內容為空，視為可以更新（可能是之前新增失敗留下的空記錄）
                    if (existingContent !== '' && newContent !== '' && existingContent !== newContent) {
                        duplicateNumbers.push({
                            number: trimmedNumber,
                            existingContent: existingContent
                        });
                        continue; // 跳過這個項目，不進行更新
                    }
                    // 如果內容相同或現有內容為空，允許更新（視為正常的新增/更新操作）
                }
                
                // 權限：只能更新自己群組（或 admin rescue）
                const canEdit = await canEditByOwnership(
                    { id: req.session.user.id, role: req.session.user.role },
                    { ...check.rows[0], __type: 'issue' },
                    client
                );
                if (!canEdit) {
                    operationResults.push({ number: trimmedNumber, action: 'skipped_no_permission' });
                    continue;
                }

                // 允許更新：更新現有記錄
                const hCol = r===1 ? 'handling' : `handling${r}`;
                const rCol = r===1 ? 'review' : `review${r}`;
                const replyCol = `reply_date_r${r}`;
                const respCol = `response_date_r${r}`;
                
                // 如果是新增事項（round=1），也更新內容和其他欄位
                // 優先使用 item.replyDate，如果沒有則使用統一的 replyDate
                const itemReplyDate = item.replyDate || replyDate || '';
                if (r === 1) {
                    await client.query(
                        `UPDATE issues SET 
                            status=$1, content=$2, ${hCol}=$3, ${rCol}=$4, ${replyCol}=$5, ${respCol}=$6,
                            plan_name=COALESCE($7, plan_name), issue_date=COALESCE($8, issue_date),
                            year=COALESCE($9, year), unit=COALESCE($10, unit),
                            division_name=COALESCE($11, division_name),
                            inspection_category_name=COALESCE($12, inspection_category_name),
                            item_kind_code=COALESCE($13, item_kind_code),
                            updated_at=CURRENT_TIMESTAMP 
                        WHERE TRIM(number)=$14`,
                        [
                            item.status, item.content, item.handling||'', item.review||'', 
                            itemReplyDate, reviewDate||'', item.planName || null, item.issueDate || null,
                            item.year || null, item.unit || null,
                            item.divisionName || null, item.inspectionCategoryName || null,
                            item.itemKindCode || null, trimmedNumber
                        ]
                    );
                    // 記錄為更新操作
                    operationResults.push({ number: trimmedNumber, action: 'updated' });
                } else {
                    // 更新輪次資料
                    await client.query(
                        `UPDATE issues SET 
                            status=$1, ${hCol}=$2, ${rCol}=$3, ${replyCol}=$4, ${respCol}=$5,
                            plan_name=COALESCE($6, plan_name), updated_at=CURRENT_TIMESTAMP 
                        WHERE TRIM(number)=$7`,
                        [item.status, item.handling||'', item.review||'', itemReplyDate, reviewDate||'', item.planName || null, trimmedNumber]
                    );
                    operationResults.push({ number: trimmedNumber, action: 'updated' });
                }
            } else {
                // 新增記錄（使用trimmedNumber確保編號沒有前後空格）
                // 優先使用 item.replyDate，如果沒有則使用統一的 replyDate
                const itemReplyDate = item.replyDate || replyDate || '';
                await client.query(
                    `INSERT INTO issues (
                        number, year, unit, content, status, item_kind_code, category, division_name, inspection_category_name,
                        handling, review, plan_name, issue_date, response_date_r1, reply_date_r1,
                        owner_group_id, owner_user_id, edit_mode
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
                    [
                        trimmedNumber, item.year, item.unit, item.content, item.status||'持續列管',
                        item.itemKindCode, item.category, item.divisionName, item.inspectionCategoryName,
                        item.handling||'', item.review||'', item.planName || null, item.issueDate || null, 
                        reviewDate || '', itemReplyDate,
                        ownerGroupId, ownerUserId, 'GROUP'
                    ]
                );
                // 記錄為新增操作
                operationResults.push({ number: trimmedNumber, action: 'created' });
            }
        }
        
        // 如果有重複編號且內容不同，回滾事務並返回錯誤
        if (duplicateNumbers.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                error: '編號重複',
                message: `以下編號已存在且內容不同：${duplicateNumbers.map(d => d.number).join(', ')}`,
                duplicates: duplicateNumbers
            });
        }
        
        await client.query('COMMIT');
        
        // 統計新增和更新的項目（使用操作記錄）
        let newCount = 0, updateCount = 0;
        let skippedNoPermission = 0;
        const results = operationResults.map(op => {
            if (op.action === 'created') {
                newCount++;
            } else if (op.action === 'updated') {
                updateCount++;
            } else if (op.action === 'skipped_no_permission') {
                skippedNoPermission++;
            }
            return op;
        });
        
        const roundInfo = r > 1 ? `，第 ${r} 次審查` : '，初次開立';
        const planInfo = data[0]?.planName ? `，檢查計畫：${data[0].planName}` : '';
        logAction(req.session.user.username, 'IMPORT_ISSUES', `匯入開立事項：共 ${data.length} 筆（新增 ${newCount} 筆，更新 ${updateCount} 筆）${roundInfo}${planInfo}`, req);
        res.json({ 
            success: true, 
            count: data.length,
            newCount: newCount,
            updateCount: updateCount,
            skippedNoPermission,
            results: results
        });
    } catch (e) {
        await client.query('ROLLBACK');
        handleApiError(e, req, res, 'Import issues error');
    } finally {
        client.release();
    }
});

// --- Groups API ---
app.get('/api/groups', requireAuth, requireAdminOrManager, async (req, res) => {
    try {
        const r = await pool.query("SELECT id, name, is_admin_group FROM groups ORDER BY is_admin_group DESC, name ASC, id ASC");
        res.json({ data: r.rows || [] });
    } catch (e) {
        handleApiError(e, req, res, 'Get groups error');
    }
});

// --- User lookup (for managers to select collaborators) ---
// 注意：/api/users 仍維持僅系統管理群組可用；此端點僅提供最小必要欄位供 UI 選人
app.get('/api/users/lookup', requireAuth, requireAdminOrManager, async (req, res) => {
    try {
        const q = String(req.query.q || '').trim();
        let limit = parseInt(req.query.limit || '500', 10);
        if (!Number.isFinite(limit) || limit <= 0) limit = 500;
        if (limit > 5000) limit = 5000;

        const where = [];
        const params = [];
        let idx = 1;
        if (q) {
            where.push(`(u.username ILIKE $${idx} OR u.name ILIKE $${idx})`);
            params.push(`%${q}%`);
            idx++;
        }
        const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

        const r = await pool.query(
            `SELECT u.id, u.username, u.name, u.role,
                    COALESCE(BOOL_OR(g.is_admin_group = true), false) AS is_admin
             FROM users u
             LEFT JOIN user_groups ug ON ug.user_id = u.id
             LEFT JOIN groups g ON g.id = ug.group_id
             ${whereSql}
             GROUP BY u.id
             ORDER BY COALESCE(BOOL_OR(g.is_admin_group = true), false) DESC, u.role ASC, u.username ASC
             LIMIT $${idx}`,
            [...params, limit]
        );
        const data = (r.rows || []).map(u => ({
            id: u.id,
            username: u.username,
            name: u.name,
            role: u.role,
            isAdmin: u.is_admin === true
        }));
        res.json({ data });
    } catch (e) {
        handleApiError(e, req, res, 'User lookup error');
    }
});

app.post('/api/groups', requireAuth, requireAdmin, verifyCsrf, async (req, res) => {
    const name = String(req.body?.name || '').trim();
    if (!name) return res.status(400).json({ error: '群組名稱為必填' });
    try {
        const r = await pool.query("INSERT INTO groups (name) VALUES ($1) RETURNING id, name", [name]);
        logAction(req.session.user.username, 'CREATE_GROUP', `新增群組：${name}`, req).catch(() => {});
        res.json({ success: true, group: r.rows[0] });
    } catch (e) {
        handleApiError(e, req, res, 'Create group error');
    }
});

app.put('/api/groups/:id', requireAuth, requireAdmin, verifyCsrf, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const name = String(req.body?.name || '').trim();
    if (!id) return res.status(400).json({ error: 'Invalid id' });
    if (!name) return res.status(400).json({ error: '群組名稱為必填' });
    try {
        await pool.query("UPDATE groups SET name = $1 WHERE id = $2", [name, id]);
        logAction(req.session.user.username, 'UPDATE_GROUP', `更新群組：ID ${id} → ${name}`, req).catch(() => {});
        res.json({ success: true });
    } catch (e) {
        handleApiError(e, req, res, 'Update group error');
    }
});

// --- User Management API ---

app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    const { page=1, pageSize=20, q, sortField='id', sortDir='asc' } = req.query;
    const limit = parseInt(pageSize);
    const offset = (page-1)*limit;
    let where = ["1=1"], params = [], idx = 1;
    if(q) { where.push(`(u.username LIKE $${idx} OR u.name LIKE $${idx})`); params.push(`%${q}%`); idx++; }
    const safeSortFields = ['id', 'username', 'name', 'role', 'created_at'];
    const safeField = safeSortFields.includes(sortField) ? sortField : 'id';
    const order = `u.${safeField} ${sortDir==='desc'?'DESC':'ASC'}`;
    try {
        const cRes = await pool.query(`SELECT count(*) FROM users u WHERE ${where.join(" AND ")}`, params);
        const total = parseInt(cRes.rows[0].count);
        const dRes = await pool.query(
            `SELECT u.id, u.username, u.name, u.role, u.created_at,
                    COALESCE(array_agg(ug.group_id) FILTER (WHERE ug.group_id IS NOT NULL), '{}') AS group_ids,
                    COALESCE(BOOL_OR(g.is_admin_group = true), false) AS is_admin
             FROM users u
             LEFT JOIN user_groups ug ON ug.user_id = u.id
             LEFT JOIN groups g ON g.id = ug.group_id
             WHERE ${where.join(" AND ")}
             GROUP BY u.id
             ORDER BY ${order}
             LIMIT $${idx} OFFSET $${idx+1}`,
            [...params, limit, offset]
        );
        const users = (dRes.rows || []).map(u => ({
            id: u.id,
            username: u.username,
            name: u.name,
            role: u.role,
            isAdmin: u.is_admin === true,
            created_at: u.created_at,
            groupIds: Array.isArray(u.group_ids) ? u.group_ids.map(x => parseInt(x, 10)).filter(n => Number.isFinite(n)) : []
        }));
        res.json({data: users, total, page: parseInt(page), pages: Math.ceil(total/limit)});
    } catch (e) { 
        handleApiError(e, req, res, 'Get users error');
    }
});

app.post('/api/users', requireAuth, requireAdmin, verifyCsrf, async (req, res) => {
    const { username, password, name, role, groupIds } = req.body;
    const safeRoleRaw = String(role || '').toLowerCase();
    const safeRole = safeRoleRaw === 'admin' ? 'manager' : (['manager', 'viewer'].includes(safeRoleRaw) ? safeRoleRaw : 'viewer');
    const gids = Array.isArray(groupIds)
        ? groupIds.map(x => parseInt(x, 10)).filter(n => Number.isFinite(n))
        : null; // null = 不更新群組
    try {
        // Basic Validation
        if (!username || !password) return res.status(400).json({error: 'Username and password required'});
        
        // 驗證密碼複雜度
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
            return res.status(400).json({ error: passwordValidation.message });
        }
        
        const hash = bcrypt.hashSync(password, 10);
        const ins = await pool.query(
            "INSERT INTO users (username, password, name, role, must_change_password) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            [username, hash, name, safeRole, true]
        );
        const newId = ins.rows[0]?.id;
        if (newId && gids) {
            // 驗證群組存在
            const gRows = await pool.query("SELECT id FROM groups WHERE id = ANY($1)", [gids]);
            const allowedIds = new Set((gRows.rows || []).map(r => parseInt(r.id, 10)));
            for (const gid of gids) {
                if (!allowedIds.has(gid)) continue;
                await pool.query(
                    "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    [newId, gid]
                );
            }
        }
        logAction(req.session.user.username, 'CREATE_USER', `新增使用者：${name} (${username})，權限：${safeRole}`, req);
        res.json({success:true});
    } catch (e) { 
        handleApiError(e, req, res, 'Create user error');
    }
});

app.put('/api/users/:id', requireAuth, requireAdmin, verifyCsrf, async (req, res) => {
    const { name, password, role, groupIds } = req.body;
    const id = parseInt(req.params.id, 10);
    const safeRoleRaw = String(role || '').toLowerCase();
    const safeRole = safeRoleRaw === 'admin' ? 'manager' : (['manager', 'viewer'].includes(safeRoleRaw) ? safeRoleRaw : 'viewer');
    const gids = Array.isArray(groupIds)
        ? groupIds.map(x => parseInt(x, 10)).filter(n => Number.isFinite(n))
        : null; // null = 不更新群組
    try {
        // 先查詢使用者資訊以便記錄
        const userRes = await pool.query("SELECT username, name FROM users WHERE id=$1", [id]);
        const targetUser = userRes.rows[0];
        const targetUsername = targetUser ? targetUser.username : `ID:${id}`;
        const targetName = targetUser ? targetUser.name : '未知';
        
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            if (password) {
            // 驗證密碼複雜度
            const passwordValidation = validatePassword(password);
            if (!passwordValidation.valid) {
                await client.query('ROLLBACK');
                return res.status(400).json({ error: passwordValidation.message });
            }
            const hash = bcrypt.hashSync(password, 10);
            await client.query("UPDATE users SET name=$1, role=$2, password=$3, must_change_password=$4 WHERE id=$5", [name, safeRole, hash, true, id]);
            logAction(req.session.user.username, 'UPDATE_USER', `修改使用者：${targetName} (${targetUsername})，已更新姓名、權限和密碼`, req);
        } else {
            await client.query("UPDATE users SET name=$1, role=$2 WHERE id=$3", [name, safeRole, id]);
            logAction(req.session.user.username, 'UPDATE_USER', `修改使用者：${targetName} (${targetUsername})，已更新姓名和權限`, req);
        }

            if (gids !== null) {
                // replace mappings
                await client.query("DELETE FROM user_groups WHERE user_id = $1", [id]);
                if (gids.length > 0) {
                    const gRows = await client.query("SELECT id FROM groups WHERE id = ANY($1)", [gids]);
                    const allowedIds = new Set((gRows.rows || []).map(r => parseInt(r.id, 10)));
                    for (const gid of gids) {
                        if (!allowedIds.has(gid)) continue;
                        await client.query(
                            "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                            [id, gid]
                        );
                    }
                }
            }
            await client.query('COMMIT');
        } catch (e) {
            try { await client.query('ROLLBACK'); } catch (_) {}
            throw e;
        } finally {
            client.release();
        }
        res.json({success:true});
    } catch (e) { 
        handleApiError(e, req, res, 'Update user error');
    }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, verifyCsrf, async (req, res) => {
    if(parseInt(req.params.id) === req.session.user.id) return res.status(400).json({error:'Cannot self delete'});
    try {
        // 先查詢使用者資訊以便記錄
        const userRes = await pool.query("SELECT username, name FROM users WHERE id=$1", [req.params.id]);
        const targetUser = userRes.rows[0];
        const targetUsername = targetUser ? targetUser.username : `ID:${req.params.id}`;
        const targetName = targetUser ? targetUser.name : '未知';
        
        await pool.query("DELETE FROM users WHERE id=$1", [req.params.id]);
        logAction(req.session.user.username, 'DELETE_USER', `刪除使用者：${targetName} (${targetUsername})`, req);
        res.json({success:true});
    } catch (e) { 
        handleApiError(e, req, res, 'Delete user error');
    }
});

// 帳號匯入 API
app.post('/api/users/import', requireAuth, requireAdmin, verifyCsrf, async (req, res) => {
    const { data } = req.body;
    if (!data || !Array.isArray(data)) return res.status(400).json({error: '無效的資料格式'});
    
    const results = { success: 0, failed: 0, errors: [] };
    
    for (let i = 0; i < data.length; i++) {
        const row = data[i];
        const { name, username, role, password } = row;
        
        // 驗證必填欄位
        if (!name || !username || !role) {
            results.failed++;
            results.errors.push(`第 ${i + 2} 行：姓名、帳號和權限為必填`);
            continue;
        }
        
        // 驗證權限值（admin 改由「系統管理群組」決定）
        // 方案A：移除 editor
        const validRoles = ['manager', 'viewer', 'admin']; // 兼容舊匯入：admin 會存成 manager
        const roleLower = String(role || '').toLowerCase();
        if (!validRoles.includes(roleLower)) {
            results.failed++;
            results.errors.push(`第 ${i + 2} 行（${name}）：無效的權限值 "${role}"，應為：${validRoles.join(', ')}`);
            continue;
        }
        const safeRole = roleLower === 'admin' ? 'manager' : roleLower;
        
        try {
            // 檢查是否已存在相同帳號
            const checkRes = await pool.query("SELECT id FROM users WHERE username = $1", [username]);
            const exists = checkRes.rows.length > 0;
            
            if (exists) {
                // 如果已存在，更新資料（但不更新密碼，除非有提供）
                if (password) {
                    // 驗證密碼複雜度
                    const passwordValidation = validatePassword(password);
                    if (!passwordValidation.valid) {
                        results.failed++;
                        results.errors.push(`第 ${i + 2} 行（${name}）：${passwordValidation.message}`);
                        continue;
                    }
                    const hash = bcrypt.hashSync(password, 10);
                    await pool.query(
                        "UPDATE users SET name=$1, role=$2, password=$3, must_change_password=$4 WHERE username=$5",
                        [name, safeRole, hash, true, username]
                    );
                } else {
                    await pool.query(
                        "UPDATE users SET name=$1, role=$2 WHERE username=$3",
                        [name, safeRole, username]
                    );
                }
                results.success++;
            } else {
                // 如果不存在，新增帳號
                // 如果沒有提供密碼，使用預設密碼（建議在匯入時提供）
                let hash;
                if (password) {
                    // 驗證密碼複雜度
                    const passwordValidation = validatePassword(password);
                    if (!passwordValidation.valid) {
                        results.failed++;
                        results.errors.push(`第 ${i + 2} 行（${name}）：${passwordValidation.message}`);
                        continue;
                    }
                    hash = bcrypt.hashSync(password, 10);
                } else {
                    // 預設密碼為 username@123456（建議匯入時提供密碼）
                    hash = bcrypt.hashSync(`${username}@123456`, 10);
                }
                
                await pool.query(
                    "INSERT INTO users (name, username, role, password, must_change_password) VALUES ($1, $2, $3, $4, $5) RETURNING id",
                    [name, username, safeRole, hash, true]
                );
                results.success++;
            }
        } catch (e) {
            results.failed++;
            const errorMsg = `第 ${i + 2} 行（${name}）：${e.message}`;
            results.errors.push(errorMsg);
            logError(e, `Import user error - row ${i + 2}`, req).catch(() => {});
        }
    }
    
    if (results.success > 0) {
        logAction(req.session.user.username, 'IMPORT_USERS', `匯入帳號：成功 ${results.success} 筆，失敗 ${results.failed} 筆`, req);
    }
    
    res.json({
        success: true,
        successCount: results.success,
        failed: results.failed,
        errors: results.errors
    });
});

// --- Admin Logs API ---

app.get('/api/admin/logs', requireAuth, async (req, res) => {
    const isAdmin = await isAdminUser(req.session.user.id, pool);
    if(!isAdmin) return res.status(403).json({error:'Denied'});
    try {
        const { page = 1, pageSize = 50, q } = req.query;
        const limit = parseInt(pageSize);
        const offset = (parseInt(page) - 1) * limit;
        let where = ["action='LOGIN'"];
        let params = [];
        let idx = 1;
        
        if (q) {
            // 搜尋所有欄位：username, ip_address, details, login_time, created_at
            where.push(`(
                COALESCE(username, '') LIKE $${idx} OR 
                COALESCE(ip_address, '') LIKE $${idx} OR 
                COALESCE(details, '') LIKE $${idx} OR
                COALESCE(CAST(login_time AS TEXT), '') LIKE $${idx} OR
                COALESCE(CAST(created_at AS TEXT), '') LIKE $${idx}
            )`);
            params.push(`%${q}%`);
            idx++;
        }
        
        const whereClause = where.join(' AND ');
        const countQuery = `SELECT COUNT(*) FROM logs WHERE ${whereClause}`;
        const dataQuery = `SELECT * FROM logs WHERE ${whereClause} ORDER BY login_time DESC LIMIT $${idx} OFFSET $${idx + 1}`;
        
        const countResult = await pool.query(countQuery, params);
        const total = parseInt(countResult.rows[0].count);
        const pages = Math.ceil(total / limit);
        
        params.push(limit, offset);
        const { rows } = await pool.query(dataQuery, params);
        
        res.json({data:rows, total, page:parseInt(page), pages});
    } catch (e) { 
        handleApiError(e, req, res, 'Get admin logs error');
    }
});

app.get('/api/admin/action_logs', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { page = 1, pageSize = 50, q } = req.query;
        const limit = parseInt(pageSize);
        const offset = (parseInt(page) - 1) * limit;
        let where = ["action!='LOGIN'"];
        let params = [];
        let idx = 1;
        
        if (q) {
            // 搜尋所有欄位：username, action, details, ip_address, created_at
            where.push(`(
                COALESCE(username, '') LIKE $${idx} OR 
                COALESCE(action, '') LIKE $${idx} OR 
                COALESCE(details, '') LIKE $${idx} OR
                COALESCE(ip_address, '') LIKE $${idx} OR
                COALESCE(CAST(created_at AS TEXT), '') LIKE $${idx}
            )`);
            params.push(`%${q}%`);
            idx++;
        }
        
        const whereClause = where.join(' AND ');
        const countQuery = `SELECT COUNT(*) FROM logs WHERE ${whereClause}`;
        const dataQuery = `SELECT * FROM logs WHERE ${whereClause} ORDER BY created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`;
        
        const countResult = await pool.query(countQuery, params);
        const total = parseInt(countResult.rows[0].count);
        const pages = Math.ceil(total / limit);
        
        params.push(limit, offset);
        const { rows } = await pool.query(dataQuery, params);
        
        res.json({data:rows, total, page:parseInt(page), pages});
    } catch (e) { 
        handleApiError(e, req, res, 'Get admin logs error');
    }
});

app.delete('/api/admin/logs', requireAuth, requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query("DELETE FROM logs WHERE action='LOGIN'");
    res.json({success:true});
});

app.delete('/api/admin/action_logs', requireAuth, requireAdmin, verifyCsrf, async (req, res) => {
    await pool.query("DELETE FROM logs WHERE action!='LOGIN'");
    res.json({success:true});
});

// 根據時間範圍清除舊記錄
app.post('/api/admin/logs/cleanup', requireAuth, requireAdmin, verifyCsrf, async (req, res) => {
    try {
        const { days } = req.body;
        if (!days || days < 1) {
            return res.status(400).json({error:'請提供有效的保留天數（至少1天）'});
        }
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - parseInt(days));
        
        const result = await pool.query(
            "DELETE FROM logs WHERE action='LOGIN' AND login_time < $1",
            [cutoffDate]
        );
        
        logAction(req.session.user.username, 'CLEANUP_LOGS', `清除 ${days} 天前的登入紀錄，刪除 ${result.rowCount} 筆`, req);
        res.json({success:true, deleted: result.rowCount});
    } catch (e) {
        handleApiError(e, req, res, 'Cleanup logs error');
    }
});

app.post('/api/admin/action_logs/cleanup', requireAuth, requireAdmin, verifyCsrf, async (req, res) => {
    try {
        const { days } = req.body;
        if (!days || days < 1) {
            return res.status(400).json({error:'請提供有效的保留天數（至少1天）'});
        }
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - parseInt(days));
        
        const result = await pool.query(
            "DELETE FROM logs WHERE action!='LOGIN' AND created_at < $1",
            [cutoffDate]
        );
        
        logAction(req.session.user.username, 'CLEANUP_ACTION_LOGS', `清除 ${days} 天前的操作紀錄，刪除 ${result.rowCount} 筆`, req);
        res.json({success:true, deleted: result.rowCount});
    } catch (e) {
        handleApiError(e, req, res, 'Cleanup logs error');
    }
});

app.get('/api/options/plans', requireAuth, async (req, res) => {
    try {
        const { withIssues, year: yearFilter } = req.query;
        const yearCond = yearFilter ? ` AND year = $${req.query.withIssues === 'true' ? 1 : 1}` : '';
        const yearParam = yearFilter ? [String(yearFilter).trim()] : [];
        
        let planResult;
        try {
            if (withIssues === 'true') {
                const params = yearParam.length ? yearParam : [];
                const whereYear = yearParam.length ? ` AND s.year = $1` : '';
                planResult = await pool.query(`
                    SELECT DISTINCT s.plan_name AS name, s.year 
                    FROM inspection_plan_schedule s
                    INNER JOIN issues i ON i.plan_name = s.plan_name AND i.year = s.year
                    WHERE s.plan_name IS NOT NULL AND s.plan_name != ''
                        AND i.plan_name IS NOT NULL AND i.plan_name != ''
                        AND i.year IS NOT NULL AND i.year != ''
                        AND s.year IS NOT NULL AND s.year != ''
                        ${whereYear}
                    ORDER BY s.year DESC, s.plan_name ASC
                `, params);
            } else {
                const params = yearParam.length ? yearParam : [];
                const whereYear = yearParam.length ? ` AND year = $1` : '';
                planResult = await pool.query(`
                    SELECT DISTINCT plan_name AS name, year 
                    FROM inspection_plan_schedule 
                    WHERE plan_name IS NOT NULL AND plan_name != ''
                        AND year IS NOT NULL AND year != ''
                        ${whereYear}
                    ORDER BY year DESC, plan_name ASC
                `, params);
            }
        } catch (queryError) {
            console.error('Database query error in /api/options/plans:', queryError);
            return res.status(500).json({ error: '查詢資料庫時發生錯誤', details: queryError.message });
        }
        
        res.set('Cache-Control', 'no-store');
        const plans = (planResult?.rows || [])
            .filter(r => r && r.name && String(r.name).trim() !== '')
            .map(r => {
                const name = String(r.name || '').trim();
                const year = String(r.year || '').trim();
                return {
                    name,
                    year,
                    display: `${name}${year ? ` (${year})` : ''}`,
                    value: `${name}|||${year}`
                };
            });
        res.json({ data: plans });
    } catch (e) {
        console.error('Get plan options error:', e);
        handleApiError(e, req, res, 'Get plan options error');
    }
});

// --- Inspection Plans Management API ---

// 取得檢查計畫所有可用年度（用於年度選單）
app.get('/api/plans/dashboard-stats/years', requireAuth, async (req, res) => {
    try {
        const yearRes = await pool.query(`
            SELECT DISTINCT year FROM inspection_plan_schedule 
            WHERE year IS NOT NULL AND year != '' 
            ORDER BY year DESC
        `);
        const years = (yearRes.rows || []).map(r => String(r.year || '').trim()).filter(Boolean);
        res.json({ years });
    } catch (e) {
        handleApiError(e, req, res, 'Get dashboard years error');
    }
});

// 檢查計畫月曆看板統計（所有人可讀，可指定年度）
app.get('/api/plans/dashboard-stats', requireAuth, async (req, res) => {
    try {
        let selectedYear = req.query.year;
        if (!selectedYear) {
            selectedYear = String(new Date().getFullYear() - 1911).replace(/\D/g, '').slice(-3).padStart(3, '0');
        } else {
            selectedYear = String(selectedYear).replace(/\D/g, '').slice(-3).padStart(3, '0');
        }
        const thisYear = selectedYear;
        const planCountRes = await pool.query(`
            SELECT count(*) AS cnt FROM (
                SELECT plan_name, year FROM inspection_plan_schedule WHERE year = $1 GROUP BY plan_name, year
            ) g
        `, [thisYear]);
        const totalPlans = parseInt(planCountRes.rows[0]?.cnt, 10) || 0;
        const scheduleCountRes = await pool.query(`
            SELECT count(*) AS cnt FROM inspection_plan_schedule 
            WHERE (plan_number IS NULL OR plan_number <> '(手動)') AND year = $1
        `, [thisYear]);
        const totalSchedules = parseInt(scheduleCountRes.rows[0]?.cnt, 10) || 0;
        const withIssuesRes = await pool.query(`
            SELECT count(*) AS cnt FROM (
                SELECT DISTINCT s.plan_name, s.year
                FROM inspection_plan_schedule s
                INNER JOIN issues i ON i.plan_name = s.plan_name AND i.year = s.year
                WHERE s.year = $1
            ) t
        `, [thisYear]);
        const withIssues = parseInt(withIssuesRes.rows[0]?.cnt, 10) || 0;
        const byTypeRes = await pool.query(`
            SELECT inspection_type AS type, count(*) AS cnt FROM inspection_plan_schedule 
            WHERE (plan_number IS NULL OR plan_number <> '(手動)') AND year = $1
            GROUP BY inspection_type ORDER BY inspection_type
        `, [thisYear]);
        const byType = {};
        (byTypeRes.rows || []).forEach(r => { byType[String(r.type || '').trim()] = parseInt(r.cnt, 10) || 0; });
        const progressRes = await pool.query(`
            WITH g AS (
                SELECT plan_name AS name, year, MIN(id) AS min_id
                FROM inspection_plan_schedule WHERE year = $1 GROUP BY plan_name, year
            ),
            header AS (
                SELECT plan_name, year, planned_count FROM inspection_plan_schedule WHERE inspection_seq = '00' AND year = $1
            ),
            schedule_counts AS (
                SELECT plan_name, year, COUNT(*) AS cnt FROM inspection_plan_schedule 
                WHERE (plan_number IS NULL OR plan_number <> '(手動)') AND year = $1 GROUP BY plan_name, year
            )
            SELECT g.name, g.year, h.planned_count, COALESCE(sc.cnt, 0) AS schedule_count
            FROM g
            LEFT JOIN header h ON h.plan_name = g.name AND h.year = g.year
            LEFT JOIN schedule_counts sc ON sc.plan_name = g.name AND sc.year = g.year
            ORDER BY COALESCE(sc.cnt, 0) DESC
        `, [thisYear]);
        const planProgress = (progressRes.rows || []).map(r => ({
            name: r.name,
            year: r.year,
            planned_count: r.planned_count != null ? parseInt(r.planned_count, 10) : null,
            schedule_count: parseInt(r.schedule_count, 10) || 0
        }));
        const plannedSumRes = await pool.query(`
            SELECT COALESCE(SUM(CAST(planned_count AS INTEGER)), 0) AS total
            FROM inspection_plan_schedule WHERE year = $1 AND inspection_seq = '00' AND planned_count IS NOT NULL
        `, [thisYear]);
        const totalPlanned = parseInt(plannedSumRes.rows[0]?.total, 10) || 0;
        res.json({
            year: thisYear,
            totalPlans,
            totalSchedules,
            totalPlanned,
            withIssues,
            byType,
            planProgress
        });
    } catch (e) {
        handleApiError(e, req, res, 'Dashboard stats error');
    }
});

app.get('/api/plans', requireAuth, requireAdminOrManager, async (req, res) => {
    const { page=1, pageSize=20, q, year, sortField='id', sortDir='desc' } = req.query;
    const limit = parseInt(pageSize);
    const offset = (page-1)*limit;
    let where = ["1=1"], params = [], idx = 1;
    if(q) { where.push(`s.plan_name LIKE $${idx}`); params.push(`%${q}%`); idx++; }
    if(year) { where.push(`s.year = $${idx}`); params.push(year); idx++; }
    const safeSortFields = ['id', 'name', 'year', 'created_at', 'updated_at'];
    const safeField = safeSortFields.includes(sortField) ? sortField : 'id';
    const safeSortDir = sortDir === 'asc' ? 'ASC' : 'DESC';
    const orderCol = safeField === 'id' ? 'g.min_id' : safeField === 'name' ? 'g.name' : `g.${safeField}`;
    const order = `${orderCol} ${safeSortDir}`;
    try {
        const countQuery = `
            SELECT count(*) FROM (
                SELECT plan_name, year FROM inspection_plan_schedule s WHERE ${where.join(" AND ")}
                GROUP BY plan_name, year
            ) g`;
        const cRes = await pool.query(countQuery, params);
        const total = parseInt(cRes.rows[0].count);
        
        const dataQuery = `
            WITH g AS (
                SELECT plan_name AS name, year, MIN(id) AS min_id,
                    MIN(created_at) AS created_at, MAX(updated_at) AS updated_at
                FROM inspection_plan_schedule s WHERE ${where.join(" AND ")}
                GROUP BY plan_name, year
            ),
            header AS (
                SELECT plan_name, year, planned_count, business, railway, inspection_type
                FROM inspection_plan_schedule WHERE inspection_seq = '00'
            ),
            schedule_counts AS (
                SELECT plan_name, year, COUNT(*) AS cnt FROM inspection_plan_schedule WHERE (plan_number IS NULL OR plan_number <> '(手動)') GROUP BY plan_name, year
            )
            SELECT g.min_id AS id, g.name, g.year, g.created_at, g.updated_at,
                   COALESCE(COUNT(DISTINCT i.id), 0) AS issue_count,
                   h.planned_count, h.business, h.railway, h.inspection_type, COALESCE(sc.cnt, 0) AS schedule_count
            FROM g
            LEFT JOIN issues i ON i.plan_name = g.name AND i.year = g.year
            LEFT JOIN header h ON h.plan_name = g.name AND h.year = g.year
            LEFT JOIN schedule_counts sc ON sc.plan_name = g.name AND sc.year = g.year
            GROUP BY g.min_id, g.name, g.year, g.created_at, g.updated_at, h.planned_count, h.business, h.railway, h.inspection_type, sc.cnt
            ORDER BY ${order}
            LIMIT $${idx} OFFSET $${idx+1}
        `;
        const dRes = await pool.query(dataQuery, [...params, limit, offset]);
        
        const plansWithCounts = dRes.rows.map(row => ({
            id: row.id,
            name: row.name,
            year: row.year,
            created_at: row.created_at,
            updated_at: row.updated_at,
            issue_count: parseInt(row.issue_count) || 0,
            planned_count: row.planned_count != null ? parseInt(row.planned_count, 10) : null,
            business: row.business || null,
            railway: row.railway && String(row.railway).trim() !== '-' ? String(row.railway).trim() : null,
            inspection_type: row.inspection_type && String(row.inspection_type).trim() !== '-' ? String(row.inspection_type).trim() : null,
            schedule_count: parseInt(row.schedule_count) || 0
        }));
        
        res.json({data: plansWithCounts, total, page: parseInt(page), pages: Math.ceil(total/limit)});
    } catch (e) { 
        handleApiError(e, req, res, 'Get plans error');
    }
});

// 檢查計畫查詢 API
app.get('/api/plans/by-name', requireAuth, async (req, res) => {
    try {
        // 驗證參數
        const name = req.query.name;
        const year = req.query.year;
        
        if (!name || !year) {
            return res.status(400).json({ 
                error: '缺少必要參數',
                message: '請提供 name 和 year 參數'
            });
        }
        
        // 解碼參數
        let planName, planYear;
        try {
            planName = decodeURIComponent(String(name)).trim();
            planYear = String(year).trim();
        } catch (decodeErr) {
            planName = String(name).replace(/\+/g, ' ').trim();
            planYear = String(year).trim();
        }
        
        if (!planName || !planYear) {
            return res.status(400).json({ 
                error: '參數格式錯誤',
                message: '計畫名稱或年度不能為空'
            });
        }
        
        // 驗證資料庫連線
        if (!pool) {
            return res.status(503).json({ 
                error: '資料庫未初始化',
                message: '資料庫連線未初始化'
            });
        }
        
        // 標準化年度格式（移除前導零，統一為3位數）
        const normalizedYear = planYear.replace(/^0+/, '').padStart(3, '0');
        
        const byNameSelect = 'SELECT id, plan_name, year, railway, inspection_type, business, planned_count, owner_group_id FROM inspection_plan_schedule WHERE plan_name = $1 AND year = $2 ORDER BY id ASC LIMIT 1';
        let queryResult = await pool.query(byNameSelect, [planName, planYear]);
        if (!queryResult || !queryResult.rows || queryResult.rows.length === 0) {
            queryResult = await pool.query(byNameSelect, [planName, normalizedYear]);
        }
        if (!queryResult || !queryResult.rows || queryResult.rows.length === 0) {
            queryResult = await pool.query(
                `SELECT id, plan_name, year, railway, inspection_type, business, planned_count 
                 FROM inspection_plan_schedule 
                 WHERE plan_name = $1 AND (year = $2 OR year = $3 OR TRIM(LEADING '0' FROM year) = TRIM(LEADING '0' FROM $2))
                 ORDER BY id ASC LIMIT 1`,
                [planName, planYear, normalizedYear]
            );
        }
        if (!queryResult || !queryResult.rows || queryResult.rows.length === 0) {
            return res.status(404).json({ error: '找不到計畫', message: `找不到名稱為「${planName}」且年度為「${planYear}」的計畫` });
        }
        const plan = queryResult.rows[0];
        const railway = (plan.railway && plan.railway !== '-') ? String(plan.railway).trim() : '';
        const inspection_type = (plan.inspection_type && plan.inspection_type !== '-') ? String(plan.inspection_type).trim() : '';
        const business = (plan.business && plan.business !== '-') ? String(plan.business).trim() : '';
        const planned_count = plan.planned_count != null ? parseInt(plan.planned_count, 10) : null;
        const response = {
            data: [{
                id: plan.id,
                name: plan.plan_name,
                year: plan.year,
                railway,
                inspection_type,
                business,
                planned_count,
                owner_group_id: plan.owner_group_id
            }]
        };
        
        // 只檢查必要的欄位（不再檢查 business）
        if (!railway || !inspection_type) {
            response.warning = '該計畫缺少必要資訊（鐵路機構、檢查類別），請先在計畫管理中編輯';
        }
        
        return res.json(response);
        
    } catch (error) {
        // 記錄詳細錯誤以便除錯
        console.error('[API] /api/plans/by-name error:', error);
        console.error('[API] Error code:', error.code);
        console.error('[API] Error detail:', error.detail);
        console.error('[API] Error message:', error.message);
        console.error('[API] Request query:', req.query);
        
        // 檢查是否已經發送回應
        if (res.headersSent) {
            return;
        }
        
        // 處理資料庫連線錯誤
        if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
            return res.status(503).json({ 
                error: '資料庫連線失敗',
                message: '無法連接到資料庫，請稍後再試'
            });
        }
        
        // 返回錯誤（在非生產環境提供更詳細的錯誤訊息）
        const errorMessage = process.env.NODE_ENV === 'production' 
            ? '查詢失敗，請稍後再試'
            : (error.detail || error.message || '未知錯誤');
        
        return res.status(500).json({ 
            error: '查詢失敗',
            message: errorMessage
        });
    }
});

app.get('/api/plans/:id', requireAuth, requireAdminOrManager, async (req, res) => {
    try {
        if (req.params.id === 'by-name') return res.status(404).json({error: 'Invalid route'});
        const result = await pool.query(
            "SELECT id, plan_name AS name, year, created_at, updated_at, planned_count, business FROM inspection_plan_schedule WHERE id = $1",
            [req.params.id]
        );
        if (result.rows.length === 0) return res.status(404).json({error: 'Plan not found'});
        const row = result.rows[0];
        const scheduleCountRes = await pool.query(
            "SELECT COUNT(*) AS cnt FROM inspection_plan_schedule WHERE plan_name = $1 AND year = $2 AND (plan_number IS NULL OR plan_number <> '(手動)')",
            [row.name, row.year]
        );
        const schedule_count = parseInt(scheduleCountRes.rows[0]?.cnt, 10) || 0;
        res.json({ ...row, schedule_count });
    } catch (e) { 
        handleApiError(e, req, res, 'Get plan by id error');
    }
});

app.get('/api/plans/:id/issues', requireAuth, requireAdminOrManager, async (req, res) => {
    try {
        const planResult = await pool.query(
            "SELECT plan_name AS name, year FROM inspection_plan_schedule WHERE id = $1",
            [req.params.id]
        );
        if (planResult.rows.length === 0) return res.status(404).json({error: 'Plan not found'});
        const planName = planResult.rows[0].name;
        const planYear = planResult.rows[0].year || '';
        
        const { page=1, pageSize=20 } = req.query;
        const limit = parseInt(pageSize);
        const offset = (page-1)*limit;
        
        // 修正：加入年度條件，確保只查詢相同名稱且年度匹配的事項
        const countRes = await pool.query("SELECT count(*) FROM issues WHERE plan_name = $1 AND year = $2", [planName, planYear]);
        const total = parseInt(countRes.rows[0].count);
        const dataRes = await pool.query("SELECT * FROM issues WHERE plan_name = $1 AND year = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4", [planName, planYear, limit, offset]);
        
        res.json({data: dataRes.rows, total, page: parseInt(page), pages: Math.ceil(total/limit)});
    } catch (e) { 
        handleApiError(e, req, res, 'Get plan issues error');
    }
});

app.get('/api/plans/:id/schedules', requireAuth, requireAdminOrManager, async (req, res) => {
    try {
        const planResult = await pool.query(
            "SELECT plan_name AS name, year FROM inspection_plan_schedule WHERE id = $1",
            [req.params.id]
        );
        if (planResult.rows.length === 0) return res.status(404).json({error: 'Plan not found'});
        const planName = planResult.rows[0].name;
        const planYear = planResult.rows[0].year || '';
        
        const scheduleRes = await pool.query(
            `SELECT id, start_date, end_date, plan_number, inspection_seq, railway, inspection_type, business, plan_type, location, inspector 
             FROM inspection_plan_schedule 
             WHERE plan_name = $1 AND year = $2 
             ORDER BY start_date ASC, id ASC`,
            [planName, planYear]
        );
        
        res.json({data: scheduleRes.rows || []});
    } catch (e) { 
        handleApiError(e, req, res, 'Get plan schedules error');
    }
});

app.post('/api/plans', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    const { name, year, railway, inspection_type, business, planned_count, ownerGroupId: ownerGroupIdInput } = req.body;
    try {
        if (!name || !year) return res.status(400).json({error: '計畫名稱和年度為必填'});
        if (!railway || !inspection_type) return res.status(400).json({error: '鐵路機構、檢查類別為必填'});
        const n = name.trim();
        const y = year.trim();
        const rCode = String(railway).toUpperCase();
        const it = String(inspection_type);
        const b = business ? String(business).toUpperCase() : null;
        const pc = planned_count != null && planned_count !== '' ? parseInt(planned_count, 10) : null;
        if (pc != null && (isNaN(pc) || pc < 0)) return res.status(400).json({error: '規劃檢查次數請填寫大於等於 0 的數字'});
        const exists = await pool.query(
            "SELECT 1 FROM inspection_plan_schedule WHERE plan_name = $1 AND year = $2 LIMIT 1",
            [n, y]
        );
        if (exists.rows.length > 0) {
            return res.status(400).json({ error: `計畫名稱「${n}」在年度「${y}」已存在` });
        }
        let ownerGroupId = ownerGroupIdInput != null ? parseInt(ownerGroupIdInput, 10) : null;
        if (!Number.isFinite(ownerGroupId)) ownerGroupId = null;
        const isAdmin = await isAdminUser(req.session.user.id, pool);
        if (!isAdmin) {
            const myGids = await getUserDataGroupIds(req.session.user.id, pool);
            if (ownerGroupId == null) ownerGroupId = myGids[0] ?? null;
            if (ownerGroupId != null && !myGids.includes(ownerGroupId)) {
                return res.status(403).json({ error: 'Denied' });
            }
        } else {
            if (ownerGroupId != null) {
                const g = await pool.query("SELECT 1 FROM groups WHERE id = $1 AND COALESCE(is_admin_group, false) = false LIMIT 1", [ownerGroupId]);
                if (g.rows.length === 0) return res.status(400).json({ error: '群組不存在' });
            } else {
                ownerGroupId = await getPrimaryGroupId(req.session.user.id, pool);
            }
        }
        if (ownerGroupId == null) return res.status(400).json({ error: '請先將帳號加入至少一個資料群組' });
        const ownerUserId = req.session.user.id;
        await pool.query(
            `INSERT INTO inspection_plan_schedule (
                start_date, end_date, plan_name, year, railway, inspection_type, business, inspection_seq, plan_number, planned_count,
                owner_group_id, owner_user_id, edit_mode
             ) VALUES (NULL, NULL, $1, $2, $3, $4, $5, '00', '(手動)', $6, $7, $8, $9)`,
            [n, y, rCode, it, b, pc, ownerGroupId, ownerUserId, 'GROUP']
        );
        logAction(req.session.user.username, 'CREATE_PLAN', `新增檢查計畫：${n} (年度：${y})`, req);
        res.json({success:true});
    } catch (e) {
        handleApiError(e, req, res, 'Create plan error');
    }
});

app.put('/api/plans/:id', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    const { name, year, business, planned_count } = req.body;
    const id = req.params.id;
    try {
        const planRes = await pool.query(
            "SELECT id, plan_name AS name, year, owner_group_id, owner_user_id, edit_mode FROM inspection_plan_schedule WHERE id = $1",
            [id]
        );
        if (planRes.rows.length === 0) return res.status(404).json({error: 'Plan not found'});
        const canEdit = await canEditByOwnership(
            { id: req.session.user.id, role: req.session.user.role },
            { ...planRes.rows[0], __type: 'plan_header' },
            pool
        );
        if (!canEdit) return res.status(403).json({ error: 'Denied' });
        const oldName = planRes.rows[0].name;
        const oldYear = planRes.rows[0].year || '';
        
        if (!name || !year) return res.status(400).json({error: '計畫名稱和年度為必填'});
        const n = name.trim();
        const y = year.trim();
        const pc = planned_count != null && planned_count !== '' ? parseInt(planned_count, 10) : null;
        if (pc != null && (isNaN(pc) || pc < 0)) return res.status(400).json({error: '規劃檢查次數請填寫大於等於 0 的數字'});
        const b = business ? String(business).toUpperCase() : null;
        
        if (n !== oldName || y !== oldYear) {
            const conflict = await pool.query(
                "SELECT 1 FROM inspection_plan_schedule WHERE plan_name = $1 AND year = $2 LIMIT 1",
                [n, y]
            );
            if (conflict.rows.length > 0) {
                return res.status(400).json({ error: '計畫名稱與年度組合已存在' });
            }
            await pool.query(
                "UPDATE issues SET plan_name = $1, year = $2 WHERE plan_name = $3 AND year = $4",
                [n, y, oldName, oldYear]
            );
            await pool.query(
                "UPDATE inspection_plan_schedule SET plan_name = $1, year = $2, updated_at = CURRENT_TIMESTAMP WHERE plan_name = $3 AND year = $4",
                [n, y, oldName, oldYear]
            );
        }
        await pool.query(
            "UPDATE inspection_plan_schedule SET planned_count = $1, business = $2, updated_at = CURRENT_TIMESTAMP WHERE plan_name = $3 AND year = $4 AND inspection_seq = '00'",
            [pc, b, n, y]
        );
        logAction(req.session.user.username, 'UPDATE_PLAN', `修改檢查計畫：${oldName} → ${n} (年度：${y})`, req);
        res.json({success:true});
    } catch (e) { 
        handleApiError(e, req, res, 'Update plan error');
    }
});

app.delete('/api/plans/:id', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    try {
        const planRes = await pool.query(
            "SELECT id, plan_name AS name, year, owner_group_id, owner_user_id, edit_mode FROM inspection_plan_schedule WHERE id = $1",
            [req.params.id]
        );
        if (planRes.rows.length === 0) return res.status(404).json({error: 'Plan not found'});
        const canEdit = await canEditByOwnership(
            { id: req.session.user.id, role: req.session.user.role },
            { ...planRes.rows[0], __type: 'plan_header' },
            pool
        );
        if (!canEdit) return res.status(403).json({ error: 'Denied' });
        const planName = planRes.rows[0].name;
        const planYear = planRes.rows[0].year || '';
        
        const issueCount = await pool.query("SELECT count(*) FROM issues WHERE plan_name = $1 AND year = $2", [planName, planYear]);
        const count = parseInt(issueCount.rows[0].count);
        if (count > 0) {
            return res.status(400).json({error: `無法刪除計畫，因為尚有 ${count} 筆相關開立事項。請先刪除或轉移相關事項。`});
        }
        
        if (planYear) {
            await pool.query("DELETE FROM inspection_plan_schedule WHERE plan_name = $1 AND year = $2", [planName, planYear]);
        } else {
            await pool.query("DELETE FROM inspection_plan_schedule WHERE plan_name = $1", [planName]);
        }
        logAction(req.session.user.username, 'DELETE_PLAN', `刪除檢查計畫：${planName}${planYear ? ` (年度：${planYear})` : ''}`, req);
        res.json({success:true});
    } catch (e) { 
        handleApiError(e, req, res, 'Delete plan error');
    }
});

// 協作編修（檢查計畫主檔 00）：取得/設定可編修人員名單（跨群組）
app.get('/api/plans/:id/editors', requireAuth, requireAdminOrManager, async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id' });

        const metaRes = await pool.query(
            "SELECT id, plan_name, year, inspection_seq, owner_group_id, owner_user_id, edit_mode FROM inspection_plan_schedule WHERE id=$1",
            [id]
        );
        if (metaRes.rows.length === 0) return res.status(404).json({ error: 'Not found' });
        const meta = metaRes.rows[0];
        if (String(meta.inspection_seq) !== '00') return res.status(400).json({ error: '此端點僅適用計畫主檔（inspection_seq=00）' });

        const canEdit = await canEditByOwnership(
            { id: req.session.user.id, role: req.session.user.role },
            { ...meta, __type: 'plan_header' },
            pool
        );
        if (!canEdit) return res.status(403).json({ error: 'Denied' });

        const r = await pool.query(
            `SELECT u.id, u.username, u.name, u.role,
                    COALESCE(BOOL_OR(g.is_admin_group = true), false) AS is_admin
             FROM plan_editors pe
             JOIN users u ON u.id = pe.user_id
             LEFT JOIN user_groups ug ON ug.user_id = u.id
             LEFT JOIN groups g ON g.id = ug.group_id
             WHERE pe.plan_id = $1
             GROUP BY u.id
             ORDER BY COALESCE(BOOL_OR(g.is_admin_group = true), false) DESC, u.role ASC, u.username ASC`,
            [id]
        );
        res.json({
            data: (r.rows || []).map(u => ({
                id: u.id,
                username: u.username,
                name: u.name,
                role: u.role,
                isAdmin: u.is_admin === true
            }))
        });
    } catch (e) {
        handleApiError(e, req, res, 'Get plan editors error');
    }
});

app.put('/api/plans/:id/editors', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const editorUserIdsRaw = req.body?.editorUserIds;
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id' });
    const editorUserIds = Array.isArray(editorUserIdsRaw)
        ? Array.from(new Set(editorUserIdsRaw.map(x => parseInt(x, 10)).filter(n => Number.isFinite(n))))
        : [];
    try {
        const metaRes = await pool.query(
            "SELECT id, plan_name, year, inspection_seq, owner_group_id, owner_user_id, edit_mode FROM inspection_plan_schedule WHERE id=$1",
            [id]
        );
        if (metaRes.rows.length === 0) return res.status(404).json({ error: 'Not found' });
        const meta = metaRes.rows[0];
        if (String(meta.inspection_seq) !== '00') return res.status(400).json({ error: '此端點僅適用計畫主檔（inspection_seq=00）' });

        const canEdit = await canEditByOwnership(
            { id: req.session.user.id, role: req.session.user.role },
            { ...meta, __type: 'plan_header' },
            pool
        );
        if (!canEdit) return res.status(403).json({ error: 'Denied' });

        // 僅允許指派「資料管理者」或「系統管理群組」成員
        if (editorUserIds.length > 0) {
            const uRes = await pool.query(
                `SELECT u.id, u.role, COALESCE(BOOL_OR(g.is_admin_group = true), false) AS is_admin
                 FROM users u
                 LEFT JOIN user_groups ug ON ug.user_id = u.id
                 LEFT JOIN groups g ON g.id = ug.group_id
                 WHERE u.id = ANY($1)
                 GROUP BY u.id`,
                [editorUserIds]
            );
            const byId = new Map((uRes.rows || []).map(r => [parseInt(r.id, 10), r]));
            const invalid = editorUserIds.filter(uid => !byId.has(uid));
            if (invalid.length) return res.status(400).json({ error: `找不到使用者：${invalid.join(', ')}` });
            const notAllowed = editorUserIds.filter(uid => {
                const row = byId.get(uid);
                const isAdmin = row?.is_admin === true;
                const role = String(row?.role || '');
                return !(isAdmin || role === 'manager');
            });
            if (notAllowed.length) return res.status(400).json({ error: `僅可指派「資料管理者」或「系統管理員」：${notAllowed.join(', ')}` });
        }

        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query("DELETE FROM plan_editors WHERE plan_id = $1", [id]);
            if (editorUserIds.length > 0) {
                await client.query(
                    "INSERT INTO plan_editors (plan_id, user_id) SELECT $1, x FROM UNNEST($2::int[]) AS x ON CONFLICT DO NOTHING",
                    [id, editorUserIds]
                );
            }
            await client.query('COMMIT');
        } catch (e) {
            try { await client.query('ROLLBACK'); } catch (_) {}
            throw e;
        } finally {
            client.release();
        }
        logAction(req.session.user.username, 'UPDATE_PLAN_EDITORS', `更新檢查計畫協作編修：${meta.plan_name || ''} (${meta.year || ''})，共 ${editorUserIds.length} 人`, req).catch(()=>{});
        res.json({ success: true });
    } catch (e) {
        handleApiError(e, req, res, 'Update plan editors error');
    }
});

// 檢查計畫 CSV 匯入 API
app.post('/api/plans/import', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    const { data } = req.body; // 接收解析後的 CSV 資料
    if (!data || !Array.isArray(data)) return res.status(400).json({error: '無效的資料格式'});
    
    // 收到匯入資料（日誌已移除，只在需要時記錄錯誤）
    
    const results = { success: 0, failed: 0, errors: [], skipped: 0 };
    const ownerGroupId = await getPrimaryGroupId(req.session.user.id, pool);
    if (ownerGroupId == null) return res.status(400).json({ error: '請先將帳號加入至少一個資料群組' });
    const ownerUserId = req.session.user.id;
    
    for (let i = 0; i < data.length; i++) {
        const row = data[i];
        const name = String(row.name || row.planName || row['計畫名稱'] || row['計劃名稱'] || '').trim();
        let year = String(row.year || row['年度'] || '').trim();
        const railway = String(row.railway || row['鐵路機構'] || '').trim();
        const inspection_type = String(row.inspection_type || row.inspectionType || row['檢查類別'] || '').trim();
        const business = String(row.business || row['業務類型'] || row['業務類別'] || '').trim();
        const planned_count_raw = row.planned_count ?? row.plannedCount ?? row['規劃檢查幾次'] ?? row['規劃檢查次數'];
        const planned_count = planned_count_raw !== undefined && planned_count_raw !== null && String(planned_count_raw).trim() !== ''
            ? parseInt(String(planned_count_raw).trim(), 10)
            : null;

        if (!name && !year && !railway && !inspection_type && !business && planned_count == null) {
            results.skipped++;
            continue;
        }

        year = String(year).replace(/\D/g, '').slice(-3).padStart(3, '0');
        if (!name || !/^\d{3}$/.test(year) || !railway || !inspection_type) {
            results.failed++;
            results.errors.push(`第 ${i + 2} 行：年度、計畫名稱、鐵路機構、檢查類別為必填`);
            continue;
        }
        if (planned_count != null && (Number.isNaN(planned_count) || planned_count < 0)) {
            results.failed++;
            results.errors.push(`第 ${i + 2} 行（${name}）：規劃檢查幾次需為大於等於 0 的數字`);
            continue;
        }

        try {
            // 防止重複（同年度同名稱）
            const exists = await pool.query(
                "SELECT 1 FROM inspection_plan_schedule WHERE plan_name = $1 AND year = $2 LIMIT 1",
                [name, year]
            );
            if (exists.rows.length > 0) {
                results.failed++;
                results.errors.push(`第 ${i + 2} 行（${name}）：計畫已存在（年度 ${year}）`);
                continue;
            }

            const rCode = String(railway).toUpperCase();
            const it = String(inspection_type);
            const b = business ? String(business).toUpperCase() : null;

            await pool.query(
                `INSERT INTO inspection_plan_schedule (
                    start_date, end_date, plan_name, year, railway, inspection_type, business, inspection_seq, plan_number, planned_count,
                    owner_group_id, owner_user_id, edit_mode
                 ) VALUES (NULL, NULL, $1, $2, $3, $4, $5, '00', '(手動)', $6, $7, $8, $9)`,
                [name, year, rCode, it, b, planned_count, ownerGroupId, ownerUserId, 'GROUP']
            );
            results.success++;
        } catch (e) {
            results.failed++;
            results.errors.push(`第 ${i + 2} 行（${name || '未命名'}）：${e.message}`);
        }
    }
    
    // 完成資訊已在 logAction 中記錄
    
    if (results.success > 0) {
        logAction(req.session.user.username, 'IMPORT_PLANS', `匯入檢查計畫：成功 ${results.success} 筆，失敗 ${results.failed} 筆，跳過 ${results.skipped || 0} 筆`, req);
    }
    
    // 返回結果，使用 successCount 來避免與 success 布林值衝突
    res.json({ 
        success: true, 
        successCount: results.success,
        failed: results.failed, 
        errors: results.errors, 
        skipped: results.skipped 
    });
});

// --- 檢查計畫規劃（月曆排程）API ---
// 取號規則：年度(3碼)-鐵路機構-檢查類別-檢查次數；檢查次數由 01 起自動加 1（不再包含業務類別）
const RAILWAY_CODES = { T: '臺鐵', H: '高鐵', A: '林鐵', S: '糖鐵' };
const INSPECTION_CODES = { '1': '年度定期檢查', '2': '特別檢查', '3': '例行性檢查', '4': '臨時檢查', '5': '調查' };
const BUSINESS_CODES = { OP: '運轉', CV: '土建', ME: '機務', EL: '電務', SM: '安全管理', AD: '營運', OT: '其他' };

function getPlanScheduleLockKey(year3, railwayCode, inspectionType) {
    return `plan-schedule|${year3}|${railwayCode}|${inspectionType}`;
}

async function getNextAvailableScheduleSeq(db, year3, railwayCode, inspectionType, excludeId = null) {
    // 取最小未使用的正整數序號（01 起），不靠暫存，完全由 DB 現況推導
    // 允許 2~3 位以上（例如 100），但格式仍以 padStart(2,'0') 呈現
    const params = [year3, railwayCode, inspectionType];
    let sql = `
        SELECT inspection_seq
        FROM inspection_plan_schedule
        WHERE year = $1 AND railway = $2 AND inspection_type = $3
          AND inspection_seq <> '00'
    `;
    if (excludeId != null) {
        sql += ` AND id <> $4`;
        params.push(excludeId);
    }
    const r = await db.query(sql, params);
    const used = new Set();
    for (const row of (r.rows || [])) {
        const s = String(row.inspection_seq || '').trim();
        if (!s) continue;
        const n = parseInt(s, 10);
        if (Number.isFinite(n) && n > 0) used.add(n);
    }
    let next = 1;
    while (used.has(next)) next++;
    return String(next).padStart(2, '0');
}

app.get('/api/plan-schedule', requireAuth, async (req, res) => {
    const { year, month } = req.query;
    try {
        if (!year || !month) {
            return res.status(400).json({ error: '請提供 year 與 month 參數（西元年、月）' });
        }
        const y = parseInt(String(year), 10);
        const m = parseInt(String(month), 10);
        const start = `${y}-${String(m).padStart(2, '0')}-01`;
        const lastDay = new Date(y, m, 0).getDate();
        const end = `${y}-${String(m).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;
        const rows = await pool.query(
            `SELECT id, start_date, end_date, plan_name, year, railway, inspection_type, business, inspection_seq, plan_number, created_at, location, inspector 
             FROM inspection_plan_schedule 
             WHERE (start_date <= $2::date AND (end_date IS NULL OR end_date >= $1::date))
             ORDER BY start_date ASC, id ASC`,
            [start, end]
        );
        res.json({ data: rows.rows || [] });
    } catch (e) {
        handleApiError(e, req, res, 'Get plan schedule error');
    }
});

app.get('/api/plan-schedule/next-number', requireAuth, async (req, res) => {
    const { year, railway, inspectionType } = req.query;
    try {
        if (!year || !railway || !inspectionType) {
            return res.status(400).json({ error: '請提供 year, railway, inspectionType' });
        }
        const y = String(year).replace(/\D/g, '').slice(-3).padStart(3, '0');
        const r = String(railway).toUpperCase();
        const it = String(inspectionType);
        const seq = await getNextAvailableScheduleSeq(pool, y, r, it);
        const planNumber = `${y}${r}${it}-${seq}`;
        res.json({ nextSeq: seq, planNumber });
    } catch (e) {
        handleApiError(e, req, res, 'Get next plan number error');
    }
});

app.post('/api/plan-schedule', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    const { plan_name, start_date, end_date, year, railway, inspection_type, business, location, inspector, plan_number: clientPlanNumber } = req.body;
    const client = await pool.connect();
    try {
        // 驗證必填欄位
        if (!plan_name || !start_date || !end_date || !year || !railway || !inspection_type) {
            const missingFields = [];
            if (!plan_name) missingFields.push('計畫名稱');
            if (!start_date) missingFields.push('開始日期');
            if (!end_date) missingFields.push('結束日期');
            if (!year) missingFields.push('年度');
            if (!railway) missingFields.push('鐵路機構');
            if (!inspection_type) missingFields.push('檢查類別');
            return res.status(400).json({ 
                error: `以下欄位為必填：${missingFields.join('、')}`,
                missingFields: missingFields
            });
        }
        
        // 驗證日期格式
        if (end_date < start_date) {
            return res.status(400).json({ error: '結束日期不能早於開始日期' });
        }
        
        const y = String(year).replace(/\D/g, '').slice(-3).padStart(3, '0');
        const r = String(railway).toUpperCase();
        const it = String(inspection_type);
        
        // 驗證鐵路機構、檢查類別的值
        const validRailways = ['T', 'H', 'A', 'S'];
        const validInspectionTypes = ['1', '2', '3', '4', '5'];
        
        if (!validRailways.includes(r)) {
            return res.status(400).json({ error: `無效的鐵路機構：${r}，請選擇有效的鐵路機構` });
        }
        if (!validInspectionTypes.includes(it)) {
            return res.status(400).json({ error: `無效的檢查類別：${it}，請選擇有效的檢查類別` });
        }
        
        const name = String(plan_name).trim();
        let planNumber;
        let seq;
        
        await client.query('BEGIN');
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [getPlanScheduleLockKey(y, r, it)]);

        const ownerGroupId = await getPrimaryGroupId(req.session.user.id, client);
        if (ownerGroupId == null) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: '請先將帳號加入至少一個資料群組' });
        }
        const ownerUserId = req.session.user.id;

        // 若該計畫主檔（00）存在，需符合主檔歸屬才能新增排程，避免跨組把行程塞到別組計畫
        try {
            const headerRes = await client.query(
                "SELECT id, plan_name, year, owner_group_id, owner_user_id, edit_mode FROM inspection_plan_schedule WHERE plan_name = $1 AND year = $2 AND inspection_seq = '00' LIMIT 1",
                [name, y]
            );
            if (headerRes.rows.length > 0) {
                const ok = await canEditByOwnership(
                    { id: req.session.user.id, role: req.session.user.role },
                    { ...headerRes.rows[0], __type: 'plan_header' },
                    client
                );
                if (!ok) {
                    await client.query('ROLLBACK');
                    return res.status(403).json({ error: 'Denied' });
                }
            }
        } catch (e) {
            // 若查詢主檔失敗，讓後續流程走統一錯誤處理
            throw e;
        }

        const manualNumber = clientPlanNumber && String(clientPlanNumber).trim();
        if (manualNumber) {
            planNumber = manualNumber;
            const seqMatch = manualNumber.match(/-(\d{2,3})$/);
            if (seqMatch) {
                seq = seqMatch[1];
            } else {
                // 手動取號若未包含序號，仍自動補最小可用序號（向後兼容）
                seq = await getNextAvailableScheduleSeq(client, y, r, it);
            }
        } else {
            seq = await getNextAvailableScheduleSeq(client, y, r, it);
            planNumber = `${y}${r}${it}-${seq}`;
        }

        // 檢查序號是否已被占用（避免手動取號重複）
        const seqExists = await client.query(
            `SELECT 1 FROM inspection_plan_schedule
             WHERE year = $1 AND railway = $2 AND inspection_type = $3
               AND inspection_seq = $4 AND inspection_seq <> '00'
             LIMIT 1`,
            [y, r, it, seq]
        );
        if (seqExists.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: `取號序號 ${seq} 已被使用，請重新新增或改用自動取號` });
        }
        
        // business 欄位仍然儲存（為了向後兼容），但取號編碼不再使用
        const b = business ? String(business).toUpperCase() : null;
        
        await client.query(
            `INSERT INTO inspection_plan_schedule (
                start_date, end_date, plan_name, year, railway, inspection_type, business, inspection_seq, plan_number,
                location, inspector, owner_group_id, owner_user_id, edit_mode
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
            [start_date, end_date, name, y, r, it, b, seq, planNumber, location || null, inspector || null, ownerGroupId, ownerUserId, 'GROUP']
        );
        await client.query('COMMIT');

        const dateRange = end_date ? `${start_date} ~ ${end_date}` : start_date;
        logAction(req.session.user.username, 'CREATE_PLAN_SCHEDULE', `新增檢查計畫規劃：${name}，取號 ${planNumber}，日期 ${dateRange}`, req);
        res.json({ success: true, planNumber, inspectionSeq: seq });
    } catch (e) {
        try { await client.query('ROLLBACK'); } catch (_) {}
        // 如果是資料庫約束錯誤，提供更清楚的錯誤訊息
        if (e.code === '23505') { // 唯一約束違反
            return res.status(400).json({ error: '取號衝突（序號已被使用），請重新再試' });
        } else if (e.code === '23502') { // NOT NULL 約束違反
            return res.status(400).json({ error: '必填欄位不能為空，請檢查輸入的資料' });
        } else if (e.code === '22007' || e.code === '22008') { // 日期格式錯誤
            return res.status(400).json({ error: '日期格式錯誤，請使用正確的日期格式（YYYY-MM-DD）' });
        }
        handleApiError(e, req, res, 'Create plan schedule error');
    } finally {
        client.release();
    }
});

app.get('/api/plan-schedule/all', requireAuth, requireAdminOrManager, async (req, res) => {
    try {
        const rows = await pool.query(
            `SELECT s.id, s.start_date, s.end_date, s.plan_name, s.year, s.railway, s.inspection_type, s.business, s.inspection_seq, s.plan_number, s.created_at, s.updated_at, s.location, s.inspector,
                    (SELECT h.planned_count FROM inspection_plan_schedule h WHERE h.plan_name = s.plan_name AND h.year = s.year AND h.inspection_seq = '00' LIMIT 1) AS planned_count
             FROM inspection_plan_schedule s 
             ORDER BY s.year DESC, s.start_date ASC NULLS LAST, s.id ASC`
        );
        res.json({ data: rows.rows || [] });
    } catch (e) {
        handleApiError(e, req, res, 'Get all plan schedules error');
    }
});

// 假日資料來源：GitHub ruyut/TaiwanCalendar（中華民國政府行政機關辦公日曆）
// https://github.com/ruyut/TaiwanCalendar | CDN: cdn.jsdelivr.net/gh/ruyut/TaiwanCalendar/data/{year}.json
app.get('/api/holidays/:year', requireAuth, async (req, res) => {
    try {
        const year = parseInt(req.params.year);
        if (!year || year < 2000 || year > 2100) {
            return res.status(400).json({ error: '無效的年份' });
        }
        
        const https = require('https');
        const url = `https://cdn.jsdelivr.net/gh/ruyut/TaiwanCalendar/data/${year}.json`;
        
        return new Promise((resolve) => {
            const request = https.get(url, { timeout: 8000 }, (response) => {
                if (response.statusCode !== 200) {
                    res.json({ data: [] });
                    return resolve();
                }
                let data = '';
                response.setEncoding('utf8');
                response.on('data', (chunk) => { data += chunk; });
                response.on('end', () => {
                    try {
                        const rawData = JSON.parse(data);
                        const arr = Array.isArray(rawData) ? rawData : [];
                        const holidays = arr.map(h => {
                            const d = String(h.date || '').trim();
                            const dateStr = d.match(/^\d{8}$/)
                                ? `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}`
                                : d;
                            return {
                                date: dateStr,
                                name: (h.description || '').trim() || '假日',
                                isHoliday: h.isHoliday === true
                            };
                        });
                        res.json({ data: holidays });
                        resolve();
                    } catch (e) {
                        res.json({ data: [] });
                        resolve();
                    }
                });
            });
            request.on('error', () => {
                res.json({ data: [] });
                resolve();
            });
            request.on('timeout', () => {
                request.destroy();
                res.json({ data: [] });
                resolve();
            });
        });
    } catch (e) {
        res.json({ data: [] });
    }
});

// 下載/上傳：檢查計畫匯入 Excel 範例檔（存於資料庫）
app.get('/api/templates/plans-import-xlsx', requireAuth, async (req, res) => {
    try {
        const r = await pool.query('SELECT filename, mime, data FROM app_files WHERE key = $1', ['plans_import_xlsx']);
        if (!r.rows || r.rows.length === 0) {
            return res.status(404).json({ error: 'Template not set' });
        }
        const row = r.rows[0];
        const filename = row.filename || '檢查計畫匯入範例.xlsx';
        const mime = row.mime || 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
        res.setHeader('Content-Type', mime);
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
        res.send(row.data);
    } catch (e) {
        handleApiError(e, req, res, 'Get plans import template error');
    }
});

app.post('/api/templates/plans-import-xlsx', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    try {
        const filename = String(req.body.filename || '檢查計畫匯入範例.xlsx');
        const dataBase64 = String(req.body.dataBase64 || '');
        if (!dataBase64) return res.status(400).json({ error: '缺少檔案內容' });
        const buf = Buffer.from(dataBase64, 'base64');
        if (!buf || buf.length === 0) return res.status(400).json({ error: '檔案內容無效' });
        const mime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
        await pool.query(
            `INSERT INTO app_files (key, filename, mime, data, updated_at)
             VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
             ON CONFLICT (key) DO UPDATE SET filename = EXCLUDED.filename, mime = EXCLUDED.mime, data = EXCLUDED.data, updated_at = CURRENT_TIMESTAMP`,
            ['plans_import_xlsx', filename, mime, buf]
        );
        logAction(req.session.user.username, 'UPLOAD_TEMPLATE', `更新檢查計畫匯入範例檔：${filename}`, req);
        res.json({ success: true });
    } catch (e) {
        handleApiError(e, req, res, 'Upload plans import template error');
    }
});

// 帳號匯入 CSV 範例檔（存於資料庫）
app.get('/api/templates/users-import-csv', requireAuth, async (req, res) => {
    try {
        const r = await pool.query('SELECT filename, mime, data FROM app_files WHERE key = $1', ['users_import_csv']);
        if (!r.rows || r.rows.length === 0) {
            return res.status(404).json({ error: 'Template not set' });
        }
        const row = r.rows[0];
        const filename = row.filename || '帳號匯入範例.csv';
        const mime = row.mime || 'text/csv; charset=utf-8';
        res.setHeader('Content-Type', mime);
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
        res.send(row.data);
    } catch (e) {
        handleApiError(e, req, res, 'Get users import csv template error');
    }
});

app.post('/api/templates/users-import-csv', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    try {
        const filename = String(req.body.filename || '帳號匯入範例.csv');
        const dataBase64 = String(req.body.dataBase64 || '');
        if (!dataBase64) return res.status(400).json({ error: '缺少檔案內容' });
        const buf = Buffer.from(dataBase64, 'base64');
        if (!buf || buf.length === 0) return res.status(400).json({ error: '檔案內容無效' });
        const mime = 'text/csv; charset=utf-8';
        await pool.query(
            `INSERT INTO app_files (key, filename, mime, data, updated_at)
             VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
             ON CONFLICT (key) DO UPDATE SET filename = EXCLUDED.filename, mime = EXCLUDED.mime, data = EXCLUDED.data, updated_at = CURRENT_TIMESTAMP`,
            ['users_import_csv', filename, mime, buf]
        );
        logAction(req.session.user.username, 'UPLOAD_TEMPLATE', `更新帳號匯入範例檔：${filename}`, req);
        res.json({ success: true });
    } catch (e) {
        handleApiError(e, req, res, 'Upload users import csv template error');
    }
});

app.put('/api/plan-schedule/:id', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    const { plan_name, start_date, end_date, year, railway, inspection_type, business, location, inspector, plan_number: clientPlanNumber } = req.body;
    const client = await pool.connect();
    try {
        if (!plan_name || !start_date || !end_date || !year || !railway || !inspection_type) {
            return res.status(400).json({ error: '計畫名稱、開始日期、結束日期、年度、鐵路機構、檢查類別為必填' });
        }
        if (end_date < start_date) {
            return res.status(400).json({ error: '結束日期不能早於開始日期' });
        }
        
        await client.query('BEGIN');
        // 鎖住該筆（避免同筆同時更新）
        const r = await client.query('SELECT * FROM inspection_plan_schedule WHERE id = $1 FOR UPDATE', [req.params.id]);
        if (r.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: '找不到該筆排程' });
        }
        const oldRow = r.rows[0];

        // 依歸屬限制：避免不同 manager/群組互相誤改
        const canEdit = await canEditByOwnership({ id: req.session.user.id, role: req.session.user.role }, { ...oldRow, __type: 'schedule' }, client);
        if (!canEdit) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: 'Denied' });
        }
        
        const y = String(year).replace(/\D/g, '').slice(-3).padStart(3, '0');
        const rCode = String(railway).toUpperCase();
        const it = String(inspection_type);
        const b = business ? String(business).toUpperCase() : null;

        // 若目標計畫主檔（00）存在，需符合主檔歸屬才能把排程移入/更新到該計畫
        const targetPlanName = String(plan_name).trim();
        try {
            const headerRes = await client.query(
                "SELECT id, plan_name, year, owner_group_id, owner_user_id, edit_mode FROM inspection_plan_schedule WHERE plan_name = $1 AND year = $2 AND inspection_seq = '00' LIMIT 1",
                [targetPlanName, y]
            );
            if (headerRes.rows.length > 0) {
                const ok = await canEditByOwnership(
                    { id: req.session.user.id, role: req.session.user.role },
                    { ...headerRes.rows[0], __type: 'plan_header' },
                    client
                );
                if (!ok) {
                    await client.query('ROLLBACK');
                    return res.status(403).json({ error: 'Denied' });
                }
            }
        } catch (e) {
            throw e;
        }

        // 鎖定目標序號池，避免多人同時更新/取號撞號
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [getPlanScheduleLockKey(y, rCode, it)]);
        
        let inspection_seq = oldRow.inspection_seq;
        let plan_number = oldRow.plan_number;
        
        const manualNumber = clientPlanNumber && String(clientPlanNumber).trim();
        if (String(oldRow.inspection_seq) === '00' || String(oldRow.plan_number) === '(手動)') {
            // 計畫主檔：保持 00 / (手動)
            inspection_seq = '00';
            plan_number = '(手動)';
        } else if (manualNumber) {
            plan_number = manualNumber;
            const seqMatch = manualNumber.match(/-(\d{2,3})$/);
            if (seqMatch) {
                inspection_seq = seqMatch[1];
            } else {
                inspection_seq = await getNextAvailableScheduleSeq(client, y, rCode, it, oldRow.id);
            }
        } else {
            const oldYear = String(oldRow.year || '').trim();
            const oldRailway = String(oldRow.railway || '').trim();
            const oldType = String(oldRow.inspection_type || '').trim();
            const poolChanged = (y !== oldYear) || (rCode !== oldRailway) || (it !== oldType);
            if (poolChanged) {
                // 盡量沿用原序號（若在新池未被占用），否則改取新池最小可用序號
                const candidate = String(oldRow.inspection_seq || '').trim();
                let canKeep = false;
                if (candidate && candidate !== '00' && /^[0-9]+$/.test(candidate)) {
                    const used = await client.query(
                        `SELECT 1 FROM inspection_plan_schedule
                         WHERE year = $1 AND railway = $2 AND inspection_type = $3
                           AND inspection_seq = $4 AND id <> $5 AND inspection_seq <> '00'
                         LIMIT 1`,
                        [y, rCode, it, candidate, oldRow.id]
                    );
                    canKeep = used.rows.length === 0;
                }
                inspection_seq = canKeep ? candidate : await getNextAvailableScheduleSeq(client, y, rCode, it, oldRow.id);
                plan_number = `${y}${rCode}${it}-${inspection_seq}`;
            }
        }

        // 防呆：更新時仍檢查序號唯一性（避免手動號碼/異常狀況）
        if (String(inspection_seq) !== '00') {
            const ex = await client.query(
                `SELECT 1 FROM inspection_plan_schedule
                 WHERE year = $1 AND railway = $2 AND inspection_type = $3
                   AND inspection_seq = $4 AND id <> $5 AND inspection_seq <> '00'
                 LIMIT 1`,
                [y, rCode, it, inspection_seq, oldRow.id]
            );
            if (ex.rows.length > 0) {
                await client.query('ROLLBACK');
                return res.status(400).json({ error: `取號序號 ${inspection_seq} 已被使用，請重新選擇或改用自動取號` });
            }
        }
        
        await client.query(
            `UPDATE inspection_plan_schedule 
             SET plan_name = $1, start_date = $2, end_date = $3, year = $4, railway = $5, 
                 inspection_type = $6, business = $7, inspection_seq = $8, plan_number = $9, 
                 location = $10, inspector = $11, updated_at = CURRENT_TIMESTAMP
             WHERE id = $12`,
            [plan_name.trim(), start_date, end_date, y, rCode, it, b, inspection_seq, plan_number, location || null, inspector || null, req.params.id]
        );
        await client.query('COMMIT');
        
        const dateRange = `${start_date} ~ ${end_date}`;
        logAction(req.session.user.username, 'UPDATE_PLAN_SCHEDULE', `更新檢查計畫規劃：${plan_name}，取號 ${plan_number}，日期 ${dateRange}`, req);
        res.json({ success: true, planNumber: plan_number });
    } catch (e) {
        try { await client.query('ROLLBACK'); } catch (_) {}
        handleApiError(e, req, res, 'Update plan schedule error');
    } finally {
        client.release();
    }
});

app.delete('/api/plan-schedule/:id', requireAuth, requireAdminOrManager, verifyCsrf, async (req, res) => {
    try {
        const r = await pool.query(
            'SELECT id, plan_name, plan_number, year, railway, inspection_type, inspection_seq, owner_group_id, owner_user_id, edit_mode FROM inspection_plan_schedule WHERE id = $1',
            [req.params.id]
        );
        if (r.rows.length === 0) return res.status(404).json({ error: '找不到該筆排程' });
        const row = r.rows[0];
        if (row.plan_number === '(手動)' || row.inspection_seq === '00') {
            return res.status(400).json({ error: '不可刪除計畫主檔，請從計畫管理刪除整個計畫' });
        }
        const canEdit = await canEditByOwnership({ id: req.session.user.id, role: req.session.user.role }, { ...row, __type: 'schedule' }, pool);
        if (!canEdit) return res.status(403).json({ error: 'Denied' });
        await pool.query('DELETE FROM inspection_plan_schedule WHERE id = $1', [req.params.id]);
        // 不再刪除後重新編號：避免一次刪除影響大量資料；缺號會在下一次新增時以「最小可用序號」補回
        logAction(req.session.user.username, 'DELETE_PLAN_SCHEDULE', `刪除檢查計畫規劃：${row.plan_name}（${row.plan_number}）`, req);
        res.json({ success: true });
    } catch (e) {
        handleApiError(e, req, res, 'Delete plan schedule error');
    }
});

async function startServer() {
    try {
        await initDB();
        app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
        });
    } catch (e) {
        console.error("Server start failed:", e);
        process.exit(1);
    }
}

startServer();