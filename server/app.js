import express from 'express';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const scrypt = promisify(scryptCallback);
const lifetime = 7 * 24 * 60 * 60 * 1000;
const hashToken = token => createHash('sha256').update(token).digest('hex');
const safeUser = user => ({ id: user.id, name: user.name, email: user.email, isDemo: Boolean(user.is_demo) });
const fail = (status, message) => Object.assign(new Error(message), { status });
async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  return `${salt}:${(await scrypt(password, salt, 64)).toString('hex')}`;
}
async function verifyPassword(password, stored) {
  const [salt, digest] = stored.split(':');
  const actual = await scrypt(password, salt, 64);
  const expected = Buffer.from(digest, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
function textField(value, label, max, required = false) {
  if (value === undefined && !required) return '';
  if (typeof value !== 'string') throw fail(400, `${label} must be text.`);
  const text = value.trim();
  if ((required && !text) || text.length > max) throw fail(400, `${label} is required and must be under ${max + 1} characters.`);
  return text;
}
export const categories = ['Food', 'Transport', 'Shopping', 'Housing', 'Health', 'Entertainment', 'Education', 'Salary', 'Freelance', 'Other'];
function monthInput(value) {
  if (typeof value !== 'string' || !/^20\d{2}-(0[1-9]|1[0-2])$/.test(value)) throw fail(400, 'Choose a valid month (2000–2099).');
  return value;
}
function amountInput(value) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,6})(\.\d{1,2})?$/.test(value)) throw fail(400, 'Enter an amount with up to two decimal places.');
  const [whole, fraction = ''] = value.split('.');
  const cents = Number(whole) * 100 + Number(fraction.padEnd(2, '0'));
  if (cents <= 0) throw fail(400, 'Amount must be greater than zero.');
  return cents;
}
function transactionInput(body) {
  const description = textField(body.description, 'Description', 120, true);
  if (!['income', 'expense'].includes(body.type)) throw fail(400, 'Choose income or expense.');
  if (!categories.includes(body.category)) throw fail(400, 'Choose a valid category.');
  const occurred_on = textField(body.occurred_on, 'Date', 10, true);
  if (!/^20\d{2}-\d{2}-\d{2}$/.test(occurred_on) || !Number.isFinite(Date.parse(occurred_on)) || new Date(occurred_on).toISOString().slice(0,10) !== occurred_on) throw fail(400, 'Choose a valid date (2000–2099).');
  return {description, type: body.type, category: body.category, amount_cents: amountInput(body.amount), occurred_on};
}

export function createApp(db, options = {}) {
  const app = express();
  app.disable('x-powered-by');
  const production = options.production ?? process.env.NODE_ENV === 'production';
  const origin = options.origin || process.env.APP_ORIGIN || 'http://localhost:5174';
  app.use(helmet({ strictTransportSecurity: production ? undefined : false, contentSecurityPolicy: { directives: { 'upgrade-insecure-requests': production ? [] : null } } }));
  app.use(express.json({ limit: '16kb' }));
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.get('origin') && req.get('origin') !== origin) return next(fail(403, 'This request came from an untrusted origin.'));
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !req.is('application/json')) return next(fail(415, 'Send application/json.'));
    next();
  });
  app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 60, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many attempts. Please try again in 15 minutes.' } }));

  const cookieOptions = { httpOnly: true, sameSite: 'lax', secure: production, path: '/', maxAge: lifetime };
  function readToken(req) {
    return (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith('pennywise_session='))?.slice('pennywise_session='.length);
  }
  async function session(req, res, user) {
    const old = readToken(req);
    if (old) await db.run('DELETE FROM sessions WHERE token_hash = ?', [hashToken(old)]);
    const token = randomBytes(32).toString('hex');
    await db.run('DELETE FROM sessions WHERE expires_at < ?', [Date.now()]);
    await db.run('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)', [hashToken(token), user.id, Date.now() + lifetime]);
    res.cookie('pennywise_session', token, cookieOptions);
    return safeUser(user);
  }
  async function authenticate(req, res, next) {
    const token = readToken(req);
    const user = token && await db.get('SELECT users.* FROM users JOIN sessions ON sessions.user_id = users.id WHERE sessions.token_hash = ? AND sessions.expires_at > ?', [hashToken(token), Date.now()]);
    if (!user) throw fail(401, 'Please sign in to continue.');
    req.user = user;
    next();
  }
  async function insertTransaction(userId, fields) {
    const row = { id: randomUUID(), ...fields, created_at: Date.now() };
    await db.run('INSERT INTO transactions (id,user_id,description,type,category,amount_cents,occurred_on,created_at) VALUES (?,?,?,?,?,?,?,?)', [row.id,userId,row.description,row.type,row.category,row.amount_cents,row.occurred_on,row.created_at]);
    return row;
  }
  app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
  app.post('/api/auth/register', async (req, res) => {
    const name = textField(req.body?.name, 'Name', 80, true);
    const email = textField(req.body?.email, 'Email', 254, true).toLowerCase();
    const password = req.body?.password;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw fail(400, 'Enter a valid email address.');
    if (typeof password !== 'string' || password.length < 10 || password.length > 128) throw fail(400, 'Use a password with 10 to 128 characters.');
    if (await db.get('SELECT id FROM users WHERE email = ?', [email])) throw fail(409, 'An account with this email already exists.');
    const user = { id: randomUUID(), name, email, is_demo: 0 };
    try {
      await db.run('INSERT INTO users (id, name, email, password_hash, is_demo, created_at) VALUES (?, ?, ?, ?, ?, ?)', [user.id, name, email, await hashPassword(password), 0, Date.now()]);
    } catch (error) {
      if (error.code === 'ER_DUP_ENTRY' || error.code?.startsWith('ERR_SQLITE') && error.message.includes('UNIQUE')) throw fail(409, 'An account with this email already exists.');
      throw error;
    }
    res.status(201).json({ user: await session(req, res, user) });
  });
  app.post('/api/auth/login', async (req, res) => {
    const email = textField(req.body?.email, 'Email', 254, true).toLowerCase();
    const password = req.body?.password;
    if (typeof password !== 'string' || password.length > 128) throw fail(400, 'Enter a valid password.');
    const user = await db.get('SELECT * FROM users WHERE email = ? AND is_demo = 0', [email]);
    // A dummy derivation avoids skipping the slow hash for unknown accounts.
    const valid = await verifyPassword(password, user?.password_hash || `${'0'.repeat(32)}:${'0'.repeat(128)}`);
    if (!user || !valid) throw fail(401, 'Email or password is incorrect.');
    res.json({ user: await session(req, res, user) });
  });
  app.post('/api/auth/demo', async (req, res) => {
    await db.run('DELETE FROM users WHERE is_demo = 1 AND created_at < ?', [Date.now() - lifetime]);
    const user = { id: randomUUID(), name: 'Alex', email: `${randomUUID()}@demo.invalid`, is_demo: 1 };
    await db.run('INSERT INTO users (id, name, email, password_hash, is_demo, created_at) VALUES (?, ?, ?, ?, ?, ?)', [user.id, user.name, user.email, await hashPassword(randomBytes(32).toString('hex')), 1, Date.now()]);
    const month = new Date().toISOString().slice(0,7);
    const samples = [
      ['Monthly salary','income','Salary',4200000,'01'],
      ['Weekend freelance','income','Freelance',800000,'08'],
      ['Apartment rent','expense','Housing',1200000,'02'],
      ['Weekly groceries','expense','Food',235050,'06'],
      ['Metro pass','expense','Transport',120000,'03'],
      ['Dinner with friends','expense','Food',145000,'12'],
      ['New headphones','expense','Shopping',299900,'15'],
      ['Movie night','expense','Entertainment',65000,'18'],
      ['Online course','expense','Education',149900,'20']
    ];
    for (const [description,type,category,amount_cents,day] of samples) await insertTransaction(user.id, {description,type,category,amount_cents,occurred_on: month+'-'+day});
    await db.run('INSERT INTO budgets (user_id,month,amount_cents) VALUES (?,?,?)',[user.id,month,3000000]);
    res.status(201).json({ user: await session(req, res, user) });
  });
  app.get('/api/auth/me', authenticate, (req, res) => res.json({ user: safeUser(req.user) }));
  app.post('/api/auth/logout', async (req, res) => {
    const token = readToken(req);
    if (token) await db.run('DELETE FROM sessions WHERE token_hash = ?', [hashToken(token)]);
    res.clearCookie('pennywise_session', { httpOnly: true, sameSite: 'lax', secure: production, path: '/' });
    res.json({ ok: true });
  });
  app.get('/api/dashboard', authenticate, async (req,res) => {
    const month = monthInput(req.query.month);
    const where = 'user_id = ? AND occurred_on LIKE ?';
    const args = [req.user.id, month+'-%'];
    const transactions = await db.all(`SELECT id,description,type,category,amount_cents,occurred_on FROM transactions WHERE ${where} ORDER BY occurred_on DESC,created_at DESC`,args);
    const totals = await db.get(`SELECT COALESCE(SUM(CASE WHEN type = 'income' THEN amount_cents ELSE 0 END),0) AS income, COALESCE(SUM(CASE WHEN type = 'expense' THEN amount_cents ELSE 0 END),0) AS expenses FROM transactions WHERE ${where}`,args);
    const categories = await db.all(`SELECT category, SUM(amount_cents) AS total FROM transactions WHERE ${where} AND type = 'expense' GROUP BY category ORDER BY total DESC`,args);
    const daily = await db.all(`SELECT occurred_on, SUM(amount_cents) AS total FROM transactions WHERE ${where} AND type = 'expense' GROUP BY occurred_on ORDER BY occurred_on`,args);
    const budget = await db.get('SELECT amount_cents FROM budgets WHERE user_id = ? AND month = ?',[req.user.id,month]);
    res.json({transactions, income:Number(totals.income), expenses:Number(totals.expenses), categories:categories.map(x=>({...x,total:Number(x.total)})),daily:daily.map(x=>({...x,total:Number(x.total)})),budget:budget ? Number(budget.amount_cents) : null});
  });
  app.post('/api/transactions', authenticate, async (req,res) => res.status(201).json({transaction:await insertTransaction(req.user.id,transactionInput(req.body || {}))}));
  app.put('/api/transactions/:id', authenticate, async (req,res) => {
    if (!await db.get('SELECT id FROM transactions WHERE id = ? AND user_id = ?',[req.params.id,req.user.id])) throw fail(404,'Transaction not found.');
    const v=transactionInput(req.body || {});
    await db.run('UPDATE transactions SET description=?,type=?,category=?,amount_cents=?,occurred_on=? WHERE id=? AND user_id=?',[v.description,v.type,v.category,v.amount_cents,v.occurred_on,req.params.id,req.user.id]);
    res.json({ok:true});
  });
  app.delete('/api/transactions/:id', authenticate, async (req,res) => {
    if (!await db.get('SELECT id FROM transactions WHERE id = ? AND user_id = ?',[req.params.id,req.user.id])) throw fail(404,'Transaction not found.');
    await db.run('DELETE FROM transactions WHERE id = ? AND user_id = ?',[req.params.id,req.user.id]);
    res.json({ok:true});
  });
  app.put('/api/budget', authenticate, async (req,res) => {
    const month=monthInput(req.body?.month), amount=amountInput(req.body?.amount);
    await db.run('INSERT INTO budgets (user_id,month,amount_cents) VALUES (?,?,?) ON DUPLICATE KEY UPDATE amount_cents = ?',[req.user.id,month,amount,amount]);
    res.json({ok:true});
  });
  app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint not found.' }));
  const dist = resolve('dist');
  if (existsSync(dist)) {
    app.use(express.static(dist));
    app.get('/{*path}', (req, res) => res.sendFile(resolve(dist, 'index.html')));
  }
  app.use((err, req, res, next) => {
    if (err.status && err.status < 500) return res.status(err.status).json({ error: err.type === 'entity.parse.failed' ? 'Invalid JSON.' : err.message });
    console.error('Request failed:', err.message);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  });
  return app;
}
