import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { Pool } = pg;
const required = ['DATABASE_URL','JWT_SECRET','ADMIN_PASSWORD'];
for (const key of required) if (!process.env[key]) throw new Error(\`Missing required environment variable: \${key}\`);
if (process.env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters');
if (process.env.ADMIN_PASSWORD.length < 12) throw new Error('ADMIN_PASSWORD must be at least 12 characters');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false } });
const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc:["'self'"], scriptSrc:["'self'"], styleSrc:["'self'"], imgSrc:["'self'","data:"], connectSrc:["'self'"], objectSrc:["'none'"], frameAncestors:["'none'"] } } }));
app.use(cors({ origin(origin, cb) { if (!origin || origin.startsWith('chrome-extension://') || origin.startsWith('https://')) return cb(null, true); return cb(new Error('Origin not allowed')); }, methods:['GET','POST','PUT','PATCH','DELETE','OPTIONS'], allowedHeaders:['Content-Type','Authorization'] }));
app.use(express.json({ limit:'1mb' }));
app.use('/api/auth/login', rateLimit({ windowMs: 15*60*1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false }));

const cleanUser = r => ({ uid:r.id, email:r.username, displayName:r.display_name, role:r.role, status:r.status, online:!!r.online, expiresAt:r.expires_at ? new Date(r.expires_at).toISOString() : undefined, createdAt:new Date(r.created_at).toISOString(), updatedAt:new Date(r.updated_at).toISOString() });

async function init(){
  await pool.query(\`
    CREATE TABLE IF NOT EXISTS td_users (
      id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','operator')),
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
      online BOOLEAN NOT NULL DEFAULT FALSE, expires_at TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  \`);
  await pool.query(\`
    CREATE TABLE IF NOT EXISTS td_activity (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES td_users(id) ON DELETE CASCADE,
      action TEXT NOT NULL, detail JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  \`);
  const username = String(process.env.ADMIN_USERNAME || 'admin').trim();
  const password = String(process.env.ADMIN_PASSWORD || '');
  const displayName = process.env.ADMIN_DISPLAY_NAME || 'TEAM DUONG ADMIN';
  const existing = await pool.query("SELECT id FROM td_users WHERE role='admin' ORDER BY created_at ASC LIMIT 1");
  const hash = await bcrypt.hash(password, 12);
  if (existing.rowCount) {
    await pool.query("UPDATE td_users SET username=$1,password_hash=$2,display_name=$3,status='active',updated_at=NOW() WHERE id=$4",[username,hash,displayName,existing.rows[0].id]);
  } else {
    await pool.query("INSERT INTO td_users(id,username,password_hash,display_name,role,status) VALUES($1,$2,$3,$4,'admin','active')",[crypto.randomUUID(),username,hash,displayName]);
  }
}
function auth(req,res,next){
  const h=req.headers.authorization||'', token=h.startsWith('Bearer ')?h.slice(7):'';
  try { req.user=jwt.verify(token,process.env.JWT_SECRET); next(); }
  catch { return res.status(401).json({error:'Phiên đăng nhập không hợp lệ hoặc đã hết hạn.'}); }
}
function admin(req,res,next){ if(req.user?.role!=='admin') return res.status(403).json({error:'Chỉ Admin mới được phép thực hiện.'}); next(); }
async function logActivity(userId, action, detail={}) {
  await pool.query('INSERT INTO td_activity(id,user_id,action,detail) VALUES($1,$2,$3,$4)',[crypto.randomUUID(),userId,action,JSON.stringify(detail)]);
}

app.get('/health',(_req,res)=>res.json({ok:true,service:'TEAM DUONG Auth API'}));
app.post('/api/auth/login',async(req,res)=>{
  try {
    const identifier=String(req.body?.identifier||'').trim(), password=String(req.body?.password||'');
    if(!identifier||!password) return res.status(400).json({error:'Vui lòng nhập tài khoản và mật khẩu.'});
    const q=await pool.query('SELECT * FROM td_users WHERE LOWER(username)=LOWER($1)',[identifier]), u=q.rows[0];
    if(!u||!(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'Tài khoản hoặc mật khẩu không đúng.'});
    if(u.status!=='active') return res.status(403).json({error:'Tài khoản đã bị vô hiệu hóa.'});
    if(u.expires_at&&new Date(u.expires_at)<new Date()) return res.status(403).json({error:'Tài khoản đã hết hạn.'});
    await pool.query('UPDATE td_users SET online=TRUE,updated_at=NOW() WHERE id=$1',[u.id]);
    const token=jwt.sign({sub:u.id,role:u.role,username:u.username},process.env.JWT_SECRET,{expiresIn:'12h'});
    await logActivity(u.id,'Đăng nhập',{});
    res.json({token,user:cleanUser({...u,online:true})});
  } catch(e) { console.error(e); res.status(500).json({error:'Không thể đăng nhập lúc này.'}); }
});
app.get('/api/auth/me',auth,async(req,res)=>{
  const q=await pool.query('SELECT * FROM td_users WHERE id=$1',[req.user.sub]);
  if(!q.rowCount||q.rows[0].status!=='active') return res.status(401).json({error:'Tài khoản không còn hoạt động.'});
  res.json({user:cleanUser(q.rows[0])});
});
app.post('/api/auth/logout',auth,async(req,res)=>{
  await pool.query('UPDATE td_users SET online=FALSE,updated_at=NOW() WHERE id=$1',[req.user.sub]);
  await logActivity(req.user.sub,'Đăng xuất',{});
  res.json({ok:true});
});
app.get('/api/overview',auth,async(req,res)=>{
  const own=await pool.query('SELECT COUNT(*)::int AS total FROM td_activity WHERE user_id=$1',[req.user.sub]);
  const recent=await pool.query('SELECT action,detail,created_at FROM td_activity WHERE user_id=$1 ORDER BY created_at DESC LIMIT 8',[req.user.sub]);
  if(req.user.role==='admin'){
    const users=await pool.query("SELECT COUNT(*)::int AS total,COUNT(*) FILTER(WHERE status='active')::int AS active,COUNT(*) FILTER(WHERE online)::int AS online FROM td_users WHERE role='operator'");
    return res.json({activityCount:own.rows[0].total,users:users.rows[0],recent:recent.rows});
  }
  res.json({activityCount:own.rows[0].total,recent:recent.rows});
});
app.get('/api/admin/users',auth,admin,async(_req,res)=>{
  const q=await pool.query("SELECT * FROM td_users WHERE role='operator' ORDER BY created_at DESC");
  res.json({users:q.rows.map(cleanUser)});
});
app.put('/api/admin/users/:id',auth,admin,async(req,res)=>{
  try {
    const id=String(req.params.id), username=String(req.body?.email||'').trim(), password=String(req.body?.password||'');
    const status=req.body?.status==='disabled'?'disabled':'active', displayName=String(req.body?.displayName||username).trim();
    const expiresAt=req.body?.expiresAt?new Date(req.body.expiresAt):null;
    if(!username) return res.status(400).json({error:'Tên đăng nhập không được để trống.'});
    if(password&&password.length<8) return res.status(400).json({error:'Mật khẩu thành viên phải có ít nhất 8 ký tự.'});
    if(expiresAt&&Number.isNaN(expiresAt.getTime())) return res.status(400).json({error:'Ngày hết hạn không hợp lệ.'});
    const old=await pool.query("SELECT id,role FROM td_users WHERE id=$1",[id]);
    if(old.rowCount&&old.rows[0].role!=='operator') return res.status(403).json({error:'Không thể sửa tài khoản Admin tại đây.'});
    if(!old.rowCount&&!password) return res.status(400).json({error:'Cần đặt mật khẩu cho tài khoản mới.'});
    const hash=password?await bcrypt.hash(password,12):null;
    if(old.rowCount) await pool.query("UPDATE td_users SET username=$2,display_name=$3,status=$4,expires_at=$5,password_hash=COALESCE($6,password_hash),updated_at=NOW() WHERE id=$1",[id,username,displayName,status,expiresAt,hash]);
    else await pool.query("INSERT INTO td_users(id,username,password_hash,display_name,role,status,expires_at) VALUES($1,$2,$3,$4,'operator',$5,$6)",[id,username,hash,displayName,status,expiresAt]);
    const q=await pool.query('SELECT * FROM td_users WHERE id=$1',[id]);
    await logActivity(req.user.sub,old.rowCount?'Cập nhật Member':'Tạo Member',{username});
    res.json({user:cleanUser(q.rows[0])});
  } catch(e) { if(e.code==='23505') return res.status(409).json({error:'Tên đăng nhập đã được sử dụng.'}); console.error(e); res.status(500).json({error:'Không thể lưu tài khoản.'}); }
});
app.patch('/api/admin/users/:id/status',auth,admin,async(req,res)=>{
  const status=req.body?.status==='disabled'?'disabled':'active';
  const q=await pool.query("UPDATE td_users SET status=$2,updated_at=NOW() WHERE id=$1 AND role='operator' RETURNING id",[req.params.id,status]);
  if(!q.rowCount) return res.status(404).json({error:'Không tìm thấy Member.'});
  await logActivity(req.user.sub,'Đổi trạng thái Member',{id:req.params.id,status});
  res.json({ok:true});
});
app.delete('/api/admin/users/:id',auth,admin,async(req,res)=>{
  const q=await pool.query("DELETE FROM td_users WHERE id=$1 AND role='operator' RETURNING id",[req.params.id]);
  if(!q.rowCount) return res.status(404).json({error:'Không tìm thấy Member.'});
  await logActivity(req.user.sub,'Xóa Member',{id:req.params.id});
  res.json({ok:true});
});
app.post('/api/activity',auth,async(req,res)=>{
  const allowed=['Mở Zalo Web','Lưu chiến dịch','Nhập danh sách CSV','Sao chép nội dung'];
  const action=String(req.body?.action||'');
  if(!allowed.includes(action)) return res.status(400).json({error:'Hoạt động không hợp lệ.'});
  await logActivity(req.user.sub,action,{});
  res.json({ok:true});
});
app.get('/api/activity',auth,async(req,res)=>{
  const q=await pool.query('SELECT action,detail,created_at FROM td_activity WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[req.user.sub]);
  res.json({activities:q.rows});
});
app.use(express.static(path.join(__dirname,'../public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'../public/index.html')));
app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:'Lỗi máy chủ.'});});
const port=Number(process.env.PORT||10000);
init().then(()=>app.listen(port,()=>console.log(\`TEAM DUONG dashboard listening on \${port}\`))).catch(e=>{console.error('Startup failed',e);process.exit(1)});
