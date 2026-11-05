import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import crypto from 'node:crypto';

const { Pool } = pg;
const required = ['DATABASE_URL','JWT_SECRET','ADMIN_PASSWORD'];
for (const key of required) if (!process.env[key]) throw new Error(`Missing required environment variable: ${key}`);
if (process.env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters');
if (process.env.ADMIN_PASSWORD.length < 12) throw new Error('ADMIN_PASSWORD must be at least 12 characters');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false } });
const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({ origin(origin, cb) { if (!origin || origin.startsWith('chrome-extension://') || origin.startsWith('https://')) return cb(null, true); return cb(new Error('Origin not allowed')); }, methods:['GET','POST','PUT','PATCH','DELETE','OPTIONS'], allowedHeaders:['Content-Type','Authorization'] }));
app.use(express.json({ limit:'1mb' }));
app.use('/api/auth/login', rateLimit({ windowMs: 15*60*1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false }));

const cleanUser = r => ({ uid:r.id, email:r.username, displayName:r.display_name, role:r.role, status:r.status, online:!!r.online, expiresAt:r.expires_at ? new Date(r.expires_at).toISOString() : undefined, createdAt:new Date(r.created_at).toISOString(), updatedAt:new Date(r.updated_at).toISOString() });
async function init(){
 await pool.query(`CREATE TABLE IF NOT EXISTS td_users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','operator')), status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')), online BOOLEAN NOT NULL DEFAULT FALSE, expires_at TIMESTAMPTZ NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
 const username=String(process.env.ADMIN_USERNAME||'admin').trim();
 const existing=await pool.query('SELECT id FROM td_users WHERE username=$1',[username]);
 if(!existing.rowCount){const hash=await bcrypt.hash(process.env.ADMIN_PASSWORD,12);await pool.query('INSERT INTO td_users(id,username,password_hash,display_name,role,status) VALUES($1,$2,$3,$4,\'admin\',\'active\')',[crypto.randomUUID(),username,hash,process.env.ADMIN_DISPLAY_NAME||'TEAM DUONG ADMIN']);}
}
function auth(req,res,next){const h=req.headers.authorization||'';const token=h.startsWith('Bearer ')?h.slice(7):'';try{req.user=jwt.verify(token,process.env.JWT_SECRET);next()}catch{return res.status(401).json({error:'Phiên đăng nhập không hợp lệ hoặc đã hết hạn.'})}}
function admin(req,res,next){if(req.user?.role!=='admin')return res.status(403).json({error:'Chỉ Admin mới được phép thực hiện.'});next()}
app.get('/health',(_req,res)=>res.json({ok:true,service:'TEAM DUONG Auth API'}));
app.post('/api/auth/login',async(req,res)=>{try{const identifier=String(req.body?.identifier||'').trim();const password=String(req.body?.password||'');if(!identifier||!password)return res.status(400).json({error:'Vui lòng nhập tài khoản và mật khẩu.'});const q=await pool.query('SELECT * FROM td_users WHERE LOWER(username)=LOWER($1)',[identifier]);const u=q.rows[0];if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:'Tài khoản hoặc mật khẩu không đúng.'});if(u.status!=='active')return res.status(403).json({error:'Tài khoản đã bị vô hiệu hóa.'});if(u.expires_at&&new Date(u.expires_at)<new Date())return res.status(403).json({error:'Tài khoản đã hết hạn.'});await pool.query('UPDATE td_users SET online=TRUE,updated_at=NOW() WHERE id=$1',[u.id]);const token=jwt.sign({sub:u.id,role:u.role,username:u.username},process.env.JWT_SECRET,{expiresIn:'12h'});res.json({token,user:{...cleanUser({...u,online:false}),online:false}})}catch(e){console.error(e);res.status(500).json({error:'Không thể đăng nhập lúc này.'})}});
app.get('/api/admin/users',auth,admin,async(_req,res)=>{try{const q=await pool.query('SELECT * FROM td_users ORDER BY created_at DESC');res.json({users:q.rows.map(cleanUser)})}catch(e){console.error(e);res.status(500).json({error:'Không thể tải danh sách người dùng.'})}});
app.put('/api/admin/users/:id',auth,admin,async(req,res)=>{try{const id=String(req.params.id);const username=String(req.body?.email||'').trim();const password=String(req.body?.password||'');const role=req.body?.role==='admin'?'admin':'operator';const status=req.body?.status==='disabled'?'disabled':'active';const displayName=String(req.body?.displayName||username).trim();const expiresAt=req.body?.expiresAt?new Date(req.body.expiresAt):null;if(!username)return res.status(400).json({error:'Tên đăng nhập không được để trống.'});if(password&&password.length<8)return res.status(400).json({error:'Mật khẩu thành viên phải có ít nhất 8 ký tự.'});if(expiresAt&&Number.isNaN(expiresAt.getTime()))return res.status(400).json({error:'Ngày hết hạn không hợp lệ.'});const old=await pool.query('SELECT id FROM td_users WHERE id=$1',[id]);if(!old.rowCount&&!password)return res.status(400).json({error:'Cần đặt mật khẩu cho tài khoản mới.'});const hash=password?await bcrypt.hash(password,12):null;if(old.rowCount){await pool.query('UPDATE td_users SET username=$2,display_name=$3,role=$4,status=$5,expires_at=$6,password_hash=COALESCE($7,password_hash),updated_at=NOW() WHERE id=$1',[id,username,displayName,role,status,expiresAt,hash]);}else{await pool.query('INSERT INTO td_users(id,username,password_hash,display_name,role,status,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)',[id,username,hash,displayName,role,status,expiresAt]);}const q=await pool.query('SELECT * FROM td_users WHERE id=$1',[id]);res.json({user:cleanUser(q.rows[0])})}catch(e){if(e.code==='23505')return res.status(409).json({error:'Tên đăng nhập đã được sử dụng.'});console.error(e);res.status(500).json({error:'Không thể lưu tài khoản.'})}});
app.patch('/api/admin/users/:id/status',auth,admin,async(req,res)=>{const status=req.body?.status==='disabled'?'disabled':'active';const q=await pool.query('UPDATE td_users SET status=$2,updated_at=NOW() WHERE id=$1 RETURNING id',[req.params.id,status]);if(!q.rowCount)return res.status(404).json({error:'Không tìm thấy tài khoản.'});res.json({ok:true})});
app.patch('/api/admin/users/:id/online',auth,async(req,res)=>{if(req.user.sub!==req.params.id&&req.user.role!=='admin')return res.status(403).json({error:'Không có quyền.'});const q=await pool.query('UPDATE td_users SET online=$2,updated_at=NOW() WHERE id=$1',[req.params.id,!!req.body?.online]);if(!q.rowCount)return res.status(404).json({error:'Không tìm thấy tài khoản.'});res.json({ok:true})});
app.delete('/api/admin/users/:id',auth,admin,async(req,res)=>{if(req.params.id===req.user.sub)return res.status(400).json({error:'Không thể tự xóa tài khoản đang đăng nhập.'});const q=await pool.query('DELETE FROM td_users WHERE id=$1',[req.params.id]);if(!q.rowCount)return res.status(404).json({error:'Không tìm thấy tài khoản.'});res.json({ok:true})});
app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:'Lỗi máy chủ.'})});
const port=Number(process.env.PORT||10000);
init().then(()=>app.listen(port,()=>console.log(`TEAM DUONG Auth API listening on ${port}`))).catch(e=>{console.error('Startup failed',e);process.exit(1)});
