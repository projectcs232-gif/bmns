import express from "express";
import mysql from "mysql2/promise";
import jwt from "jsonwebtoken";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
dotenv.config();

const app=express();
const pool=mysql.createPool({
  host:process.env.DB_HOST||"localhost",
  port:Number(process.env.DB_PORT||3306),
  user:process.env.DB_USER||"root",
  password:process.env.DB_PASSWORD||"",
  database:process.env.DB_NAME||"bmns_keyvault",
  waitForConnections:true,connectionLimit:10,queueLimit:0
});
const JWT_SECRET=process.env.JWT_SECRET;
const PORT=Number(process.env.PORT||3000);
if(!JWT_SECRET||JWT_SECRET.length<32) throw new Error("Set JWT_SECRET to at least 32 characters in .env");
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"10mb"}));
app.use(express.static("public"));
const authLimit=rateLimit({windowMs:15*60*1000,limit:25,standardHeaders:true,legacyHeaders:false});
const apiLimit=rateLimit({windowMs:60*1000,limit:150,standardHeaders:true,legacyHeaders:false});
const validHex=(v,n=null)=>typeof v==="string"&&/^[0-9a-f]+$/i.test(v)&&(n===null||v.length===n);
const validText=(v,n)=>typeof v==="string"&&v.trim().length>0&&v.length<=n;
const tokenFor=u=>jwt.sign({sub:String(u.id),email:u.email},JWT_SECRET,{expiresIn:"2h"});
function auth(req,res,next){
 try{const h=req.headers.authorization||"";if(!h.startsWith("Bearer "))throw 0;req.user=jwt.verify(h.slice(7),JWT_SECRET);next();}
 catch{res.status(401).json({error:"Session expired. Please log in again."});}
}

app.post("/api/auth/register",authLimit,async(req,res)=>{
 const {email,saltHex,verifierIvHex,verifierDataHex}=req.body||{};
 if(!validText(email,320)||!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)||!validHex(saltHex,32)||!validHex(verifierIvHex,24)||!validHex(verifierDataHex)||verifierDataHex.length<2)
  return res.status(400).json({error:"Invalid registration details."});
 try{
  const [r]=await pool.execute("INSERT INTO vault_users(email,salt_hex,verifier_iv_hex,verifier_data_hex) VALUES(?,?,?,?)",[email.trim().toLowerCase(),saltHex,verifierIvHex,verifierDataHex]);
  res.status(201).json({token:tokenFor({id:r.insertId,email:email.trim().toLowerCase()})});
 }catch(e){if(e.code==="ER_DUP_ENTRY")return res.status(409).json({error:"This email already exists. Please log in."});console.error(e);res.status(500).json({error:"Could not create account."});}
});
app.post("/api/auth/login",authLimit,async(req,res)=>{
 const {email}=req.body||{};
 if(!validText(email,320))return res.status(400).json({error:"Enter your email."});
 try{
  const [rows]=await pool.execute("SELECT id,email,salt_hex,verifier_iv_hex,verifier_data_hex FROM vault_users WHERE email_normalized=LOWER(TRIM(?))",[email]);
  if(!rows.length)return res.status(401).json({error:"Account not found. Register or import your old vault first."});
  const u=rows[0];
  res.json({token:tokenFor(u),saltHex:u.salt_hex,verifierIvHex:u.verifier_iv_hex,verifierDataHex:u.verifier_data_hex});
 }catch(e){console.error(e);res.status(500).json({error:"Login failed."});}
});
app.get("/api/entries",auth,apiLimit,async(req,res)=>{
 try{const [rows]=await pool.execute("SELECT id,account_name,account_username,password_iv_hex,password_data_hex FROM vault_entries WHERE user_id=? ORDER BY created_at DESC",[req.user.sub]);res.json(rows);}
 catch(e){console.error(e);res.status(500).json({error:"Could not load vault entries."});}
});
app.post("/api/entries",auth,apiLimit,async(req,res)=>{
 const {accountName,accountUsername,passwordIvHex,passwordDataHex}=req.body||{};
 if(!validText(accountName,255)||typeof accountUsername!=="string"||accountUsername.length>320||!validHex(passwordIvHex,24)||!validHex(passwordDataHex)||passwordDataHex.length<2)return res.status(400).json({error:"Invalid credential details."});
 try{const [r]=await pool.execute("INSERT INTO vault_entries(user_id,account_name,account_username,password_iv_hex,password_data_hex) VALUES(?,?,?,?,?)",[req.user.sub,accountName.trim(),accountUsername.trim(),passwordIvHex,passwordDataHex]);res.status(201).json({id:r.insertId});}
 catch(e){console.error(e);res.status(500).json({error:"Could not save credential."});}
});
app.put("/api/entries/:id",auth,apiLimit,async(req,res)=>{
 const {accountName,accountUsername,passwordIvHex,passwordDataHex}=req.body||{};
 if(!/^\d+$/.test(req.params.id)||!validText(accountName,255)||typeof accountUsername!=="string"||accountUsername.length>320||!validHex(passwordIvHex,24)||!validHex(passwordDataHex)||passwordDataHex.length<2)return res.status(400).json({error:"Invalid credential details."});
 try{const [r]=await pool.execute("UPDATE vault_entries SET account_name=?,account_username=?,password_iv_hex=?,password_data_hex=? WHERE id=? AND user_id=?",[accountName.trim(),accountUsername.trim(),passwordIvHex,passwordDataHex,req.params.id,req.user.sub]);if(!r.affectedRows)return res.status(404).json({error:"Credential not found."});res.json({success:true});}
 catch(e){console.error(e);res.status(500).json({error:"Could not update credential."});}
});
app.delete("/api/entries/:id",auth,apiLimit,async(req,res)=>{
 if(!/^\d+$/.test(req.params.id))return res.status(400).json({error:"Invalid ID."});
 try{const [r]=await pool.execute("DELETE FROM vault_entries WHERE id=? AND user_id=?",[req.params.id,req.user.sub]);if(!r.affectedRows)return res.status(404).json({error:"Credential not found."});res.json({success:true});}
 catch(e){console.error(e);res.status(500).json({error:"Could not delete credential."});}
});

/* Import the legacy localStorage object. Existing encrypted values are copied unchanged.
   No master passwords or plaintext vault passwords are needed for this transfer. */
app.post("/api/migrate-legacy",async(req,res)=>{
 const migrationKey=req.headers["x-migration-key"];
 if(!process.env.MIGRATION_KEY || migrationKey!==process.env.MIGRATION_KEY)
  return res.status(401).json({error:"Invalid migration key."});
 const accounts=req.body?.accounts;
 if(!accounts||typeof accounts!=="object"||Array.isArray(accounts))return res.status(400).json({error:"Upload the exported keyvault_accounts JSON object."});
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  let importedUsers=0,importedEntries=0,skipped=0;
  for(const [email,record] of Object.entries(accounts)){
   if(!validText(email,320)||!record||!validHex(record.salt,32)||!record.verifier||!validHex(record.verifier.iv,24)||!validHex(record.verifier.data)||!Array.isArray(record.vault)){skipped++;continue;}
   const normalized=email.trim().toLowerCase();
   const [existing]=await conn.execute("SELECT id FROM vault_users WHERE email_normalized=LOWER(?)",[normalized]);
   let userId;
   if(existing.length){
    userId=existing[0].id;
    const [mark]=await conn.execute("SELECT id FROM legacy_imports WHERE legacy_email=?",[normalized]);
    if(mark.length){skipped++;continue;}
    await conn.execute("UPDATE vault_users SET salt_hex=?,verifier_iv_hex=?,verifier_data_hex=? WHERE id=?",
      [record.salt,record.verifier.iv,record.verifier.data,userId]);
   }else{
    const [u]=await conn.execute("INSERT INTO vault_users(email,salt_hex,verifier_iv_hex,verifier_data_hex) VALUES(?,?,?,?)",[normalized,record.salt,record.verifier.iv,record.verifier.data]);
    userId=u.insertId;importedUsers++;
   }
   for(const entry of record.vault){
    if(!entry||!validText(entry.account,255)||typeof entry.user!=="string"||!entry.encryptedPwd||!validHex(entry.encryptedPwd.iv,24)||!validHex(entry.encryptedPwd.data)){skipped++;continue;}
    await conn.execute("INSERT INTO vault_entries(user_id,account_name,account_username,password_iv_hex,password_data_hex) VALUES(?,?,?,?,?)",[userId,entry.account,entry.user,entry.encryptedPwd.iv,entry.encryptedPwd.data]);
    importedEntries++;
   }
   await conn.execute("INSERT IGNORE INTO legacy_imports(legacy_email) VALUES(?)",[normalized]);
  }
  await conn.commit();
  res.json({success:true,importedUsers,importedEntries,skipped});
 }catch(e){await conn.rollback();console.error(e);res.status(500).json({error:"Import failed; transaction rolled back."});}
 finally{conn.release();}
});
app.get("/api/health",async(_req,res)=>{try{await pool.query("SELECT 1");res.json({status:"ok",database:"connected"});}catch{res.status(503).json({status:"error",database:"unavailable"});}});
app.listen(PORT,()=>console.log(`BMNS KeyVault running at http://localhost:${PORT}`));
