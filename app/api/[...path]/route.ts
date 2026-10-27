import { createHmac, createHash, pbkdf2Sync, randomBytes, randomInt, randomUUID, timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { MongoClient, ObjectId, type Db, type Document } from "mongodb";
import nodemailer from "nodemailer";

export const runtime = "nodejs";
const COOKIE = "daybook_session";
const SESSION_DAYS = 30;
const PRAYERS = new Set(["Fajr", "Dhuhr", "Asr", "Maghrib", "Isha"]);
const PBKDF2_ROUNDS = 310_000;
class HttpError extends Error { constructor(public status: number, message: string) { super(message); } }

declare global { var daybookMongo: Promise<MongoClient> | undefined; var daybookIndexes: Promise<void> | undefined; }
async function database(): Promise<Db> {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error("MONGODB_URI is not configured. Add your MongoDB Atlas connection string to the Next.js environment variables.");
  global.daybookMongo ??= new MongoClient(uri, { serverApi: { version: "1" }, connectTimeoutMS: 10_000, serverSelectionTimeoutMS: 10_000, appName: "Daybook-Next" }).connect();
  const db = (await global.daybookMongo).db(process.env.MONGODB_DB || "daybook");
  global.daybookIndexes ??= Promise.all([
    db.collection("users").createIndex({ email: 1 }, { unique: true }),
    db.collection("users").createIndex({ phone: 1 }, { unique: true, sparse: true }),
    db.collection("users").createIndex({ google_sub: 1 }, { unique: true, sparse: true }),
    db.collection("users").createIndex({ firebase_uid: 1 }, { unique: true, sparse: true }),
    db.collection("sessions").createIndex({ token_hash: 1 }, { unique: true }),
    db.collection("sessions").createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 }),
    db.collection("email_verifications").createIndex({ email: 1 }, { unique: true }),
    db.collection("email_verifications").createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 }),
    db.collection("prayers").createIndex({ user_id: 1, date: 1, prayer: 1 }, { unique: true }),
    db.collection("quran_sessions").createIndex({ user_id: 1, date: -1, created_at: -1 }),
  ]).then(() => undefined);
  await global.daybookIndexes;
  return db;
}

function publicUser(user: Document) {
  const email = user.email || "";
  return { id: String(user._id), email: email.endsWith("@phone.daybook.invalid") ? "" : email, phone: user.phone || "", name: user.name || "", identifier: user.phone || email };
}
function tokenHash(token: string) { return createHash("sha256").update(token).digest("hex"); }
function hashPassword(password: string) { const salt = randomBytes(16); const value = pbkdf2Sync(password, salt, PBKDF2_ROUNDS, 32, "sha256"); return `pbkdf2_sha256$${PBKDF2_ROUNDS}$${salt.toString("hex")}$${value.toString("hex")}`; }
function verifyPassword(password: string, stored = "") {
  try { const [scheme, roundsText, saltHex, expected] = stored.split("$", 4); if (scheme !== "pbkdf2_sha256") return false; const got = pbkdf2Sync(password, Buffer.from(saltHex, "hex"), Number(roundsText), 32, "sha256").toString("hex"); return timingSafeEqual(Buffer.from(got, "hex"), Buffer.from(expected, "hex")); } catch { return false; }
}
function validDate(value: unknown) { if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false; const date = new Date(`${value}T00:00:00Z`); return !Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 10) === value; }
async function bodyJson(request: NextRequest): Promise<Record<string, any>> {
  const length = Number(request.headers.get("content-length") || 0); if (length > 32_768) throw new HttpError(400, "Request body is empty or too large.");
  let value: unknown; try { value = await request.json(); } catch { throw new HttpError(400, "Send valid JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new HttpError(400, "Send a JSON object.");
  if (Buffer.byteLength(JSON.stringify(value)) > 32_768) throw new HttpError(400, "Request body is empty or too large.");
  return value as Record<string, any>;
}
function response(request: NextRequest, payload: unknown, status = 200, token?: string | null, expiry?: Date) {
  const result = NextResponse.json(payload, { status, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY" } });
  if (token !== undefined) result.cookies.set(COOKIE, token || "", { httpOnly: true, sameSite: "lax", secure: request.nextUrl.protocol === "https:", path: "/", expires: expiry || new Date(0), ...(expiry ? { maxAge: SESSION_DAYS * 86400 } : { maxAge: 0 }) });
  return result;
}
async function createSession(request: NextRequest, db: Db, user: Document, status = 200) {
  const token = randomBytes(32).toString("base64url"), expiry = new Date(Date.now() + SESSION_DAYS * 86400_000);
  await db.collection("sessions").insertOne({ token_hash: tokenHash(token), user_id: user._id, expires_at: expiry });
  return response(request, { user: publicUser(user) }, status, token, expiry);
}
async function currentUser(request: NextRequest, db: Db) {
  const token = request.cookies.get(COOKIE)?.value; if (!token) return null;
  const session = await db.collection("sessions").findOne({ token_hash: tokenHash(token), expires_at: { $gt: new Date() } });
  return session ? db.collection("users").findOne({ _id: session.user_id }) : null;
}
function registrationEmail(value: unknown) {
  const email = String(value || "").trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, "Enter a valid email address.");
  return email;
}
async function firebaseIdentity(body: Record<string, any>) {
  const idToken = body.idToken, apiKey = process.env.FIREBASE_API_KEY;
  if (typeof idToken !== "string" || !idToken || idToken.length > 8192) throw new HttpError(400, "Complete Firebase sign-in and try again.");
  if (!apiKey) throw new HttpError(503, "Firebase sign-in is not configured yet.");
  let result: any;
  try { const res = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(apiKey)}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ idToken }), cache: "no-store", signal: AbortSignal.timeout(12_000) }); if (!res.ok) throw new Error(); result = await res.json(); }
  catch { throw new HttpError(401, "Firebase sign-in expired or could not be confirmed. Please try again."); }
  const users = result.users || []; if (users.length !== 1 || !users[0].localId) throw new HttpError(401, "Firebase sign-in could not be confirmed. Please try again.");
  return users[0];
}
function duplicate(error: unknown) { return !!error && typeof error === "object" && "code" in error && (error as {code?:number}).code === 11000; }

async function get(request: NextRequest, endpoint: string) {
  if (endpoint === "firebase-config") {
    const config = { apiKey: process.env.FIREBASE_API_KEY || "", authDomain: process.env.FIREBASE_AUTH_DOMAIN || "", projectId: process.env.FIREBASE_PROJECT_ID || "", appId: process.env.FIREBASE_APP_ID || "" };
    if (Object.values(config).some(value => !value)) throw new HttpError(503, "Firebase sign-in is not configured yet.");
    return response(request, { config });
  }
  const db = await database();
  if (endpoint === "me") { const user = await currentUser(request, db); return response(request, { user: user ? publicUser(user) : null }); }
  const user = await currentUser(request, db); if (!user) throw new HttpError(401, "Please sign in again.");
  if (endpoint === "data") {
    const [prayerRows, rows] = await Promise.all([
      db.collection("prayers").find({ user_id: user._id, prayed: true }, { projection: { _id: 0, date: 1, prayer: 1 } }).sort({ date: 1 }).toArray(),
      db.collection("quran_sessions").find({ user_id: user._id }).sort({ date: -1, created_at: -1 }).limit(1000).toArray(),
    ]);
    const prayers: Record<string,string[]> = {}; for (const row of prayerRows) (prayers[row.date] ||= []).push(row.prayer);
    const sessions = rows.map(row => ({ id: String(row._id), date: row.date, surah: row.surah || "", pages: row.pages, minutes: row.minutes || 0 }));
    return response(request, { user: publicUser(user), prayers, sessions });
  }
  if (endpoint === "export") {
    const [prayers, rows] = await Promise.all([
      db.collection("prayers").find({ user_id: user._id, prayed: true }, { projection: { _id: 0, date: 1, prayer: 1 } }).sort({ date: 1 }).toArray(),
      db.collection("quran_sessions").find({ user_id: user._id }).sort({ date: -1, created_at: -1 }).toArray(),
    ]);
    return response(request, { user: publicUser(user), prayers, sessions: rows.map(row => ({ id: String(row._id), date: row.date, surah: row.surah || "", pages: row.pages, minutes: row.minutes || 0, created_at: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at })), exportedAt: new Date().toISOString() });
  }
  throw new HttpError(404, "API endpoint not found.");
}

async function post(request: NextRequest, endpoint: string, body: Record<string, any>) {
  if (endpoint === "logout") { const token=request.cookies.get(COOKIE)?.value; if(token) { try { await (await database()).collection("sessions").deleteOne({token_hash:tokenHash(token)}); } catch {} } return response(request,{ok:true},200,null); }
  const db = await database();
  if (endpoint === "login") {
    const email=String(body.email||"").trim().toLowerCase(), password=body.password, user=await db.collection("users").findOne({email});
    if(!user||typeof password!=="string"||!verifyPassword(password,user.password_hash)) throw new HttpError(401,"Email or password is incorrect.");
    return createSession(request,db,user);
  }
  if (endpoint === "register-code") {
    const email=registrationEmail(body.email), password=body.password, name=String(body.name||"").trim().slice(0,32);
    if(typeof password!=="string"||password.length<10||password.length>200) throw new HttpError(400,"Use a password between 10 and 200 characters.");
    const smtpEmail=process.env.SMTP_EMAIL, smtpPassword=process.env.SMTP_APP_PASSWORD, secret=process.env.OTP_SECRET;
    if(!smtpEmail||!smtpPassword||!secret) throw new HttpError(503,"Email verification is not configured yet. Add the Gmail SMTP and OTP settings to the server.");
    if(await db.collection("users").findOne({email})) throw new HttpError(409,"An account with that email already exists. Sign in instead.");
    const now=new Date(), pending=await db.collection("email_verifications").findOne({email});
    if(pending?.last_sent_at&&now.getTime()-new Date(pending.last_sent_at).getTime()<60_000) throw new HttpError(429,"Wait a minute before requesting another code.");
    const sendTimes=(pending?.send_times||[]).filter((stamp:Date)=>now.getTime()-new Date(stamp).getTime()<3_600_000);
    if(sendTimes.length>=5) throw new HttpError(429,"Too many codes requested for this email. Try again in an hour.");
    const code=String(randomInt(0,1_000_000)).padStart(6,"0"), codeHash=createHmac("sha256",secret).update(`${email}:${code}`).digest("hex"), expiresAt=new Date(now.getTime()+600_000);
    await db.collection("email_verifications").updateOne({email},{$set:{code_hash:codeHash,name,password_hash:hashPassword(password),created_at:now,last_sent_at:now,expires_at:expiresAt,attempts:0,send_times:[...sendTimes,now]}},{upsert:true});
    try {
      const transport=nodemailer.createTransport({host:"smtp.gmail.com",port:465,secure:true,auth:{user:smtpEmail,pass:smtpPassword.replace(/\s/g,"")},connectionTimeout:12_000,greetingTimeout:12_000,socketTimeout:12_000});
      await transport.sendMail({from:`Daybook <${smtpEmail}>`,to:email,subject:"Your Daybook verification code",text:`Your Daybook verification code is ${code}. It expires in 10 minutes. If you did not request this, you can ignore this email.`,html:`<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;color:#21382f"><h2>Verify your email</h2><p>Enter this code in Daybook to finish creating your account:</p><p style="font-size:30px;font-weight:700;letter-spacing:8px">${code}</p><p>This code expires in 10 minutes. If you did not request it, you can ignore this email.</p></div>`});
    } catch { await db.collection("email_verifications").deleteOne({email,code_hash:codeHash}); throw new HttpError(502,"Could not send the verification email. Check the Gmail address and App Password."); }
    return response(request,{ok:true,message:"If this address can be registered, a verification code has been sent."});
  }
  if (endpoint === "register-verify") {
    const email=registrationEmail(body.email), code=String(body.code||"").trim(); if(!/^\d{6}$/.test(code)) throw new HttpError(400,"Enter the six-digit code from your email.");
    const secret=process.env.OTP_SECRET; if(!secret) throw new HttpError(503,"Email verification is not configured yet.");
    const pending=await db.collection("email_verifications").findOne({email}), now=new Date();
    if(!pending||pending.expires_at<=now){if(pending)await db.collection("email_verifications").deleteOne({_id:pending._id});throw new HttpError(400,"That code expired. Request a new one and try again.");}
    if((pending.attempts||0)>=5){await db.collection("email_verifications").deleteOne({_id:pending._id});throw new HttpError(429,"Too many incorrect attempts. Request a new code.");}
    const expected=createHmac("sha256",secret).update(`${email}:${code}`).digest("hex"), actual=pending.code_hash||"";
    if(expected.length!==actual.length||!timingSafeEqual(Buffer.from(expected),Buffer.from(actual))){await db.collection("email_verifications").updateOne({_id:pending._id},{$inc:{attempts:1}});throw new HttpError(401,"That code is incorrect. Check it and try again.");}
    if(await db.collection("users").findOne({email})){await db.collection("email_verifications").deleteOne({_id:pending._id});throw new HttpError(409,"An account with that email already exists. Sign in instead.");}
    let userId:ObjectId; try { userId=(await db.collection("users").insertOne({email,name:pending.name||"",password_hash:pending.password_hash,email_verified:true,created_at:now})).insertedId; }
    catch(error){if(duplicate(error)){await db.collection("email_verifications").deleteOne({_id:pending._id});throw new HttpError(409,"An account with that email already exists. Sign in instead.");}throw error;}
    await db.collection("email_verifications").deleteOne({_id:pending._id}); const user=await db.collection("users").findOne({_id:userId}); return createSession(request,db,user!,201);
  }
  if (endpoint === "firebase-login" || endpoint === "phone-verify") {
    const identity=await firebaseIdentity(body);
    if(endpoint==="phone-verify") {
      if(!/^\+[1-9]\d{7,14}$/.test(String(identity.phoneNumber||""))) throw new HttpError(401,"Phone sign-in could not be confirmed. Please try again.");
      const phone=identity.phoneNumber, uid=identity.localId; let user=await db.collection("users").findOne({firebase_uid:uid})||await db.collection("users").findOne({phone});
      if(!user){const syntheticEmail=`phone+${createHash("sha256").update(phone).digest("hex")}@phone.daybook.invalid`;try{const id=(await db.collection("users").insertOne({email:syntheticEmail,phone,firebase_uid:uid,name:"",created_at:new Date()})).insertedId;user=await db.collection("users").findOne({_id:id});}catch(error){if(duplicate(error))user=await db.collection("users").findOne({firebase_uid:uid})||await db.collection("users").findOne({phone});else throw error;}}
      else if(!user.firebase_uid){await db.collection("users").updateOne({_id:user._id,firebase_uid:{$exists:false}},{$set:{firebase_uid:uid}});user=await db.collection("users").findOne({_id:user._id});}
      if(!user)throw new HttpError(409,"Could not create your account. Please try again."); return createSession(request,db,user);
    }
    const email=String(identity.email||"").trim().toLowerCase(), google=Array.isArray(identity.providerUserInfo)&&identity.providerUserInfo.some((p:any)=>p.providerId==="google.com");
    if(!google||identity.emailVerified!==true||!email) throw new HttpError(401,"Verified Google sign-in could not be confirmed.");
    const uid=identity.localId; let user=await db.collection("users").findOne({firebase_uid:uid})||await db.collection("users").findOne({email});
    if(user){if(user.firebase_uid&&user.firebase_uid!==uid)throw new HttpError(409,"This email belongs to a different sign-in account.");await db.collection("users").updateOne({_id:user._id,firebase_uid:{$exists:false}},{$set:{firebase_uid:uid,name:user.name||String(identity.displayName||"").slice(0,32)}});user=await db.collection("users").findOne({_id:user._id});}
    else {try{const inserted=await db.collection("users").insertOne({email,firebase_uid:uid,name:String(identity.displayName||"").slice(0,32),created_at:new Date()});user=await db.collection("users").findOne({_id:inserted.insertedId});}catch(error){if(duplicate(error))user=await db.collection("users").findOne({firebase_uid:uid})||await db.collection("users").findOne({email});else throw error;}}
    if(!user)throw new HttpError(409,"Could not create your account. Please try again.");
    if(user.firebase_uid!==uid){await db.collection("users").updateOne({_id:user._id,firebase_uid:{$exists:false}},{$set:{firebase_uid:uid}});user=await db.collection("users").findOne({_id:user._id});}
    if(user?.firebase_uid!==uid)throw new HttpError(409,"This email belongs to a different sign-in account."); return createSession(request,db,user!);
  }
  throw new HttpError(404,"API endpoint not found.");
}

async function patch(request: NextRequest, endpoint: string, body: Record<string, any>) {
  if(endpoint!=="profile")throw new HttpError(404,"API endpoint not found.");
  const name=body.name; if(typeof name!=="string"||name.trim().length>32)throw new HttpError(400,"Name must be 32 characters or fewer.");
  const db=await database(), user=await currentUser(request,db); if(!user)throw new HttpError(401,"Please sign in again.");
  const clean=name.trim(); await db.collection("users").updateOne({_id:user._id},{$set:{name:clean}}); return response(request,{user:{...publicUser(user),name:clean}});
}
async function deleteRequest(request: NextRequest, endpoint: string) {
  if(endpoint!=="data")throw new HttpError(404,"API endpoint not found.");
  const db=await database(), user=await currentUser(request,db); if(!user)throw new HttpError(401,"Please sign in again.");
  await Promise.all([db.collection("prayers").deleteMany({user_id:user._id}),db.collection("quran_sessions").deleteMany({user_id:user._id})]); return response(request,{ok:true});
}
async function postRecord(request:NextRequest,endpoint:string,body:Record<string,any>){
  if(endpoint!=="prayers"&&endpoint!=="sessions")throw new HttpError(404,"API endpoint not found.");
  const db=await database(), user=await currentUser(request,db); if(!user)throw new HttpError(401,"Please sign in again.");
  if(endpoint==="prayers"){
    const {date,prayer,prayed}=body; if(!validDate(date)||!PRAYERS.has(prayer)||typeof prayed!=="boolean")throw new HttpError(400,"Provide a valid date, prayer and prayed status.");
    const query={user_id:user._id,date,prayer}; if(prayed)await db.collection("prayers").updateOne(query,{$set:{prayed:true}},{upsert:true});else await db.collection("prayers").deleteOne(query); return response(request,{ok:true});
  }
  const {date,pages}=body, minutes=body.minutes??0, surah=body.surah??"";
  if(!validDate(date)||!Number.isInteger(pages)||pages<1||pages>604||!Number.isInteger(minutes)||minutes<0||minutes>1440||typeof surah!=="string"||surah.trim().length>60)throw new HttpError(400,"Check the date, surah, pages and minutes and try again.");
  const inserted=await db.collection("quran_sessions").insertOne({user_id:user._id,date,surah:surah.trim(),pages,minutes,created_at:new Date()}); return response(request,{id:String(inserted.insertedId),ok:true},201);
}

async function dispatch(request: NextRequest, context: { params: Promise<{path:string[]}> }) {
  try {
    const {path}=await context.params, endpoint=path.join("/");
    if(!["GET","POST","PATCH","DELETE"].includes(request.method))throw new HttpError(405,"Method not allowed.");
    if(["POST","PATCH","DELETE"].includes(request.method)){const origin=request.headers.get("origin");if(origin&&new URL(origin).origin!==request.nextUrl.origin)throw new HttpError(403,"Request origin was rejected.");}
    if(request.method==="GET")return await get(request,endpoint);
    if(request.method==="DELETE")return await deleteRequest(request,endpoint);
    const body=await bodyJson(request);
    if(request.method==="PATCH")return await patch(request,endpoint,body);
    if(endpoint==="prayers"||endpoint==="sessions")return await postRecord(request,endpoint,body);
    return await post(request,endpoint,body);
  } catch(error) {
    if(error instanceof HttpError)return response(request,{error:error.message},error.status);
    console.error("[Daybook Next API]",error);
    return response(request,{error:"The request could not be completed. Check the app's database configuration and try again."},500);
  }
}
export const GET=dispatch;
export const POST=dispatch;
export const PATCH=dispatch;
export const DELETE=dispatch;
