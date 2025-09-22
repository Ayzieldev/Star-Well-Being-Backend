import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import puppeteer from 'puppeteer';
import { v4 as uuidv4 } from 'uuid'; // Import uuid

dotenv.config();
const app = express();
app.use(helmet());
// CORS: allow specific origins incl. Hostinger domain and local dev
const allowedOrigins = [
  'https://lightgreen-pig-834553.hostingersite.com',
  process.env.FRONTEND_URL,
  process.env.ALLOWED_ORIGINS
].filter(Boolean).flatMap(v => String(v).split(',').map(s => s.trim())).filter(Boolean);

app.use(cors({
  origin: function(origin, cb) {
    if (!origin) return cb(null, true);
    if (allowedOrigins.length === 0) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
// Explicit preflight for all routes
app.options('*', cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('tiny'));

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/star_assessment', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  age: { type: Number, required: true },
  address: { type: String, required: true },
  consentGiven: { type: Boolean, default: false },
  uid: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now }
});

// Assessment Schema
const AssessmentSchema = new mongoose.Schema({
  assessmentUid: { type: String, required: true, unique: true }, // Unique ID for the assessment
  user_parent_uid: { type: String, required: true, ref: 'User' }, // Link to User via uid
  assessmentData: { type: Object, required: true }, // Store the assessment choices
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
// Auth: register
app.post('/auth/register', async (req, res) => {
  try {
    const { fullName, email, password, age, address, consentGiven } = req.body;
    if (!fullName || !email || !password || !age || !address) {
      return res.status(400).json({ error: 'fullName, email, password, age, and address are required' });
    }

    const existing = await User.findOne({ email: String(email).toLowerCase() });
    if (existing) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const uid = uuidv4();
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const user = new User({
      fullName,
      email: String(email).toLowerCase(),
      passwordHash,
      role: 'user',
      age: Number(age),
      address,
      consentGiven: !!consentGiven,
      uid
    });
    await user.save();
    return res.status(201).json({ ok: true, message: 'Registered', uid, role: user.role });
  } catch (e) {
    return res.status(500).json({ error: 'Registration failed' });
  }
});

// Auth: login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }
    const user = await User.findOne({ email: String(email).toLowerCase() });
    if (!user || !user.passwordHash) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ sub: user.uid, role: user.role, email: user.email }, process.env.JWT_SECRET || 'dev_secret', { expiresIn: '7d' });
    return res.status(200).json({ ok: true, token, role: user.role, uid: user.uid, fullName: user.fullName });
  } catch (e) {
    return res.status(500).json({ error: 'Login failed' });
  }
});

const Assessment = mongoose.model('Assessment', AssessmentSchema);

// UserInformation Schema
const UserInformationSchema = new mongoose.Schema({
  parent_uid: { type: String, required: true, ref: 'User' },
  fullName: { type: String, required: true },
  email: { type: String, required: true },
  company: { type: String },
  position: { type: String },
  age: { type: Number, required: true },
  address: { type: String, required: true },
  consentGiven: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const UserInformation = mongoose.model('UserInformation', UserInformationSchema);

// Rate limiter
const limiter = new RateLimiterMemory({ points: 100, duration: 60 }); // 100 requests per minute
app.use(async (req, res, next) => {
  try { await limiter.consume(req.ip); next(); }
  catch { return res.status(429).json({ error: 'Too many requests' }); }
});

// Submission endpoint
app.post('/submit', async (req, res) => {
  try {
    const { 
      fullName, 
      email, 
      company, 
      position, 
      age, 
      address, 
      consentGiven,
      data // Assessment choices
    } = req.body;

    // Validate required fields
    if (!fullName || !email || !age || !address || !data) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const userUid = uuidv4(); // Generate unique UID for the user
    const assessmentUid = uuidv4(); // Generate unique UID for the assessment

    // Create new user
    const newUser = new User({
      fullName,
      email,
      company,
      position,
      age,
      address,
      consentGiven: consentGiven || false,
      uid: userUid // Save userUid as uid with user
    });

    // Create new assessment
    const newAssessment = new Assessment({
      assessmentUid, // Unique ID for this assessment
      user_parent_uid: userUid, // Link assessment to user via userUid
      assessmentData: data
    });

    // Save to database
    const savedUser = await newUser.save();
    const savedAssessment = await newAssessment.save();

    return res.status(201).json({ 
      ok: true, 
      message: 'User and assessment data saved successfully', 
      userId: savedUser._id,
      assessmentId: savedAssessment._id,
      uid: savedUser.uid, // Return uid
      assessmentUid: savedAssessment.assessmentUid // Return assessmentUid
    });
  } catch (error) {
    console.error('Submission error:', error);
    return res.status(500).json({ error: 'Submission failed', details: error.message });
  }
});

app.get('/users', async (req, res) => {
  try {
    const users = await User.find({});
    return res.status(200).json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    return res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/assessments', async (req, res) => {
  try {
    const assessments = await Assessment.find({});
    return res.status(200).json(assessments);
  } catch (error) {
    console.error('Error fetching assessments:', error);
    return res.status(500).json({ error: 'Failed to fetch assessments' });
  }
});

// Auth middleware
function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const [, token] = header.split(' ');
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret');
    req.user = payload; // { sub, role, email }
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// Save user information under the authenticated user
app.post('/user-information', requireAuth, async (req, res) => {
  try {
    const {
      fullName,
      email,
      company,
      position,
      age,
      address,
      consentGiven
    } = req.body;

    if (!fullName || !email || !age || !address) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const record = new UserInformation({
      parent_uid: req.user.sub,
      fullName,
      email,
      company,
      position,
      age,
      address,
      consentGiven: !!consentGiven
    });
    const saved = await record.save();
    return res.status(201).json({ ok: true, id: saved._id });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to save user information' });
  }
});

app.get('/generate-pdf', async (req, res) => {
  try {
    const { name = 'Anonymous', data = '{}' } = req.query;
    const reportPath = path.resolve(__dirname, '../assets/pdf-template/report.html');
    const reportUrl = `file://${reportPath}?name=${encodeURIComponent(name)}&data=${encodeURIComponent(data)}`;
    const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox','--disable-setuid-sandbox'] });
    const page = await browser.newPage();
    await page.goto(reportUrl, { waitUntil: 'networkidle0' });
    const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true });
    await browser.close();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="star-report.pdf"');
    return res.send(pdfBuffer);
  } catch (e) {
    return res.status(500).json({ error: 'PDF generation failed' });
  }
});

// Lightweight health check endpoint for platform monitoring
app.get('/healthz', (req, res) => {
  const state = mongoose.connection.readyState; // 0=disconnected,1=connected,2=connecting,3=disconnecting
  const status = state === 1 ? 'ok' : (state === 2 ? 'connecting' : 'db_down');
  return res.status(status === 'ok' ? 200 : 503).json({ status, dbState: state });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));
