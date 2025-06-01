const express = require('express');
const cors = require('cors');
const path = require('path'); // <-- Added
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'secret123';

app.use(cors());
app.use(bodyParser.json());

// Serve static frontend files from "public" folder
app.use(express.static(path.join(__dirname, 'frontend')));

// MySQL connection
const db = mysql.createConnection({
  host: 'sql7.freesqldatabase.com',
  user: 'sql7782505',
  password: 'T4myggMb9h',
  database: 'sql7782505'
});

db.connect(err => {
  if (err) throw err;
  console.log('MySQL Connected');
});

// JWT authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Register user
app.post('/api/register', (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  db.query(
    'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
    [username, hashedPassword, role],
    (err, result) => {
      if (err) return res.status(500).json({ error: err });
      res.json({ message: 'User registered' });
    }
  );
});

// Login user
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.query(
    'SELECT * FROM users WHERE username = ?',
    [username],
    (err, results) => {
      if (err) return res.status(500).json({ error: err });
      if (results.length === 0) return res.status(401).json({ error: 'User not found' });

      const user = results[0];
      const isPasswordValid = bcrypt.compareSync(password, user.password);

      if (!isPasswordValid) return res.status(401).json({ error: 'Invalid password' });

      const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

      res.json({ token, role: user.role });
    }
  );
});

// Lecturer creates class session code
app.post('/api/create-session', authenticateToken, (req, res) => {
  if (req.user.role !== 'lecturer') return res.status(403).json({ error: 'Not allowed' });

  const code = Math.random().toString(36).substr(2, 6).toUpperCase();

  db.query(
    'INSERT INTO class_sessions (code, created_by) VALUES (?, ?)',
    [code, req.user.id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err });
      res.json({ message: 'Session created', code });
    }
  );
});

// Student marks attendance
app.post('/api/mark-attendance', authenticateToken, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Not allowed' });

  const { sessionCode } = req.body;

  db.query(
    'SELECT id FROM class_sessions WHERE code = ?',
    [sessionCode],
    (err, results) => {
      if (err) return res.status(500).json({ error: err });
      if (results.length === 0) return res.status(404).json({ error: 'Session not found' });

      const sessionId = results[0].id;

      // Check if attendance already marked
      db.query(
        'SELECT * FROM attendance WHERE student_id = ? AND session_id = ?',
        [req.user.id, sessionId],
        (err2, results2) => {
          if (err2) return res.status(500).json({ error: err2 });
          if (results2.length > 0) {
            return res.status(400).json({ error: 'Attendance already marked for this session' });
          }

          // Insert attendance record
          db.query(
            'INSERT INTO attendance (student_id, session_id) VALUES (?, ?)',
            [req.user.id, sessionId],
            (err3, result) => {
              if (err3) return res.status(500).json({ error: err3 });
              res.json({ message: 'Attendance marked' });
            }
          );
        }
      );
    }
  );
});

// Student views attendance records
app.get('/api/attendance', authenticateToken, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Not allowed' });

  db.query(
    `SELECT cs.code, cs.created_at, a.marked_at 
     FROM attendance a 
     JOIN class_sessions cs ON a.session_id = cs.id 
     WHERE a.student_id = ?`,
    [req.user.id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err });
      res.json(results);
    }
  );
});
// Lecturer views attendance for a specific session
app.get('/api/session-attendance/:sessionCode', authenticateToken, (req, res) => {
  if (req.user.role !== 'lecturer') return res.status(403).json({ error: 'Not allowed' });

  const sessionCode = req.params.sessionCode;

  // Check if session belongs to this lecturer
  db.query(
    'SELECT id FROM class_sessions WHERE code = ? AND created_by = ?',
    [sessionCode, req.user.id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err });
      if (results.length === 0) return res.status(404).json({ error: 'Session not found or not yours' });

      const sessionId = results[0].id;

      // Get attendance records for this session
      db.query(
        `SELECT u.username, a.marked_at 
         FROM attendance a
         JOIN users u ON a.student_id = u.id
         WHERE a.session_id = ?`,
        [sessionId],
        (err2, attendanceResults) => {
          if (err2) return res.status(500).json({ error: err2 });
          res.json({ sessionCode, attendance: attendanceResults });
        }
      );
    }
  );
});
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
