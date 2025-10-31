const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const cors = require('cors');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/planning-task-manager';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('✓ Połączono z MongoDB Atlas'))
  .catch(err => console.error('✗ Błąd połączenia z MongoDB:', err));

// Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  fullName: { type: String, required: true },
  role: { type: String, default: 'user' }
});

const taskSchema = new mongoose.Schema({
  nrZlecenia: String,
  klient: String,
  urzadzenie: String,
  typUrzadzenia: String,
  nrInwentarzowy: String,
  opis: String,
  priorytet: String,
  status: { type: String, default: 'Nowe' },
  dataOdbioru: String,
  dataRealizacji: String,
  dataTworzenia: { type: String, default: () => new Date().toISOString().slice(0, 16).replace('T', ' ') },
  utworzonePrzez: String,
  odpowiedzialnyTechnik: String,
  kosztMaterialow: Number,
  kosztRobocizny: Number,
  materialy: String,
  kolory: String,
  pakowanie: String,
  montaz: String,
  kategoria: String,
  nrNiezgodnosci: String,
  dotyczaceID: String,
  powod: String,
  uwagi: String,
  ostatniaEdycjaPrzez: String,
  dataOstatniejEdycji: String
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Task = mongoose.model('Task', taskSchema);

// Inicjalizacja użytkowników (tylko raz)
async function initializeUsers() {
  try {
    const count = await User.countDocuments();
    if (count === 0) {
      await User.create([
        { username: 'admin', password: 'admin123', fullName: 'Administrator', role: 'admin' },
        { username: 'witold', password: 'witold123', fullName: 'Witold Mikołajczak', role: 'admin' },
        { username: 'user', password: 'user123', fullName: 'Użytkownik Testowy', role: 'user' }
      ]);
      console.log('✓ Utworzono domyślnych użytkowników');
    }
  } catch (error) {
    console.error('Błąd inicjalizacji użytkowników:', error);
  }
}

initializeUsers();

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'planning-task-manager-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  },
  proxy: true
}));

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());

// Middleware do sprawdzania autoryzacji
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.status(401).json({ error: 'Wymagane zalogowanie' });
}

// Serwuj pliki statyczne z kontrolą dostępu
app.use((req, res, next) => {
  const publicFiles = ['/login.html', '/test-connection.html'];
  
  if (publicFiles.includes(req.path) || req.path.startsWith('/api/login') || req.path.startsWith('/api/check-session')) {
    return next();
  }
  
  if (req.path.endsWith('.html') || req.path === '/') {
    if (!req.session || !req.session.userId) {
      return res.redirect('/login.html');
    }
  }
  
  next();
});

app.use(express.static(__dirname));

// ==========================================
// AUTHENTICATION ENDPOINTS
// ==========================================

app.get('/api/check-session', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({
      loggedIn: true,
      user: {
        id: req.session.userId,
        username: req.session.username,
        fullName: req.session.fullName,
        role: req.session.role
      }
    });
  } else {
    res.json({ loggedIn: false });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log('Próba logowania:', username);
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Brak nazwy użytkownika lub hasła' });
    }
    
    const user = await User.findOne({ username, password });
    
    if (user) {
      req.session.userId = user._id.toString();
      req.session.username = user.username;
      req.session.fullName = user.fullName;
      req.session.role = user.role;
      
      req.session.save((err) => {
        if (err) {
          console.error('Błąd zapisu sesji:', err);
          return res.status(500).json({ error: 'Błąd zapisu sesji' });
        }
        
        res.json({
          success: true,
          user: {
            id: user._id,
            username: user.username,
            fullName: user.fullName,
            role: user.role
          }
        });
      });
    } else {
      res.status(401).json({ error: 'Nieprawidłowa nazwa użytkownika lub hasło' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Błąd serwera podczas logowania' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Błąd podczas wylogowania' });
    }
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

app.get('/api/current-user', requireAuth, (req, res) => {
  res.json({
    id: req.session.userId,
    username: req.session.username,
    fullName: req.session.fullName,
    role: req.session.role
  });
});

// ==========================================
// TASKS ENDPOINTS
// ==========================================

app.get('/api/tasks', requireAuth, async (req, res) => {
  try {
    const tasks = await Task.find().sort({ createdAt: -1 });
    res.json(tasks);
  } catch (error) {
    console.error('Błąd pobierania zadań:', error);
    res.status(500).json({ error: 'Błąd pobierania zadań' });
  }
});

app.get('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    
    if (task) {
      res.json(task);
    } else {
      res.status(404).json({ error: 'Zadanie nie znalezione' });
    }
  } catch (error) {
    console.error('Błąd pobierania zadania:', error);
    res.status(500).json({ error: 'Błąd pobierania zadania' });
  }
});

app.post('/api/tasks', requireAuth, async (req, res) => {
  try {
    const newTask = new Task({
      ...req.body,
      utworzonePrzez: req.session.fullName || req.session.username
    });
    
    await newTask.save();
    console.log('✓ Zadanie zapisane w MongoDB:', newTask._id);
    
    res.status(201).json(newTask);
  } catch (error) {
    console.error('Błąd dodawania zadania:', error);
    res.status(500).json({ error: 'Błąd dodawania zadania' });
  }
});

app.put('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const task = await Task.findByIdAndUpdate(
      req.params.id,
      {
        ...req.body,
        ostatniaEdycjaPrzez: req.session.fullName || req.session.username,
        dataOstatniejEdycji: new Date().toISOString().slice(0, 16).replace('T', ' ')
      },
      { new: true }
    );
    
    if (task) {
      console.log('✓ Zadanie zaktualizowane:', task._id);
      res.json(task);
    } else {
      res.status(404).json({ error: 'Zadanie nie znalezione' });
    }
  } catch (error) {
    console.error('Błąd aktualizacji zadania:', error);
    res.status(500).json({ error: 'Błąd aktualizacji zadania' });
  }
});

app.delete('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const task = await Task.findByIdAndDelete(req.params.id);
    
    if (task) {
      console.log('✓ Zadanie usunięte:', task._id);
      res.json({ message: 'Zadanie usunięte', id: task._id });
    } else {
      res.status(404).json({ error: 'Zadanie nie znalezione' });
    }
  } catch (error) {
    console.error('Błąd usuwania zadania:', error);
    res.status(500).json({ error: 'Błąd usuwania zadania' });
  }
});

app.get('/api/backup', requireAuth, async (req, res) => {
  try {
    const tasks = await Task.find();
    const timestamp = new Date().toISOString().replace(/:/g, '-').slice(0, 19);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="tasks-backup-${timestamp}.json"`);
    res.send(JSON.stringify(tasks, null, 2));
  } catch (error) {
    console.error('Błąd tworzenia backupu:', error);
    res.status(500).json({ error: 'Błąd tworzenia backupu' });
  }
});

app.post('/api/import', requireAuth, async (req, res) => {
  try {
    const importedTasks = req.body;
    
    if (Array.isArray(importedTasks)) {
      await Task.insertMany(importedTasks);
      res.json({ message: 'Dane zaimportowane pomyślnie', count: importedTasks.length });
    } else {
      res.status(400).json({ error: 'Nieprawidłowy format danych' });
    }
  } catch (error) {
    console.error('Błąd importu danych:', error);
    res.status(500).json({ error: 'Błąd importu danych' });
  }
});

// Start serwera
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
===============================================================
  Planning Task Manager - MongoDB Edition
===============================================================
  Port: ${PORT}
  MongoDB: ${MONGODB_URI ? '✓ Skonfigurowane' : '✗ Brak'}
  Environment: ${process.env.NODE_ENV || 'development'}
  
  Endpointy:
  - POST /api/login
  - GET  /api/tasks
  - POST /api/tasks
  - PUT  /api/tasks/:id
  - DELETE /api/tasks/:id
 
===============================================================
  `);
});
