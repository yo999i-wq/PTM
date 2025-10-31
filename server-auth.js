const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;
const TASKS_FILE = path.join(__dirname, 'tasks.json');
const USERS_FILE = path.join(__dirname, 'users.json');

// POPRAWIONA konfiguracja sesji dla Render (HTTPS)
app.use(session({
  secret: process.env.SESSION_SECRET || 'planning-task-manager-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // ZMIENIONE: false dla kompatybilności (Render używa proxy)
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 godziny
    sameSite: 'lax' // DODANE: dla lepszej kompatybilności
  },
  proxy: true // DODANE: Render używa proxy
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
  // Publiczne pliki - dostępne bez logowania
  const publicFiles = ['/login.html', '/test-connection.html'];
  
  if (publicFiles.includes(req.path) || req.path.startsWith('/api/login') || req.path.startsWith('/api/check-session')) {
    return next();
  }
  
  // Inne pliki wymagają logowania
  if (req.path.endsWith('.html') || req.path === '/') {
    if (!req.session || !req.session.userId) {
      return res.redirect('/login.html');
    }
  }
  
  next();
});

app.use(express.static(__dirname));

// Pomocnicza funkcja do odczytu użytkowników
async function readUsers() {
  try {
    const data = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Błąd odczytu users.json:', error);
    return [];
  }
}

// Pomocnicza funkcja do odczytu zadań
async function readTasks() {
  try {
    const data = await fs.readFile(TASKS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Błąd odczytu tasks.json:', error);
    return [];
  }
}

// Pomocnicza funkcja do zapisu zadań
async function writeTasks(tasks) {
  try {
    await fs.writeFile(TASKS_FILE, JSON.stringify(tasks, null, 2), 'utf8');
    return true;
  } catch (error) {
    console.error('Błąd zapisu tasks.json:', error);
    return false;
  }
}

// ==========================================
// AUTHENTICATION ENDPOINTS
// ==========================================

// Sprawdź sesję
app.get('/api/check-session', (req, res) => {
  console.log('Sprawdzanie sesji:', req.session); // DEBUG
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

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log('Próba logowania:', username); // DEBUG
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Brak nazwy użytkownika lub hasła' });
    }
    
    const users = await readUsers();
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
      // Zapisz dane użytkownika w sesji
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.fullName = user.fullName;
      req.session.role = user.role;
      
      // WAŻNE: Zapisz sesję przed odpowiedzią
      req.session.save((err) => {
        if (err) {
          console.error('Błąd zapisu sesji:', err);
          return res.status(500).json({ error: 'Błąd zapisu sesji' });
        }
        
        console.log('Sesja zapisana:', req.session); // DEBUG
        
        res.json({
          success: true,
          user: {
            id: user.id,
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

// Logout endpoint
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Błąd podczas wylogowania' });
    }
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// Pobierz dane zalogowanego użytkownika
app.get('/api/current-user', requireAuth, (req, res) => {
  res.json({
    id: req.session.userId,
    username: req.session.username,
    fullName: req.session.fullName,
    role: req.session.role
  });
});

// ==========================================
// TASKS ENDPOINTS (chronione autoryzacją)
// ==========================================

// GET - Pobierz wszystkie zadania
app.get('/api/tasks', requireAuth, async (req, res) => {
  try {
    const tasks = await readTasks();
    res.json(tasks);
  } catch (error) {
    res.status(500).json({ error: 'Błąd pobierania zadań' });
  }
});

// GET - Pobierz jedno zadanie po ID
app.get('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const tasks = await readTasks();
    const task = tasks.find(t => t.id === parseInt(req.params.id));
    
    if (task) {
      res.json(task);
    } else {
      res.status(404).json({ error: 'Zadanie nie znalezione' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Błąd pobierania zadania' });
  }
});

// POST - Dodaj nowe zadanie
app.post('/api/tasks', requireAuth, async (req, res) => {
  try {
    const tasks = await readTasks();
    const newTask = {
      ...req.body,
      id: tasks.length > 0 ? Math.max(...tasks.map(t => t.id)) + 1 : 1,
      dataTworzenia: new Date().toISOString().slice(0, 16).replace('T', ' '),
      utworzonePrzez: req.session.fullName || req.session.username
    };
    
    tasks.push(newTask);
    const success = await writeTasks(tasks);
    
    if (success) {
      res.status(201).json(newTask);
    } else {
      res.status(500).json({ error: 'Błąd zapisu zadania' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Błąd dodawania zadania' });
  }
});

// PUT - Aktualizuj zadanie
app.put('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const tasks = await readTasks();
    const index = tasks.findIndex(t => t.id === parseInt(req.params.id));
    
    if (index !== -1) {
      tasks[index] = { 
        ...tasks[index], 
        ...req.body,
        ostatniaEdycjaPrzez: req.session.fullName || req.session.username,
        dataOstatniejEdycji: new Date().toISOString().slice(0, 16).replace('T', ' ')
      };
      const success = await writeTasks(tasks);
      
      if (success) {
        res.json(tasks[index]);
      } else {
        res.status(500).json({ error: 'Błąd aktualizacji zadania' });
      }
    } else {
      res.status(404).json({ error: 'Zadanie nie znalezione' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Błąd aktualizacji zadania' });
  }
});

// DELETE - Usuń zadanie
app.delete('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const tasks = await readTasks();
    const filteredTasks = tasks.filter(t => t.id !== parseInt(req.params.id));
    
    if (filteredTasks.length < tasks.length) {
      const success = await writeTasks(filteredTasks);
      
      if (success) {
        res.json({ message: 'Zadanie usunięte', id: parseInt(req.params.id) });
      } else {
        res.status(500).json({ error: 'Błąd usuwania zadania' });
      }
    } else {
      res.status(404).json({ error: 'Zadanie nie znalezione' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Błąd usuwania zadania' });
  }
});

// Backup - Eksportuj wszystkie dane
app.get('/api/backup', requireAuth, async (req, res) => {
  try {
    const tasks = await readTasks();
    const timestamp = new Date().toISOString().replace(/:/g, '-').slice(0, 19);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="tasks-backup-${timestamp}.json"`);
    res.send(JSON.stringify(tasks, null, 2));
  } catch (error) {
    res.status(500).json({ error: 'Błąd tworzenia backupu' });
  }
});

// Import - Zaimportuj dane z backupu
app.post('/api/import', requireAuth, async (req, res) => {
  try {
    const importedTasks = req.body;
    
    if (Array.isArray(importedTasks)) {
      const success = await writeTasks(importedTasks);
      
      if (success) {
        res.json({ message: 'Dane zaimportowane pomyślnie', count: importedTasks.length });
      } else {
        res.status(500).json({ error: 'Błąd importu danych' });
      }
    } else {
      res.status(400).json({ error: 'Nieprawidłowy format danych' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Błąd importu danych' });
  }
});

// Funkcja do pobrania lokalnego IP
const os = require('os');
function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

// Start serwera - nasłuchuj na wszystkich interfejsach (0.0.0.0)
app.listen(PORT, '0.0.0.0', () => {
  const localIP = getLocalIP();
  console.log(`
===============================================================
  Planning Task Manager - Serwer API (z Logowaniem)
===============================================================
  DOSTEP LOKALNY:
  http://localhost:${PORT}
  http://127.0.0.1:${PORT}

  DOSTEP W SIECI LOKALNEJ:
  http://${localIP}:${PORT}

  LOGOWANIE:
  http://${localIP}:${PORT}/login.html

  Environment: ${process.env.NODE_ENV || 'development'}
  
  Pliki:
  - Dane: tasks.json
  - Uzytkownicy: users.json

  Dostepne endpointy:
  AUTH:
  POST   /api/login          - Zaloguj sie
  POST   /api/logout         - Wyloguj sie
  GET    /api/check-session  - Sprawdz sesje
  GET    /api/current-user   - Pobierz dane usera

  TASKS (wymagaja logowania):
  GET    /api/tasks          - Pobierz wszystkie
  GET    /api/tasks/:id      - Pobierz jedno
  POST   /api/tasks          - Dodaj nowe
  PUT    /api/tasks/:id      - Zaktualizuj
  DELETE /api/tasks/:id      - Usun
  GET    /api/backup         - Eksportuj backup
  POST   /api/import         - Importuj dane

 
===============================================================
  `);
});
