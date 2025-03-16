const express = require('express');
const session = require('express-session');
const path = require('path');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

// Configurazione dell'app
const app = express();
const PORT = process.env.PORT || 3000;

// Configurazione del middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: 'see-platform-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 giorni in millisecondi
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict'
  }
}));

// Configurazione del motore di template
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Inizializzazione del database
const dbPath = path.join(__dirname, 'database', 'see.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Errore nella connessione al database:', err.message);
  } else {
    console.log('Connessione al database SQLite stabilita');
    
    // Creazione della tabella utenti se non esiste
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      profile_pic TEXT,
      bio TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) {
        console.error('Errore nella creazione della tabella utenti:', err.message);
      } else {
        console.log('Tabella utenti creata o già esistente');
      }
    });
    
    // Creazione della tabella video se non esiste
    db.run(`CREATE TABLE IF NOT EXISTS videos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT,
      description TEXT,
      file_path TEXT NOT NULL,
      thumbnail TEXT,
      views INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`, (err) => {
      if (err) {
        console.error('Errore nella creazione della tabella video:', err.message);
      } else {
        console.log('Tabella video creata o già esistente');
      }
    });
    
    // Creazione della tabella likes se non esiste
    db.run(`CREATE TABLE IF NOT EXISTS likes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      video_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (video_id) REFERENCES videos (id),
      UNIQUE(user_id, video_id)
    )`, (err) => {
      if (err) {
        console.error('Errore nella creazione della tabella likes:', err.message);
      } else {
        console.log('Tabella likes creata o già esistente');
      }
    });
    
    // Creazione della tabella saved se non esiste
    db.run(`CREATE TABLE IF NOT EXISTS saved (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      video_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (video_id) REFERENCES videos (id),
      UNIQUE(user_id, video_id)
    )`, (err) => {
      if (err) {
        console.error('Errore nella creazione della tabella saved:', err.message);
      } else {
        console.log('Tabella saved creata o già esistente');
      }
    });
    
    // Creazione della tabella followers se non esiste
    db.run(`CREATE TABLE IF NOT EXISTS followers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      follower_id INTEGER NOT NULL,
      followed_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (follower_id) REFERENCES users (id),
      FOREIGN KEY (followed_id) REFERENCES users (id),
      UNIQUE(follower_id, followed_id)
    )`, (err) => {
      if (err) {
        console.error('Errore nella creazione della tabella followers:', err.message);
      } else {
        console.log('Tabella followers creata o già esistente');
      }
    });
    
    // Creazione della tabella comments se non esiste
    db.run(`CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      video_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (video_id) REFERENCES videos (id)
    )`, (err) => {
      if (err) {
        console.error('Errore nella creazione della tabella comments:', err.message);
      } else {
        console.log('Tabella comments creata o già esistente');
      }
    });
  }
});

// Routes
app.get('/', (req, res) => {
  res.render('index', { title: 'SEE - Home' });
});

app.get('/register', (req, res) => {
  res.render('register', { title: 'SEE - Registrazione', error: null });
});

app.post('/register', (req, res) => {
  const { username, email, password, confirm_password } = req.body;
  
  // Validazione
  if (!username || !email || !password || !confirm_password) {
    return res.render('register', { 
      title: 'SEE - Registrazione', 
      error: 'Tutti i campi sono obbligatori' 
    });
  }
  
  if (password !== confirm_password) {
    return res.render('register', { 
      title: 'SEE - Registrazione', 
      error: 'Le password non corrispondono' 
    });
  }
  
  // Verifica se l'utente esiste già
  db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], (err, user) => {
    if (err) {
      console.error(err.message);
      return res.render('register', { 
        title: 'SEE - Registrazione', 
        error: 'Errore del server' 
      });
    }
    
    if (user) {
      return res.render('register', { 
        title: 'SEE - Registrazione', 
        error: 'Username o email già in uso' 
      });
    }
    
    // Hash della password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error(err.message);
        return res.render('register', { 
          title: 'SEE - Registrazione', 
          error: 'Errore del server' 
        });
      }
      
      // Inserimento del nuovo utente
      const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
      db.run(sql, [username, email, hashedPassword], function(err) {
        if (err) {
          console.error(err.message);
          return res.render('register', { 
            title: 'SEE - Registrazione', 
            error: 'Errore nella registrazione' 
          });
        }
        
        // Registrazione completata
        req.session.userId = this.lastID;
        req.session.username = username;
        res.redirect('/feed');
      });
    });
  });
});

app.get('/login', (req, res) => {
  res.render('login', { title: 'SEE - Accesso', error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Validazione
  if (!username || !password) {
    return res.render('login', { 
      title: 'SEE - Accesso', 
      error: 'Inserisci username e password' 
    });
  }
  
  // Verifica credenziali
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error(err.message);
      return res.render('login', { 
        title: 'SEE - Accesso', 
        error: 'Errore del server' 
      });
    }
    
    if (!user) {
      return res.render('login', { 
        title: 'SEE - Accesso', 
        error: 'Username o password non validi' 
      });
    }
    
    // Verifica password
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        console.error(err.message);
        return res.render('login', { 
          title: 'SEE - Accesso', 
          error: 'Errore del server' 
        });
      }
      
      if (!result) {
        return res.render('login', { 
          title: 'SEE - Accesso', 
          error: 'Username o password non validi' 
        });
      }
      
      // Login completato
      req.session.userId = user.id;
      req.session.username = user.username;
      res.redirect('/feed');
    });
  });
});

app.get('/feed', (req, res) => {
  // Verifica se l'utente è loggato
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  // Ottieni i video dal database
  db.all(`
    SELECT v.*, u.username, 
    (SELECT COUNT(*) FROM likes WHERE video_id = v.id) as likes_count,
    (SELECT COUNT(*) FROM comments WHERE video_id = v.id) as comments_count,
    (SELECT COUNT(*) FROM likes WHERE video_id = v.id AND user_id = ?) as user_liked
    FROM videos v
    JOIN users u ON v.user_id = u.id
    ORDER BY v.created_at DESC
  `, [req.session.userId], (err, videos) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send('Errore del server');
    }
    
    res.render('feed', { 
      title: 'SEE - Feed', 
      username: req.session.username,
      videos: videos
    });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Configurazione di Multer per il caricamento dei file
const multer = require('multer');
const fs = require('fs');

// Configurazione dello storage per i file caricati
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'public', 'uploads'));
  },
  filename: function (req, file, cb) {
    // Genera un nome file unico con timestamp
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, 'video-' + uniqueSuffix + ext);
  }
});

// Filtro per accettare solo file video
const fileFilter = (req, file, cb) => {
  // Accetta solo file video
  if (file.mimetype.startsWith('video/')) {
    cb(null, true);
  } else {
    cb(new Error('Il file deve essere un video'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 50 * 1024 * 1024, // Limite di 50MB
  }
});

// Route per il caricamento di un nuovo video
app.get('/upload', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  res.render('upload', { 
    title: 'SEE - Carica Video',
    username: req.session.username,
    error: null
  });
});

// Route POST per gestire il caricamento dei video
app.post('/upload', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Non autorizzato' });
  }

  upload.single('video')(req, res, function (err) {
    if (err instanceof multer.MulterError) {
      // Errore di Multer durante il caricamento
      console.error('Errore Multer:', err.message);
      return res.render('upload', {
        title: 'SEE - Carica Video',
        username: req.session.username,
        error: err.code === 'LIMIT_FILE_SIZE' ? 'Il file è troppo grande (max 50MB)' : 'Errore nel caricamento del file'
      });
    } else if (err) {
      // Altro tipo di errore
      console.error('Errore:', err.message);
      return res.render('upload', {
        title: 'SEE - Carica Video',
        username: req.session.username,
        error: err.message
      });
    }

    // Se non c'è un file
    if (!req.file) {
      return res.render('upload', {
        title: 'SEE - Carica Video',
        username: req.session.username,
        error: 'Seleziona un file video da caricare'
      });
    }

    // Ottieni i dati dal form
    const { title, description } = req.body;
    const filePath = '/uploads/' + req.file.filename;

    // Salva le informazioni del video nel database
    const sql = 'INSERT INTO videos (user_id, title, description, file_path) VALUES (?, ?, ?, ?)';
    db.run(sql, [req.session.userId, title || null, description || null, filePath], function(err) {
      if (err) {
        console.error('Errore nel salvataggio del video:', err.message);
        // In caso di errore, elimina il file caricato
        fs.unlink(path.join(__dirname, 'public', filePath), (unlinkErr) => {
          if (unlinkErr) console.error('Errore nella rimozione del file:', unlinkErr.message);
        });
        
        return res.render('upload', {
          title: 'SEE - Carica Video',
          username: req.session.username,
          error: 'Errore nel salvataggio del video'
        });
      }

      // Caricamento completato con successo
      res.redirect('/feed');
    });
  });
});

// API per gestire i like
app.post('/api/like', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Non autorizzato' });
  }
  
  const { videoId } = req.body;
  
  if (!videoId) {
    return res.status(400).json({ error: 'ID video mancante' });
  }
  
  // Controlla se l'utente ha già messo like
  db.get('SELECT * FROM likes WHERE user_id = ? AND video_id = ?', 
    [req.session.userId, videoId], 
    (err, like) => {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: 'Errore del server' });
      }
      
      if (like) {
        // Rimuovi il like
        db.run('DELETE FROM likes WHERE user_id = ? AND video_id = ?', 
          [req.session.userId, videoId], 
          (err) => {
            if (err) {
              console.error(err.message);
              return res.status(500).json({ error: 'Errore del server' });
            }
            
            res.json({ liked: false });
          });
      } else {
        // Aggiungi il like
        db.run('INSERT INTO likes (user_id, video_id) VALUES (?, ?)', 
          [req.session.userId, videoId], 
          (err) => {
            if (err) {
              console.error(err.message);
              return res.status(500).json({ error: 'Errore del server' });
            }
            
            res.json({ liked: true });
          });
      }
    });
});

// API per gestire i salvataggi
app.post('/api/save', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Non autorizzato' });
  }
  
  const { videoId } = req.body;
  
  if (!videoId) {
    return res.status(400).json({ error: 'ID video mancante' });
  }
  
  // Controlla se l'utente ha già salvato il video
  db.get('SELECT * FROM saved WHERE user_id = ? AND video_id = ?', 
    [req.session.userId, videoId], 
    (err, saved) => {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: 'Errore del server' });
      }
      
      if (saved) {
        // Rimuovi il salvataggio
        db.run('DELETE FROM saved WHERE user_id = ? AND video_id = ?', 
          [req.session.userId, videoId], 
          (err) => {
            if (err) {
              console.error(err.message);
              return res.status(500).json({ error: 'Errore del server' });
            }
            
            res.json({ saved: false });
          });
      } else {
        // Aggiungi il salvataggio
        db.run('INSERT INTO saved (user_id, video_id) VALUES (?, ?)', 
          [req.session.userId, videoId], 
          (err) => {
            if (err) {
              console.error(err.message);
              return res.status(500).json({ error: 'Errore del server' });
            }
            
            res.json({ saved: true });
          });
      }
    });
});

// Route per visualizzare i video salvati
app.get('/saved', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  // Ottieni i video salvati dall'utente
  db.all(`
    SELECT v.*, u.username, 
    (SELECT COUNT(*) FROM likes WHERE video_id = v.id) as likes_count
    FROM videos v
    JOIN users u ON v.user_id = u.id
    JOIN saved s ON v.id = s.video_id
    WHERE s.user_id = ?
    ORDER BY s.created_at DESC
  `, [req.session.userId], (err, videos) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send('Errore del server');
    }
    
    res.render('saved', { 
      title: 'SEE - Video Salvati',
      username: req.session.username,
      videos: videos
    });
  });
});

// Route per la pagina del profilo
app.get('/profile/:username?', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  // Se non è specificato un username, mostra il profilo dell'utente loggato
  const profileUsername = req.params.username || req.session.username;
  
  // Ottieni le informazioni dell'utente
  db.get('SELECT * FROM users WHERE username = ?', [profileUsername], (err, user) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send('Errore del server');
    }
    
    if (!user) {
      return res.status(404).send('Utente non trovato');
    }
    
    // Controlla se l'utente loggato segue questo profilo
    db.get('SELECT * FROM followers WHERE follower_id = ? AND followed_id = ?', 
      [req.session.userId, user.id], 
      (err, following) => {
        if (err) {
          console.error(err.message);
          return res.status(500).send('Errore del server');
        }
        
        // Ottieni il conteggio dei follower
        db.get('SELECT COUNT(*) as count FROM followers WHERE followed_id = ?', 
          [user.id], 
          (err, followerResult) => {
            if (err) {
              console.error(err.message);
              return res.status(500).send('Errore del server');
            }
            
            // Ottieni il conteggio degli utenti seguiti
            db.get('SELECT COUNT(*) as count FROM followers WHERE follower_id = ?', 
              [user.id], 
              (err, followingResult) => {
                if (err) {
                  console.error(err.message);
                  return res.status(500).send('Errore del server');
                }
                
                // Ottieni i video dell'utente
                db.all(`
                  SELECT v.*, 
                  (SELECT COUNT(*) FROM likes WHERE video_id = v.id) as likes_count
                  FROM videos v
                  WHERE v.user_id = ?
                  ORDER BY v.created_at DESC
                `, [user.id], (err, videos) => {
                  if (err) {
                    console.error(err.message);
                    return res.status(500).send('Errore del server');
                  }
                  
                  // Ottieni i video a cui l'utente ha messo like
                  db.all(`
                    SELECT v.*, u.username, 
                    (SELECT COUNT(*) FROM likes WHERE video_id = v.id) as likes_count
                    FROM videos v
                    JOIN users u ON v.user_id = u.id
                    JOIN likes l ON v.id = l.video_id
                    WHERE l.user_id = ?
                    ORDER BY l.created_at DESC
                  `, [user.id], (err, likedVideos) => {
                    if (err) {
                      console.error(err.message);
                      return res.status(500).send('Errore del server');
                    }
                    
                    // Ottieni il conteggio dei video
                    db.get('SELECT COUNT(*) as count FROM videos WHERE user_id = ?', 
                      [user.id], 
                      (err, videoResult) => {
                        if (err) {
                          console.error(err.message);
                          return res.status(500).send('Errore del server');
                        }
                        
                        res.render('profile', {
                          title: `SEE - Profilo di ${user.username}`,
                          username: req.session.username,
                          user: user,
                          isOwnProfile: user.id === req.session.userId,
                          isFollowing: !!following,
                          followerCount: followerResult.count,
                          followingCount: followingResult.count,
                          videoCount: videoResult.count,
                          videos: videos,
                          likedVideos: likedVideos
                        });
                      });
                  });
                });
              });
          });
      });
  });
});

// Route per la pagina del profilo dell'utente loggato
app.get('/profile', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  res.redirect(`/profile/${req.session.username}`);
});

// Route per la pagina di modifica del profilo
app.get('/edit-profile', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  // Ottieni le informazioni dell'utente
  db.get('SELECT * FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send('Errore del server');
    }
    
    if (!user) {
      return res.status(404).send('Utente non trovato');
    }
    
    res.render('edit-profile', {
      title: 'SEE - Modifica Profilo',
      username: req.session.username,
      user: user,
      error: null,
      success: null
    });
  });
});

// Route POST per gestire la modifica del profilo
app.post('/edit-profile', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Non autorizzato' });
  }
  
  const { username, bio } = req.body;
  
  if (!username) {
    return res.render('edit-profile', {
      title: 'SEE - Modifica Profilo',
      username: req.session.username,
      user: { username: req.session.username, bio: bio || '' },
      error: 'Il nome utente è obbligatorio',
      success: null
    });
  }
  
  // Verifica se il nuovo username è già in uso (se è stato cambiato)
  if (username !== req.session.username) {
    db.get('SELECT * FROM users WHERE username = ? AND id != ?', [username, req.session.userId], (err, existingUser) => {
      if (err) {
        console.error(err.message);
        return res.render('edit-profile', {
          title: 'SEE - Modifica Profilo',
          username: req.session.username,
          user: { username: req.session.username, bio: bio || '' },
          error: 'Errore del server',
          success: null
        });
      }
      
      if (existingUser) {
        return res.render('edit-profile', {
          title: 'SEE - Modifica Profilo',
          username: req.session.username,
          user: { username: req.session.username, bio: bio || '' },
          error: 'Nome utente già in uso',
          success: null
        });
      }
      
      // Aggiorna il profilo
      updateProfile(req, res, username, bio);
    });
  } else {
    // Aggiorna il profilo senza verificare l'username (non è cambiato)
    updateProfile(req, res, username, bio);
  }
});

// Funzione per aggiornare il profilo
function updateProfile(req, res, username, bio) {
  db.run('UPDATE users SET username = ?, bio = ? WHERE id = ?', 
    [username, bio || null, req.session.userId], 
    (err) => {
      if (err) {
        console.error(err.message);
        return res.render('edit-profile', {
          title: 'SEE - Modifica Profilo',
          username: req.session.username,
          user: { username: req.session.username, bio: bio || '' },
          error: 'Errore nell\'aggiornamento del profilo',
          success: null
        });
      }
      
      // Aggiorna la sessione con il nuovo username
      req.session.username = username;
      
      // Profilo aggiornato con successo
      res.render('edit-profile', {
        title: 'SEE - Modifica Profilo',
        username: username,
        user: { username: username, bio: bio || '' },
        error: null,
        success: 'Profilo aggiornato con successo'
      });
    });
}

// API per seguire/non seguire un utente
app.post('/api/follow', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Non autorizzato' });
  }
  
  const { userId } = req.body;
  
  if (!userId) {
    return res.status(400).json({ error: 'ID utente mancante' });
  }
  
  // Controlla se l'utente sta cercando di seguire se stesso
  if (parseInt(userId) === req.session.userId) {
    return res.status(400).json({ error: 'Non puoi seguire te stesso' });
  }
  
  // Controlla se l'utente esiste
  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Errore del server' });
    }
    
    if (!user) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }
    
    // Controlla se l'utente già segue questo profilo
    db.get('SELECT * FROM followers WHERE follower_id = ? AND followed_id = ?', 
      [req.session.userId, userId], 
      (err, following) => {
        if (err) {
          console.error(err.message);
          return res.status(500).json({ error: 'Errore del server' });
        }
        
        if (following) {
          // Rimuovi il follow
          db.run('DELETE FROM followers WHERE follower_id = ? AND followed_id = ?', 
            [req.session.userId, userId], 
            (err) => {
              if (err) {
                console.error(err.message);
                return res.status(500).json({ error: 'Errore del server' });
              }
              
              res.json({ following: false });
            });
        } else {
          // Aggiungi il follow
          db.run('INSERT INTO followers (follower_id, followed_id) VALUES (?, ?)', 
            [req.session.userId, userId], 
            (err) => {
              if (err) {
                console.error(err.message);
                return res.status(500).json({ error: 'Errore del server' });
              }
              
              res.json({ following: true });
            });
        }
      });
  });
});

// API per i commenti
app.post('/api/comment', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Non autorizzato' });
  }
  
  const { videoId, content } = req.body;
  
  if (!videoId || !content) {
    return res.status(400).json({ error: 'Dati mancanti' });
  }
  
  // Controlla se il video esiste
  db.get('SELECT * FROM videos WHERE id = ?', [videoId], (err, video) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Errore del server' });
    }
    
    if (!video) {
      return res.status(404).json({ error: 'Video non trovato' });
    }
    
    // Aggiungi il commento
    db.run('INSERT INTO comments (user_id, video_id, content) VALUES (?, ?, ?)', 
      [req.session.userId, videoId, content], 
      function(err) {
        if (err) {
          console.error(err.message);
          return res.status(500).json({ error: 'Errore del server' });
        }
        
        // Ottieni le informazioni dell'utente per il commento
        db.get('SELECT username FROM users WHERE id = ?', [req.session.userId], (err, user) => {
          if (err) {
            console.error(err.message);
            return res.status(500).json({ error: 'Errore del server' });
          }
          
          res.json({
            id: this.lastID,
            user_id: req.session.userId,
            username: user.username,
            content: content,
            created_at: new Date().toISOString()
          });
        });
      });
  });
});

// API per ottenere i commenti di un video
app.get('/api/comments/:videoId', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Non autorizzato' });
  }
  
  const videoId = req.params.videoId;
  
  // Ottieni i commenti del video
  db.all(`
    SELECT c.*, u.username
    FROM comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.video_id = ?
    ORDER BY c.created_at DESC
  `, [videoId], (err, comments) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Errore del server' });
    }
    
    res.json(comments);
  });
});

// Route per la visualizzazione di un video specifico
app.get('/video/:id', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  const videoId = req.params.id;
  
  // Ottieni le informazioni del video
  db.get(`
    SELECT v.*, u.username, u.profile_pic,
    (SELECT COUNT(*) FROM likes WHERE video_id = v.id) as likes_count,
    (SELECT COUNT(*) FROM likes WHERE video_id = v.id AND user_id = ?) as user_liked,
    (SELECT COUNT(*) FROM saved WHERE video_id = v.id AND user_id = ?) as user_saved
    FROM videos v
    JOIN users u ON v.user_id = u.id
    WHERE v.id = ?
  `, [req.session.userId, req.session.userId, videoId], (err, video) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send('Errore del server');
    }
    
    if (!video) {
      return res.status(404).send('Video non trovato');
    }
    
    // Incrementa il contatore delle visualizzazioni
    db.run('UPDATE videos SET views = views + 1 WHERE id = ?', [videoId], (err) => {
      if (err) {
        console.error('Errore nell\'aggiornamento delle visualizzazioni:', err.message);
      }
      
      // Ottieni i commenti del video
      db.all(`
        SELECT c.*, u.username
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.video_id = ?
        ORDER BY c.created_at DESC
      `, [videoId], (err, comments) => {
        if (err) {
          console.error(err.message);
          return res.status(500).send('Errore del server');
        }
        
        res.render('video', {
          title: video.title ? `SEE - ${video.title}` : 'SEE - Video',
          username: req.session.username,
          video: video,
          userLiked: !!video.user_liked,
          userSaved: !!video.user_saved,
          comments: comments
        });
      });
    });
  });
});

// Route per la pagina explore
app.get('/explore', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  // Ottieni i video in tendenza (i più visti)
  db.all(`
    SELECT v.*, u.username, 
    (SELECT COUNT(*) FROM likes WHERE video_id = v.id) as likes_count
    FROM videos v
    JOIN users u ON v.user_id = u.id
    ORDER BY v.views DESC
    LIMIT 12
  `, [], (err, videos) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send('Errore del server');
    }
    
    res.render('explore', {
      title: 'SEE - Esplora',
      username: req.session.username,
      trendingVideos: videos
    });
  });
});

// API per la ricerca dei video
app.get('/api/search', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Non autorizzato' });
  }
  
  const query = req.query.q;
  
  if (!query) {
    return res.status(400).json({ error: 'Query di ricerca mancante' });
  }
  
  // Cerca video per titolo o descrizione
  db.all(`
    SELECT v.*, u.username, 
    (SELECT COUNT(*) FROM likes WHERE video_id = v.id) as likes_count
    FROM videos v
    JOIN users u ON v.user_id = u.id
    WHERE v.title LIKE ? OR v.description LIKE ?
    ORDER BY v.views DESC
  `, [`%${query}%`, `%${query}%`], (err, videos) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Errore del server' });
    }
    
    res.json(videos);
  });
});

// Avvio del server
app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});