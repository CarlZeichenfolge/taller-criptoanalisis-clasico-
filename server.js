const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'taller-seg-info-2026-ii-cambiar-en-produccion',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 1000 * 60 * 60 } // secure:false porque no usamos HTTPS (requisito del taller)
}));

app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database(path.join(__dirname, 'database', 'security.db'));

// ===== MIDDLEWARE ANTI-FUERZA BRUTA (con bloqueo escalonado) =====
const intentosIP = new Map();
const MAX_INTENTOS = 5;
const VENTANA_TIEMPO = 4 * 60 * 1000; // ventana para contar los 5 intentos

// Niveles de bloqueo: 1er bloqueo 30seg, 2do 5min, 3ro en adelante 1 hora
const NIVELES_BLOQUEO = [30 * 1000, 5 * 60 * 1000, 60 * 60 * 1000];

function middlewareProteccionFuerzaBruta(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const ahora = Date.now();

  if (!intentosIP.has(ip)) {
    intentosIP.set(ip, { conteo: 0, primerIntento: ahora, bloqueadoHasta: 0, nivelBloqueo: 0 });
  }
  const registro = intentosIP.get(ip);

  if (registro.bloqueadoHasta > ahora) {
    const segundosRestantes = Math.ceil((registro.bloqueadoHasta - ahora) / 1000);
    return res.status(429).json({
      error: `Demasiados intentos fallidos. Su IP ha sido bloqueada temporalmente. Intente de nuevo en ${segundosRestantes} segundos.`
    });
  }

  if (ahora - registro.primerIntento > VENTANA_TIEMPO) {
    registro.conteo = 0;
    registro.primerIntento = ahora;
  }

  req.registroIP = registro;
  next();
}

function registrarFallo(registro) {
  registro.conteo++;
  if (registro.conteo >= MAX_INTENTOS) {
    const duracion = NIVELES_BLOQUEO[Math.min(registro.nivelBloqueo, NIVELES_BLOQUEO.length - 1)];
    registro.bloqueadoHasta = Date.now() + duracion;
    registro.nivelBloqueo++;
    registro.conteo = 0;
    registro.primerIntento = Date.now();
  }
}

// ===== MIDDLEWARE: EXIGE SESIÓN ACTIVA =====
function requiereSesion(req, res, next) {
  if (req.session && req.session.usuario) return next();
  return res.redirect('/');
}

// ===== RUTAS =====
app.post('/login', middlewareProteccionFuerzaBruta, (req, res) => {
  const { username, password } = req.body;
  const registro = req.registroIP;

  db.get(`SELECT * FROM usuarios WHERE username = ?`, [username], (err, usuario) => {
    if (err) return res.status(500).json({ error: 'Error interno' });

    if (!usuario) {
      registrarFallo(registro);
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    bcrypt.compare(password, usuario.password_hash, (err, esValido) => {
      if (err) return res.status(500).json({ error: 'Error interno' });

      if (!esValido) {
        registrarFallo(registro);
        return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
      }

      // Login correcto: reinicia TODO (intentos y nivel de escalada)
      registro.conteo = 0;
      registro.nivelBloqueo = 0;
      req.session.usuario = usuario.username;
      res.json({ mensaje: `Bienvenido, ${usuario.username}.`, redirect: '/criptoanalisis' });
    });
  });
});

app.get('/criptoanalisis', requiereSesion, (req, res) => {
  res.sendFile(path.join(__dirname, 'protected', 'taller-cifrado.html'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.listen(3000, () => {
  console.log('Servidor ejecutándose en http://localhost:3000');
});