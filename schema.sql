-- ============================================
-- Script SQL: Sistema de Autenticación Segura
-- Taller de Seguridad de la Información - 2026-II
-- Universidad El Bosque
-- ============================================

CREATE TABLE roles (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nombre VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE usuarios (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  rol_id INT NOT NULL,
  intentos_fallidos INT DEFAULT 0,
  bloqueado_hasta DATETIME NULL,
  FOREIGN KEY (rol_id) REFERENCES roles(id)
);

-- Datos iniciales: roles del sistema
INSERT INTO roles (nombre) VALUES ('Administrador'), ('Usuario');

-- Usuario de prueba (contraseña real: admin123)
-- NOTA: el hash de abajo se genera dinámicamente con bcrypt en tiempo de
-- ejecución (ver database/init.js), NUNCA se guarda la contraseña en texto
-- plano. Este INSERT es solo ilustrativo de la estructura final esperada:
--
-- INSERT INTO usuarios (username, password_hash, rol_id)
-- VALUES ('admin', '$2b$10$<hash_generado_por_bcrypt>', 1);
