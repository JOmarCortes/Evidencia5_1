const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Importar el modelo de usuario
const User = mongoose.model('User');
const ResetToken = mongoose.model('ResetToken');

// Ruta para registrar un nuevo usuario
router.post('/register', async (req, res) => {
  try {
    // Obtener los datos del usuario del cuerpo de la solicitud
    const { username, password, email } = req.body;

    // Hashear la contraseña del usuario
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear un nuevo usuario con los datos proporcionados
    const user = new User({ username, password: hashedPassword, email });
    await user.save();

    // Enviar una respuesta de éxito
    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (err) {
    // Manejar errores y enviar una respuesta de error
    console.error(err);
    res.status(400).json({ message: 'Error al registrar usuario' });
  }
});

// Ruta para iniciar sesión de un usuario
router.post('/login', async (req, res) => {
  try {
    // Obtener los datos del usuario del cuerpo de la solicitud
    const { username, password } = req.body;

    // Buscar el usuario en la base de datos por su nombre de usuario
    const user = await User.findOne({ username });
    if (!user) {
      // Si el usuario no se encuentra, enviar una respuesta de error
      return res.status(401).json({ message: 'Usuario no encontrado' });
    }

    // Comparar la contraseña proporcionada con la contraseña hasheada almacenada
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      // Si la contraseña no coincide, enviar una respuesta de error
      return res.status(401).json({ message: 'Contraseña incorrecta' });
    }

    // Enviar una respuesta de éxito
    res.status(200).json({ message: 'Autenticación exitosa' });
  } catch (err) {
    // Manejar errores y enviar una respuesta de error
    console.error(err);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Exportar el enrutador para su uso en la aplicación principal
module.exports = router;
