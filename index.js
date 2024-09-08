const express = require('express');
const bcrypt = require('bcrypt'); // Para encriptar contraseñas
const mongoose = require('mongoose'); // Para interactuar con la base de datos
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const port = process.env.PORT || 3000;

const cors = require('cors');
app.use(cors());



// Conectar a MongoDB (reemplaza con tu URI de conexión)
mongoose.connect('mongodb://localhost:27017/Registro_Loguin_BS', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Conectado a MongoDB'))
  .catch(err => console.error('Error al conectar a MongoDB', err));

// Definir el esquema de usuario
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true }
});

const User = mongoose.model('User', userSchema);

// Middleware para parsear JSON
app.use(express.json());

// Ruta para registrar un nuevo usuario
app.post('/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); // Encriptar contraseña

    const user = new User({ username, password: hashedPassword, email });
    await user.save();

    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (err) {
    console.error(err);
    res.status(400).json({ message: 'Error al registrar usuario' });
  }
});

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Usuario no encontrado' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Contraseña incorrecta' });
    }

    res.status(200).json({ message: 'Autenticación exitosa' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.listen(port, () => {
  console.log(`Servidor escuchando en el puerto ${port}`);
});

