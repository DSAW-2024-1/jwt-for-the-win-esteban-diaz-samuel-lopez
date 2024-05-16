require("dotenv").config();

const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const saltRounds = 10;
const cors = require("cors");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");

const PORT = process.env.PORT || 4000;

const listUserAdmin = [{ email: "admin@admin.com", password: "admin" }];

const listUsers = [
  {
    username: "John",
    lastName: "Doe",
    email: "john.doe@example.com",
    dateOfBirth: "1990-05-15",
  },
  {
    username: "Pepito",
    lastName: "perez",
    email: "admin@admin.com",
    dateOfBirth: "2005-08-07",
  },
  {
    username: "Alice",
    lastName: "Smith",
    email: "alice.smith@example.com",
    dateOfBirth: "1988-02-10",
  },
  {
    username: "Bob",
    lastName: "Johnson",
    email: "bob.johnson@example.com",
    dateOfBirth: "1975-11-20",
  },
  {
    username: "Emily",
    lastName: "Brown",
    email: "emily.brown@example.com",
    dateOfBirth: "1995-07-03",
  },
  {
    username: "Michael",
    lastName: "Davis",
    email: "michael.davis@example.com",
    dateOfBirth: "1980-09-28",
  },
  {
    username: "Emma",
    lastName: "Wilson",
    email: "emma.wilson@example.com",
    dateOfBirth: "1993-04-15",
  },
  {
    username: "David",
    lastName: "Martinez",
    email: "david.martinez@example.com",
    dateOfBirth: "1973-06-22",
  },
  {
    username: "Olivia",
    lastName: "Taylor",
    email: "olivia.taylor@example.com",
    dateOfBirth: "1987-12-05",
  },
  {
    username: "James",
    lastName: "Anderson",
    email: "james.anderson@example.com",
    dateOfBirth: "1998-08-14",
  },
  {
    username: "Sophia",
    lastName: "Thomas",
    email: "sophia.thomas@example.com",
    dateOfBirth: "1982-03-25",
  },
  {
    username: "William",
    lastName: "White",
    email: "william.white@example.com",
    dateOfBirth: "1991-10-17",
  },
];

let refreshTokens = [];

app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

app.get("/", (req, res) => {
  res.send("Hola");
});

app.get("/profile", authenticateToken, (req, res) => {
  const userEmail = req.user.email;
  const user = listUsers.find((user) => user.email === userEmail);

  if (!user) {
    return res.status(404).json({ message: "Usuario no encontrado" });
  }

  res.json({
    username: user.username,
    lastName: user.lastName,
    email: user.email,
    dateOfBirth: user.dateOfBirth,
  });
});

app.post("/form", authenticateToken, (req, res) => {
  const text = req.body.text;
  res.json({ text: text });
});

app.get("/contacts", authenticateToken, (req, res) => {
  res.json(listUsers);
});

app.post("/token", (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ email: user.email });
    res.json({ accessToken: accessToken });
  });
});

app.delete("/logout", (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.sendStatus(400);
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.clearCookie("session"); // Elimina la cookie de sesión al cerrar sesión
  res.sendStatus(204);
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = listUserAdmin.find(
    (user) => user.email === email && user.password === password
  );

  if (!user) {
    return res
      .status(401)
      .json({ message: "Correo electrónico o contraseña incorrectos" });
  }

  try {
    const accessToken = generateAccessToken({ email: user.email });
    const refreshToken = jwt.sign(
      { email: user.email },
      process.env.REFRESH_TOKEN_SECRET
    );
    refreshTokens.push(refreshToken);
    res.cookie("session", refreshToken, {
      httpOnly: true,
      secure: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    }); // Cookie de sesión con tiempo de vida de una semana
    res.json({ accessToken: accessToken, refreshToken: refreshToken });
  } catch (error) {
    console.error("Error al generar tokens:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" }); // Tiempo de vida del token de acceso: 15 minutos
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
