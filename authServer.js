require("dotenv").config();

const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const saltRounds = 10;
const cors = require("cors");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");

app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

app.get("/", (req, res) => {
  res.send("Hola");
});

let refreshTokens = [];

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

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" }); // Tiempo de vida del token de acceso: 15 minutos
}

const listUserAdmin = [
  { email: "admin@admin.com", password: bcrypt.hashSync("admin", saltRounds) },
];

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = listUserAdmin.find((user) => user.email === email);

  if (!user) {
    return res
      .status(401)
      .json({ message: "Correo electrónico o contraseña incorrectos" });
  }

  try {
    if (await bcrypt.compare(password, user.password)) {
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
    } else {
      res
        .status(401)
        .json({ message: "Correo electrónico o contraseña incorrectos" });
    }
  } catch (error) {
    console.error("Error al comparar contraseñas:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

app.listen(4000);
