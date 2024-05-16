require("dotenv").config();

const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");

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
];

app.use(express.json());
app.use(cors());

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

app.listen(8080);
