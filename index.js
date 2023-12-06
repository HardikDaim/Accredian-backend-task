const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcrypt");
const app = express();
const port = 3001;
app.use(cors())
app.use(express.json());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "hardikdon2004",
  database: "test",
  table:"users",
});

db.connect((err) => {
  if (err) {
    console.log("Error connecting to MySQL:", err);
  } else {
    console.log("Connected to MySQL");
  }
});

app.get("/", (req, res) => {
    console.log("Hello");
  });
  
  const util = require('util');
  const dbQuery = util.promisify(db.query).bind(db);
  
  app.post("/api/login", async (req, res) => {
    const { usernameOrEmail, password } = req.body;
  
    try {
      // Retrieve user from the database
      const query = "SELECT * FROM users WHERE username = ? OR email = ?";
      const results = await dbQuery(query, [usernameOrEmail, usernameOrEmail]);
  
      if (results.length === 0) {
        return res.status(401).json({ error: "Invalid credentials" });
      }
  
      const user = results[0];
  
      // Compare the provided password with the hashed password in the database
      const match = await bcrypt.compare(password, user.password);
  
      if (match) {
        // Passwords match, user is authenticated
        res.status(200).json({ message: "Login successful" });
      } else {
        // Passwords do not match
        res.status(401).json({ error: "Invalid credentials" });
      }
    } catch (error) {
      console.error("Error during login:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  });
  
  app.post("/api/signup", async (req, res) => {
    const { username, email, password } = req.body;
  
    // Validate the input (you may want to add more validation)
    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }
  
    try {
      // Check if the email is already registered
      const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
      const emailCheckResult = await dbQuery(checkEmailQuery, [email]);
  
      if (emailCheckResult.length > 0) {
        return res.status(400).json({ error: "Email is already registered" });
      }
  
      // Hash the password before storing it in the database
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Insert the new user into the database
      const insertUserQuery = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
      await dbQuery(insertUserQuery, [username, email, hashedPassword]);
  
      res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
      console.error("Error during signup:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  });
  

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
