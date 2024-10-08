import sqlite3 from 'sqlite3';
import path from 'path';
import bcrypt from 'bcrypt';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { open } from 'sqlite';


const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dbPath = path.resolve(__dirname, 'database.db');

// Open the SQLite Database
async function openDb() {
  return open({
      filename: './db/database.db',
      driver: sqlite3.Database
  });
}



const dbinit = async () => {
  try {
    const db = new sqlite3.Database(dbPath);
    const sql = `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT not null,
      user_webauthen_data TEXT
    )`;
    db.run(sql); 
    return db;
  }
  catch (err) {
    console.log(err);
    throw err;
  }
};

export const signin = async ( username, password ) => {
  const db = await dbinit();
  const sql = `SELECT * FROM users WHERE username = ?`;
  return new Promise((resolve, reject) =>
    db.get(sql, [username], async (err, row) => {
      db.close();
      if (err) {
        return reject(err);
      }
      // no user found
      if (!row) {
        return resolve(null);
      }
      // check password
      const match = await bcrypt.compare(password, row.password);
      if (match) {
        return resolve(row);
      } else {
        return resolve(null);
      }
    })
  );
};

export const signup = async ( username, password) => {
  const db = await dbinit();
  // hash the password
  const hashedPassword = await bcrypt.hash(password, 10);
  // add the user and hashed password to the database
  const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
  try {
    db.run(sql, [username, hashedPassword]);
    db.close();
    return true;
  }
  catch (err) {
    console.log(err);
    throw err;
  }
};



// Function to get user by username
async function getUser(username) {
  const db = await openDb();
  const user = await db.get(`SELECT user_webauthen_data FROM users WHERE username = ?`, [username]);
  await db.close();
  return user ? JSON.parse(user.user_webauthen_data) : null;
}

// Function to add a new user
async function addUser(username, user) {
  const db = await openDb();
  const existingUser = await getUser(username);
  if (existingUser) {
      throw Error('username already exists');
  }
  await db.run(`INSERT INTO users (username, user_webauthen_data) VALUES (?, ?)`, [username, JSON.stringify(user)]);
  await db.close();
}

export async function signupWebAuthn(username, user) {
  await addUser(username, user);
}

export async function signinWebAuthn(username) {
  return await getUser(username);
}

