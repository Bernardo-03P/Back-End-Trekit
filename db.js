const { Pool } = require("pg");
require("dotenv").config(); // Garante que as variáveis do .env sejam lidas para testes locais

const isProduction = process.env.NODE_ENV === "production";

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
    throw new Error("A variável de ambiente DATABASE_URL não foi definida.");
}

// Configuração SSL exigida por provedores como Heroku e Render
const sslConfig = isProduction 
    ? { ssl: { rejectUnauthorized: false } } 
    : {};

const pool = new Pool({
    connectionString,
    ...sslConfig // Adiciona a configuração de SSL se estiver em produção
});

// Apenas um teste de conexão para o console
pool.query('SELECT NOW()', (err) => {
    if (err) {
        console.error('CRITICAL ERROR: Failed to connect to PostgreSQL.', err.stack);
    } else {
        console.log('Successfully connected to PostgreSQL database pool.');
    }
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  getClient: () => pool.connect(), 
};