const { Pool } = require("pg");

const connectionString = process.env.DATABASE_URL; // Lê a URL do ambiente

if (!connectionString) {
    throw new Error("A variável de ambiente DATABASE_URL não foi definida.");
}

const pool = new Pool({
    connectionString,
    // Adiciona configuração SSL, necessária para conexões em produção no Render
    ssl: {
        rejectUnauthorized: false 
    }
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  getClient: () => pool.connect(), 
};