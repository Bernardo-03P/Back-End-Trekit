const { Pool } = require("pg");

let pool; // Variável para armazenar a conexão (padrão singleton)

function getPool() {
    if (!pool) {
        console.log("Creating new PostgreSQL connection pool...");

        if (!process.env.DATABASE_URL) {
            throw new Error("FATAL: DATABASE_URL environment variable is not set.");
        }

        pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            // Configuração SSL exigida por provedores como Heroku e Render
            ssl: {
                rejectUnauthorized: false
            }
        });

        // Teste de conexão ao criar o pool
        pool.query('SELECT NOW()', (err, res) => {
            if (err) {
                console.error('CRITICAL ERROR: Failed to connect to PostgreSQL.', err.stack);
                // Em caso de falha, resetamos o pool para tentar reconectar na próxima vez
                pool = null; 
            } else {
                console.log('Successfully connected to PostgreSQL database pool.');
            }
        });
    }
    return pool;
}

module.exports = {
  query: (text, params) => getPool().query(text, params),
  getClient: () => getPool().connect(), 
};