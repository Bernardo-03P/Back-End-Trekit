require("dotenv").config(); 
const db = require("./db");
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;

const port = process.env.PORT || 5000;
const app = express();

app.use(express.json());
app.use(cors());

// --- CONFIGURAÇÃO CLOUDINARY E MULTER ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
const createCloudinaryStorage = (folderName) => {
    return new CloudinaryStorage({
        cloudinary: cloudinary,
        params: {
            folder: `trekit/${folderName}`,
            allowed_formats: ['jpg', 'png', 'jpeg'],
            transformation: [{ width: 1600, height: 1600, crop: "limit" }]
        }
    });
};
const uploadAvatar = multer({ storage: createCloudinaryStorage('avatars') });
const uploadComment = multer({ storage: createCloudinaryStorage('comments') });
const uploadTrilha = multer({ storage: createCloudinaryStorage('trilhas') });

// --- MIDDLEWARE JWT ---
const decodeToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (!err) req.user = user;
        });
    }
    next();
};
app.use(decodeToken);


/* ==================================================================
   1. ROTAS DE AUTENTICAÇÃO
   ================================================================== */

app.post('/api/auth/register', async (req, res) => {
    try {
        const { nome, email, username, senha } = req.body;
        
        // Validação de entrada
        if (!nome || !email || !username || !senha) {
            return res.status(400).json({ message: "Todos os campos são obrigatórios." });
        }

        const userCheck = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userCheck.rows.length > 0) {
            return res.status(409).json({ message: "E-mail já cadastrado." });
        }

        const salt = await bcrypt.genSalt(10);
        const senhaCriptografada = await bcrypt.hash(senha, salt);
        
        await db.query("INSERT INTO users(nome, email, username, senha) VALUES ($1, $2, $3, $4)", [nome, email, username, senhaCriptografada]);
        
        // Retorna apenas uma mensagem de sucesso. O usuário agora precisa fazer login.
        res.status(201).json({ message: "Usuário registrado com sucesso! Por favor, faça o login." });
    
    } catch (err) {
        console.error("ERRO NO REGISTRO:", err.stack); // Isso mostrará o erro exato no log do Render
        res.status(500).json({ error: "Erro interno ao tentar registrar usuário." });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, senha } = req.body;
        const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        const user = result.rows[0];
        if (!user || !(await bcrypt.compare(senha, user.senha))) {
            return res.status(401).json({ message: "Credenciais inválidas." });
        }
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.status(200).json({ token, user: { id: user.id, nome: user.nome, role: user.role, avatar_url: user.avatar_url } });
    } catch (err) {
        console.error("Erro em POST /api/auth/login:", err);
        res.status(500).json({ error: "Erro interno ao tentar fazer login." });
    }
});


/* ==================================================================
   2. ROTAS DE TRILHAS
   ================================================================== */

app.get('/api/trilhas', async (req, res) => {
     try {
        const loggedInUserId = req.user ? req.user.id : null;
        let baseQuery = `
            SELECT t.*, u.nome AS autor_nome, u.id AS autor_id,
                   (SELECT ti.caminho_arquivo FROM trilha_imagens ti WHERE ti.trilha_id = t.id ORDER BY ti.id ASC LIMIT 1) as imagem_principal_url,
                   CASE WHEN l.autor_id IS NOT NULL THEN true ELSE false END AS is_liked_by_user
            FROM trilhas t
            INNER JOIN users u ON t.autor_id = u.id
            LEFT JOIN trilha_likes l ON t.id = l.trilha_id AND l.autor_id = $1
        `;
        const whereClauses = ["t.status = 'aprovada'"];
        const queryParams = [loggedInUserId];
        let paramIndex = 2;
        if (req.query.busca) { whereClauses.push(`(t.nome ILIKE $${paramIndex} OR t.bairro ILIKE $${paramIndex} OR t.descricao ILIKE $${paramIndex})`); queryParams.push(`%${req.query.busca}%`); paramIndex++; }
        if (req.query.dificuldade) { whereClauses.push(`t.dificuldade = $${paramIndex++}`); queryParams.push(req.query.dificuldade); }
        if (req.query.bairro) { whereClauses.push(`t.bairro ILIKE $${paramIndex++}`); queryParams.push(`%${req.query.bairro}%`); }
        if (req.query.sinalizacao) { whereClauses.push(`t.sinalizacao = $${paramIndex++}`); queryParams.push(req.query.sinalizacao); }
        if (req.query.distanciaMin) { whereClauses.push(`t.distancia_km >= $${paramIndex++}`); queryParams.push(parseFloat(req.query.distanciaMin)); }
        if (req.query.distanciaMax) { whereClauses.push(`t.distancia_km <= $${paramIndex++}`); queryParams.push(parseFloat(req.query.distanciaMax)); }
        if (whereClauses.length > 0) baseQuery += " WHERE " + whereClauses.join(" AND ");
        baseQuery += " ORDER BY t.created_at DESC;";
        const result = await db.query(baseQuery, queryParams);
        res.json(result.rows);
    } catch (err) {
        console.error("Erro em GET /api/trilhas:", err);
        res.status(500).json({ error: "Erro ao buscar trilhas." });
    }
});

// Rota específica de SUGESTÕES (deve vir antes da rota genérica /:id)
app.get('/api/trilhas/sugestoes', async (req, res) => {
    try {
        const trilhaIdExcluida = parseInt(req.query.excluir_id);
        if (isNaN(trilhaIdExcluida)) return res.status(400).json({ error: "ID inválido." });
        const sql = `
            SELECT t.id, t.nome, u.nome as autor_nome,
                   (SELECT ti.caminho_arquivo FROM trilha_imagens ti WHERE ti.trilha_id = t.id LIMIT 1) as imagem_principal_url
            FROM trilhas t JOIN users u ON t.autor_id = u.id
            WHERE t.status = 'aprovada' AND t.id != $1 ORDER BY RANDOM() LIMIT 4;
        `;
        const result = await db.query(sql, [trilhaIdExcluida]);
        res.json(result.rows);
    } catch (err) {
        console.error("Erro ao buscar sugestões de trilhas:", err);
        res.status(500).json({ error: "Erro interno do servidor." });
    }
});

// Rota genérica para buscar uma trilha por ID
app.get('/api/trilhas/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const loggedInUserId = req.user ? req.user.id : null;
        if (isNaN(id)) return res.status(400).json({ error: "ID inválido." });

        // Passo 1: Busca a trilha principal.
        const trilhaSql = `
            SELECT t.*, u.nome AS autor_nome, u.avatar_url AS autor_avatar_url,
                   CASE WHEN l.autor_id IS NOT NULL THEN true ELSE false END AS is_liked_by_user
            FROM trilhas t
            JOIN users u ON t.autor_id = u.id
            LEFT JOIN trilha_likes l ON t.id = l.trilha_id AND l.autor_id = $1
            WHERE t.id = $2;
        `;
        const trilhaResult = await db.query(trilhaSql, [loggedInUserId, id]);
        
        // Passo 2: Verifica se a trilha foi encontrada.
        if (trilhaResult.rows.length === 0) {
            return res.status(404).json({ error: "Trilha não encontrada." });
        }
        const trilha = trilhaResult.rows[0];

        // Passo 3: Busca as imagens da trilha encontrada.
        const imagensResult = await db.query('SELECT id, nome_arquivo, caminho_arquivo FROM trilha_imagens WHERE trilha_id = $1 ORDER BY id ASC;', [id]);
        
        // Passo 4: Anexa as imagens ao objeto da trilha.
        trilha.imagens = imagensResult.rows;

        // Passo 5: Envia a resposta completa.
        res.json(trilha);

    } catch (err) {
        console.error(`Erro em GET /api/trilhas/${req.params.id}:`, err.stack);
        res.status(500).json({ error: "Erro ao buscar detalhes da trilha." });
    }
});

app.post('/api/trilhas', uploadTrilha.array('imagens', 5), async (req, res) => {
    let client;
    try {
        if (!req.user) return res.status(401).json({ error: "Autenticação necessária." });
        
        client = await db.getClient();
        await client.query('BEGIN');

        const autor_id = req.user.id; 
        const { nome, bairro, distancia_km, dificuldade, sinalizacao, tempo_min, ...outrosCampos } = req.body;
        if (!nome || !bairro || !distancia_km || !dificuldade || !sinalizacao) return res.status(400).json({ error: "Campos obrigatórios estão faltando." });
        
        const trilhaSql = `
            INSERT INTO trilhas(nome, bairro, cidade, localizacao_maps, distancia_km, tempo_min, dificuldade, sinalizacao, autor_id, descricao, mapa_embed_url) 
            VALUES ($1, $2, 'Florianópolis-SC', $3, $4, $5, $6, $7, $8, $9, $10) 
            RETURNING id;
        `;
        const values = [nome, bairro, outrosCampos.localizacao_maps, distancia_km, tempo_min || null, dificuldade, sinalizacao, autor_id, outrosCampos.descricao, outrosCampos.mapa_embed_url];
        const trilhaResult = await client.query(trilhaSql, values);
        const newTrilhaId = trilhaResult.rows[0].id;

        if (req.files && req.files.length > 0) {
            const imagePromises = req.files.map(file => {
                const imageSql = `INSERT INTO trilha_imagens(trilha_id, nome_arquivo, caminho_arquivo) VALUES ($1, $2, $3);`;
                return client.query(imageSql, [newTrilhaId, file.filename, file.path]);
            });
            await Promise.all(imagePromises);
        }
        await client.query('COMMIT');
        res.status(201).json({ message: 'Trilha criada com sucesso!', id: newTrilhaId });
        
    } catch (err) {
        if (client) { await client.query('ROLLBACK'); }
        console.error("ERRO DETALHADO em POST /api/trilhas:", err.stack);
        res.status(500).json({ error: "Erro interno ao criar a trilha." });
    } finally {
        if (client) { client.release(); }
    }
});

/* ==================================================================
   3. ROTAS DE COMENTÁRIOS E CURTIDAS (LIKES)
   ================================================================== */

// A) Likes na TRILHA principal
app.post('/api/trilhas/:id/like', async (req, res) => {
    try {
        if (!req.user) return res.status(401).json({ error: "Autenticação necessária." });
        const trilhaId = parseInt(req.params.id);
        const autorId = req.user.id;
        if (isNaN(trilhaId)) return res.status(400).json({ error: "ID inválido."});
        await db.query(`INSERT INTO trilha_likes (autor_id, trilha_id) VALUES ($1, $2)`, [autorId, trilhaId]);
        res.status(201).json({ message: "Trilha curtida." });
    } catch (err) {
        if (err.code === '23505') return res.status(409).json({ error: "Trilha já curtida." });
        res.status(500).json({ error: "Erro ao curtir a trilha." });
    }
});

app.delete('/api/trilhas/:id/like', async (req, res) => {
    try {
        if (!req.user) return res.status(401).json({ error: "Autenticação necessária." });
        const trilhaId = parseInt(req.params.id);
        const autorId = req.user.id;
        if (isNaN(trilhaId)) return res.status(400).json({ error: "ID inválido."});
        await db.query(`DELETE FROM trilha_likes WHERE autor_id = $1 AND trilha_id = $2`, [autorId, trilhaId]);
        res.status(200).json({ message: "Curtida removida." });
    } catch (err) {
        res.status(500).json({ error: "Erro ao remover a curtida." });
    }
});

// B) Comentários
app.get('/api/trilhas/:id/comentarios', async (req, res) => {
    try {
        const idDaTrilha = parseInt(req.params.id); // Usando um nome de variável claro
        const loggedInUserId = req.user ? req.user.id : null;

        if (isNaN(idDaTrilha)) {
            return res.status(400).json({ error: "ID da trilha inválido." });
        }

        const sql = `
            SELECT 
                c.id, c.conteudo, c.created_at, 
                u.nome AS autor_nome, u.id as autor_id, u.avatar_url as autor_avatar_url,
                (SELECT COUNT(*) FROM comentario_likes cl WHERE cl.comentario_id = c.id) as like_count,
                CASE WHEN EXISTS (
                    SELECT 1 FROM comentario_likes cl WHERE cl.comentario_id = c.id AND cl.autor_id = $2
                ) THEN true ELSE false END AS is_liked_by_user
            FROM comentarios c 
            JOIN users u ON c.autor_id = u.id 
            WHERE c.trilha_id = $1 
            ORDER BY c.created_at DESC;
        `;
        
        const commentsResult = await db.query(sql, [idDaTrilha, loggedInUserId]);
        const comentarios = commentsResult.rows;

        // Anexa as imagens a cada comentário (esta parte já estava correta)
        for (const comentario of comentarios) {
            const imagesResult = await db.query('SELECT id, nome_arquivo FROM comentario_imagens WHERE comentario_id = $1', [comentario.id]);
            comentario.imagens = imagesResult.rows;
        }

        res.json(comentarios);
    } catch (err) {
        console.error("ERRO DETALHADO em /comentarios:", err.stack); // Log mais detalhado
        res.status(500).json({ error: "Erro ao buscar comentários." });
    }
});

app.post('/api/trilhas/:id/comentarios', uploadComment.array('imagens', 3), async (req, res) => {
    let client;
    try {
        client = await db.getClient();
        await client.query('BEGIN');
        const trilhaId = parseInt(req.params.id);
        const { conteudo, autor_id } = req.body;
        if (isNaN(trilhaId) || (!conteudo && (!req.files || req.files.length === 0)) || !autor_id) return res.status(400).json({ error: "Dados do comentário incompletos." });
        
        const commentResult = await client.query('INSERT INTO comentarios(conteudo, trilha_id, autor_id) VALUES ($1, $2, $3) RETURNING id;', [conteudo || '', trilhaId, autor_id]);
        const newCommentId = commentResult.rows[0].id;

         if (req.files && req.files.length > 0) {
            const imagePromises = req.files.map(file => {
                return client.query(`INSERT INTO comentario_imagens(comentario_id, nome_arquivo, caminho_arquivo) VALUES ($1, $2, $3);`, [newCommentId, file.filename, file.path]);
            });
            await Promise.all(imagePromises);
        }
        await client.query('COMMIT');
        
        // Retornando o comentário completo para a UI
        const commentDetailsResult = await db.query('SELECT c.id, c.conteudo, c.created_at, u.nome AS autor_nome, u.id AS autor_id, u.avatar_url AS autor_avatar_url FROM comentarios c JOIN users u ON c.autor_id = u.id WHERE c.id = $1;', [newCommentId]);
        const novoComentario = commentDetailsResult.rows[0];
        const imagesResult = await db.query('SELECT id, nome_arquivo FROM comentario_imagens WHERE comentario_id = $1;', [newCommentId]);
        novoComentario.imagens = imagesResult.rows;
        
        res.status(201).json(novoComentario);
    } catch (err) {
        if (client) await client.query('ROLLBACK');
        res.status(500).json({ error: "Erro ao postar comentário." });
    } finally {
        if (client) client.release();
    }
});

// C) Likes em COMENTÁRIOS específicos
app.post('/api/comentarios/:id/like', async (req, res) => {
    try {
        if (!req.user) return res.status(401).json({ error: "Autenticação necessária." });
        const comentarioId = parseInt(req.params.id);
        const autorId = req.user.id;
        await db.query(`INSERT INTO comentario_likes (autor_id, comentario_id) VALUES ($1, $2)`, [autorId, comentarioId]);
        res.status(201).send();
    } catch (err) {
        if (err.code === '23505') return res.status(409).send(); // Já curtido
        res.status(500).json({ error: "Erro ao curtir o comentário." });
    }
});

app.delete('/api/comentarios/:id/like', async (req, res) => {
    try {
        if (!req.user) return res.status(401).json({ error: "Autenticação necessária." });
        const comentarioId = parseInt(req.params.id);
        const autorId = req.user.id;
        await db.query(`DELETE FROM comentario_likes WHERE autor_id = $1 AND comentario_id = $2`, [autorId, comentarioId]);
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ error: "Erro ao remover a curtida." });
    }
});


/* ==================================================================
   4. ROTAS DE PERFIL DE USUÁRIO (E TRILHAS CURTIDAS)
   ================================================================== */

app.get('/api/me/trilhas-curtidas', async (req, res) => {
    try {
        if (!req.user) return res.status(401).json({ error: "Autenticação necessária." });
        const loggedInUserId = req.user.id;
        const sql = `
            SELECT t.*, u.nome AS autor_nome, true AS is_liked_by_user
            FROM trilha_likes l JOIN trilhas t ON l.trilha_id = t.id JOIN users u ON t.autor_id = u.id
            WHERE l.autor_id = $1 ORDER BY l.created_at DESC;
        `;
        const result = await db.query(sql, [loggedInUserId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Erro ao buscar trilhas curtidas." });
    }
});

app.get('/api/users/:id', async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        if (isNaN(userId)) return res.status(400).json({ error: "ID de usuário inválido." });
        const result = await db.query('SELECT id, nome, username, bio, email, role, avatar_url FROM users WHERE id = $1', [userId]);
        if (result.rows.length === 0) return res.status(404).json({ error: "Usuário não encontrado." });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: "Erro ao buscar dados do perfil." });
    }
});

app.get('/api/users/:id/trilhas', async (req, res) => {
    try {
        const profileOwnerId = parseInt(req.params.id);
        const loggedInUserId = req.user ? req.user.id : null;
        if (isNaN(profileOwnerId)) return res.status(400).json({ error: "ID de usuário inválido." });
        const sql = `
            SELECT t.*, u.nome AS autor_nome, CASE WHEN l.autor_id IS NOT NULL THEN true ELSE false END AS is_liked_by_user
            FROM trilhas t JOIN users u ON t.autor_id = u.id LEFT JOIN trilha_likes l ON t.id = l.trilha_id AND l.autor_id = $1
            WHERE t.autor_id = $2 ORDER BY t.created_at DESC;
        `;
        const result = await db.query(sql, [loggedInUserId, profileOwnerId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Erro ao buscar trilhas do usuário." });
    }
});

app.put('/api/users/:id', async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        if (!req.user || (req.user.id !== userId && req.user.role !== 'admin')) return res.status(403).json({ error: "Ação não autorizada." });

        const { nome, username, bio, email } = req.body;
        if (isNaN(userId)) return res.status(400).json({ error: "ID inválido." });
        
        const result = await db.query('UPDATE users SET nome = $1, username = $2, bio = $3, email = $4 WHERE id = $5 RETURNING *;', [nome, username, bio, email, userId]);
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: "Erro ao atualizar perfil." });
    }
});

app.put('/api/users/:id/avatar', uploadAvatar.single('avatar'), async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        if (!req.user || (req.user.id !== userId && req.user.role !== 'admin')) return res.status(403).json({ error: "Ação não autorizada." });
        if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
        
        const avatarUrl = req.file.path; // A URL segura do Cloudinary

        const result = await db.query(`UPDATE users SET avatar_url = $1 WHERE id = $2 RETURNING id, nome, role, avatar_url, username, bio, email;`, [avatarUrl, userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }
        res.json(result.rows[0]);
    } catch (err) {
        console.error("Erro em PUT /api/users/:id/avatar:", err);
        res.status(500).json({ error: "Erro interno ao atualizar o avatar." });
    }
});


/* ==================================================================
   5. ROTAS DE ADMINISTRAÇÃO
   ================================================================== */

app.get('/api/admin/todas-as-trilhas', async (req, res) => {
    try {
        const result = await db.query(`
            SELECT t.*, u.nome AS autor_nome,
                   
                   -- PADRONIZAÇÃO APLICADA AQUI
                   (SELECT ti.caminho_arquivo FROM trilha_imagens ti WHERE ti.trilha_id = t.id ORDER BY ti.id ASC LIMIT 1) as imagem_principal_url

            FROM trilhas t JOIN users u ON t.autor_id = u.id ORDER BY t.created_at DESC;
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Erro ao buscar trilhas de admin."});
    }
});

app.get('/api/admin/trilhas-pendentes', async (req, res) => {
    try {
        const result = await db.query("SELECT t.*, u.nome AS autor_nome FROM trilhas t JOIN users u ON t.autor_id = u.id WHERE t.status = 'pendente' ORDER BY t.created_at ASC;");
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Erro ao buscar trilhas pendentes." });
    }
});

app.patch('/api/admin/trilhas/:id/status', async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        if (!status || !['aprovada', 'rejeitada'].includes(status)) return res.status(400).json({ error: "Status inválido." });
        
        if (status === 'rejeitada') {
            await db.query("DELETE FROM trilhas WHERE id = $1", [id]);
        } else {
            await db.query("UPDATE trilhas SET status = $1 WHERE id = $2", [status, id]);
        }
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ error: "Erro ao atualizar status da trilha." });
    }
});

app.delete('/api/admin/trilhas/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await db.query("DELETE FROM trilhas WHERE id = $1", [id]);
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ error: "Erro ao deletar a trilha." });
    }
});


/* ==================================================================
   INICIALIZAÇÃO DO SERVIDOR
   ================================================================== */

app.listen(port, () => {
    console.log(`Backend do Trekit Rodando na porta ${port}!`);
});