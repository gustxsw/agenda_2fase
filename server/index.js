import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import { ensureSignatureColumn } from './database/signatureColumn.js';
import createUpload from './middleware/upload.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { generateDocumentPDF } from './utils/documentGenerator.js';

// ES modules compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// CORS configuration
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://www.cartaoquiroferreira.com.br',
    'https://cartaoquiroferreira.com.br'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static(path.join(__dirname, '../dist')));

// Initialize database
const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database...');
    await ensureSignatureColumn();
    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
};

// Initialize upload middleware
let upload;
try {
  upload = createUpload();
  console.log('✅ Upload middleware initialized');
} catch (error) {
  console.error('❌ Upload middleware initialization failed:', error);
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    const result = await pool.query(
      'SELECT id, name, cpf, password_hash, roles FROM users WHERE cpf = $1',
      [cpf]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);

    if (!isValidPassword) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    res.json({
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        roles: user.roles || []
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;

    if (!userId || !role) {
      return res.status(400).json({ message: 'UserId e role são obrigatórios' });
    }

    const result = await pool.query(
      'SELECT id, name, cpf, roles FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];

    if (!user.roles || !user.roles.includes(role)) {
      return res.status(403).json({ message: 'Role não autorizada para este usuário' });
    }

    const token = jwt.sign(
      { id: user.id, currentRole: role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        roles: user.roles,
        currentRole: role
      }
    });
  } catch (error) {
    console.error('Role selection error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/switch-role', authenticate, async (req, res) => {
  try {
    const { role } = req.body;

    if (!role) {
      return res.status(400).json({ message: 'Role é obrigatória' });
    }

    if (!req.user.roles.includes(role)) {
      return res.status(403).json({ message: 'Role não autorizada para este usuário' });
    }

    const token = jwt.sign(
      { id: req.user.id, currentRole: role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.json({
      token,
      user: {
        ...req.user,
        currentRole: role
      }
    });
  } catch (error) {
    console.error('Role switch error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      name,
      cpf,
      email,
      phone,
      birth_date,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      password
    } = req.body;

    if (!name || !cpf || !password) {
      return res.status(400).json({ message: 'Nome, CPF e senha são obrigatórios' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user with client role and pending subscription
    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, 
        roles, subscription_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW()) 
      RETURNING id, name, cpf, roles`,
      [
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, passwordHash,
        ['client'], 'pending'
      ]
    );

    const user = result.rows[0];

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        roles: user.roles
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Documents routes
app.get('/api/documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Fetching documents for professional:', req.user.id);
    
    const result = await pool.query(
      `SELECT d.*, pp.name as patient_name 
       FROM documents d
       LEFT JOIN private_patients pp ON d.private_patient_id = pp.id
       WHERE d.professional_id = $1
       ORDER BY d.created_at DESC`,
      [req.user.id]
    );

    console.log('✅ Documents found:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching documents:', error);
    res.status(500).json({ message: 'Erro ao carregar documentos' });
  }
});

app.post('/api/documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Creating document:', req.body);
    
    const { document_type, title, private_patient_id, template_data } = req.body;

    if (!document_type || !title || !private_patient_id || !template_data) {
      return res.status(400).json({ message: 'Dados obrigatórios não fornecidos' });
    }

    // Generate document
    const documentResult = await generateDocumentPDF(
      document_type,
      template_data,
      req.user.id
    );

    // Save document record
    const result = await pool.query(
      `INSERT INTO documents (
        professional_id, private_patient_id, document_type, title, 
        document_url, template_data, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW()) 
      RETURNING *`,
      [
        req.user.id,
        private_patient_id,
        document_type,
        title,
        documentResult.url,
        JSON.stringify(template_data)
      ]
    );

    console.log('✅ Document created:', result.rows[0]);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating document:', error);
    res.status(500).json({ 
      message: error.message || 'Erro ao criar documento' 
    });
  }
});

// Private patients routes
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Fetching private patients for professional:', req.user.id);
    
    const result = await pool.query(
      'SELECT * FROM private_patients WHERE professional_id = $1 ORDER BY name',
      [req.user.id]
    );

    console.log('✅ Private patients found:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro ao carregar pacientes' });
  }
});

app.post('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    const result = await pool.query(
      `INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW()) 
      RETURNING *`,
      [
        req.user.id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating private patient:', error);
    res.status(500).json({ message: 'Erro ao criar paciente' });
  }
});

// Users routes
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.*, sc.name as category_name 
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      ORDER BY u.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro ao carregar usuários' });
  }
});

app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(`
      SELECT u.*, sc.name as category_name 
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.id = $1
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Erro ao carregar usuário' });
  }
});

// Services routes
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.*, sc.name as category_name 
      FROM services s
      LEFT JOIN service_categories sc ON s.category_id = sc.id
      ORDER BY s.name
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Erro ao carregar serviços' });
  }
});

// Service categories routes
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM service_categories ORDER BY name');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro ao carregar categorias' });
  }
});

// Consultations routes
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.*,
        COALESCE(cl.name, pp.name) as client_name,
        s.name as service_name,
        u.name as professional_name,
        CASE 
          WHEN c.dependent_id IS NOT NULL THEN true 
          ELSE false 
        END as is_dependent
      FROM consultations c
      LEFT JOIN users cl ON c.client_id = cl.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users u ON c.professional_id = u.id
    `;

    const params = [];

    // Filter by professional if not admin
    if (req.user.currentRole === 'professional') {
      query += ' WHERE c.professional_id = $1';
      params.push(req.user.id);
    }

    query += ' ORDER BY c.date DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching consultations:', error);
    res.status(500).json({ message: 'Erro ao carregar consultas' });
  }
});

app.post('/api/consultations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      client_id,
      dependent_id,
      private_patient_id,
      service_id,
      location_id,
      value,
      date,
      status = 'completed',
      notes
    } = req.body;

    if (!service_id || !value || !date) {
      return res.status(400).json({ message: 'Serviço, valor e data são obrigatórios' });
    }

    if (!client_id && !dependent_id && !private_patient_id) {
      return res.status(400).json({ message: 'É necessário especificar um cliente, dependente ou paciente particular' });
    }

    const result = await pool.query(
      `INSERT INTO consultations (
        professional_id, client_id, dependent_id, private_patient_id,
        service_id, location_id, value, date, status, notes, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW()) 
      RETURNING *`,
      [
        req.user.id, client_id, dependent_id, private_patient_id,
        service_id, location_id, value, date, status, notes
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro ao criar consulta' });
  }
});

// Professionals routes
app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.*, sc.name as category_name 
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.roles @> '["professional"]'
      ORDER BY u.name
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro ao carregar profissionais' });
  }
});

// Image upload route
app.post('/api/upload-image', authenticate, (req, res) => {
  if (!upload) {
    return res.status(500).json({ message: 'Upload não configurado' });
  }

  upload.single('image')(req, res, async (err) => {
    if (err) {
      console.error('Upload error:', err);
      return res.status(400).json({ message: err.message || 'Erro no upload' });
    }

    if (!req.file) {
      return res.status(400).json({ message: 'Nenhum arquivo enviado' });
    }

    try {
      // Update user photo URL
      await pool.query(
        'UPDATE users SET photo_url = $1 WHERE id = $2',
        [req.file.path, req.user.id]
      );

      res.json({ imageUrl: req.file.path });
    } catch (error) {
      console.error('Error updating photo URL:', error);
      res.status(500).json({ message: 'Erro ao salvar URL da imagem' });
    }
  });
});

// Signature upload route
app.post('/api/upload-signature', authenticate, (req, res) => {
  if (!upload) {
    return res.status(500).json({ message: 'Upload não configurado' });
  }

  upload.single('signature')(req, res, async (err) => {
    if (err) {
      console.error('Signature upload error:', err);
      return res.status(400).json({ message: err.message || 'Erro no upload da assinatura' });
    }

    if (!req.file) {
      return res.status(400).json({ message: 'Nenhum arquivo de assinatura enviado' });
    }

    try {
      // Update user signature URL
      await pool.query(
        'UPDATE users SET signature_url = $1 WHERE id = $2',
        [req.file.path, req.user.id]
      );

      console.log('✅ Signature URL updated for user:', req.user.id);
      res.json({ signatureUrl: req.file.path });
    } catch (error) {
      console.error('❌ Error updating signature URL:', error);
      res.status(500).json({ message: 'Erro ao salvar URL da assinatura' });
    }
  });
});

// Remove signature route
app.delete('/api/remove-signature', authenticate, async (req, res) => {
  try {
    console.log('🔄 Removing signature for user:', req.user.id);

    // Update user signature URL to null
    await pool.query(
      'UPDATE users SET signature_url = NULL WHERE id = $1',
      [req.user.id]
    );

    console.log('✅ Signature removed successfully');
    res.json({ message: 'Assinatura removida com sucesso' });
  } catch (error) {
    console.error('❌ Error removing signature:', error);
    res.status(500).json({ message: 'Erro ao remover assinatura' });
  }
});

// Catch-all handler for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Erro interno do servidor' });
});

// Start server
const startServer = async () => {
  try {
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📱 Frontend: http://localhost:${PORT}`);
      console.log(`🔗 API: http://localhost:${PORT}/api`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();