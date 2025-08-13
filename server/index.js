import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import createUpload from './middleware/upload.js';
import { generateDocumentPDF } from './utils/documentGenerator.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://cartaoquiroferreira.com.br',
    'https://www.cartaoquiroferreira.com.br'
  ],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static('dist'));

// Database initialization
const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database schema...');

    // Create service categories table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create services table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        base_price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
        category_id INTEGER REFERENCES service_categories(id) ON DELETE SET NULL,
        is_base_service BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create users table with roles array
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) UNIQUE NOT NULL,
        email VARCHAR(255),
        phone VARCHAR(20),
        birth_date DATE,
        address TEXT,
        address_number VARCHAR(20),
        address_complement VARCHAR(100),
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        zip_code VARCHAR(8),
        password_hash VARCHAR(255) NOT NULL,
        roles TEXT[] NOT NULL DEFAULT '{}',
        percentage INTEGER DEFAULT 50,
        category_id INTEGER REFERENCES service_categories(id) ON DELETE SET NULL,
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry DATE,
        has_scheduling_access BOOLEAN DEFAULT FALSE,
        access_expires_at TIMESTAMP,
        access_granted_by VARCHAR(255),
        access_granted_at TIMESTAMP,
        photo_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create dependents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dependents (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) UNIQUE NOT NULL,
        birth_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create private patients table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS private_patients (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) NOT NULL,
        email VARCHAR(255),
        phone VARCHAR(20),
        birth_date DATE,
        address TEXT,
        address_number VARCHAR(20),
        address_complement VARCHAR(100),
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        zip_code VARCHAR(8),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(professional_id, cpf)
      )
    `);

    // Create attendance locations table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS attendance_locations (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        address TEXT,
        address_number VARCHAR(20),
        address_complement VARCHAR(100),
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        zip_code VARCHAR(8),
        phone VARCHAR(20),
        is_default BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create appointments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        client_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        dependent_id INTEGER REFERENCES dependents(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id) ON DELETE CASCADE,
        service_id INTEGER REFERENCES services(id) ON DELETE SET NULL,
        location_id INTEGER REFERENCES attendance_locations(id) ON DELETE SET NULL,
        appointment_date DATE NOT NULL,
        appointment_time TIME NOT NULL,
        status VARCHAR(20) DEFAULT 'scheduled',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CHECK (
          (client_id IS NOT NULL AND dependent_id IS NULL AND private_patient_id IS NULL) OR
          (client_id IS NULL AND dependent_id IS NOT NULL AND private_patient_id IS NULL) OR
          (client_id IS NULL AND dependent_id IS NULL AND private_patient_id IS NOT NULL)
        )
      )
    `);

    // Create consultations table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        dependent_id INTEGER REFERENCES dependents(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id) ON DELETE CASCADE,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        service_id INTEGER REFERENCES services(id) ON DELETE SET NULL,
        location_id INTEGER REFERENCES attendance_locations(id) ON DELETE SET NULL,
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CHECK (
          (client_id IS NOT NULL AND dependent_id IS NULL AND private_patient_id IS NULL) OR
          (client_id IS NULL AND dependent_id IS NOT NULL AND private_patient_id IS NULL) OR
          (client_id IS NULL AND dependent_id IS NULL AND private_patient_id IS NOT NULL)
        )
      )
    `);

    // Create medical records table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_records (
        id SERIAL PRIMARY KEY,
        private_patient_id INTEGER NOT NULL REFERENCES private_patients(id) ON DELETE CASCADE,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        chief_complaint TEXT,
        history_present_illness TEXT,
        past_medical_history TEXT,
        medications TEXT,
        allergies TEXT,
        physical_examination TEXT,
        diagnosis TEXT,
        treatment_plan TEXT,
        notes TEXT,
        vital_signs JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create medical documents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_documents (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        document_type VARCHAR(50) NOT NULL,
        document_url TEXT NOT NULL,
        template_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create indexes for better performance
    await pool.query('CREATE INDEX IF NOT EXISTS idx_users_cpf ON users(cpf)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_users_roles ON users USING GIN(roles)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_consultations_professional ON consultations(professional_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_consultations_date ON consultations(date)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_dependents_client ON dependents(client_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_dependents_cpf ON dependents(cpf)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_private_patients_professional ON private_patients(professional_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_appointments_professional ON appointments(professional_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(appointment_date)');

    // Insert default service categories
    await pool.query(`
      INSERT INTO service_categories (name, description) VALUES
      ('Medicina Geral', 'Consultas médicas gerais e clínica médica'),
      ('Fisioterapia', 'Tratamentos fisioterapêuticos e reabilitação'),
      ('Psicologia', 'Atendimento psicológico e terapia'),
      ('Nutrição', 'Consultas nutricionais e planejamento alimentar'),
      ('Odontologia', 'Tratamentos dentários e saúde bucal'),
      ('Quiropraxia', 'Tratamentos quiropráticos e ajustes da coluna'),
      ('Massoterapia', 'Massagens terapêuticas e relaxantes'),
      ('Acupuntura', 'Tratamentos com acupuntura'),
      ('Dermatologia', 'Cuidados com a pele e tratamentos dermatológicos'),
      ('Cardiologia', 'Consultas cardiológicas e exames do coração')
      ON CONFLICT (name) DO NOTHING
    `);

    // Insert default services
    await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      SELECT 
        'Consulta ' || sc.name,
        'Consulta básica de ' || sc.name,
        CASE 
          WHEN sc.name = 'Medicina Geral' THEN 150.00
          WHEN sc.name = 'Fisioterapia' THEN 80.00
          WHEN sc.name = 'Psicologia' THEN 120.00
          WHEN sc.name = 'Nutrição' THEN 100.00
          WHEN sc.name = 'Odontologia' THEN 200.00
          WHEN sc.name = 'Quiropraxia' THEN 120.00
          WHEN sc.name = 'Massoterapia' THEN 90.00
          WHEN sc.name = 'Acupuntura' THEN 100.00
          WHEN sc.name = 'Dermatologia' THEN 180.00
          WHEN sc.name = 'Cardiologia' THEN 200.00
          ELSE 100.00
        END,
        sc.id,
        true
      FROM service_categories sc
      WHERE NOT EXISTS (
        SELECT 1 FROM services s 
        WHERE s.name = 'Consulta ' || sc.name 
        AND s.category_id = sc.id
      )
    `);

    // Create admin user if not exists
    const adminExists = await pool.query(
      "SELECT id FROM users WHERE cpf = '00000000000'"
    );

    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.query(`
        INSERT INTO users (name, cpf, email, password_hash, roles, subscription_status)
        VALUES ('Administrador', '00000000000', 'admin@quiroferreira.com.br', $1, $2, 'active')
      `, [hashedPassword, ['admin']]);
      
      console.log('✅ Admin user created with CPF: 00000000000 and password: admin123');
    }

    console.log('✅ Database schema initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    throw error;
  }
};

// Initialize database on startup
initializeDatabase().catch(console.error);

// ==================== AUTH ROUTES ====================

// Login route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    // Clean CPF
    const cleanCpf = cpf.replace(/\D/g, '');

    // Find user by CPF
    const result = await pool.query(
      'SELECT id, name, cpf, password_hash, roles FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const user = result.rows[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    // Return user data without token (will be created when role is selected)
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

// Role selection route
app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;

    if (!userId || !role) {
      return res.status(400).json({ message: 'ID do usuário e role são obrigatórios' });
    }

    // Get user and verify role
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

    // Generate JWT token with selected role
    const token = jwt.sign(
      { id: user.id, currentRole: role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
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

// Switch role route
app.post('/api/auth/switch-role', authenticate, async (req, res) => {
  try {
    const { role } = req.body;

    if (!role) {
      return res.status(400).json({ message: 'Role é obrigatória' });
    }

    // Verify user has this role
    if (!req.user.roles || !req.user.roles.includes(role)) {
      return res.status(403).json({ message: 'Role não autorizada para este usuário' });
    }

    // Generate new JWT token with new role
    const token = jwt.sign(
      { id: req.user.id, currentRole: role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    res.json({
      token,
      user: {
        id: req.user.id,
        name: req.user.name,
        cpf: req.user.cpf,
        roles: req.user.roles,
        currentRole: role
      }
    });
  } catch (error) {
    console.error('Role switch error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Register route (clients only)
app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, password
    } = req.body;

    if (!name || !cpf || !password) {
      return res.status(400).json({ message: 'Nome, CPF e senha são obrigatórios' });
    }

    // Clean CPF
    const cleanCpf = cpf.replace(/\D/g, '');

    if (cleanCpf.length !== 11) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Usuário já cadastrado com este CPF' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with client role
    const result = await pool.query(`
      INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id, name, cpf, roles
    `, [
      name, cleanCpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, hashedPassword, ['client']
    ]);

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

// Logout route
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// ==================== USER ROUTES ====================

// Get all users (admin only)
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date,
        u.address, u.address_number, u.address_complement,
        u.neighborhood, u.city, u.state, u.roles, u.percentage,
        u.category_id, u.subscription_status, u.subscription_expiry,
        u.created_at, sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      ORDER BY u.created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro ao buscar usuários' });
  }
});

// Get user by ID
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Users can only access their own data unless they're admin
    if (req.user.currentRole !== 'admin' && parseInt(id) !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date,
        u.address, u.address_number, u.address_complement,
        u.neighborhood, u.city, u.state, u.roles, u.percentage,
        u.category_id, u.subscription_status, u.subscription_expiry,
        u.photo_url, u.created_at, sc.name as category_name
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
    res.status(500).json({ message: 'Erro ao buscar usuário' });
  }
});

// Create user (admin only)
app.post('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, password, roles,
      percentage, category_id
    } = req.body;

    if (!name || !cpf || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Campos obrigatórios: nome, CPF, senha e pelo menos uma role' });
    }

    // Clean CPF
    const cleanCpf = cpf.replace(/\D/g, '');

    if (cleanCpf.length !== 11) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Usuário já cadastrado com este CPF' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(`
      INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles,
        percentage, category_id, subscription_status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
      RETURNING id, name, cpf, roles
    `, [
      name, cleanCpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, hashedPassword, roles,
      percentage, category_id, roles.includes('client') ? 'pending' : 'active'
    ]);

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Erro ao criar usuário' });
  }
});

// Update user
app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, roles,
      percentage, category_id, currentPassword, newPassword
    } = req.body;

    // Users can only update their own data unless they're admin
    if (req.user.currentRole !== 'admin' && parseInt(id) !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    // If changing password, verify current password
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Senha atual é obrigatória para alterar a senha' });
      }

      const userResult = await pool.query(
        'SELECT password_hash FROM users WHERE id = $1',
        [id]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
      }

      const isValidPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
      if (!isValidPassword) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }
    }

    // Build update query
    let updateFields = [];
    let values = [];
    let paramCount = 1;

    if (name !== undefined) {
      updateFields.push(`name = $${paramCount}`);
      values.push(name);
      paramCount++;
    }

    if (email !== undefined) {
      updateFields.push(`email = $${paramCount}`);
      values.push(email);
      paramCount++;
    }

    if (phone !== undefined) {
      updateFields.push(`phone = $${paramCount}`);
      values.push(phone);
      paramCount++;
    }

    if (birth_date !== undefined) {
      updateFields.push(`birth_date = $${paramCount}`);
      values.push(birth_date);
      paramCount++;
    }

    if (address !== undefined) {
      updateFields.push(`address = $${paramCount}`);
      values.push(address);
      paramCount++;
    }

    if (address_number !== undefined) {
      updateFields.push(`address_number = $${paramCount}`);
      values.push(address_number);
      paramCount++;
    }

    if (address_complement !== undefined) {
      updateFields.push(`address_complement = $${paramCount}`);
      values.push(address_complement);
      paramCount++;
    }

    if (neighborhood !== undefined) {
      updateFields.push(`neighborhood = $${paramCount}`);
      values.push(neighborhood);
      paramCount++;
    }

    if (city !== undefined) {
      updateFields.push(`city = $${paramCount}`);
      values.push(city);
      paramCount++;
    }

    if (state !== undefined) {
      updateFields.push(`state = $${paramCount}`);
      values.push(state);
      paramCount++;
    }

    if (roles !== undefined && req.user.currentRole === 'admin') {
      updateFields.push(`roles = $${paramCount}`);
      values.push(roles);
      paramCount++;
    }

    if (percentage !== undefined && req.user.currentRole === 'admin') {
      updateFields.push(`percentage = $${paramCount}`);
      values.push(percentage);
      paramCount++;
    }

    if (category_id !== undefined && req.user.currentRole === 'admin') {
      updateFields.push(`category_id = $${paramCount}`);
      values.push(category_id);
      paramCount++;
    }

    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updateFields.push(`password_hash = $${paramCount}`);
      values.push(hashedPassword);
      paramCount++;
    }

    updateFields.push(`updated_at = CURRENT_TIMESTAMP`);

    if (updateFields.length === 1) { // Only updated_at
      return res.status(400).json({ message: 'Nenhum campo para atualizar' });
    }

    values.push(id);

    const result = await pool.query(`
      UPDATE users 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramCount}
      RETURNING id, name, cpf, email, roles
    `, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({
      message: 'Usuário atualizado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Erro ao atualizar usuário' });
  }
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM users WHERE id = $1 RETURNING id',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({ message: 'Usuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Erro ao excluir usuário' });
  }
});

// Activate client (admin only)
app.put('/api/users/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { expiry_date } = req.body;

    if (!expiry_date) {
      return res.status(400).json({ message: 'Data de expiração é obrigatória' });
    }

    const result = await pool.query(`
      UPDATE users 
      SET subscription_status = 'active', subscription_expiry = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2 AND 'client' = ANY(roles)
      RETURNING id, name, subscription_status, subscription_expiry
    `, [expiry_date, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    res.json({
      message: 'Cliente ativado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Error activating client:', error);
    res.status(500).json({ message: 'Erro ao ativar cliente' });
  }
});

// ==================== PROFESSIONAL ROUTES ====================

// Get all professionals (for clients)
app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.roles,
        u.address, u.address_number, u.address_complement,
        u.neighborhood, u.city, u.state, u.photo_url,
        sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro ao buscar profissionais' });
  }
});

// Get professionals with scheduling access (admin only)
app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone,
        sc.name as category_name,
        u.has_scheduling_access,
        u.access_expires_at,
        u.access_granted_by,
        u.access_granted_at
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals scheduling access:', error);
    res.status(500).json({ message: 'Erro ao buscar dados de acesso à agenda' });
  }
});

// Grant scheduling access (admin only)
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: 'ID do profissional e data de expiração são obrigatórios' });
    }

    const result = await pool.query(`
      UPDATE users 
      SET 
        has_scheduling_access = true,
        access_expires_at = $1,
        access_granted_by = $2,
        access_granted_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $3 AND 'professional' = ANY(roles)
      RETURNING id, name, has_scheduling_access, access_expires_at
    `, [expires_at, req.user.name, professional_id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    res.json({
      message: 'Acesso à agenda concedido com sucesso',
      professional: result.rows[0]
    });
  } catch (error) {
    console.error('Error granting scheduling access:', error);
    res.status(500).json({ message: 'Erro ao conceder acesso à agenda' });
  }
});

// Revoke scheduling access (admin only)
app.post('/api/admin/revoke-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id } = req.body;

    if (!professional_id) {
      return res.status(400).json({ message: 'ID do profissional é obrigatório' });
    }

    const result = await pool.query(`
      UPDATE users 
      SET 
        has_scheduling_access = false,
        access_expires_at = NULL,
        access_granted_by = NULL,
        access_granted_at = NULL,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $1 AND 'professional' = ANY(roles)
      RETURNING id, name, has_scheduling_access
    `, [professional_id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    res.json({
      message: 'Acesso à agenda revogado com sucesso',
      professional: result.rows[0]
    });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro ao revogar acesso à agenda' });
  }
});

// ==================== CLIENT ROUTES ====================

// Lookup client by CPF (for professionals)
app.get('/api/clients/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.toString().replace(/\D/g, '');

    const result = await pool.query(`
      SELECT id, name, cpf, subscription_status, subscription_expiry
      FROM users 
      WHERE cpf = $1 AND 'client' = ANY(roles)
    `, [cleanCpf]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error looking up client:', error);
    res.status(500).json({ message: 'Erro ao buscar cliente' });
  }
});

// ==================== DEPENDENTS ROUTES ====================

// Get dependents by client ID
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    // Clients can only access their own dependents
    if (req.user.currentRole === 'client' && parseInt(clientId) !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      SELECT id, name, cpf, birth_date, created_at
      FROM dependents 
      WHERE client_id = $1
      ORDER BY name
    `, [clientId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro ao buscar dependentes' });
  }
});

// Lookup dependent by CPF (for professionals)
app.get('/api/dependents/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.toString().replace(/\D/g, '');

    const result = await pool.query(`
      SELECT 
        d.id, d.name, d.cpf, d.birth_date, d.client_id,
        u.name as client_name, u.subscription_status as client_subscription_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.cpf = $1
    `, [cleanCpf]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error looking up dependent:', error);
    res.status(500).json({ message: 'Erro ao buscar dependente' });
  }
});

// Create dependent
app.post('/api/dependents', authenticate, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    if (!client_id || !name || !cpf) {
      return res.status(400).json({ message: 'ID do cliente, nome e CPF são obrigatórios' });
    }

    // Clients can only create dependents for themselves
    if (req.user.currentRole === 'client' && client_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    if (cleanCpf.length !== 11) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
    }

    // Check if CPF already exists
    const existingDependent = await pool.query(
      'SELECT id FROM dependents WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingDependent.rows.length > 0) {
      return res.status(409).json({ message: 'Já existe um dependente cadastrado com este CPF' });
    }

    // Check if CPF exists in users table
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Este CPF já está cadastrado como usuário' });
    }

    const result = await pool.query(`
      INSERT INTO dependents (client_id, name, cpf, birth_date)
      VALUES ($1, $2, $3, $4)
      RETURNING id, name, cpf, birth_date, created_at
    `, [client_id, name, cleanCpf, birth_date]);

    res.status(201).json({
      message: 'Dependente criado com sucesso',
      dependent: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating dependent:', error);
    res.status(500).json({ message: 'Erro ao criar dependente' });
  }
});

// Update dependent
app.put('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    // Get dependent to check ownership
    const dependentResult = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [id]
    );

    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    // Clients can only update their own dependents
    if (req.user.currentRole === 'client' && dependentResult.rows[0].client_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const result = await pool.query(`
      UPDATE dependents 
      SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP
      WHERE id = $3
      RETURNING id, name, cpf, birth_date
    `, [name, birth_date, id]);

    res.json({
      message: 'Dependente atualizado com sucesso',
      dependent: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro ao atualizar dependente' });
  }
});

// Delete dependent
app.delete('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Get dependent to check ownership
    const dependentResult = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [id]
    );

    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    // Clients can only delete their own dependents
    if (req.user.currentRole === 'client' && dependentResult.rows[0].client_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    await pool.query('DELETE FROM dependents WHERE id = $1', [id]);

    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro ao excluir dependente' });
  }
});

// ==================== SERVICE CATEGORIES ROUTES ====================

// Get all service categories
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, description, created_at
      FROM service_categories
      ORDER BY name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro ao buscar categorias de serviços' });
  }
});

// Create service category (admin only)
app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    const result = await pool.query(`
      INSERT INTO service_categories (name, description)
      VALUES ($1, $2)
      RETURNING id, name, description, created_at
    `, [name, description]);

    res.status(201).json({
      message: 'Categoria criada com sucesso',
      category: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating service category:', error);
    if (error.code === '23505') { // Unique violation
      res.status(409).json({ message: 'Já existe uma categoria com este nome' });
    } else {
      res.status(500).json({ message: 'Erro ao criar categoria' });
    }
  }
});

// ==================== SERVICES ROUTES ====================

// Get all services
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        s.id, s.name, s.description, s.base_price, s.category_id,
        s.is_base_service, s.created_at,
        sc.name as category_name
      FROM services s
      LEFT JOIN service_categories sc ON s.category_id = sc.id
      ORDER BY sc.name, s.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Erro ao buscar serviços' });
  }
});

// Create service (admin only)
app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !description || base_price === undefined) {
      return res.status(400).json({ message: 'Nome, descrição e preço base são obrigatórios' });
    }

    const result = await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, name, description, base_price, category_id, is_base_service
    `, [name, description, base_price, category_id, is_base_service]);

    res.status(201).json({
      message: 'Serviço criado com sucesso',
      service: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating service:', error);
    res.status(500).json({ message: 'Erro ao criar serviço' });
  }
});

// Update service (admin only)
app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(`
      UPDATE services 
      SET name = $1, description = $2, base_price = $3, category_id = $4, 
          is_base_service = $5, updated_at = CURRENT_TIMESTAMP
      WHERE id = $6
      RETURNING id, name, description, base_price, category_id, is_base_service
    `, [name, description, base_price, category_id, is_base_service, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    res.json({
      message: 'Serviço atualizado com sucesso',
      service: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating service:', error);
    res.status(500).json({ message: 'Erro ao atualizar serviço' });
  }
});

// Delete service (admin only)
app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM services WHERE id = $1 RETURNING id',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    res.json({ message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting service:', error);
    res.status(500).json({ message: 'Erro ao excluir serviço' });
  }
});

// ==================== CONSULTATIONS ROUTES ====================

// Get consultations
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id, c.date, c.value, c.notes, c.created_at,
        s.name as service_name,
        u_prof.name as professional_name,
        COALESCE(u_client.name, d.name, pp.name) as client_name,
        CASE 
          WHEN c.dependent_id IS NOT NULL THEN true
          WHEN c.private_patient_id IS NOT NULL THEN false
          ELSE false
        END as is_dependent
      FROM consultations c
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users u_prof ON c.professional_id = u_prof.id
      LEFT JOIN users u_client ON c.client_id = u_client.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
    `;

    let params = [];

    if (req.user.currentRole === 'client') {
      query += ` WHERE (c.client_id = $1 OR c.dependent_id IN (
        SELECT id FROM dependents WHERE client_id = $1
      ))`;
      params.push(req.user.id);
    } else if (req.user.currentRole === 'professional') {
      query += ` WHERE c.professional_id = $1`;
      params.push(req.user.id);
    }

    query += ` ORDER BY c.date DESC`;

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching consultations:', error);
    res.status(500).json({ message: 'Erro ao buscar consultas' });
  }
});

// Create consultation
app.post('/api/consultations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      client_id, dependent_id, private_patient_id, service_id,
      location_id, value, date, notes, appointment_date,
      appointment_time, create_appointment
    } = req.body;

    if (!service_id || !value || !date) {
      return res.status(400).json({ message: 'Serviço, valor e data são obrigatórios' });
    }

    // Validate that exactly one patient type is provided
    const patientCount = [client_id, dependent_id, private_patient_id].filter(Boolean).length;
    if (patientCount !== 1) {
      return res.status(400).json({ message: 'Deve ser especificado exatamente um tipo de paciente' });
    }

    // Start transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Create consultation
      const consultationResult = await client.query(`
        INSERT INTO consultations (
          client_id, dependent_id, private_patient_id, professional_id,
          service_id, location_id, value, date, notes
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, date, value
      `, [
        client_id, dependent_id, private_patient_id, req.user.id,
        service_id, location_id, parseFloat(value), date, notes
      ]);

      let appointmentResult = null;

      // Create appointment if requested
      if (create_appointment && appointment_date && appointment_time) {
        appointmentResult = await client.query(`
          INSERT INTO appointments (
            professional_id, client_id, dependent_id, private_patient_id,
            service_id, location_id, appointment_date, appointment_time,
            status, notes
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
          RETURNING id, appointment_date, appointment_time, status
        `, [
          req.user.id, client_id, dependent_id, private_patient_id,
          service_id, location_id, appointment_date, appointment_time,
          'completed', 'Consulta registrada automaticamente'
        ]);
      }

      await client.query('COMMIT');

      res.status(201).json({
        message: 'Consulta registrada com sucesso',
        consultation: consultationResult.rows[0],
        appointment: appointmentResult ? appointmentResult.rows[0] : null
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro ao registrar consulta' });
  }
});

// ==================== PRIVATE PATIENTS ROUTES ====================

// Get private patients for professional
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, birth_date,
        address, address_number, address_complement,
        neighborhood, city, state, zip_code, created_at
      FROM private_patients 
      WHERE professional_id = $1
      ORDER BY name
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro ao buscar pacientes particulares' });
  }
});

// Create private patient
app.post('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    if (!name || !cpf) {
      return res.status(400).json({ message: 'Nome e CPF são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    if (cleanCpf.length !== 11) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
    }

    // Check if patient already exists for this professional
    const existingPatient = await pool.query(
      'SELECT id FROM private_patients WHERE professional_id = $1 AND cpf = $2',
      [req.user.id, cleanCpf]
    );

    if (existingPatient.rows.length > 0) {
      return res.status(409).json({ message: 'Paciente já cadastrado' });
    }

    const result = await pool.query(`
      INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date,
        address, address_number, address_complement, neighborhood,
        city, state, zip_code
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id, name, cpf, email, phone, birth_date, created_at
    `, [
      req.user.id, name, cleanCpf, email, phone, birth_date,
      address, address_number, address_complement, neighborhood,
      city, state, zip_code
    ]);

    res.status(201).json({
      message: 'Paciente criado com sucesso',
      patient: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating private patient:', error);
    res.status(500).json({ message: 'Erro ao criar paciente' });
  }
});

// Update private patient
app.put('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    const result = await pool.query(`
      UPDATE private_patients 
      SET 
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, zip_code = $11,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $12 AND professional_id = $13
      RETURNING id, name, cpf, email, phone, birth_date
    `, [
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code, id, req.user.id
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    res.json({
      message: 'Paciente atualizado com sucesso',
      patient: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating private patient:', error);
    res.status(500).json({ message: 'Erro ao atualizar paciente' });
  }
});

// Delete private patient
app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM private_patients WHERE id = $1 AND professional_id = $2 RETURNING id',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    res.json({ message: 'Paciente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting private patient:', error);
    res.status(500).json({ message: 'Erro ao excluir paciente' });
  }
});

// ==================== MEDICAL RECORDS ROUTES ====================

// Get medical records for professional
app.get('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        mr.id, mr.chief_complaint, mr.history_present_illness,
        mr.past_medical_history, mr.medications, mr.allergies,
        mr.physical_examination, mr.diagnosis, mr.treatment_plan,
        mr.notes, mr.vital_signs, mr.created_at, mr.updated_at,
        pp.name as patient_name
      FROM medical_records mr
      JOIN private_patients pp ON mr.private_patient_id = pp.id
      WHERE mr.professional_id = $1
      ORDER BY mr.created_at DESC
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro ao buscar prontuários' });
  }
});

// Create medical record
app.post('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id, chief_complaint, history_present_illness,
      past_medical_history, medications, allergies, physical_examination,
      diagnosis, treatment_plan, notes, vital_signs
    } = req.body;

    if (!private_patient_id) {
      return res.status(400).json({ message: 'ID do paciente é obrigatório' });
    }

    // Verify patient belongs to this professional
    const patientCheck = await pool.query(
      'SELECT id FROM private_patients WHERE id = $1 AND professional_id = $2',
      [private_patient_id, req.user.id]
    );

    if (patientCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    const result = await pool.query(`
      INSERT INTO medical_records (
        private_patient_id, professional_id, chief_complaint,
        history_present_illness, past_medical_history, medications,
        allergies, physical_examination, diagnosis, treatment_plan,
        notes, vital_signs
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING id, created_at
    `, [
      private_patient_id, req.user.id, chief_complaint,
      history_present_illness, past_medical_history, medications,
      allergies, physical_examination, diagnosis, treatment_plan,
      notes, JSON.stringify(vital_signs)
    ]);

    res.status(201).json({
      message: 'Prontuário criado com sucesso',
      record: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating medical record:', error);
    res.status(500).json({ message: 'Erro ao criar prontuário' });
  }
});

// Update medical record
app.put('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      chief_complaint, history_present_illness, past_medical_history,
      medications, allergies, physical_examination, diagnosis,
      treatment_plan, notes, vital_signs
    } = req.body;

    const result = await pool.query(`
      UPDATE medical_records 
      SET 
        chief_complaint = $1, history_present_illness = $2,
        past_medical_history = $3, medications = $4, allergies = $5,
        physical_examination = $6, diagnosis = $7, treatment_plan = $8,
        notes = $9, vital_signs = $10, updated_at = CURRENT_TIMESTAMP
      WHERE id = $11 AND professional_id = $12
      RETURNING id, updated_at
    `, [
      chief_complaint, history_present_illness, past_medical_history,
      medications, allergies, physical_examination, diagnosis,
      treatment_plan, notes, JSON.stringify(vital_signs), id, req.user.id
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    res.json({
      message: 'Prontuário atualizado com sucesso',
      record: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating medical record:', error);
    res.status(500).json({ message: 'Erro ao atualizar prontuário' });
  }
});

// Delete medical record
app.delete('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM medical_records WHERE id = $1 AND professional_id = $2 RETURNING id',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    res.json({ message: 'Prontuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting medical record:', error);
    res.status(500).json({ message: 'Erro ao excluir prontuário' });
  }
});

// ==================== MEDICAL DOCUMENTS ROUTES ====================

// Get medical documents for professional
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        md.id, md.title, md.document_type, md.document_url, md.created_at,
        COALESCE(pp.name, 'Paciente não identificado') as patient_name
      FROM medical_documents md
      LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
      WHERE md.professional_id = $1
      ORDER BY md.created_at DESC
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro ao buscar documentos médicos' });
  }
});

// Create medical document
app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { title, document_type, private_patient_id, template_data } = req.body;

    if (!title || !document_type || !template_data) {
      return res.status(400).json({ message: 'Título, tipo de documento e dados do template são obrigatórios' });
    }

    // Generate document
    const documentResult = await generateDocumentPDF(document_type, template_data);

    // Save document record
    const result = await pool.query(`
      INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type,
        document_url, template_data
      ) VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, title, document_url, created_at
    `, [
      req.user.id, private_patient_id, title, document_type,
      documentResult.url, JSON.stringify(template_data)
    ]);

    res.status(201).json({
      message: 'Documento criado com sucesso',
      title: result.rows[0].title,
      documentUrl: result.rows[0].document_url,
      document: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating medical document:', error);
    res.status(500).json({ message: 'Erro ao criar documento médico' });
  }
});

// ==================== ATTENDANCE LOCATIONS ROUTES ====================

// Get attendance locations for professional
app.get('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default, created_at
      FROM attendance_locations 
      WHERE professional_id = $1
      ORDER BY is_default DESC, name
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching attendance locations:', error);
    res.status(500).json({ message: 'Erro ao buscar locais de atendimento' });
  }
});

// Create attendance location
app.post('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome do local é obrigatório' });
    }

    // If setting as default, remove default from other locations
    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1',
        [req.user.id]
      );
    }

    const result = await pool.query(`
      INSERT INTO attendance_locations (
        professional_id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id, name, is_default, created_at
    `, [
      req.user.id, name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    ]);

    res.status(201).json({
      message: 'Local de atendimento criado com sucesso',
      location: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating attendance location:', error);
    res.status(500).json({ message: 'Erro ao criar local de atendimento' });
  }
});

// Update attendance location
app.put('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

    // If setting as default, remove default from other locations
    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1 AND id != $2',
        [req.user.id, id]
      );
    }

    const result = await pool.query(`
      UPDATE attendance_locations 
      SET 
        name = $1, address = $2, address_number = $3, address_complement = $4,
        neighborhood = $5, city = $6, state = $7, zip_code = $8,
        phone = $9, is_default = $10, updated_at = CURRENT_TIMESTAMP
      WHERE id = $11 AND professional_id = $12
      RETURNING id, name, is_default
    `, [
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default, id, req.user.id
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Local de atendimento não encontrado' });
    }

    res.json({
      message: 'Local de atendimento atualizado com sucesso',
      location: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating attendance location:', error);
    res.status(500).json({ message: 'Erro ao atualizar local de atendimento' });
  }
});

// Delete attendance location
app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM attendance_locations WHERE id = $1 AND professional_id = $2 RETURNING id',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Local de atendimento não encontrado' });
    }

    res.json({ message: 'Local de atendimento excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting attendance location:', error);
    res.status(500).json({ message: 'Erro ao excluir local de atendimento' });
  }
});

// ==================== IMAGE UPLOAD ROUTES ====================

// Upload image route
app.post('/api/upload-image', authenticate, async (req, res) => {
  try {
    console.log('🔄 Starting image upload process...');
    
    // Create upload middleware instance
    const upload = createUpload();
    const uploadSingle = upload.single('image');
    
    // Use multer middleware
    uploadSingle(req, res, async (err) => {
      if (err) {
        console.error('❌ Multer error:', err);
        return res.status(400).json({ 
          message: err.message || 'Erro no upload da imagem' 
        });
      }

      if (!req.file) {
        console.error('❌ No file received');
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      console.log('✅ File uploaded successfully:', req.file);

      try {
        // Update user's photo_url in database
        const result = await pool.query(
          'UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING photo_url',
          [req.file.path, req.user.id]
        );

        if (result.rows.length === 0) {
          return res.status(404).json({ message: 'Usuário não encontrado' });
        }

        console.log('✅ Database updated with new photo URL');

        res.json({
          message: 'Imagem enviada com sucesso',
          imageUrl: req.file.path
        });
      } catch (dbError) {
        console.error('❌ Database error:', dbError);
        res.status(500).json({ message: 'Erro ao salvar URL da imagem no banco de dados' });
      }
    });
  } catch (error) {
    console.error('❌ Upload route error:', error);
    res.status(500).json({ message: 'Erro interno no upload' });
  }
});

// ==================== REPORTS ROUTES ====================

// 🔥 FIXED: Professional revenue report with proper type handling
app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    console.log('🔄 Generating professional revenue report for user:', req.user.id);
    console.log('🔄 Date range:', { start_date, end_date });

    // Get professional percentage
    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    if (professionalResult.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professionalPercentage = parseInt(professionalResult.rows[0].percentage) || 50;
    console.log('🔄 Professional percentage:', professionalPercentage);

    // 🔥 FIXED: Get consultations with proper decimal handling
    const consultationsResult = await pool.query(`
      SELECT 
        c.date,
        COALESCE(u_client.name, d.name, pp.name) as client_name,
        s.name as service_name,
        ROUND(c.value, 2) as total_value,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN ROUND(c.value, 2)
          ELSE ROUND(c.value * (100 - $3) / 100.0, 2)
        END as amount_to_pay
      FROM consultations c
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users u_client ON c.client_id = u_client.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      WHERE c.professional_id = $1 
        AND c.date >= $2::date 
        AND c.date <= $4::date + interval '1 day'
      ORDER BY c.date DESC
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    console.log('✅ Consultations found:', consultationsResult.rows.length);

    // 🔥 FIXED: Calculate summary with proper number handling
    const consultations = consultationsResult.rows;
    const totalRevenue = consultations.reduce((sum, c) => sum + parseFloat(c.total_value), 0);
    const totalAmountToPay = consultations.reduce((sum, c) => sum + parseFloat(c.amount_to_pay), 0);

    const summary = {
      professional_percentage: professionalPercentage,
      total_revenue: Math.round(totalRevenue * 100) / 100,
      consultation_count: consultations.length,
      amount_to_pay: Math.round(totalAmountToPay * 100) / 100
    };

    console.log('✅ Summary calculated:', summary);

    const reportData = {
      summary,
      consultations: consultations.map(c => ({
        ...c,
        total_value: Math.round(parseFloat(c.total_value) * 100) / 100,
        amount_to_pay: Math.round(parseFloat(c.amount_to_pay) * 100) / 100
      }))
    };

    res.json(reportData);
  } catch (error) {
    console.error('❌ Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de receita' });
  }
});

// Professional detailed report
app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    // Get professional percentage
    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = parseInt(professionalResult.rows[0]?.percentage) || 50;

    // Get consultations summary
    const summaryResult = await pool.query(`
      SELECT 
        COUNT(*) as total_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        COALESCE(SUM(ROUND(c.value, 2)), 0) as total_revenue,
        COALESCE(SUM(CASE WHEN c.private_patient_id IS NULL THEN ROUND(c.value, 2) ELSE 0 END), 0) as convenio_revenue,
        COALESCE(SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN ROUND(c.value, 2) ELSE 0 END), 0) as private_revenue,
        COALESCE(SUM(CASE WHEN c.private_patient_id IS NULL THEN ROUND(c.value * (100 - $3) / 100.0, 2) ELSE 0 END), 0) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $1 
        AND c.date >= $2::date 
        AND c.date <= $4::date + interval '1 day'
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    const summary = summaryResult.rows[0];

    res.json({
      summary: {
        total_consultations: parseInt(summary.total_consultations),
        convenio_consultations: parseInt(summary.convenio_consultations),
        private_consultations: parseInt(summary.private_consultations),
        total_revenue: parseFloat(summary.total_revenue),
        convenio_revenue: parseFloat(summary.convenio_revenue),
        private_revenue: parseFloat(summary.private_revenue),
        professional_percentage: professionalPercentage,
        amount_to_pay: parseFloat(summary.amount_to_pay)
      }
    });
  } catch (error) {
    console.error('Error generating professional detailed report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório detalhado' });
  }
});

// Admin revenue report
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    // Get revenue by professional
    const professionalRevenueResult = await pool.query(`
      SELECT 
        u.name as professional_name,
        u.percentage as professional_percentage,
        COALESCE(SUM(ROUND(c.value, 2)), 0) as revenue,
        COUNT(c.id) as consultation_count,
        COALESCE(SUM(ROUND(c.value * u.percentage / 100.0, 2)), 0) as professional_payment,
        COALESCE(SUM(ROUND(c.value * (100 - u.percentage) / 100.0, 2)), 0) as clinic_revenue
      FROM users u
      LEFT JOIN consultations c ON u.id = c.professional_id 
        AND c.date >= $1::date 
        AND c.date <= $2::date + interval '1 day'
        AND c.private_patient_id IS NULL
      WHERE 'professional' = ANY(u.roles)
      GROUP BY u.id, u.name, u.percentage
      HAVING COUNT(c.id) > 0
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Get revenue by service
    const serviceRevenueResult = await pool.query(`
      SELECT 
        s.name as service_name,
        COALESCE(SUM(ROUND(c.value, 2)), 0) as revenue,
        COUNT(c.id) as consultation_count
      FROM services s
      LEFT JOIN consultations c ON s.id = c.service_id 
        AND c.date >= $1::date 
        AND c.date <= $2::date + interval '1 day'
      GROUP BY s.id, s.name
      HAVING COUNT(c.id) > 0
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Calculate total revenue
    const totalRevenue = professionalRevenueResult.rows.reduce(
      (sum, prof) => sum + parseFloat(prof.revenue), 0
    );

    res.json({
      total_revenue: totalRevenue,
      revenue_by_professional: professionalRevenueResult.rows.map(prof => ({
        ...prof,
        revenue: parseFloat(prof.revenue),
        professional_payment: parseFloat(prof.professional_payment),
        clinic_revenue: parseFloat(prof.clinic_revenue),
        consultation_count: parseInt(prof.consultation_count),
        professional_percentage: parseInt(prof.professional_percentage)
      })),
      revenue_by_service: serviceRevenueResult.rows.map(service => ({
        ...service,
        revenue: parseFloat(service.revenue),
        consultation_count: parseInt(service.consultation_count)
      }))
    });
  } catch (error) {
    console.error('Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de receita' });
  }
});

// Clients by city report (admin only)
app.get('/api/reports/clients-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        city,
        state,
        COUNT(*) as client_count,
        COUNT(CASE WHEN subscription_status = 'active' THEN 1 END) as active_clients,
        COUNT(CASE WHEN subscription_status = 'pending' THEN 1 END) as pending_clients,
        COUNT(CASE WHEN subscription_status = 'expired' THEN 1 END) as expired_clients
      FROM users 
      WHERE 'client' = ANY(roles) AND city IS NOT NULL AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC, city
    `);

    res.json(result.rows.map(row => ({
      ...row,
      client_count: parseInt(row.client_count),
      active_clients: parseInt(row.active_clients),
      pending_clients: parseInt(row.pending_clients),
      expired_clients: parseInt(row.expired_clients)
    })));
  } catch (error) {
    console.error('Error generating clients by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de clientes por cidade' });
  }
});

// Professionals by city report (admin only)
app.get('/api/reports/professionals-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.city,
        u.state,
        COUNT(u.id) as total_professionals,
        json_agg(
          json_build_object(
            'category_name', COALESCE(sc.name, 'Sem categoria'),
            'count', 1
          )
        ) as categories
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles) AND u.city IS NOT NULL AND u.city != ''
      GROUP BY u.city, u.state
      ORDER BY total_professionals DESC, u.city
    `);

    // Process the results to group categories properly
    const processedResults = result.rows.map(row => {
      const categoryMap = new Map();
      
      row.categories.forEach((cat: any) => {
        const name = cat.category_name;
        if (categoryMap.has(name)) {
          categoryMap.set(name, categoryMap.get(name) + 1);
        } else {
          categoryMap.set(name, 1);
        }
      });

      return {
        city: row.city,
        state: row.state,
        total_professionals: parseInt(row.total_professionals),
        categories: Array.from(categoryMap.entries()).map(([category_name, count]) => ({
          category_name,
          count
        }))
      };
    });

    res.json(processedResults);
  } catch (error) {
    console.error('Error generating professionals by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de profissionais por cidade' });
  }
});

// ==================== PAYMENT ROUTES ====================

// Create subscription payment
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { user_id, dependent_ids } = req.body;

    // Verify user
    if (user_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    // Calculate total amount
    const baseAmount = 250; // R$250 for titular
    const dependentAmount = (dependent_ids?.length || 0) * 50; // R$50 per dependent
    const totalAmount = baseAmount + dependentAmount;

    // Create payment preference (mock implementation)
    const preference = {
      items: [
        {
          title: 'Assinatura Cartão Quiro Ferreira',
          quantity: 1,
          unit_price: totalAmount
        }
      ],
      payer: {
        name: req.user.name,
        email: req.user.email || 'cliente@quiroferreira.com.br'
      },
      back_urls: {
        success: `${req.protocol}://${req.get('host')}/payment/success`,
        failure: `${req.protocol}://${req.get('host')}/payment/failure`,
        pending: `${req.protocol}://${req.get('host')}/payment/pending`
      },
      auto_return: 'approved'
    };

    // Mock MercadoPago response
    const mockResponse = {
      id: `MP-${Date.now()}`,
      init_point: `https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=MP-${Date.now()}`,
      sandbox_init_point: `https://sandbox.mercadopago.com.br/checkout/v1/redirect?pref_id=MP-${Date.now()}`
    };

    res.json(mockResponse);
  } catch (error) {
    console.error('Error creating subscription payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento de assinatura' });
  }
});

// Create professional payment
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor deve ser maior que zero' });
    }

    // Create payment preference (mock implementation)
    const preference = {
      items: [
        {
          title: 'Repasse ao Convênio Quiro Ferreira',
          quantity: 1,
          unit_price: parseFloat(amount)
        }
      ],
      payer: {
        name: req.user.name,
        email: req.user.email || 'profissional@quiroferreira.com.br'
      },
      back_urls: {
        success: `${req.protocol}://${req.get('host')}/payment/success`,
        failure: `${req.protocol}://${req.get('host')}/payment/failure`,
        pending: `${req.protocol}://${req.get('host')}/payment/pending`
      },
      auto_return: 'approved'
    };

    // Mock MercadoPago response
    const mockResponse = {
      id: `MP-PROF-${Date.now()}`,
      init_point: `https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=MP-PROF-${Date.now()}`,
      sandbox_init_point: `https://sandbox.mercadopago.com.br/checkout/v1/redirect?pref_id=MP-PROF-${Date.now()}`
    };

    res.json(mockResponse);
  } catch (error) {
    console.error('Error creating professional payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento profissional' });
  }
});

// ==================== CATCH-ALL ROUTE ====================

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'dist', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ message: 'Erro interno do servidor' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
});