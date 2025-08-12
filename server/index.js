import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';
import dotenv from 'dotenv';
import multer from 'multer';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import { v2 as cloudinary } from 'cloudinary';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

// Configure multer with Cloudinary storage
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'quiro-ferreira/professionals',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [
      {
        width: 400,
        height: 400,
        crop: 'fill',
        gravity: 'face',
        quality: 'auto:good'
      }
    ]
  },
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Apenas arquivos de imagem são permitidos'), false);
    }
  },
});

// Middleware
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://www.cartaoquiroferreira.com.br',
    'https://cartaoquiroferreira.com.br'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Auth middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'Não autorizado' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');

    const result = await pool.query(
      'SELECT id, name, cpf, roles FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];

    req.user = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles || [],
      currentRole: decoded.currentRole || (user.roles && user.roles[0])
    };

    next();
  } catch (error) {
    console.error('Auth error:', error);
    return res.status(401).json({ message: 'Token inválido' });
  }
};

// Initialize database tables
const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database tables...');

    // Create tables
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
        password_hash VARCHAR(255) NOT NULL,
        roles TEXT[] DEFAULT ARRAY['client'],
        percentage INTEGER DEFAULT 50,
        category_id INTEGER,
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry DATE,
        photo_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        base_price DECIMAL(10,2) NOT NULL,
        category_id INTEGER REFERENCES service_categories(id),
        is_base_service BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS dependents (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) UNIQUE NOT NULL,
        birth_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS private_patients (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
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
        UNIQUE(professional_id, cpf)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS attendance_locations (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        address TEXT,
        address_number VARCHAR(20),
        address_complement VARCHAR(100),
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        zip_code VARCHAR(8),
        phone VARCHAR(20),
        is_default BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        client_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        dependent_id INTEGER REFERENCES dependents(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id) ON DELETE CASCADE,
        service_id INTEGER REFERENCES services(id),
        location_id INTEGER REFERENCES attendance_locations(id),
        appointment_date DATE NOT NULL,
        appointment_time TIME NOT NULL,
        value DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'scheduled',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        client_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        dependent_id INTEGER REFERENCES dependents(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id) ON DELETE CASCADE,
        service_id INTEGER REFERENCES services(id),
        location_id INTEGER REFERENCES attendance_locations(id),
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Insert default categories
    await pool.query(`
      INSERT INTO service_categories (name, description) 
      VALUES 
        ('Fisioterapia', 'Serviços de fisioterapia e reabilitação'),
        ('Psicologia', 'Atendimento psicológico e terapêutico'),
        ('Nutrição', 'Consultas nutricionais e acompanhamento'),
        ('Medicina', 'Consultas médicas gerais'),
        ('Odontologia', 'Tratamentos dentários')
      ON CONFLICT DO NOTHING;
    `);

    // Insert default services
    await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      SELECT 
        'Consulta de Fisioterapia', 
        'Consulta inicial de fisioterapia', 
        150.00, 
        sc.id, 
        true
      FROM service_categories sc 
      WHERE sc.name = 'Fisioterapia'
      ON CONFLICT DO NOTHING;
    `);

    await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      SELECT 
        'Consulta Psicológica', 
        'Sessão de psicoterapia', 
        200.00, 
        sc.id, 
        true
      FROM service_categories sc 
      WHERE sc.name = 'Psicologia'
      ON CONFLICT DO NOTHING;
    `);

    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    throw error;
  }
};

// Initialize database on startup
initializeDatabase().catch(console.error);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    const result = await pool.query(
      'SELECT id, name, cpf, password_hash, roles FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);

    if (!isValidPassword) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles || ['client']
    };

    res.json({
      message: 'Login realizado com sucesso',
      user: userData
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

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles,
      currentRole: role
    };

    res.json({
      message: 'Role selecionada com sucesso',
      user: userData,
      token
    });
  } catch (error) {
    console.error('Select role error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, password
    } = req.body;

    if (!name || !cpf || !password) {
      return res.status(400).json({ message: 'Nome, CPF e senha são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Usuário já cadastrado com este CPF' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

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

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// 🔥 SCHEDULING ROUTES - COMPLETELY REBUILT
app.get('/api/scheduling/appointments', authenticate, async (req, res) => {
  try {
    console.log('🔄 GET /api/scheduling/appointments called');
    console.log('📅 Query params:', req.query);
    console.log('👤 User:', req.user);

    const { start_date, end_date } = req.query;
    const professionalId = req.user.id;

    let query = `
      SELECT 
        a.id,
        a.appointment_date,
        a.appointment_time,
        a.value,
        a.status,
        a.notes,
        a.created_at,
        CASE 
          WHEN a.private_patient_id IS NOT NULL THEN pp.name
          WHEN a.dependent_id IS NOT NULL THEN d.name
          ELSE u.name
        END as patient_name,
        CASE 
          WHEN a.private_patient_id IS NOT NULL THEN pp.cpf
          WHEN a.dependent_id IS NOT NULL THEN d.cpf
          ELSE u.cpf
        END as patient_cpf,
        s.name as service_name,
        al.name as location_name,
        al.address as location_address
      FROM appointments a
      LEFT JOIN users u ON a.client_id = u.id
      LEFT JOIN dependents d ON a.dependent_id = d.id
      LEFT JOIN private_patients pp ON a.private_patient_id = pp.id
      LEFT JOIN services s ON a.service_id = s.id
      LEFT JOIN attendance_locations al ON a.location_id = al.id
      WHERE a.professional_id = $1
    `;

    const params = [professionalId];

    if (start_date && end_date) {
      query += ` AND a.appointment_date BETWEEN $2 AND $3`;
      params.push(start_date, end_date);
    }

    query += ` ORDER BY a.appointment_date, a.appointment_time`;

    console.log('📡 Executing query:', query);
    console.log('📡 With params:', params);

    const result = await pool.query(query, params);

    console.log('✅ Query result:', result.rows.length, 'appointments found');
    console.log('📋 Sample appointment:', result.rows[0]);

    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching appointments:', error);
    res.status(500).json({ message: 'Erro ao carregar agendamentos' });
  }
});

app.post('/api/scheduling/appointments', authenticate, async (req, res) => {
  try {
    console.log('🔄 POST /api/scheduling/appointments called');
    console.log('📝 Request body:', req.body);

    const {
      private_patient_id,
      service_id,
      appointment_date,
      appointment_time,
      location_id,
      notes,
      value
    } = req.body;

    const professionalId = req.user.id;

    // Validate required fields
    if (!service_id || !appointment_date || !appointment_time || !value) {
      return res.status(400).json({ 
        message: 'Serviço, data, hora e valor são obrigatórios' 
      });
    }

    // Check for time conflicts
    const conflictCheck = await pool.query(`
      SELECT id FROM appointments 
      WHERE professional_id = $1 
      AND appointment_date = $2 
      AND appointment_time = $3
    `, [professionalId, appointment_date, appointment_time]);

    if (conflictCheck.rows.length > 0) {
      return res.status(409).json({ 
        message: 'Já existe um agendamento para este horário' 
      });
    }

    const result = await pool.query(`
      INSERT INTO appointments (
        professional_id, private_patient_id, service_id, location_id,
        appointment_date, appointment_time, value, notes, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'scheduled')
      RETURNING *
    `, [
      professionalId,
      private_patient_id || null,
      service_id,
      location_id || null,
      appointment_date,
      appointment_time,
      value,
      notes || null
    ]);

    console.log('✅ Appointment created:', result.rows[0]);

    res.status(201).json({
      message: 'Agendamento criado com sucesso',
      appointment: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error creating appointment:', error);
    res.status(500).json({ message: 'Erro ao criar agendamento' });
  }
});

app.put('/api/scheduling/appointments/:id', authenticate, async (req, res) => {
  try {
    console.log('🔄 PUT /api/scheduling/appointments/:id called');
    
    const appointmentId = req.params.id;
    const {
      service_id,
      appointment_date,
      appointment_time,
      location_id,
      notes,
      value,
      status
    } = req.body;

    const professionalId = req.user.id;

    // Verify ownership
    const ownershipCheck = await pool.query(
      'SELECT id FROM appointments WHERE id = $1 AND professional_id = $2',
      [appointmentId, professionalId]
    );

    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Agendamento não encontrado' });
    }

    const result = await pool.query(`
      UPDATE appointments SET
        service_id = COALESCE($1, service_id),
        appointment_date = COALESCE($2, appointment_date),
        appointment_time = COALESCE($3, appointment_time),
        location_id = COALESCE($4, location_id),
        notes = COALESCE($5, notes),
        value = COALESCE($6, value),
        status = COALESCE($7, status),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $8 AND professional_id = $9
      RETURNING *
    `, [
      service_id,
      appointment_date,
      appointment_time,
      location_id,
      notes,
      value,
      status,
      appointmentId,
      professionalId
    ]);

    console.log('✅ Appointment updated:', result.rows[0]);

    res.json({
      message: 'Agendamento atualizado com sucesso',
      appointment: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error updating appointment:', error);
    res.status(500).json({ message: 'Erro ao atualizar agendamento' });
  }
});

app.delete('/api/scheduling/appointments/:id', authenticate, async (req, res) => {
  try {
    console.log('🔄 DELETE /api/scheduling/appointments/:id called');
    
    const appointmentId = req.params.id;
    const professionalId = req.user.id;

    const result = await pool.query(
      'DELETE FROM appointments WHERE id = $1 AND professional_id = $2 RETURNING *',
      [appointmentId, professionalId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Agendamento não encontrado' });
    }

    console.log('✅ Appointment deleted:', result.rows[0]);

    res.json({ message: 'Agendamento excluído com sucesso' });
  } catch (error) {
    console.error('❌ Error deleting appointment:', error);
    res.status(500).json({ message: 'Erro ao excluir agendamento' });
  }
});

// Services routes
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.*, sc.name as category_name 
      FROM services s
      LEFT JOIN service_categories sc ON s.category_id = sc.id
      ORDER BY sc.name, s.name
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Erro ao carregar serviços' });
  }
});

app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM service_categories ORDER BY name');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Erro ao carregar categorias' });
  }
});

// Private patients routes
app.get('/api/private-patients', authenticate, async (req, res) => {
  try {
    const professionalId = req.user.id;
    
    const result = await pool.query(
      'SELECT * FROM private_patients WHERE professional_id = $1 ORDER BY name',
      [professionalId]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro ao carregar pacientes' });
  }
});

app.post('/api/private-patients', authenticate, async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    const professionalId = req.user.id;
    const cleanCpf = cpf.replace(/\D/g, '');

    const result = await pool.query(`
      INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING *
    `, [
      professionalId, name, cleanCpf, email, phone, birth_date, address,
      address_number, address_complement, neighborhood, city, state, zip_code
    ]);

    res.status(201).json({
      message: 'Paciente criado com sucesso',
      patient: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating private patient:', error);
    if (error.code === '23505') {
      res.status(409).json({ message: 'Já existe um paciente com este CPF' });
    } else {
      res.status(500).json({ message: 'Erro ao criar paciente' });
    }
  }
});

// Attendance locations routes
app.get('/api/attendance-locations', authenticate, async (req, res) => {
  try {
    const professionalId = req.user.id;
    
    const result = await pool.query(
      'SELECT * FROM attendance_locations WHERE professional_id = $1 ORDER BY is_default DESC, name',
      [professionalId]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching locations:', error);
    res.status(500).json({ message: 'Erro ao carregar locais' });
  }
});

app.post('/api/attendance-locations', authenticate, async (req, res) => {
  try {
    const {
      name, address, address_number, address_complement, neighborhood,
      city, state, zip_code, phone, is_default
    } = req.body;

    const professionalId = req.user.id;

    // If setting as default, remove default from others
    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1',
        [professionalId]
      );
    }

    const result = await pool.query(`
      INSERT INTO attendance_locations (
        professional_id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING *
    `, [
      professionalId, name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    ]);

    res.status(201).json({
      message: 'Local criado com sucesso',
      location: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating location:', error);
    res.status(500).json({ message: 'Erro ao criar local' });
  }
});

// 🔥 PROFESSIONAL REVENUE REPORT - FIXED
app.get('/api/reports/professional-revenue', authenticate, async (req, res) => {
  try {
    console.log('🔄 Professional revenue report requested');
    
    const { start_date, end_date } = req.query;
    const professionalId = req.user.id;

    console.log('📊 Report params:', { start_date, end_date, professionalId });

    // Get professional percentage
    const profResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [professionalId]
    );

    const professionalPercentage = profResult.rows[0]?.percentage || 50;
    console.log('💰 Professional percentage:', professionalPercentage);

    // Get consultations data - FIXED QUERY
    const consultationsQuery = `
      SELECT 
        c.date,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN pp.name
          WHEN c.dependent_id IS NOT NULL THEN d.name
          ELSE u.name
        END as client_name,
        s.name as service_name,
        c.value as total_value
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      WHERE c.professional_id = $1
    `;

    const params = [professionalId];

    if (start_date && end_date) {
      consultationsQuery += ` AND DATE(c.date) BETWEEN $2 AND $3`;
      params.push(start_date, end_date);
    }

    consultationsQuery += ` ORDER BY c.date DESC`;

    const consultationsResult = await pool.query(consultationsQuery, params);
    console.log('📋 Consultations found:', consultationsResult.rows.length);

    // Calculate amounts - FIXED CALCULATIONS
    const consultations = consultationsResult.rows.map(consultation => {
      const totalValue = parseFloat(consultation.total_value) || 0;
      
      // For private patients, professional keeps 100%
      // For convenio patients, professional pays percentage to clinic
      const isPrivate = consultation.client_name && consultation.client_name.includes('Particular');
      
      let amountToPay = 0;
      if (!isPrivate) {
        // Convenio consultation - calculate amount to pay to clinic
        const clinicPercentage = 100 - professionalPercentage;
        amountToPay = (totalValue * clinicPercentage) / 100;
      }

      return {
        ...consultation,
        total_value: totalValue,
        amount_to_pay: amountToPay
      };
    });

    // Calculate summary
    const totalRevenue = consultations.reduce((sum, c) => sum + c.total_value, 0);
    const totalAmountToPay = consultations.reduce((sum, c) => sum + c.amount_to_pay, 0);
    const consultationCount = consultations.length;

    const summary = {
      professional_percentage: professionalPercentage,
      total_revenue: totalRevenue,
      consultation_count: consultationCount,
      amount_to_pay: totalAmountToPay
    };

    console.log('📊 Report summary:', summary);

    res.json({
      summary,
      consultations
    });
  } catch (error) {
    console.error('❌ Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

// Users routes
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const userId = req.params.id;
    
    const result = await pool.query(
      'SELECT id, name, cpf, email, phone, birth_date, address, address_number, address_complement, neighborhood, city, state, roles, percentage, category_id, subscription_status, subscription_expiry, photo_url, created_at FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Erro ao carregar usuário' });
  }
});

// Upload image route
app.post('/api/upload-image', authenticate, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
    }

    const imageUrl = req.file.path;
    const userId = req.user.id;

    // Update user photo URL in database
    await pool.query(
      'UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [imageUrl, userId]
    );

    res.json({
      message: 'Imagem enviada com sucesso',
      imageUrl: imageUrl
    });
  } catch (error) {
    console.error('Error uploading image:', error);
    res.status(500).json({ message: 'Erro ao fazer upload da imagem' });
  }
});

// Consultations route for register consultation
app.post('/api/consultations', authenticate, async (req, res) => {
  try {
    const {
      client_id,
      dependent_id,
      private_patient_id,
      service_id,
      location_id,
      value,
      date,
      appointment_date,
      appointment_time,
      create_appointment
    } = req.body;

    const professionalId = req.user.id;

    // Create consultation
    const consultationResult = await pool.query(`
      INSERT INTO consultations (
        professional_id, client_id, dependent_id, private_patient_id,
        service_id, location_id, value, date
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `, [
      professionalId,
      client_id || null,
      dependent_id || null,
      private_patient_id || null,
      service_id,
      location_id || null,
      value,
      date
    ]);

    let appointmentResult = null;

    // Create appointment if requested
    if (create_appointment && appointment_date && appointment_time) {
      appointmentResult = await pool.query(`
        INSERT INTO appointments (
          professional_id, client_id, dependent_id, private_patient_id,
          service_id, location_id, appointment_date, appointment_time,
          value, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'completed')
        RETURNING *
      `, [
        professionalId,
        client_id || null,
        dependent_id || null,
        private_patient_id || null,
        service_id,
        location_id || null,
        appointment_date,
        appointment_time,
        value
      ]);
    }

    res.status(201).json({
      message: 'Consulta registrada com sucesso',
      consultation: consultationResult.rows[0],
      appointment: appointmentResult?.rows[0] || null
    });
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro ao registrar consulta' });
  }
});

// Client lookup routes
app.get('/api/clients/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;
    
    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

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

app.get('/api/dependents/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;
    
    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    const result = await pool.query(`
      SELECT 
        d.id,
        d.name,
        d.cpf,
        d.client_id,
        u.name as client_name,
        u.subscription_status as client_subscription_status
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

app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const clientId = req.params.clientId;
    
    const result = await pool.query(
      'SELECT * FROM dependents WHERE client_id = $1 ORDER BY name',
      [clientId]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro ao carregar dependentes' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ message: 'Erro interno do servidor' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Rota não encontrada' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully');
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Database: Connected`);
});