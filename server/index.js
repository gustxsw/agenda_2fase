import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';

// Import routes
import authRoutes from './routes/auth.js';
import usersRoutes from './routes/users.js';
import clientsRoutes from './routes/clients.js';
import professionalsRoutes from './routes/professionals.js';
import consultationsRoutes from './routes/consultations.js';
import reportsRoutes from './routes/reports.js';
import dependentsRoutes from './routes/dependents.js';

dotenv.config();

// ES module compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

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

app.use(express.json());
app.use(cookieParser());

// Serve static files from dist directory
const distPath = path.join(__dirname, '../dist');
app.use(express.static(distPath));

// Simple auth middleware for inline routes
const simpleAuth = (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Não autorizado' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido' });
  }
};

// API routes (existing)
app.use('/api/auth', authRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/clients', clientsRoutes);
app.use('/api/professionals', professionalsRoutes);
app.use('/api/consultations', consultationsRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/api/dependents', dependentsRoutes);

// Services routes - directly in index.js
app.get('/api/services', simpleAuth, async (req, res) => {
  try {
    console.log('📋 Fetching services...');
    const result = await pool.query(
      `SELECT s.*, sc.name as category_name 
       FROM services s
       LEFT JOIN service_categories sc ON s.category_id = sc.id
       ORDER BY sc.name, s.name`
    );
    console.log('✅ Services fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching services:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/services', simpleAuth, async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !base_price) {
      return res.status(400).json({ message: 'Nome e preço base são obrigatórios' });
    }

    const result = await pool.query(
      `INSERT INTO services (name, description, base_price, category_id, is_base_service)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [name, description, base_price, category_id, is_base_service || false]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.put('/api/services/:id', simpleAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(
      `UPDATE services 
       SET name = $1, description = $2, base_price = $3, category_id = $4, 
           is_base_service = $5, updated_at = CURRENT_TIMESTAMP
       WHERE id = $6
       RETURNING *`,
      [name, description, base_price, category_id, is_base_service, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.delete('/api/services/:id', simpleAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if service has consultations
    const consultationsCheck = await pool.query(
      `SELECT COUNT(*) FROM consultations WHERE service_id = $1`,
      [id]
    );

    if (parseInt(consultationsCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir serviço que possui consultas registradas' 
      });
    }

    const result = await pool.query(
      `DELETE FROM services WHERE id = $1 RETURNING *`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    res.json({ message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Service categories routes - directly in index.js
app.get('/api/service-categories', simpleAuth, async (req, res) => {
  try {
    console.log('🏷️ Fetching service categories...');
    const result = await pool.query(
      'SELECT * FROM service_categories ORDER BY name'
    );
    console.log('✅ Categories fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/service-categories', simpleAuth, async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }

    const result = await pool.query(
      `INSERT INTO service_categories (name, description)
       VALUES ($1, $2)
       RETURNING *`,
      [name, description]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating service category:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Private patients routes - directly in index.js
app.get('/api/private-patients', simpleAuth, async (req, res) => {
  try {
    console.log('👥 Fetching private patients for user:', req.user.id);
    const result = await pool.query(
      `SELECT * FROM private_patients 
       WHERE professional_id = $1 
       ORDER BY name`,
      [req.user.id]
    );
    console.log('✅ Private patients fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/private-patients', simpleAuth, async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    if (!name || !cpf) {
      return res.status(400).json({ message: 'Nome e CPF são obrigatórios' });
    }

    // Check if CPF already exists for this professional
    const existingPatient = await pool.query(
      `SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2`,
      [cpf, req.user.id]
    );

    if (existingPatient.rows.length > 0) {
      return res.status(400).json({ message: 'Já existe um paciente cadastrado com este CPF' });
    }

    const result = await pool.query(
      `INSERT INTO private_patients 
       (professional_id, name, cpf, email, phone, birth_date, address, 
        address_number, address_complement, neighborhood, city, state, zip_code)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING *`,
      [req.user.id, name, cpf, email, phone, birth_date, address, 
       address_number, address_complement, neighborhood, city, state, zip_code]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.put('/api/private-patients/:id', simpleAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    const result = await pool.query(
      `UPDATE private_patients 
       SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
           address_number = $6, address_complement = $7, neighborhood = $8,
           city = $9, state = $10, zip_code = $11, updated_at = CURRENT_TIMESTAMP
       WHERE id = $12 AND professional_id = $13
       RETURNING *`,
      [name, email, phone, birth_date, address, address_number, address_complement,
       neighborhood, city, state, zip_code, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.delete('/api/private-patients/:id', simpleAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if patient has appointments
    const appointmentsCheck = await pool.query(
      `SELECT COUNT(*) FROM appointments WHERE private_patient_id = $1`,
      [id]
    );

    if (parseInt(appointmentsCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir paciente que possui agendamentos' 
      });
    }

    const result = await pool.query(
      `DELETE FROM private_patients WHERE id = $1 AND professional_id = $2 RETURNING *`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    res.json({ message: 'Paciente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Attendance locations routes - directly in index.js
app.get('/api/attendance-locations', simpleAuth, async (req, res) => {
  try {
    console.log('📍 Fetching attendance locations for user:', req.user.id);
    const result = await pool.query(
      `SELECT * FROM attendance_locations 
       WHERE professional_id = $1 
       ORDER BY is_default DESC, name`,
      [req.user.id]
    );
    console.log('✅ Attendance locations fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching attendance locations:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/attendance-locations', simpleAuth, async (req, res) => {
  try {
    const {
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

    // If this is set as default, remove default from others
    if (is_default) {
      await pool.query(
        `UPDATE attendance_locations SET is_default = false WHERE professional_id = $1`,
        [req.user.id]
      );
    }

    const result = await pool.query(
      `INSERT INTO attendance_locations 
       (professional_id, name, address, address_number, address_complement, 
        neighborhood, city, state, zip_code, phone, is_default)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [req.user.id, name, address, address_number, address_complement,
       neighborhood, city, state, zip_code, phone, is_default]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.put('/api/attendance-locations/:id', simpleAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

    // If this is set as default, remove default from others
    if (is_default) {
      await pool.query(
        `UPDATE attendance_locations SET is_default = false 
         WHERE professional_id = $1 AND id != $2`,
        [req.user.id, id]
      );
    }

    const result = await pool.query(
      `UPDATE attendance_locations 
       SET name = $1, address = $2, address_number = $3, address_complement = $4,
           neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9,
           is_default = $10, updated_at = CURRENT_TIMESTAMP
       WHERE id = $11 AND professional_id = $12
       RETURNING *`,
      [name, address, address_number, address_complement, neighborhood, city, state,
       zip_code, phone, is_default, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Local de atendimento não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.delete('/api/attendance-locations/:id', simpleAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if location has appointments
    const appointmentsCheck = await pool.query(
      `SELECT COUNT(*) FROM appointments WHERE location_id = $1`,
      [id]
    );

    if (parseInt(appointmentsCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir local que possui agendamentos' 
      });
    }

    const result = await pool.query(
      `DELETE FROM attendance_locations WHERE id = $1 AND professional_id = $2 RETURNING *`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Local de atendimento não encontrado' });
    }

    res.json({ message: 'Local de atendimento excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting attendance location:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Appointments routes - directly in index.js
app.get('/api/appointments', simpleAuth, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    console.log('📅 Fetching appointments for user:', req.user.id, 'from', start_date, 'to', end_date);

    const result = await pool.query(
      `SELECT a.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name,
              COALESCE(pp.cpf, c.cpf, d.cpf) as patient_cpf,
              s.name as service_name,
              al.name as location_name,
              al.address as location_address
       FROM appointments a
       LEFT JOIN private_patients pp ON a.private_patient_id = pp.id
       LEFT JOIN users c ON a.client_id = c.id
       LEFT JOIN dependents d ON a.dependent_id = d.id
       LEFT JOIN services s ON a.service_id = s.id
       LEFT JOIN attendance_locations al ON a.location_id = al.id
       WHERE a.professional_id = $1
       AND a.appointment_date >= $2
       AND a.appointment_date <= $3
       ORDER BY a.appointment_date, a.appointment_time`,
      [req.user.id, start_date, end_date]
    );

    console.log('✅ Appointments fetched:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching appointments:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/appointments', simpleAuth, async (req, res) => {
  try {
    console.log('➕ Creating appointment for user:', req.user.id);
    console.log('📝 Appointment data:', req.body);

    const {
      private_patient_id,
      client_id,
      dependent_id,
      service_id,
      appointment_date,
      appointment_time,
      location_id,
      notes,
      value
    } = req.body;

    // Validate required fields
    if (!service_id || !appointment_date || !appointment_time || !value) {
      return res.status(400).json({ 
        message: 'Serviço, data, hora e valor são obrigatórios' 
      });
    }

    // Validate that at least one patient type is selected
    if (!private_patient_id && !client_id && !dependent_id) {
      return res.status(400).json({ 
        message: 'É necessário selecionar um paciente' 
      });
    }

    const result = await pool.query(
      `INSERT INTO appointments 
       (professional_id, private_patient_id, client_id, dependent_id, service_id, 
        appointment_date, appointment_time, location_id, notes, value, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'scheduled', CURRENT_TIMESTAMP)
       RETURNING *`,
      [req.user.id, private_patient_id, client_id, dependent_id, service_id, 
       appointment_date, appointment_time, location_id, notes, value]
    );

    console.log('✅ Appointment created:', result.rows[0]);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error creating appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.put('/api/appointments/:id', simpleAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      appointment_date,
      appointment_time,
      location_id,
      notes,
      value,
      status
    } = req.body;

    console.log('✏️ Updating appointment:', id, 'with data:', req.body);

    const result = await pool.query(
      `UPDATE appointments 
       SET appointment_date = COALESCE($1, appointment_date), 
           appointment_time = COALESCE($2, appointment_time), 
           location_id = COALESCE($3, location_id), 
           notes = COALESCE($4, notes), 
           value = COALESCE($5, value), 
           status = COALESCE($6, status), 
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $7 AND professional_id = $8
       RETURNING *`,
      [appointment_date, appointment_time, location_id, notes, value, status, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Agendamento não encontrado' });
    }

    console.log('✅ Appointment updated:', result.rows[0]);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error updating appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.delete('/api/appointments/:id', simpleAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `DELETE FROM appointments WHERE id = $1 AND professional_id = $2 RETURNING *`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Agendamento não encontrado' });
    }

    res.json({ message: 'Agendamento excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Dependents lookup - directly in index.js
app.get('/api/dependents/lookup', simpleAuth, async (req, res) => {
  try {
    const { cpf } = req.query;
    
    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.toString().replace(/\D/g, '');
    console.log('🔍 Looking up dependent with CPF:', cleanCpf);

    const result = await pool.query(
      `SELECT d.*, c.name as client_name, c.subscription_status as client_subscription_status
       FROM dependents d
       JOIN users c ON d.client_id = c.id
       WHERE d.cpf = $1`,
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    console.log('✅ Dependent found:', result.rows[0]);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error looking up dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Health check route
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.resolve(distPath, 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ message: 'Erro interno do servidor' });
});

// Create test professional function
async function createTestProfessional() {
  try {
    console.log('🔄 Verificando profissional de teste...');

    // Check if test professional already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      ['12345678901']
    );

    if (existingUser.rows.length > 0) {
      console.log('✅ Profissional de teste já existe!');
      return;
    }

    // Hash password
    const password = 'teste123';
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Check/create category
    let categoryResult = await pool.query(
      'SELECT id FROM service_categories WHERE name = $1',
      ['Fisioterapia']
    );

    let categoryId;
    if (categoryResult.rows.length === 0) {
      const newCategory = await pool.query(
        `INSERT INTO service_categories (name, description) 
         VALUES ($1, $2) 
         RETURNING id`,
        ['Fisioterapia', 'Serviços de fisioterapia e reabilitação']
      );
      categoryId = newCategory.rows[0].id;
      console.log('✅ Categoria "Fisioterapia" criada com ID:', categoryId);
    } else {
      categoryId = categoryResult.rows[0].id;
      console.log('✅ Categoria "Fisioterapia" já existe com ID:', categoryId);
    }

    // Create test professional
    const userResult = await pool.query(
      `INSERT INTO users 
       (name, cpf, email, phone, birth_date, address, address_number, 
        neighborhood, city, state, password_hash, roles, percentage, category_id, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, CURRENT_TIMESTAMP)
       RETURNING id, name, cpf`,
      [
        'Dr. João Silva',
        '12345678901',
        'joao.silva@teste.com',
        '64981234567',
        '1985-03-15',
        'Rua das Flores, 123',
        '123',
        'Centro',
        'Goiânia',
        'GO',
        passwordHash,
        JSON.stringify(['professional']),
        70,
        categoryId
      ]
    );

    const professionalId = userResult.rows[0].id;
    console.log('✅ Profissional criado:', userResult.rows[0]);

    // Create test services
    const services = [
      { name: 'Consulta Fisioterapêutica', price: 100.00 },
      { name: 'Sessão de RPG', price: 80.00 },
      { name: 'Massoterapia', price: 60.00 },
      { name: 'Pilates Terapêutico', price: 90.00 }
    ];

    for (const service of services) {
      await pool.query(
        `INSERT INTO services (name, description, base_price, category_id, is_base_service) 
         VALUES ($1, $2, $3, $4, $5)`,
        [service.name, `Serviço de ${service.name}`, service.price, categoryId, true]
      );
    }

    console.log('✅ Serviços de teste criados');

    // Create default attendance location
    await pool.query(
      `INSERT INTO attendance_locations 
       (professional_id, name, address, address_number, neighborhood, city, state, phone, is_default)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        professionalId,
        'Clínica Quiro Ferreira',
        'Rua Principal',
        '100',
        'Centro',
        'Goiânia',
        'GO',
        '6432221234',
        true
      ]
    );

    console.log('✅ Local de atendimento padrão criado');

    // Create some private patients for testing
    const privatePatients = [
      { name: 'Maria Santos', cpf: '98765432100' },
      { name: 'José Oliveira', cpf: '11122233344' },
      { name: 'Ana Costa', cpf: '55566677788' }
    ];

    for (const patient of privatePatients) {
      await pool.query(
        `INSERT INTO private_patients (professional_id, name, cpf) 
         VALUES ($1, $2, $3)`,
        [professionalId, patient.name, patient.cpf]
      );
    }

    console.log('✅ Pacientes particulares de teste criados');

    // Create some test appointments for demonstration
    const today = new Date();
    const appointments = [
      {
        date: today.toISOString().split('T')[0],
        time: '09:00',
        patient_name: 'Maria Santos',
        service: 'Consulta Fisioterapêutica',
        status: 'scheduled'
      },
      {
        date: today.toISOString().split('T')[0],
        time: '14:00',
        patient_name: 'José Oliveira',
        service: 'Sessão de RPG',
        status: 'confirmed'
      },
      {
        date: new Date(today.getTime() + 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        time: '10:30',
        patient_name: 'Ana Costa',
        service: 'Massoterapia',
        status: 'scheduled'
      }
    ];

    // Get service and patient IDs for appointments
    const serviceIds = await pool.query('SELECT id, name FROM services WHERE category_id = $1', [categoryId]);
    const patientIds = await pool.query('SELECT id, name FROM private_patients WHERE professional_id = $1', [professionalId]);
    const locationId = await pool.query('SELECT id FROM attendance_locations WHERE professional_id = $1 AND is_default = true', [professionalId]);

    for (const apt of appointments) {
      const service = serviceIds.rows.find(s => s.name === apt.service);
      const patient = patientIds.rows.find(p => p.name === apt.patient_name);
      
      if (service && patient && locationId.rows[0]) {
        await pool.query(
          `INSERT INTO appointments 
           (professional_id, private_patient_id, service_id, appointment_date, appointment_time, 
            location_id, value, status, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)`,
          [professionalId, patient.id, service.id, apt.date, apt.time, 
           locationId.rows[0].id, 80.00, apt.status]
        );
      }
    }

    console.log('✅ Agendamentos de teste criados');
    console.log('🎉 Setup completo! Use CPF: 123.456.789-01 e senha: teste123');

  } catch (error) {
    console.error('❌ Erro ao criar profissional de teste:', error);
  }
}

// Start server
const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Frontend: http://localhost:${PORT}`);
  console.log(`🔗 API: http://localhost:${PORT}/api`);
  
  // Create test professional on startup
  setTimeout(() => {
    createTestProfessional();
  }, 2000);
});