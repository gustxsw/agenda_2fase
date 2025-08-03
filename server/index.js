import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcryptjs from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import createUpload from './middleware/upload.js';
import { MercadoPagoConfig, Preference } from 'mercadopago';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize MercadoPago
const client = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN,
});

// Middleware
app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://www.cartaoquiroferreira.com.br',
    'https://cartaoquiroferreira.com.br'
  ],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static('dist'));

// 🔥 CREATE ALL TABLES ON SERVER START
const createTables = async () => {
  try {
    console.log('🔄 Creating database tables...');

    // Users table (already exists, but ensure it has all needed columns)
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
        roles TEXT[] DEFAULT '{}',
        percentage INTEGER DEFAULT 50,
        category_id INTEGER,
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry TIMESTAMP,
        photo_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Service categories
    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Services
    await pool.query(`
      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        base_price DECIMAL(10,2) NOT NULL,
        category_id INTEGER REFERENCES service_categories(id),
        is_base_service BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Dependents
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dependents (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) UNIQUE NOT NULL,
        birth_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Consultations
    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        private_patient_id INTEGER,
        professional_id INTEGER REFERENCES users(id) NOT NULL,
        service_id INTEGER REFERENCES services(id),
        location_id INTEGER,
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 🔥 NEW TABLES FOR SCHEDULING SYSTEM

    // Professional scheduling subscriptions
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_scheduling_subscriptions (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        status VARCHAR(20) DEFAULT 'pending',
        expires_at TIMESTAMP,
        payment_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Professional scheduling payments
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_scheduling_payments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        mp_preference_id VARCHAR(255),
        mp_payment_id VARCHAR(255),
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        external_reference VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Professional schedule settings
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_schedule_settings (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        work_days INTEGER[] DEFAULT '{1,2,3,4,5}',
        work_start_time TIME DEFAULT '08:00',
        work_end_time TIME DEFAULT '18:00',
        break_start_time TIME DEFAULT '12:00',
        break_end_time TIME DEFAULT '13:00',
        consultation_duration INTEGER DEFAULT 60,
        has_scheduling_subscription BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Attendance locations
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
        zip_code VARCHAR(10),
        phone VARCHAR(20),
        is_default BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Private patients
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
        zip_code VARCHAR(10),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(professional_id, cpf)
      )
    `);

    // Appointments (for scheduling system)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id),
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        service_id INTEGER REFERENCES services(id),
        appointment_date DATE NOT NULL,
        appointment_time TIME NOT NULL,
        location_id INTEGER REFERENCES attendance_locations(id),
        value DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'scheduled',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Medical records
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_records (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id),
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        appointment_id INTEGER REFERENCES appointments(id),
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

    // Medical documents
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_documents (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id),
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        document_type VARCHAR(50) NOT NULL,
        title VARCHAR(255) NOT NULL,
        document_url TEXT NOT NULL,
        template_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('✅ All tables created successfully');
  } catch (error) {
    console.error('❌ Error creating tables:', error);
  }
};

// Initialize database tables
createTables();

// 🔥 AUTH ROUTES
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    const result = await pool.query(
      'SELECT id, name, cpf, password_hash, roles FROM users WHERE cpf = $1',
      [cpf.replace(/\D/g, '')]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const user = result.rows[0];
    const isValidPassword = await bcryptjs.compare(password, user.password_hash);

    if (!isValidPassword) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const userData = {
      id: user.id,
      name: user.name,
      roles: user.roles || []
    };

    const needsRoleSelection = userData.roles.length > 1;

    res.json({
      user: userData,
      needsRoleSelection
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;

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
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
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

    const result = await pool.query(
      'SELECT id, name, cpf, roles FROM users WHERE id = $1',
      [req.user.id]
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
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        roles: user.roles,
        currentRole: role
      }
    });
  } catch (error) {
    console.error('Role switch error:', error);
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

    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    const hashedPassword = await bcryptjs.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (name, cpf, email, phone, birth_date, address, address_number, 
       address_complement, neighborhood, city, state, password_hash, roles, subscription_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
       RETURNING id, name, cpf, roles`,
      [name, cleanCpf, email, phone, birth_date, address, address_number,
       address_complement, neighborhood, city, state, hashedPassword, ['client'], 'pending']
    );

    const user = result.rows[0];

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: {
        id: user.id,
        name: user.name,
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

// 🔥 SCHEDULING SUBSCRIPTION ROUTES

// Create scheduling subscription payment
app.post('/api/create-scheduling-subscription', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Creating scheduling subscription for professional:', req.user.id);

    // Check if professional already has active subscription
    const existingSubscription = await pool.query(
      `SELECT * FROM professional_scheduling_subscriptions 
       WHERE professional_id = $1 AND status = 'active' AND expires_at > NOW()`,
      [req.user.id]
    );

    if (existingSubscription.rows.length > 0) {
      return res.status(400).json({ 
        message: 'Você já possui uma assinatura ativa do sistema de agendamentos' 
      });
    }

    const preference = new Preference(client);

    const preferenceData = {
      items: [
        {
          title: 'Sistema de Agendamentos - Quiro Ferreira',
          description: 'Assinatura mensal do sistema de agendamentos profissional',
          quantity: 1,
          unit_price: 49.90,
          currency_id: 'BRL',
        }
      ],
      payer: {
        name: req.user.name,
        email: req.user.email || `professional${req.user.id}@quiroferreira.com.br`,
      },
      back_urls: {
        success: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/scheduling?payment=success`,
        failure: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/scheduling?payment=failure`,
        pending: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/scheduling?payment=pending`,
      },
      auto_return: 'approved',
      external_reference: `scheduling_${req.user.id}_${Date.now()}`,
      notification_url: `${process.env.API_URL || 'http://localhost:3001'}/api/scheduling-payment/webhook`,
      statement_descriptor: 'QUIRO FERREIRA AGENDA',
    };

    console.log('🔄 Creating MercadoPago preference:', preferenceData);

    const result = await preference.create({ body: preferenceData });

    console.log('✅ MercadoPago preference created:', result);
    // 🧪 CREATE TEST PROFESSIONAL WITH SCHEDULING
    console.log('🧪 Creating test professional with scheduling...');
    
    // Create test category
    const categoryResult = await pool.query(
      `INSERT INTO service_categories (name, description) 
       VALUES ('Fisioterapia', 'Serviços de fisioterapia e reabilitação')
       ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
       RETURNING id`
    );
    const categoryId = categoryResult.rows[0].id;
    
    // Create test professional
    const hashedPassword = await bcryptjs.hash('123456', 10);
    const professionalResult = await pool.query(
      `INSERT INTO users (name, cpf, password, roles, percentage, category_id, subscription_status, subscription_expiry)
       VALUES ('Dr. João Silva (TESTE)', '12345678901', $1, $2, 70, $3, 'active', '2025-12-31')
       ON CONFLICT (cpf) DO UPDATE SET 
         name = EXCLUDED.name,
         roles = EXCLUDED.roles,
         percentage = EXCLUDED.percentage,
         category_id = EXCLUDED.category_id,
         subscription_status = EXCLUDED.subscription_status,
         subscription_expiry = EXCLUDED.subscription_expiry
       RETURNING id`,
      [hashedPassword, JSON.stringify(['professional']), categoryId]
    );
    const professionalId = professionalResult.rows[0].id;
    
    // Create test service
    const serviceResult = await pool.query(
      `INSERT INTO services (name, description, base_price, category_id, is_base_service)
       VALUES ('Consulta Fisioterapêutica', 'Avaliação e tratamento fisioterapêutico', 150.00, $1, true)
       ON CONFLICT (name) DO UPDATE SET 
         description = EXCLUDED.description,
         base_price = EXCLUDED.base_price,
         category_id = EXCLUDED.category_id
       RETURNING id`,
      [categoryId]
    );
    const serviceId = serviceResult.rows[0].id;
    
    // Create scheduling subscription for professional
    const expiresAt = new Date('2025-12-31');
    await pool.query(
      `INSERT INTO professional_scheduling_subscriptions (professional_id, status, expires_at)
       VALUES ($1, 'active', $2)
       ON CONFLICT (professional_id) DO UPDATE SET 
         status = 'active',
         expires_at = $2`,
      [professionalId, expiresAt]
    );
    
    // Create schedule settings
    await pool.query(
      `INSERT INTO professional_schedule_settings 
       (professional_id, work_days, work_start_time, work_end_time, break_start_time, break_end_time, consultation_duration, has_scheduling_subscription)
       VALUES ($1, $2, '08:00', '18:00', '12:00', '13:00', 60, true)
       ON CONFLICT (professional_id) DO UPDATE SET 
         work_days = EXCLUDED.work_days,
         work_start_time = EXCLUDED.work_start_time,
         work_end_time = EXCLUDED.work_end_time,
         break_start_time = EXCLUDED.break_start_time,
         break_end_time = EXCLUDED.break_end_time,
         consultation_duration = EXCLUDED.consultation_duration,
         has_scheduling_subscription = EXCLUDED.has_scheduling_subscription`,
      [professionalId, JSON.stringify([1, 2, 3, 4, 5])] // Monday to Friday
    );
    
    // Create attendance location
    const locationResult = await pool.query(
      `INSERT INTO attendance_locations 
       (professional_id, name, address, address_number, neighborhood, city, state, phone, is_default)
       VALUES ($1, 'Clínica Principal', 'Rua das Flores', '123', 'Centro', 'Goiânia', 'GO', '(62) 3333-4444', true)
       ON CONFLICT (professional_id, name) DO UPDATE SET 
         address = EXCLUDED.address,
         is_default = EXCLUDED.is_default
       RETURNING id`,
      [professionalId]
    );
    const locationId = locationResult.rows[0].id;
    
    // Create private patients
    const patient1Result = await pool.query(
      `INSERT INTO private_patients 
       (professional_id, name, cpf, email, phone, birth_date, address, city, state)
       VALUES ($1, 'Maria Santos', '11111111111', 'maria@email.com', '62999887766', '1985-03-15', 'Rua A, 100', 'Goiânia', 'GO')
       ON CONFLICT (professional_id, cpf) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`,
      [professionalId]
    );
    const patient1Id = patient1Result.rows[0].id;
    
    const patient2Result = await pool.query(
      `INSERT INTO private_patients 
       (professional_id, name, cpf, email, phone, birth_date, address, city, state)
       VALUES ($1, 'Carlos Oliveira', '22222222222', 'carlos@email.com', '62988776655', '1978-07-22', 'Rua B, 200', 'Goiânia', 'GO')
       ON CONFLICT (professional_id, cpf) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`,
      [professionalId]
    );
    const patient2Id = patient2Result.rows[0].id;
    
    // Create test appointments for this week
    const today = new Date();
    const appointments = [
      {
        date: new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1), // Tomorrow
        time: '09:00',
        patient_id: patient1Id,
        notes: 'Primeira consulta - avaliação inicial'
      },
      {
        date: new Date(today.getFullYear(), today.getMonth(), today.getDate() + 2), // Day after tomorrow
        time: '14:30',
        patient_id: patient2Id,
        notes: 'Retorno - continuidade do tratamento'
      },
      {
        date: new Date(today.getFullYear(), today.getMonth(), today.getDate() + 3), // 3 days from now
        time: '10:15',
        patient_id: patient1Id,
        notes: 'Segunda sessão de fisioterapia'
      }
    ];
    
    for (const appointment of appointments) {
      await pool.query(
        `INSERT INTO appointments 
         (professional_id, private_patient_id, service_id, appointment_date, appointment_time, location_id, value, status, notes)
         VALUES ($1, $2, $3, $4, $5, $6, 150.00, 'scheduled', $7)
         ON CONFLICT DO NOTHING`,
        [professionalId, appointment.patient_id, serviceId, appointment.date.toISOString().split('T')[0], 
         appointment.time, locationId, appointment.notes]
      );
    }
    
    // Create medical records for the patients
    await pool.query(
      `INSERT INTO medical_records 
       (professional_id, private_patient_id, chief_complaint, history_present_illness, 
        physical_examination, diagnosis, treatment_plan, vital_signs)
       VALUES ($1, $2, 'Dor lombar há 2 semanas', 'Paciente relata dor na região lombar após esforço físico', 
               'Tensão muscular em região paravertebral L3-L5', 'Lombalgia mecânica', 
               'Fisioterapia 3x/semana, exercícios de fortalecimento', $3)
       ON CONFLICT DO NOTHING`,
      [professionalId, patient1Id, JSON.stringify({
        blood_pressure: '120/80',
        heart_rate: '72 bpm',
        temperature: '36.5°C'
      })]
    );
    
    await pool.query(
      `INSERT INTO medical_records 
       (professional_id, private_patient_id, chief_complaint, history_present_illness, 
        physical_examination, diagnosis, treatment_plan, vital_signs)
       VALUES ($1, $2, 'Reabilitação pós-cirúrgica', 'Paciente em pós-operatório de cirurgia de joelho', 
               'Edema leve em joelho direito, amplitude de movimento limitada', 'Pós-operatório de meniscectomia', 
               'Protocolo de reabilitação pós-cirúrgica, 4 semanas', $3)
       ON CONFLICT DO NOTHING`,
      [professionalId, patient2Id, JSON.stringify({
        blood_pressure: '130/85',
        heart_rate: '68 bpm',
        temperature: '36.2°C'
      })]
    );
    
    console.log('✅ Test professional with scheduling created successfully!');
    console.log('📋 Login credentials:');
    console.log('   CPF: 123.456.789-01');
    console.log('   Password: 123456');
    console.log('📅 Features available:');
    console.log('   - Active scheduling subscription until 2025-12-31');
    console.log('   - 2 private patients created');
    console.log('   - 3 appointments scheduled for this week');
    console.log('   - 2 medical records created');
    console.log('   - Attendance location configured');
    console.log('   - Schedule settings configured (Mon-Fri, 8AM-6PM)');
    

    // Store the payment intent in database
    await pool.query(
      `INSERT INTO professional_scheduling_payments 
       (professional_id, mp_preference_id, amount, status, external_reference)
       VALUES ($1, $2, $3, 'pending', $4)`,
      [req.user.id, result.id, 49.90, preferenceData.external_reference]
    );

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point,
    });
  } catch (error) {
    console.error('❌ Error creating scheduling subscription:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento da assinatura',
      error: error.message 
    });
  }
});

// Handle MercadoPago webhook for scheduling payments
app.post('/api/scheduling-payment/webhook', async (req, res) => {
  try {
    console.log('🔔 Scheduling payment webhook received:', req.body);

    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      
      // Simulate payment approval for testing
      const paymentResult = await pool.query(
        `SELECT * FROM professional_scheduling_payments WHERE mp_preference_id = $1`,
        [paymentId]
      );

      if (paymentResult.rows.length > 0) {
        const payment = paymentResult.rows[0];
        
        // Update payment status
        await pool.query(
          `UPDATE professional_scheduling_payments 
           SET status = 'approved', mp_payment_id = $1, updated_at = CURRENT_TIMESTAMP
           WHERE id = $2`,
          [paymentId, payment.id]
        );

        // Create or update scheduling subscription
        const expiresAt = new Date();
        expiresAt.setMonth(expiresAt.getMonth() + 1); // 1 month from now

        await pool.query(
          `INSERT INTO professional_scheduling_subscriptions 
           (professional_id, status, expires_at, payment_id)
           VALUES ($1, 'active', $2, $3)
           ON CONFLICT (professional_id) 
           DO UPDATE SET 
             status = 'active',
             expires_at = $2,
             payment_id = $3,
             updated_at = CURRENT_TIMESTAMP`,
          [payment.professional_id, expiresAt, payment.id]
        );

        // Update professional schedule settings to enable scheduling
        await pool.query(
          `INSERT INTO professional_schedule_settings (professional_id, has_scheduling_subscription)
           VALUES ($1, true)
           ON CONFLICT (professional_id) 
           DO UPDATE SET has_scheduling_subscription = true`,
          [payment.professional_id]
        );

        console.log('✅ Scheduling subscription activated for professional:', payment.professional_id);
      }
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error('❌ Error processing scheduling payment webhook:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Get professional's scheduling subscription status
app.get('/api/scheduling-subscription-status', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM professional_scheduling_subscriptions 
       WHERE professional_id = $1 
       ORDER BY created_at DESC 
       LIMIT 1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.json({
        has_subscription: false,
        status: 'inactive',
        expires_at: null
      });
    }

    const subscription = result.rows[0];
    // 🔥 FIXED: Check if subscription is active (either by status or valid expiry date)
    const now = new Date();
    const expiryDate = subscription.expires_at ? new Date(subscription.expires_at) : null;
    const isActive = subscription.status === 'active' && (!expiryDate || expiryDate > now);

    res.json({
      has_subscription: true,
      status: isActive ? 'active' : 'expired',
      expires_at: subscription.expires_at,
      created_at: subscription.created_at
    });
  } catch (error) {
    console.error('Error fetching subscription status:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// 🔥 SCHEDULE SETTINGS ROUTES

// Get professional's schedule settings
app.get('/api/scheduling/settings', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM professional_schedule_settings WHERE professional_id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      // Return default settings if none exist
      return res.json({
        professional_id: req.user.id,
        work_days: [1, 2, 3, 4, 5], // Monday to Friday
        work_start_time: '08:00',
        work_end_time: '18:00',
        break_start_time: '12:00',
        break_end_time: '13:00',
        consultation_duration: 60,
        has_scheduling_subscription: false
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching schedule settings:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update professional's schedule settings
app.put('/api/scheduling/settings', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      work_days,
      work_start_time,
      work_end_time,
      break_start_time,
      break_end_time,
      consultation_duration
    } = req.body;

    const result = await pool.query(
      `INSERT INTO professional_schedule_settings 
       (professional_id, work_days, work_start_time, work_end_time, break_start_time, break_end_time, consultation_duration)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (professional_id) 
       DO UPDATE SET 
         work_days = $2,
         work_start_time = $3,
         work_end_time = $4,
         break_start_time = $5,
         break_end_time = $6,
         consultation_duration = $7,
         updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [req.user.id, work_days, work_start_time, work_end_time, break_start_time, break_end_time, consultation_duration]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating schedule settings:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// 🔥 APPOINTMENTS ROUTES

// Get professional's appointments
app.get('/api/appointments', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

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

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new appointment
app.post('/api/appointments', authenticate, authorize(['professional']), async (req, res) => {
  try {
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

    const result = await pool.query(
      `INSERT INTO appointments 
       (professional_id, private_patient_id, client_id, dependent_id, service_id, 
        appointment_date, appointment_time, location_id, notes, value, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'scheduled')
       RETURNING *`,
      [req.user.id, private_patient_id, client_id, dependent_id, service_id, 
       appointment_date, appointment_time, location_id, notes, value]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating appointment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// 🔥 ATTENDANCE LOCATIONS ROUTES

// Get professional's attendance locations
app.get('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM attendance_locations 
       WHERE professional_id = $1 
       ORDER BY is_default DESC, name`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching attendance locations:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new attendance location
app.post('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      zip_code,
      phone,
      is_default
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

// Update attendance location
app.put('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      zip_code,
      phone,
      is_default
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

// Delete attendance location
app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
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

// 🔥 PRIVATE PATIENTS ROUTES

// Get professional's private patients
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM private_patients 
       WHERE professional_id = $1 
       ORDER BY name`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new private patient
app.post('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
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
      zip_code
    } = req.body;

    // Check if CPF already exists for this professional
    const existingPatient = await pool.query(
      `SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2`,
      [cpf.replace(/\D/g, ''), req.user.id]
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
      [req.user.id, name, cpf.replace(/\D/g, ''), email, phone, birth_date, address, 
       address_number, address_complement, neighborhood, city, state, zip_code]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating private patient:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update private patient
app.put('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      email,
      phone,
      birth_date,
      address,
      address_number,
      address_complement,
      neighborhood,
      city,
      state,
      zip_code
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

// Delete private patient
app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
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

// 🔥 MEDICAL RECORDS ROUTES

// Get medical records for a patient
app.get('/api/medical-records/patient/:patientId/:patientType', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { patientId, patientType } = req.params;

    let whereClause = '';
    if (patientType === 'private') {
      whereClause = 'private_patient_id = $2';
    } else if (patientType === 'client') {
      whereClause = 'client_id = $2';
    } else if (patientType === 'dependent') {
      whereClause = 'dependent_id = $2';
    }

    const result = await pool.query(
      `SELECT mr.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name
       FROM medical_records mr
       LEFT JOIN private_patients pp ON mr.private_patient_id = pp.id
       LEFT JOIN users c ON mr.client_id = c.id
       LEFT JOIN dependents d ON mr.dependent_id = d.id
       WHERE mr.professional_id = $1 AND ${whereClause}
       ORDER BY mr.created_at DESC`,
      [req.user.id, patientId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get all medical records for professional
app.get('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT mr.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name
       FROM medical_records mr
       LEFT JOIN private_patients pp ON mr.private_patient_id = pp.id
       LEFT JOIN users c ON mr.client_id = c.id
       LEFT JOIN dependents d ON mr.dependent_id = d.id
       WHERE mr.professional_id = $1
       ORDER BY mr.created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create new medical record
app.post('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id,
      client_id,
      dependent_id,
      appointment_id,
      chief_complaint,
      history_present_illness,
      past_medical_history,
      medications,
      allergies,
      physical_examination,
      diagnosis,
      treatment_plan,
      notes,
      vital_signs
    } = req.body;

    const result = await pool.query(
      `INSERT INTO medical_records 
       (professional_id, private_patient_id, client_id, dependent_id, appointment_id,
        chief_complaint, history_present_illness, past_medical_history, medications,
        allergies, physical_examination, diagnosis, treatment_plan, notes, vital_signs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
       RETURNING *`,
      [req.user.id, private_patient_id, client_id, dependent_id, appointment_id,
       chief_complaint, history_present_illness, past_medical_history, medications,
       allergies, physical_examination, diagnosis, treatment_plan, notes, vital_signs]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update medical record
app.put('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      chief_complaint,
      history_present_illness,
      past_medical_history,
      medications,
      allergies,
      physical_examination,
      diagnosis,
      treatment_plan,
      notes,
      vital_signs
    } = req.body;

    const result = await pool.query(
      `UPDATE medical_records 
       SET chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
           medications = $4, allergies = $5, physical_examination = $6, diagnosis = $7,
           treatment_plan = $8, notes = $9, vital_signs = $10, updated_at = CURRENT_TIMESTAMP
       WHERE id = $11 AND professional_id = $12
       RETURNING *`,
      [chief_complaint, history_present_illness, past_medical_history, medications,
       allergies, physical_examination, diagnosis, treatment_plan, notes, vital_signs, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete medical record
app.delete('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `DELETE FROM medical_records WHERE id = $1 AND professional_id = $2 RETURNING *`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    res.json({ message: 'Prontuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting medical record:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// 🔥 MEDICAL DOCUMENTS ROUTES

// Document templates
const generateDocumentHTML = (type, data) => {
  const currentDate = new Date().toLocaleDateString('pt-BR', {
    day: '2-digit',
    month: 'long',
    year: 'numeric'
  });

  const templates = {
    certificate: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Atestado Médico</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
          .header { text-align: center; margin-bottom: 40px; }
          .content { margin: 20px 0; }
          .signature { margin-top: 60px; text-align: center; }
          .footer { margin-top: 40px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>ATESTADO MÉDICO</h1>
        </div>
        <div class="content">
          <p>Atesto para os devidos fins que o(a) paciente <strong>${data.patientName}</strong>, 
          portador(a) do CPF ${data.patientCpf}, esteve sob meus cuidados médicos.</p>
          
          <p><strong>Descrição:</strong> ${data.description}</p>
          
          ${data.cid ? `<p><strong>CID:</strong> ${data.cid}</p>` : ''}
          
          <p>Necessita de afastamento de suas atividades por <strong>${data.days} dia(s)</strong>, 
          a partir da data de hoje.</p>
          
          <p>Por ser verdade, firmo o presente atestado.</p>
        </div>
        <div class="signature">
          <p>${data.professionalName}<br>
          ${data.professionalSpecialty}<br>
          CRM: ${data.crm}</p>
        </div>
        <div class="footer">
          <p>Documento emitido em ${currentDate}</p>
        </div>
      </body>
      </html>
    `,
    
    prescription: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Receituário Médico</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
          .header { text-align: center; margin-bottom: 40px; border-bottom: 2px solid #333; padding-bottom: 20px; }
          .patient-info { margin: 20px 0; background: #f5f5f5; padding: 15px; }
          .prescription { margin: 30px 0; min-height: 300px; }
          .signature { margin-top: 60px; text-align: center; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>RECEITUÁRIO MÉDICO</h1>
          <p>${data.professionalName} - ${data.professionalSpecialty}<br>CRM: ${data.crm}</p>
        </div>
        <div class="patient-info">
          <p><strong>Paciente:</strong> ${data.patientName}<br>
          <strong>CPF:</strong> ${data.patientCpf}<br>
          <strong>Data:</strong> ${currentDate}</p>
        </div>
        <div class="prescription">
          <h3>Prescrição:</h3>
          <div style="white-space: pre-line; font-size: 14px;">${data.prescription}</div>
        </div>
        <div class="signature">
          <p>_________________________________<br>
          ${data.professionalName}<br>
          CRM: ${data.crm}</p>
        </div>
      </body>
      </html>
    `,
    
    consent_form: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Termo de Consentimento</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
          .header { text-align: center; margin-bottom: 40px; }
          .content { margin: 20px 0; }
          .signature-area { margin-top: 60px; }
          .signature-line { border-bottom: 1px solid #000; width: 300px; margin: 20px auto; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>TERMO DE CONSENTIMENTO LIVRE E ESCLARECIDO</h1>
        </div>
        <div class="content">
          <p><strong>Paciente:</strong> ${data.patientName}<br>
          <strong>CPF:</strong> ${data.patientCpf}<br>
          <strong>Data:</strong> ${currentDate}</p>
          
          <h3>Procedimento: ${data.procedure}</h3>
          
          <p><strong>Descrição do Procedimento:</strong></p>
          <p>${data.description}</p>
          
          <p><strong>Riscos e Benefícios:</strong></p>
          <p>${data.risks}</p>
          
          <p>Declaro que fui devidamente informado(a) sobre o procedimento acima descrito, 
          seus riscos e benefícios, e consinto com sua realização.</p>
        </div>
        <div class="signature-area">
          <div class="signature-line"></div>
          <p style="text-align: center;">Assinatura do Paciente</p>
          
          <div class="signature-line"></div>
          <p style="text-align: center;">${data.professionalName} - CRM: ${data.crm}</p>
        </div>
      </body>
      </html>
    `,
    
    exam_request: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Solicitação de Exames</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
          .header { text-align: center; margin-bottom: 40px; }
          .content { margin: 20px 0; }
          .signature { margin-top: 60px; text-align: center; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>SOLICITAÇÃO DE EXAMES</h1>
        </div>
        <div class="content">
          <p><strong>Paciente:</strong> ${data.patientName}<br>
          <strong>CPF:</strong> ${data.patientCpf}<br>
          <strong>Data:</strong> ${currentDate}</p>
          
          <h3>Exames Solicitados:</h3>
          <div style="white-space: pre-line; margin: 20px 0;">${data.content}</div>
        </div>
        <div class="signature">
          <p>${data.professionalName}<br>
          ${data.professionalSpecialty}<br>
          CRM: ${data.crm}</p>
        </div>
      </body>
      </html>
    `,
    
    declaration: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Declaração Médica</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
          .header { text-align: center; margin-bottom: 40px; }
          .content { margin: 20px 0; }
          .signature { margin-top: 60px; text-align: center; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>DECLARAÇÃO MÉDICA</h1>
        </div>
        <div class="content">
          <p><strong>Paciente:</strong> ${data.patientName}<br>
          <strong>CPF:</strong> ${data.patientCpf}<br>
          <strong>Data:</strong> ${currentDate}</p>
          
          <div style="white-space: pre-line; margin: 30px 0;">${data.content}</div>
          
          <p>Por ser verdade, firmo a presente declaração.</p>
        </div>
        <div class="signature">
          <p>${data.professionalName}<br>
          ${data.professionalSpecialty}<br>
          CRM: ${data.crm}</p>
        </div>
      </body>
      </html>
    `,
    
    lgpd: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Termo LGPD</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
          .header { text-align: center; margin-bottom: 40px; }
          .content { margin: 20px 0; text-align: justify; }
          .signature-area { margin-top: 60px; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>TERMO DE CONSENTIMENTO LGPD</h1>
          <h2>Lei Geral de Proteção de Dados</h2>
        </div>
        <div class="content">
          <p><strong>Paciente:</strong> ${data.patientName}<br>
          <strong>CPF:</strong> ${data.patientCpf}<br>
          <strong>Data:</strong> ${currentDate}</p>
          
          <p>Em conformidade com a Lei Geral de Proteção de Dados (LGPD - Lei 13.709/2018), 
          informamos sobre o tratamento dos seus dados pessoais:</p>
          
          <p><strong>Finalidade:</strong> Os dados coletados serão utilizados exclusivamente para 
          prestação de serviços médicos, elaboração de prontuários e cumprimento de obrigações legais.</p>
          
          <p><strong>Base Legal:</strong> Consentimento do titular e execução de contrato.</p>
          
          <p><strong>Compartilhamento:</strong> Os dados não serão compartilhados com terceiros, 
          exceto quando necessário para a prestação do serviço ou por determinação legal.</p>
          
          <p><strong>Direitos do Titular:</strong> Você tem direito de acessar, corrigir, excluir 
          ou solicitar a portabilidade dos seus dados.</p>
          
          <p>Ao assinar este termo, você consente com o tratamento dos seus dados pessoais 
          conforme descrito acima.</p>
        </div>
        <div class="signature-area">
          <p>_________________________________<br>
          Assinatura do Paciente</p>
          
          <p style="margin-top: 40px;">_________________________________<br>
          ${data.professionalName} - CRM: ${data.crm}</p>
        </div>
      </body>
      </html>
    `,
    
    other: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>${data.title}</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
          .header { text-align: center; margin-bottom: 40px; }
          .content { margin: 20px 0; }
          .signature { margin-top: 60px; text-align: center; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>${data.title.toUpperCase()}</h1>
        </div>
        <div class="content">
          <p><strong>Paciente:</strong> ${data.patientName}<br>
          <strong>CPF:</strong> ${data.patientCpf}<br>
          <strong>Data:</strong> ${currentDate}</p>
          
          <div style="white-space: pre-line; margin: 30px 0;">${data.content}</div>
        </div>
        <div class="signature">
          <p>${data.professionalName}<br>
          ${data.professionalSpecialty}<br>
          CRM: ${data.crm}</p>
        </div>
      </body>
      </html>
    `
  };

  return templates[type] || templates.other;
};

// Get medical documents
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT md.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name
       FROM medical_documents md
       LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
       LEFT JOIN users c ON md.client_id = c.id
       LEFT JOIN dependents d ON md.dependent_id = d.id
       WHERE md.professional_id = $1
       ORDER BY md.created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create medical document
app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id,
      client_id,
      dependent_id,
      document_type,
      title,
      template_data
    } = req.body;

    // Generate HTML document
    const htmlContent = generateDocumentHTML(document_type, template_data);
    
    // For now, we'll store the HTML content directly as the document URL
    // In a real implementation, you would upload this to Cloudinary
    const documentUrl = `data:text/html;base64,${Buffer.from(htmlContent).toString('base64')}`;

    const result = await pool.query(
      `INSERT INTO medical_documents 
       (professional_id, private_patient_id, client_id, dependent_id, 
        document_type, title, document_url, template_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [req.user.id, private_patient_id, client_id, dependent_id, 
       document_type, title, documentUrl, template_data]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating medical document:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// 🔥 REPORTS ROUTES

// Professional revenue report
app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    // Get professional's percentage
    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = professionalResult.rows[0]?.percentage || 50;

    // Get consultations for the period
    const consultationsResult = await pool.query(
      `SELECT c.*, 
              COALESCE(pp.name, u.name, d.name) as client_name,
              s.name as service_name,
              CASE 
                WHEN c.private_patient_id IS NOT NULL THEN 'private'
                ELSE 'convenio'
              END as consultation_type
       FROM consultations c
       LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
       LEFT JOIN users u ON c.client_id = u.id
       LEFT JOIN dependents d ON c.dependent_id = d.id
       LEFT JOIN services s ON c.service_id = s.id
       WHERE c.professional_id = $1 
       AND c.date >= $2 
       AND c.date <= $3
       ORDER BY c.date DESC`,
      [req.user.id, start_date, end_date]
    );

    const consultations = consultationsResult.rows;

    // Calculate totals
    const convenioConsultations = consultations.filter(c => c.consultation_type === 'convenio');
    const privateConsultations = consultations.filter(c => c.consultation_type === 'private');

    const convenioRevenue = convenioConsultations.reduce((sum, c) => sum + parseFloat(c.value), 0);
    const privateRevenue = privateConsultations.reduce((sum, c) => sum + parseFloat(c.value), 0);
    const totalRevenue = convenioRevenue + privateRevenue;

    // Calculate amount to pay to convenio (percentage of convenio revenue)
    const amountToPay = convenioRevenue * ((100 - professionalPercentage) / 100);

    const summary = {
      professional_percentage: professionalPercentage,
      total_revenue: totalRevenue,
      consultation_count: consultations.length,
      amount_to_pay: amountToPay
    };

    const consultationDetails = consultations.map(c => ({
      date: c.date,
      client_name: c.client_name,
      service_name: c.service_name,
      total_value: parseFloat(c.value),
      amount_to_pay: c.consultation_type === 'convenio' 
        ? parseFloat(c.value) * ((100 - professionalPercentage) / 100)
        : 0
    }));

    res.json({
      summary,
      consultations: consultationDetails
    });
  } catch (error) {
    console.error('Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Professional detailed report
app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    // Get professional's percentage
    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = professionalResult.rows[0]?.percentage || 50;

    // Get consultations for the period
    const consultationsResult = await pool.query(
      `SELECT c.*, 
              CASE 
                WHEN c.private_patient_id IS NOT NULL THEN 'private'
                ELSE 'convenio'
              END as consultation_type
       FROM consultations c
       WHERE c.professional_id = $1 
       AND c.date >= $2 
       AND c.date <= $3`,
      [req.user.id, start_date, end_date]
    );

    const consultations = consultationsResult.rows;

    // Calculate detailed statistics
    const convenioConsultations = consultations.filter(c => c.consultation_type === 'convenio');
    const privateConsultations = consultations.filter(c => c.consultation_type === 'private');

    const convenioRevenue = convenioConsultations.reduce((sum, c) => sum + parseFloat(c.value), 0);
    const privateRevenue = privateConsultations.reduce((sum, c) => sum + parseFloat(c.value), 0);
    const totalRevenue = convenioRevenue + privateRevenue;

    const amountToPay = convenioRevenue * ((100 - professionalPercentage) / 100);

    const summary = {
      total_consultations: consultations.length,
      convenio_consultations: convenioConsultations.length,
      private_consultations: privateConsultations.length,
      total_revenue: totalRevenue,
      convenio_revenue: convenioRevenue,
      private_revenue: privateRevenue,
      professional_percentage: professionalPercentage,
      amount_to_pay: amountToPay
    };

    res.json({ summary });
  } catch (error) {
    console.error('Error generating detailed report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// 🔥 EXISTING ROUTES (keeping all existing functionality)

// Get all users (admin only)
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.*, 
             sc.name as category_name,
             CASE 
               WHEN u.roles && ARRAY['client'] THEN u.subscription_status
               ELSE NULL
             END as subscription_status,
             u.subscription_expiry
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      ORDER BY u.created_at DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get specific user
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(
      'SELECT id, name, cpf, email, phone, birth_date, address, address_number, address_complement, neighborhood, city, state, roles, percentage, category_id, subscription_status, subscription_expiry, photo_url FROM users WHERE id = $1',
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
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

    const cleanCpf = cpf.replace(/\D/g, '');

    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    const hashedPassword = await bcryptjs.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (name, cpf, email, phone, birth_date, address, address_number, 
       address_complement, neighborhood, city, state, password_hash, roles, percentage, category_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
       RETURNING id, name, cpf, roles`,
      [name, cleanCpf, email, phone, birth_date, address, address_number,
       address_complement, neighborhood, city, state, hashedPassword, roles, percentage, category_id]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update user
app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, roles, percentage, category_id,
      currentPassword, newPassword
    } = req.body;

    // Check if user is updating their own profile or is admin
    if (req.user.id !== parseInt(id) && !req.user.roles?.includes('admin')) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    let updateQuery = `
      UPDATE users 
      SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
          address_number = $6, address_complement = $7, neighborhood = $8,
          city = $9, state = $10, updated_at = CURRENT_TIMESTAMP
    `;
    let queryParams = [name, email, phone, birth_date, address, address_number,
                      address_complement, neighborhood, city, state];
    let paramCount = 10;

    // Add admin-only fields
    if (req.user.roles?.includes('admin')) {
      updateQuery += `, roles = $${++paramCount}, percentage = $${++paramCount}, category_id = $${++paramCount}`;
      queryParams.push(roles, percentage, category_id);
    }

    // Handle password change
    if (newPassword && currentPassword) {
      // Verify current password
      const userResult = await pool.query('SELECT password_hash FROM users WHERE id = $1', [id]);
      if (userResult.rows.length === 0) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
      }

      const isValidPassword = await bcryptjs.compare(currentPassword, userResult.rows[0].password_hash);
      if (!isValidPassword) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }

      const hashedNewPassword = await bcryptjs.hash(newPassword, 10);
      updateQuery += `, password_hash = $${++paramCount}`;
      queryParams.push(hashedNewPassword);
    }

    updateQuery += ` WHERE id = $${++paramCount} RETURNING id, name, email, roles`;
    queryParams.push(id);

    const result = await pool.query(updateQuery, queryParams);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Activate client
app.put('/api/users/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { expiry_date } = req.body;

    const result = await pool.query(
      `UPDATE users 
       SET subscription_status = 'active', subscription_expiry = $1, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2 AND 'client' = ANY(roles)
       RETURNING id, name, subscription_status, subscription_expiry`,
      [expiry_date, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error activating client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({ message: 'Usuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get service categories
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM service_categories ORDER BY name');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create service category (admin only)
app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    const result = await pool.query(
      'INSERT INTO service_categories (name, description) VALUES ($1, $2) RETURNING *',
      [name, description]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating service category:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get services
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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create service (admin only)
app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(
      'INSERT INTO services (name, description, base_price, category_id, is_base_service) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, description, base_price, category_id, is_base_service]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update service (admin only)
app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(
      `UPDATE services 
       SET name = $1, description = $2, base_price = $3, category_id = $4, is_base_service = $5
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

// Delete service (admin only)
app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query('DELETE FROM services WHERE id = $1 RETURNING *', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    res.json({ message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get dependents for a client
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    // Check if user can access this client's dependents
    if (req.user.currentRole === 'client' && req.user.id !== parseInt(clientId)) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    const result = await pool.query(
      'SELECT * FROM dependents WHERE client_id = $1 ORDER BY name',
      [clientId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Lookup dependent by CPF
app.get('/api/dependents/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    const result = await pool.query(
      `SELECT d.*, u.name as client_name, u.subscription_status as client_subscription_status
       FROM dependents d
       JOIN users u ON d.client_id = u.id
       WHERE d.cpf = $1`,
      [cpf.replace(/\D/g, '')]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error looking up dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create dependent
app.post('/api/dependents', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    // Check if user can create dependent for this client
    if (req.user.id !== client_id) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    // Check if CPF already exists
    const existingDependent = await pool.query('SELECT id FROM dependents WHERE cpf = $1', [cleanCpf]);
    if (existingDependent.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    const result = await pool.query(
      'INSERT INTO dependents (client_id, name, cpf, birth_date) VALUES ($1, $2, $3, $4) RETURNING *',
      [client_id, name, cleanCpf, birth_date]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update dependent
app.put('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    // Check if user owns this dependent
    const dependentCheck = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [id]
    );

    if (dependentCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    if (dependentCheck.rows[0].client_id !== req.user.id) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    const result = await pool.query(
      'UPDATE dependents SET name = $1, birth_date = $2 WHERE id = $3 RETURNING *',
      [name, birth_date, id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete dependent
app.delete('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if user owns this dependent
    const dependentCheck = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [id]
    );

    if (dependentCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    if (dependentCheck.rows[0].client_id !== req.user.id) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    const result = await pool.query('DELETE FROM dependents WHERE id = $1 RETURNING *', [id]);

    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get consultations
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT c.*, 
             COALESCE(pp.name, u.name, d.name) as client_name,
             s.name as service_name,
             prof.name as professional_name,
             CASE 
               WHEN c.dependent_id IS NOT NULL THEN true
               ELSE false
             END as is_dependent
      FROM consultations c
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users prof ON c.professional_id = prof.id
    `;
    
    let queryParams = [];
    
    if (req.user.currentRole === 'client') {
      query += ' WHERE (c.client_id = $1 OR d.client_id = $1)';
      queryParams.push(req.user.id);
    } else if (req.user.currentRole === 'professional') {
      query += ' WHERE c.professional_id = $1';
      queryParams.push(req.user.id);
    }
    
    query += ' ORDER BY c.date DESC';
    
    const result = await pool.query(query, queryParams);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching consultations:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create consultation
app.post('/api/consultations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      client_id,
      dependent_id,
      private_patient_id,
      professional_id,
      service_id,
      location_id,
      value,
      date
    } = req.body;

    const result = await pool.query(
      `INSERT INTO consultations 
       (client_id, dependent_id, private_patient_id, professional_id, service_id, location_id, value, date)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [client_id, dependent_id, private_patient_id, professional_id, service_id, location_id, value, date]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Lookup client by CPF
app.get('/api/clients/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    const result = await pool.query(
      'SELECT id, name, cpf, subscription_status FROM users WHERE cpf = $1 AND $2 = ANY(roles)',
      [cpf.replace(/\D/g, ''), 'client']
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error looking up client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get professionals (for clients)
app.get('/api/professionals', authenticate, authorize(['client']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.name, u.email, u.phone, u.roles, u.address, u.address_number,
             u.address_complement, u.neighborhood, u.city, u.state, u.photo_url,
             sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Revenue report (admin only)
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    const result = await pool.query(`
      SELECT 
        SUM(c.value) as total_revenue,
        COUNT(*) as total_consultations,
        prof.name as professional_name,
        prof.percentage as professional_percentage,
        SUM(c.value) as revenue,
        COUNT(*) as consultation_count,
        SUM(c.value * (prof.percentage / 100.0)) as professional_payment,
        SUM(c.value * ((100 - prof.percentage) / 100.0)) as clinic_revenue,
        s.name as service_name
      FROM consultations c
      JOIN users prof ON c.professional_id = prof.id
      LEFT JOIN services s ON c.service_id = s.id
      WHERE c.date >= $1 AND c.date <= $2
      GROUP BY prof.id, prof.name, prof.percentage, s.id, s.name
      ORDER BY prof.name, s.name
    `, [start_date, end_date]);

    // Calculate totals
    const totalRevenue = result.rows.reduce((sum, row) => sum + parseFloat(row.total_revenue || 0), 0);

    // Group by professional
    const professionalMap = new Map();
    const serviceMap = new Map();

    result.rows.forEach(row => {
      // Professional data
      const profKey = row.professional_name;
      if (!professionalMap.has(profKey)) {
        professionalMap.set(profKey, {
          professional_name: row.professional_name,
          professional_percentage: row.professional_percentage,
          revenue: 0,
          consultation_count: 0,
          professional_payment: 0,
          clinic_revenue: 0
        });
      }
      
      const profData = professionalMap.get(profKey);
      profData.revenue += parseFloat(row.revenue || 0);
      profData.consultation_count += parseInt(row.consultation_count || 0);
      profData.professional_payment += parseFloat(row.professional_payment || 0);
      profData.clinic_revenue += parseFloat(row.clinic_revenue || 0);

      // Service data
      if (row.service_name) {
        const serviceKey = row.service_name;
        if (!serviceMap.has(serviceKey)) {
          serviceMap.set(serviceKey, {
            service_name: row.service_name,
            revenue: 0,
            consultation_count: 0
          });
        }
        
        const serviceData = serviceMap.get(serviceKey);
        serviceData.revenue += parseFloat(row.revenue || 0);
        serviceData.consultation_count += parseInt(row.consultation_count || 0);
      }
    });

    res.json({
      total_revenue: totalRevenue,
      revenue_by_professional: Array.from(professionalMap.values()),
      revenue_by_service: Array.from(serviceMap.values())
    });
  } catch (error) {
    console.error('Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Image upload route
app.post('/api/upload-image', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Starting image upload process...');
    
    // Create upload middleware
    const upload = createUpload();
    
    // Use multer middleware
    upload.single('image')(req, res, async (err) => {
      if (err) {
        console.error('❌ Multer error:', err);
        return res.status(400).json({ 
          message: err.message || 'Erro no upload da imagem' 
        });
      }

      if (!req.file) {
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      console.log('✅ Image uploaded to Cloudinary:', req.file.path);

      try {
        // Update user's photo_url in database
        await pool.query(
          'UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
          [req.file.path, req.user.id]
        );

        console.log('✅ User photo_url updated in database');

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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create professional payment
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor inválido' });
    }

    const preference = new Preference(client);

    const preferenceData = {
      items: [
        {
          title: 'Repasse ao Convênio Quiro Ferreira',
          description: 'Pagamento referente às consultas realizadas',
          quantity: 1,
          unit_price: parseFloat(amount),
          currency_id: 'BRL',
        }
      ],
      payer: {
        name: req.user.name,
        email: req.user.email || `professional${req.user.id}@quiroferreira.com.br`,
      },
      back_urls: {
        success: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional?payment=success`,
        failure: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional?payment=failure`,
        pending: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional?payment=pending`,
      },
      auto_return: 'approved',
      external_reference: `professional_payment_${req.user.id}_${Date.now()}`,
      statement_descriptor: 'QUIRO FERREIRA',
    };

    const result = await preference.create({ body: preferenceData });

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point,
    });
  } catch (error) {
    console.error('Error creating professional payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
  }
});

// Create subscription payment
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { user_id, dependent_ids } = req.body;

    if (req.user.id !== user_id) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    // Get dependents count
    const dependentsResult = await pool.query(
      'SELECT COUNT(*) FROM dependents WHERE client_id = $1',
      [user_id]
    );

    const dependentCount = parseInt(dependentsResult.rows[0].count);
    const totalAmount = 250 + (dependentCount * 50); // R$250 + R$50 per dependent

    const preference = new Preference(client);

    const items = [
      {
        title: 'Assinatura Convênio Quiro Ferreira - Titular',
        description: 'Assinatura mensal do titular',
        quantity: 1,
        unit_price: 250,
        currency_id: 'BRL',
      }
    ];

    if (dependentCount > 0) {
      items.push({
        title: 'Assinatura Convênio Quiro Ferreira - Dependentes',
        description: `Assinatura mensal para ${dependentCount} dependente(s)`,
        quantity: dependentCount,
        unit_price: 50,
        currency_id: 'BRL',
      });
    }

    const preferenceData = {
      items,
      payer: {
        name: req.user.name,
        email: req.user.email || `client${req.user.id}@quiroferreira.com.br`,
      },
      back_urls: {
        success: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client?payment=success`,
        failure: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client?payment=failure`,
        pending: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client?payment=pending`,
      },
      auto_return: 'approved',
      external_reference: `subscription_${user_id}_${Date.now()}`,
      statement_descriptor: 'QUIRO FERREIRA',
    };

    const result = await preference.create({ body: preferenceData });

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point,
      total_amount: totalAmount
    });
  } catch (error) {
    console.error('Error creating subscription:', error);
    res.status(500).json({ message: 'Erro ao criar assinatura' });
  }
});

// Catch-all route for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Frontend: http://localhost:${PORT}`);
  console.log(`🔧 API: http://localhost:${PORT}/api`);
  
  // Create test professional after server starts
  setTimeout(createTestProfessional, 2000);
});
// Function to create test professional with complete schedule
async function createTestProfessional() {
  try {
    console.log('🧪 Creating test professional with schedule...');
    
    // Check if test professional already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      ['12345678901']
    );
    
    if (existingUser.rows.length > 0) {
      console.log('✅ Test professional already exists');
      return;
    }
    
    // Hash password
    const bcrypt = await import('bcryptjs');
    const hashedPassword = await bcrypt.hash('123456', 10);
    
    // 1. Create category
    const categoryResult = await pool.query(
      `INSERT INTO service_categories (name, description) 
       VALUES ('Fisioterapia', 'Serviços de fisioterapia e reabilitação')
       ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`
    );
    const categoryId = categoryResult.rows[0].id;
    
    // 2. Create service
    const serviceResult = await pool.query(
      `INSERT INTO services (name, description, base_price, category_id, is_base_service)
       VALUES ('Consulta Fisioterapêutica', 'Consulta completa de fisioterapia', 150.00, $1, true)
       ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`,
      [categoryId]
    );
    const serviceId = serviceResult.rows[0].id;
    
    // 3. Create professional user
    const userResult = await pool.query(
      `INSERT INTO users (name, cpf, email, phone, password, roles, percentage, category_id, subscription_status, subscription_expiry)
       VALUES ('Dr. João Silva (TESTE)', '12345678901', 'joao.teste@quiroferreira.com', '64981249199', $1, $2, 70, $3, 'active', '2025-12-31')
       RETURNING id`,
      [hashedPassword, JSON.stringify(['professional']), categoryId]
    );
    const professionalId = userResult.rows[0].id;
    
    // 4. Create scheduling subscription
    const expiresAt = new Date('2025-12-31');
    await pool.query(
      `INSERT INTO professional_scheduling_subscriptions (professional_id, status, expires_at)
       VALUES ($1, 'active', $2)
       ON CONFLICT (professional_id) DO UPDATE SET status = 'active', expires_at = $2`,
      [professionalId, expiresAt]
    );
    
    // 5. Create schedule settings
    await pool.query(
      `INSERT INTO professional_schedule_settings 
       (professional_id, work_days, work_start_time, work_end_time, break_start_time, break_end_time, consultation_duration, has_scheduling_subscription)
       VALUES ($1, $2, '08:00', '18:00', '12:00', '13:00', 60, true)
       ON CONFLICT (professional_id) DO UPDATE SET has_scheduling_subscription = true`,
      [professionalId, JSON.stringify([1, 2, 3, 4, 5])]
    );
    
    // 6. Create attendance location
    const locationResult = await pool.query(
      `INSERT INTO attendance_locations 
       (professional_id, name, address, address_number, neighborhood, city, state, phone, is_default)
       VALUES ($1, 'Clínica Principal', 'Rua das Flores', '123', 'Centro', 'Goiânia', 'GO', '64981249199', true)
       RETURNING id`,
      [professionalId]
    );
    const locationId = locationResult.rows[0].id;
    
    // 7. Create private patients
    const patient1Result = await pool.query(
      `INSERT INTO private_patients 
       (professional_id, name, cpf, email, phone, birth_date, address, city, state)
       VALUES ($1, 'Maria Santos', '11111111111', 'maria@email.com', '64999999999', '1985-05-15', 'Rua A, 100', 'Goiânia', 'GO')
       RETURNING id`,
      [professionalId]
    );
    const patient1Id = patient1Result.rows[0].id;
    
    const patient2Result = await pool.query(
      `INSERT INTO private_patients 
       (professional_id, name, cpf, email, phone, birth_date, address, city, state)
       VALUES ($1, 'Carlos Oliveira', '22222222222', 'carlos@email.com', '64888888888', '1978-12-03', 'Rua B, 200', 'Goiânia', 'GO')
       RETURNING id`,
      [professionalId]
    );
    const patient2Id = patient2Result.rows[0].id;
    
    // 8. Create appointments (next 3 days)
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    const dayAfter = new Date();
    dayAfter.setDate(dayAfter.getDate() + 2);
    
    const dayAfter2 = new Date();
    dayAfter2.setDate(dayAfter2.getDate() + 3);
    
    await pool.query(
      `INSERT INTO appointments 
       (professional_id, private_patient_id, service_id, appointment_date, appointment_time, location_id, value, status, notes)
       VALUES 
       ($1, $2, $3, $4, '09:00', $5, 150.00, 'scheduled', 'Primeira consulta - avaliação inicial'),
       ($1, $6, $3, $7, '14:30', $5, 150.00, 'scheduled', 'Consulta de retorno'),
       ($1, $2, $3, $8, '10:15', $5, 150.00, 'scheduled', 'Segunda sessão de tratamento')`,
      [professionalId, patient1Id, serviceId, tomorrow.toISOString().split('T')[0], locationId, 
       patient2Id, dayAfter.toISOString().split('T')[0], dayAfter2.toISOString().split('T')[0]]
    );
    
    // 9. Create medical records
    await pool.query(
      `INSERT INTO medical_records 
       (professional_id, private_patient_id, chief_complaint, history_present_illness, 
        physical_examination, diagnosis, treatment_plan, vital_signs)
       VALUES 
       ($1, $2, 'Dor lombar há 2 semanas', 'Paciente relata dor lombar após esforço físico', 
        'Tensão muscular em região lombar, amplitude de movimento reduzida', 
        'Lombalgia mecânica', 'Fisioterapia 3x/semana, exercícios de fortalecimento', 
        $3),
       ($1, $4, 'Dor no ombro direito', 'Dor no ombro há 1 mês, piora com movimento', 
        'Limitação de movimento, dor à palpação', 'Tendinite do manguito rotador', 
        'Fisioterapia, anti-inflamatórios, repouso relativo', $5)`,
      [professionalId, patient1Id, 
       JSON.stringify({blood_pressure: '120/80', heart_rate: '72', temperature: '36.5'}),
       patient2Id,
       JSON.stringify({blood_pressure: '130/85', heart_rate: '78', temperature: '36.8'})]
    );
    
    console.log('✅ Test professional created successfully!');
    console.log('📋 Login credentials:');
    console.log('   CPF: 123.456.789-01');
    console.log('   Password: 123456');
    console.log('📅 Schedule: 3 appointments created');
    console.log('👥 Patients: 2 private patients created');
    console.log('📋 Medical records: 2 records created');
    
  } catch (error) {
    console.error('❌ Error creating test professional:', error);
  }
}