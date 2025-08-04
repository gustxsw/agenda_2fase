import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
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

    // Admin scheduling access table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_scheduling_access (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        granted_by INTEGER REFERENCES users(id),
        granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        is_active BOOLEAN DEFAULT true,
        notes TEXT
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
    const isValidPassword = await bcrypt.compare(password, user.password_hash);

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

    const hashedPassword = await bcrypt.hash(password, 10);

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

// 🔥 ADMIN SCHEDULING ACCESS ROUTES

// Grant scheduling access to professional (admin only)
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, notes } = req.body;

    // Check if professional exists
    const professionalResult = await pool.query(
      'SELECT id, name FROM users WHERE id = $1 AND $2 = ANY(roles)',
      [professional_id, 'professional']
    );

    if (professionalResult.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    // Grant or update access
    await pool.query(
      `INSERT INTO admin_scheduling_access 
       (professional_id, granted_by, expires_at, notes)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (professional_id) 
       DO UPDATE SET 
         granted_by = $2,
         expires_at = $3,
         notes = $4,
         is_active = true,
         granted_at = CURRENT_TIMESTAMP`,
      [professional_id, req.user.id, expires_at, notes]
    );

    // Update professional schedule settings to enable scheduling
    await pool.query(
      `INSERT INTO professional_schedule_settings (professional_id, has_scheduling_subscription)
       VALUES ($1, true)
       ON CONFLICT (professional_id) 
       DO UPDATE SET has_scheduling_subscription = true`,
      [professional_id]
    );

    res.json({ message: 'Acesso ao sistema de agendamentos concedido com sucesso' });
  } catch (error) {
    console.error('Error granting scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Revoke scheduling access from professional (admin only)
app.post('/api/admin/revoke-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id } = req.body;

    // Revoke access
    await pool.query(
      `UPDATE admin_scheduling_access 
       SET is_active = false 
       WHERE professional_id = $1`,
      [professional_id]
    );

    // Check if professional has paid subscription
    const subscriptionResult = await pool.query(
      `SELECT * FROM professional_scheduling_subscriptions 
       WHERE professional_id = $1 AND status = 'active' AND expires_at > NOW()`,
      [professional_id]
    );

    // If no paid subscription, disable scheduling
    if (subscriptionResult.rows.length === 0) {
      await pool.query(
        `UPDATE professional_schedule_settings 
         SET has_scheduling_subscription = false 
         WHERE professional_id = $1`,
        [professional_id]
      );
    }

    res.json({ message: 'Acesso ao sistema de agendamentos revogado com sucesso' });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Get all professionals with scheduling access status (admin only)
app.get('/api/admin/scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.phone,
              asa.is_active as admin_access_active,
              asa.expires_at as admin_access_expires,
              asa.notes as admin_access_notes,
              asa.granted_at as admin_access_granted_at,
              pss.status as subscription_status,
              pss.expires_at as subscription_expires,
              pss.has_scheduling_subscription
       FROM users u
       LEFT JOIN admin_scheduling_access asa ON u.id = asa.professional_id
       LEFT JOIN professional_scheduling_subscriptions pss ON u.id = pss.professional_id
       WHERE 'professional' = ANY(u.roles)
       ORDER BY u.name`,
      []
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching scheduling access data:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Check if professional has scheduling access (for middleware)
app.get('/api/check-scheduling-access', authenticate, authorize(['professional']), async (req, res) => {
  try {
    // Check paid subscription
    const subscriptionResult = await pool.query(
      `SELECT * FROM professional_scheduling_subscriptions 
       WHERE professional_id = $1 AND status = 'active' AND expires_at > NOW()`,
      [req.user.id]
    );

    // Check admin granted access
    const adminAccessResult = await pool.query(
      `SELECT * FROM admin_scheduling_access 
       WHERE professional_id = $1 AND is_active = true 
       AND (expires_at IS NULL OR expires_at > NOW())`,
      [req.user.id]
    );

    const hasPaidSubscription = subscriptionResult.rows.length > 0;
    const hasAdminAccess = adminAccessResult.rows.length > 0;
    const hasAccess = hasPaidSubscription || hasAdminAccess;

    res.json({
      has_access: hasAccess,
      access_type: hasPaidSubscription ? 'subscription' : (hasAdminAccess ? 'admin_granted' : 'none'),
      subscription_expires: subscriptionResult.rows[0]?.expires_at || null,
      admin_access_expires: adminAccessResult.rows[0]?.expires_at || null
    });
  } catch (error) {
    console.error('Error checking scheduling access:', error);
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