import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import createUpload from './middleware/upload.js';
import { generateDocumentPDF } from './utils/documentGenerator.js';
import { MercadoPagoConfig, Preference, Payment } from 'mercadopago';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

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
app.use(express.static('dist'));

// Initialize MercadoPago with SDK v2.0.8
const client = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN,
  options: { timeout: 5000 }
});

// Get base URL for back_urls
const getBaseUrl = () => {
  if (process.env.NODE_ENV === 'production') {
    return 'https://www.cartaoquiroferreira.com.br';
  }
  return 'http://localhost:5173';
};

// Initialize database tables
const initializeTables = async () => {
  try {
    console.log('🔄 Initializing database tables...');

    // Add columns to dependents table if they don't exist
    await pool.query(`
      DO $$
      BEGIN
        -- Add subscription_status column
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'dependents' AND column_name = 'subscription_status'
        ) THEN
          ALTER TABLE dependents ADD COLUMN subscription_status VARCHAR(20) DEFAULT 'pending';
        END IF;

        -- Add subscription_expiry column
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'dependents' AND column_name = 'subscription_expiry'
        ) THEN
          ALTER TABLE dependents ADD COLUMN subscription_expiry TIMESTAMP NULL;
        END IF;

        -- Add billing_amount column
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'dependents' AND column_name = 'billing_amount'
        ) THEN
          ALTER TABLE dependents ADD COLUMN billing_amount DECIMAL(10,2) DEFAULT 50.00;
        END IF;

        -- Add payment_reference column
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'dependents' AND column_name = 'payment_reference'
        ) THEN
          ALTER TABLE dependents ADD COLUMN payment_reference VARCHAR(255) NULL;
        END IF;

        -- Add activated_at column
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'dependents' AND column_name = 'activated_at'
        ) THEN
          ALTER TABLE dependents ADD COLUMN activated_at TIMESTAMP NULL;
        END IF;
      END $$;
    `);

    // Create dependent_payments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dependent_payments (
        id SERIAL PRIMARY KEY,
        dependent_id INTEGER REFERENCES dependents(id) ON DELETE CASCADE,
        payment_id VARCHAR(255) UNIQUE NOT NULL,
        preference_id VARCHAR(255) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        payment_method VARCHAR(100),
        payment_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create agenda_payments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS agenda_payments (
        id SERIAL PRIMARY KEY,
        appointment_id INTEGER NOT NULL,
        payment_id VARCHAR(255) UNIQUE NOT NULL,
        preference_id VARCHAR(255) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        payment_method VARCHAR(100),
        payment_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('✅ Database tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database tables:', error);
  }
};

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

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles || []
    };

    res.json({ user: userData });
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

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles,
      currentRole: role
    };

    res.json({ user: userData, token });
  } catch (error) {
    console.error('Role selection error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/switch-role', authenticate, async (req, res) => {
  try {
    const { role } = req.body;
    const userId = req.user.id;

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

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles,
      currentRole: role
    };

    res.json({ user: userData, token });
  } catch (error) {
    console.error('Role switch error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
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

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(`
      INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id, name, cpf, roles
    `, [
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, hashedPassword, ['client']
    ]);

    const user = result.rows[0];
    res.status(201).json({ user });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// Client subscription payment
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { user_id } = req.body;
    const baseUrl = getBaseUrl();

    console.log('🔄 Creating client subscription payment for user:', user_id);

    const preference = new Preference(client);

    const preferenceData = {
      items: [
        {
          title: 'Assinatura Convênio Quiro Ferreira - Titular',
          description: 'Assinatura mensal do titular do convênio',
          quantity: 1,
          unit_price: 250.00,
          currency_id: 'BRL'
        }
      ],
      payer: {
        email: 'cliente@quiroferreira.com.br'
      },
      back_urls: {
        success: `${baseUrl}/client?payment=success`,
        failure: `${baseUrl}/client?payment=failure`,
        pending: `${baseUrl}/client?payment=pending`
      },
      auto_return: 'approved',
      external_reference: `client_${user_id}_${Date.now()}`,
      notification_url: `${process.env.NODE_ENV === 'production' ? 'https://www.cartaoquiroferreira.com.br' : 'http://localhost:3001'}/api/webhook/mercadopago`
    };

    const response = await preference.create({ body: preferenceData });
    console.log('✅ Client preference created:', response.id);

    // Store payment record
    await pool.query(`
      INSERT INTO client_payments (user_id, payment_id, preference_id, amount, status)
      VALUES ($1, $2, $3, $4, $5)
    `, [user_id, response.id, response.id, 250.00, 'pending']);

    res.json({
      preference_id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point
    });
  } catch (error) {
    console.error('❌ Error creating client subscription:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
  }
});

// Professional payment
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;
    const professionalId = req.user.id;
    const baseUrl = getBaseUrl();

    console.log('🔄 Creating professional payment for amount:', amount);

    const preference = new Preference(client);

    const preferenceData = {
      items: [
        {
          title: 'Repasse ao Convênio Quiro Ferreira',
          description: 'Valor a ser repassado ao convênio referente às consultas realizadas',
          quantity: 1,
          unit_price: parseFloat(amount),
          currency_id: 'BRL'
        }
      ],
      payer: {
        email: 'profissional@quiroferreira.com.br'
      },
      back_urls: {
        success: `${baseUrl}/professional?payment=success`,
        failure: `${baseUrl}/professional?payment=failure`,
        pending: `${baseUrl}/professional?payment=pending`
      },
      auto_return: 'approved',
      external_reference: `professional_${professionalId}_${Date.now()}`,
      notification_url: `${process.env.NODE_ENV === 'production' ? 'https://www.cartaoquiroferreira.com.br' : 'http://localhost:3001'}/api/webhook/mercadopago`
    };

    const response = await preference.create({ body: preferenceData });
    console.log('✅ Professional preference created:', response.id);

    // Store payment record
    await pool.query(`
      INSERT INTO professional_payments (professional_id, payment_id, preference_id, amount, status)
      VALUES ($1, $2, $3, $4, $5)
    `, [professionalId, response.id, response.id, parseFloat(amount), 'pending']);

    res.json({
      preference_id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point
    });
  } catch (error) {
    console.error('❌ Error creating professional payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
  }
});

// Dependent payment
app.post('/api/dependents/:id/create-payment', authenticate, authorize(['client']), async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);
    const baseUrl = getBaseUrl();

    console.log('🔄 Creating dependent payment for dependent:', dependentId);

    // Verify dependent belongs to client
    const dependentResult = await pool.query(
      'SELECT id, name, client_id FROM dependents WHERE id = $1 AND client_id = $2',
      [dependentId, req.user.id]
    );

    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    const dependent = dependentResult.rows[0];

    const preference = new Preference(client);

    const preferenceData = {
      items: [
        {
          title: `Ativação de Dependente - ${dependent.name}`,
          description: 'Ativação individual de dependente no Convênio Quiro Ferreira',
          quantity: 1,
          unit_price: 50.00,
          currency_id: 'BRL'
        }
      ],
      payer: {
        email: 'cliente@quiroferreira.com.br'
      },
      back_urls: {
        success: `${baseUrl}/client?payment=success&type=dependent`,
        failure: `${baseUrl}/client?payment=failure&type=dependent`,
        pending: `${baseUrl}/client?payment=pending&type=dependent`
      },
      auto_return: 'approved',
      external_reference: `dependent_${dependentId}_${Date.now()}`,
      notification_url: `${process.env.NODE_ENV === 'production' ? 'https://www.cartaoquiroferreira.com.br' : 'http://localhost:3001'}/api/webhook/mercadopago`
    };

    const response = await preference.create({ body: preferenceData });
    console.log('✅ Dependent preference created:', response.id);

    // Store payment record
    await pool.query(`
      INSERT INTO dependent_payments (dependent_id, payment_id, preference_id, amount, status)
      VALUES ($1, $2, $3, $4, $5)
    `, [dependentId, response.id, response.id, 50.00, 'pending']);

    res.json({
      preference_id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point
    });
  } catch (error) {
    console.error('❌ Error creating dependent payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento do dependente' });
  }
});

// Agenda payment
app.post('/api/agenda/:id/create-payment', authenticate, async (req, res) => {
  try {
    const appointmentId = parseInt(req.params.id);
    const baseUrl = getBaseUrl();

    console.log('🔄 Creating agenda payment for appointment:', appointmentId);

    // Get appointment details
    const appointmentResult = await pool.query(`
      SELECT c.id, c.value, c.client_name, s.name as service_name
      FROM consultations c
      LEFT JOIN services s ON c.service_id = s.id
      WHERE c.id = $1
    `, [appointmentId]);

    if (appointmentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Consulta não encontrada' });
    }

    const appointment = appointmentResult.rows[0];

    const preference = new Preference(client);

    const preferenceData = {
      items: [
        {
          title: `Consulta - ${appointment.service_name}`,
          description: `Pagamento da consulta para ${appointment.client_name}`,
          quantity: 1,
          unit_price: parseFloat(appointment.value),
          currency_id: 'BRL'
        }
      ],
      payer: {
        email: 'cliente@quiroferreira.com.br'
      },
      back_urls: {
        success: `${baseUrl}/client?payment=success&type=agenda`,
        failure: `${baseUrl}/client?payment=failure&type=agenda`,
        pending: `${baseUrl}/client?payment=pending&type=agenda`
      },
      auto_return: 'approved',
      external_reference: `agenda_${appointmentId}_${Date.now()}`,
      notification_url: `${process.env.NODE_ENV === 'production' ? 'https://www.cartaoquiroferreira.com.br' : 'http://localhost:3001'}/api/webhook/mercadopago`
    };

    const response = await preference.create({ body: preferenceData });
    console.log('✅ Agenda preference created:', response.id);

    // Store payment record
    await pool.query(`
      INSERT INTO agenda_payments (appointment_id, payment_id, preference_id, amount, status)
      VALUES ($1, $2, $3, $4, $5)
    `, [appointmentId, response.id, response.id, parseFloat(appointment.value), 'pending']);

    res.json({
      preference_id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point
    });
  } catch (error) {
    console.error('❌ Error creating agenda payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento da consulta' });
  }
});

// MercadoPago webhook
app.post('/api/webhook/mercadopago', async (req, res) => {
  try {
    console.log('🔔 Webhook received:', req.body);

    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      console.log('💳 Processing payment:', paymentId);

      const payment = new Payment(client);
      const paymentInfo = await payment.get({ id: paymentId });

      console.log('💳 Payment info:', paymentInfo);

      const externalReference = paymentInfo.external_reference;
      const status = paymentInfo.status;

      if (status === 'approved') {
        console.log('✅ Payment approved for:', externalReference);

        // Determine payment type from external_reference
        if (externalReference.startsWith('client_')) {
          // Client subscription payment
          const userId = externalReference.split('_')[1];
          
          await pool.query(`
            UPDATE users 
            SET subscription_status = 'active',
                subscription_expiry = CURRENT_DATE + INTERVAL '30 days'
            WHERE id = $1
          `, [userId]);

          await pool.query(`
            UPDATE client_payments 
            SET status = 'approved', payment_date = CURRENT_TIMESTAMP
            WHERE payment_id = $1
          `, [paymentInfo.id]);

          console.log('✅ Client subscription activated for user:', userId);

        } else if (externalReference.startsWith('dependent_')) {
          // Dependent payment
          const dependentId = externalReference.split('_')[1];
          
          await pool.query(`
            UPDATE dependents 
            SET subscription_status = 'active',
                subscription_expiry = CURRENT_DATE + INTERVAL '30 days',
                activated_at = CURRENT_TIMESTAMP
            WHERE id = $1
          `, [dependentId]);

          await pool.query(`
            UPDATE dependent_payments 
            SET status = 'approved', payment_date = CURRENT_TIMESTAMP
            WHERE payment_id = $1
          `, [paymentInfo.id]);

          console.log('✅ Dependent activated:', dependentId);

        } else if (externalReference.startsWith('agenda_')) {
          // Agenda payment
          const appointmentId = externalReference.split('_')[1];
          
          await pool.query(`
            UPDATE consultations 
            SET status = 'confirmed'
            WHERE id = $1
          `, [appointmentId]);

          await pool.query(`
            UPDATE agenda_payments 
            SET status = 'approved', payment_date = CURRENT_TIMESTAMP
            WHERE payment_id = $1
          `, [paymentInfo.id]);

          console.log('✅ Agenda payment confirmed for appointment:', appointmentId);

        } else if (externalReference.startsWith('professional_')) {
          // Professional payment
          const professionalId = externalReference.split('_')[1];
          
          await pool.query(`
            UPDATE professional_payments 
            SET status = 'approved', payment_date = CURRENT_TIMESTAMP
            WHERE payment_id = $1
          `, [paymentInfo.id]);

          console.log('✅ Professional payment confirmed for:', professionalId);
        }
      } else if (status === 'rejected' || status === 'cancelled') {
        console.log('❌ Payment failed for:', externalReference);

        // Update payment status to failed
        if (externalReference.startsWith('client_')) {
          await pool.query(`
            UPDATE client_payments 
            SET status = 'failed'
            WHERE payment_id = $1
          `, [paymentInfo.id]);
        } else if (externalReference.startsWith('dependent_')) {
          await pool.query(`
            UPDATE dependent_payments 
            SET status = 'failed'
            WHERE payment_id = $1
          `, [paymentInfo.id]);
        } else if (externalReference.startsWith('agenda_')) {
          await pool.query(`
            UPDATE agenda_payments 
            SET status = 'failed'
            WHERE payment_id = $1
          `, [paymentInfo.id]);
        } else if (externalReference.startsWith('professional_')) {
          await pool.query(`
            UPDATE professional_payments 
            SET status = 'failed'
            WHERE payment_id = $1
          `, [paymentInfo.id]);
        }
      }
    }

    res.status(200).send('OK');
  } catch (error) {
    console.error('❌ Webhook error:', error);
    res.status(500).send('Error');
  }
});

// Get dependents with individual status
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const clientId = parseInt(req.params.clientId);

    const result = await pool.query(`
      SELECT 
        id, 
        name, 
        cpf, 
        birth_date, 
        created_at,
        subscription_status,
        subscription_expiry,
        billing_amount,
        payment_reference,
        activated_at,
        subscription_status as current_status
      FROM dependents 
      WHERE client_id = $1 
      ORDER BY created_at DESC
    `, [clientId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro ao carregar dependentes' });
  }
});

// Create dependent
app.post('/api/dependents', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    if (!name || !cpf) {
      return res.status(400).json({ message: 'Nome e CPF são obrigatórios' });
    }

    // Check if CPF already exists
    const existingDependent = await pool.query(
      'SELECT id FROM dependents WHERE cpf = $1',
      [cpf]
    );

    if (existingDependent.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado como dependente' });
    }

    const result = await pool.query(`
      INSERT INTO dependents (
        client_id, name, cpf, birth_date, subscription_status, billing_amount
      ) VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [client_id, name, cpf, birth_date, 'pending', 50.00]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating dependent:', error);
    res.status(500).json({ message: 'Erro ao criar dependente' });
  }
});

// Update dependent
app.put('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);
    const { name, birth_date } = req.body;

    const result = await pool.query(`
      UPDATE dependents 
      SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP
      WHERE id = $3 AND client_id = $4
      RETURNING *
    `, [name, birth_date, dependentId, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro ao atualizar dependente' });
  }
});

// Delete dependent
app.delete('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);

    const result = await pool.query(
      'DELETE FROM dependents WHERE id = $1 AND client_id = $2 RETURNING id',
      [dependentId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro ao excluir dependente' });
  }
});

// Lookup dependent by CPF (for consultations)
app.get('/api/dependents/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const result = await pool.query(`
      SELECT 
        d.id,
        d.name,
        d.cpf,
        d.client_id,
        d.subscription_status as dependent_subscription_status,
        u.name as client_name,
        u.subscription_status as client_subscription_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.cpf = $1
    `, [cpf]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error looking up dependent:', error);
    res.status(500).json({ message: 'Erro ao buscar dependente' });
  }
});

// Admin: Get all dependents
app.get('/api/admin/dependents', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        d.id,
        d.client_id,
        d.name,
        d.cpf,
        d.birth_date,
        d.subscription_status,
        d.subscription_expiry,
        d.billing_amount,
        d.activated_at,
        d.created_at,
        u.name as client_name,
        u.subscription_status as client_status,
        d.subscription_status as current_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      ORDER BY d.created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching all dependents:', error);
    res.status(500).json({ message: 'Erro ao carregar dependentes' });
  }
});

// Admin: Activate dependent manually
app.post('/api/admin/dependents/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);

    const result = await pool.query(`
      UPDATE dependents 
      SET subscription_status = 'active',
          subscription_expiry = CURRENT_DATE + INTERVAL '30 days',
          activated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING *
    `, [dependentId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json({ message: 'Dependente ativado com sucesso', dependent: result.rows[0] });
  } catch (error) {
    console.error('Error activating dependent:', error);
    res.status(500).json({ message: 'Erro ao ativar dependente' });
  }
});

// Users routes
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, roles, 
        subscription_status, subscription_expiry, created_at
      FROM users 
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro ao carregar usuários' });
  }
});

app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    
    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, roles, 
        subscription_status, subscription_expiry, created_at,
        photo_url, category_name, crm
      FROM users 
      WHERE id = $1
    `, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Erro ao carregar usuário' });
  }
});

app.post('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, cpf, email, phone, password, roles } = req.body;

    if (!name || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Nome, senha e pelo menos uma role são obrigatórios' });
    }

    if (cpf) {
      const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cpf]);
      if (existingUser.rows.length > 0) {
        return res.status(400).json({ message: 'CPF já cadastrado' });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(`
      INSERT INTO users (name, cpf, email, phone, password_hash, roles)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, name, cpf, email, phone, roles, subscription_status, created_at
    `, [name, cpf, email, phone, hashedPassword, roles]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Erro ao criar usuário' });
  }
});

app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { name, email, phone, roles, currentPassword, newPassword } = req.body;

    // Check if user can edit this profile
    if (req.user.id !== userId && !req.user.roles.includes('admin')) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    let updateQuery = `
      UPDATE users 
      SET name = $1, email = $2, phone = $3, updated_at = CURRENT_TIMESTAMP
    `;
    let queryParams = [name, email, phone];
    let paramCount = 3;

    // Update roles only if user is admin
    if (req.user.roles.includes('admin') && roles) {
      updateQuery += `, roles = $${++paramCount}`;
      queryParams.push(roles);
    }

    // Handle password change
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Senha atual é obrigatória para alterar a senha' });
      }

      // Verify current password
      const userResult = await pool.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
      if (userResult.rows.length === 0) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
      }

      const isValidPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
      if (!isValidPassword) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      updateQuery += `, password_hash = $${++paramCount}`;
      queryParams.push(hashedNewPassword);
    }

    updateQuery += ` WHERE id = $${++paramCount} RETURNING id, name, email, phone, roles`;
    queryParams.push(userId);

    const result = await pool.query(updateQuery, queryParams);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Erro ao atualizar usuário' });
  }
});

app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    const result = await pool.query(
      'DELETE FROM users WHERE id = $1 RETURNING id',
      [userId]
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

// Professionals routes
app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, email, phone, roles, address, address_number,
        address_complement, neighborhood, city, state, category_name, photo_url
      FROM users 
      WHERE roles @> '["professional"]'
      ORDER BY name
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro ao carregar profissionais' });
  }
});

// Clients routes
app.get('/api/clients/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const result = await pool.query(`
      SELECT id, name, cpf, subscription_status
      FROM users 
      WHERE cpf = $1 AND roles @> '["client"]'
    `, [cpf]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error looking up client:', error);
    res.status(500).json({ message: 'Erro ao buscar cliente' });
  }
});

// Services routes
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        s.id, s.name, s.description, s.base_price, s.category_id, s.is_base_service,
        sc.name as category_name
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

app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `, [name, description, base_price, category_id, is_base_service]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating service:', error);
    res.status(500).json({ message: 'Erro ao criar serviço' });
  }
});

app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const serviceId = parseInt(req.params.id);
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(`
      UPDATE services 
      SET name = $1, description = $2, base_price = $3, category_id = $4, is_base_service = $5
      WHERE id = $6
      RETURNING *
    `, [name, description, base_price, category_id, is_base_service, serviceId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating service:', error);
    res.status(500).json({ message: 'Erro ao atualizar serviço' });
  }
});

app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const serviceId = parseInt(req.params.id);

    const result = await pool.query(
      'DELETE FROM services WHERE id = $1 RETURNING id',
      [serviceId]
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

app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    const result = await pool.query(`
      INSERT INTO service_categories (name, description)
      VALUES ($1, $2)
      RETURNING *
    `, [name, description]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating service category:', error);
    res.status(500).json({ message: 'Erro ao criar categoria' });
  }
});

// Consultations routes
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id, c.date, c.value, c.notes, c.status,
        COALESCE(u.name, pp.name) as client_name,
        s.name as service_name,
        prof.name as professional_name,
        CASE WHEN c.dependent_id IS NOT NULL THEN true ELSE false END as is_dependent
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users prof ON c.professional_id = prof.id
    `;

    const params = [];

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

app.get('/api/consultations/client/:clientId', authenticate, async (req, res) => {
  try {
    const clientId = parseInt(req.params.clientId);

    const result = await pool.query(`
      SELECT 
        c.id, c.date, c.value, c.notes,
        COALESCE(u.name, d.name) as client_name,
        s.name as service_name,
        prof.name as professional_name,
        CASE WHEN c.dependent_id IS NOT NULL THEN true ELSE false END as is_dependent
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users prof ON c.professional_id = prof.id
      WHERE c.client_id = $1 OR c.dependent_id IN (
        SELECT id FROM dependents WHERE client_id = $1
      )
      ORDER BY c.date DESC
    `, [clientId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching client consultations:', error);
    res.status(500).json({ message: 'Erro ao carregar consultas do cliente' });
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
      notes,
      status = 'completed'
    } = req.body;

    const result = await pool.query(`
      INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id,
        service_id, location_id, value, date, notes, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *
    `, [
      client_id, dependent_id, private_patient_id, req.user.id,
      service_id, location_id, value, date, notes, status
    ]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro ao criar consulta' });
  }
});

app.put('/api/consultations/:id/status', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const consultationId = parseInt(req.params.id);
    const { status } = req.body;

    const result = await pool.query(`
      UPDATE consultations 
      SET status = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2 AND professional_id = $3
      RETURNING *
    `, [status, consultationId, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Consulta não encontrada' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating consultation status:', error);
    res.status(500).json({ message: 'Erro ao atualizar status da consulta' });
  }
});

// Private patients routes
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM private_patients 
      WHERE professional_id = $1 
      ORDER BY created_at DESC
    `, [req.user.id]);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching private patients:', error);
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

    if (cpf) {
      const existingPatient = await pool.query(
        'SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2',
        [cpf, req.user.id]
      );
      if (existingPatient.rows.length > 0) {
        return res.status(400).json({ message: 'CPF já cadastrado' });
      }
    }

    const result = await pool.query(`
      INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING *
    `, [
      req.user.id, name, cpf, email, phone, birth_date, address,
      address_number, address_complement, neighborhood, city, state, zip_code
    ]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating private patient:', error);
    res.status(500).json({ message: 'Erro ao criar paciente' });
  }
});

app.put('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const patientId = parseInt(req.params.id);
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    const result = await pool.query(`
      UPDATE private_patients 
      SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
          address_number = $6, address_complement = $7, neighborhood = $8,
          city = $9, state = $10, zip_code = $11, updated_at = CURRENT_TIMESTAMP
      WHERE id = $12 AND professional_id = $13
      RETURNING *
    `, [
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code, patientId, req.user.id
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating private patient:', error);
    res.status(500).json({ message: 'Erro ao atualizar paciente' });
  }
});

app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const patientId = parseInt(req.params.id);

    const result = await pool.query(
      'DELETE FROM private_patients WHERE id = $1 AND professional_id = $2 RETURNING id',
      [patientId, req.user.id]
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

// Medical records routes
app.get('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        mr.*,
        pp.name as patient_name
      FROM medical_records mr
      JOIN private_patients pp ON mr.private_patient_id = pp.id
      WHERE pp.professional_id = $1
      ORDER BY mr.created_at DESC
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro ao carregar prontuários' });
  }
});

app.post('/api/medical-records', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id, chief_complaint, history_present_illness,
      past_medical_history, medications, allergies, physical_examination,
      diagnosis, treatment_plan, notes, vital_signs
    } = req.body;

    const result = await pool.query(`
      INSERT INTO medical_records (
        private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, vital_signs
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING *
    `, [
      private_patient_id, chief_complaint, history_present_illness,
      past_medical_history, medications, allergies, physical_examination,
      diagnosis, treatment_plan, notes, JSON.stringify(vital_signs)
    ]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating medical record:', error);
    res.status(500).json({ message: 'Erro ao criar prontuário' });
  }
});

app.put('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const recordId = parseInt(req.params.id);
    const {
      chief_complaint, history_present_illness, past_medical_history,
      medications, allergies, physical_examination, diagnosis,
      treatment_plan, notes, vital_signs
    } = req.body;

    const result = await pool.query(`
      UPDATE medical_records 
      SET chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
          medications = $4, allergies = $5, physical_examination = $6,
          diagnosis = $7, treatment_plan = $8, notes = $9, vital_signs = $10,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $11
      RETURNING *
    `, [
      chief_complaint, history_present_illness, past_medical_history,
      medications, allergies, physical_examination, diagnosis,
      treatment_plan, notes, JSON.stringify(vital_signs), recordId
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating medical record:', error);
    res.status(500).json({ message: 'Erro ao atualizar prontuário' });
  }
});

app.delete('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const recordId = parseInt(req.params.id);

    const result = await pool.query(
      'DELETE FROM medical_records WHERE id = $1 RETURNING id',
      [recordId]
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

// Medical records document generation
app.post('/api/medical-records/generate-document', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { record_id, template_data } = req.body;

    const documentResult = await generateDocumentPDF('medical_record', template_data);

    res.json({
      title: `Prontuário - ${template_data.patientName}`,
      documentUrl: documentResult.url
    });
  } catch (error) {
    console.error('Error generating medical record document:', error);
    res.status(500).json({ message: 'Erro ao gerar documento' });
  }
});

// Medical documents routes
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM medical_documents 
      WHERE professional_id = $1 
      ORDER BY created_at DESC
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro ao carregar documentos' });
  }
});

app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { title, document_type, private_patient_id, template_data } = req.body;

    const documentResult = await generateDocumentPDF(document_type, template_data);

    const result = await pool.query(`
      INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type,
        patient_name, document_url
      ) VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [
      req.user.id, private_patient_id, title, document_type,
      template_data.patientName, documentResult.url
    ]);

    res.status(201).json({
      document: result.rows[0],
      title,
      documentUrl: documentResult.url
    });
  } catch (error) {
    console.error('Error creating medical document:', error);
    res.status(500).json({ message: 'Erro ao criar documento' });
  }
});

// Attendance locations routes
app.get('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM attendance_locations 
      WHERE professional_id = $1 
      ORDER BY is_default DESC, name
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching attendance locations:', error);
    res.status(500).json({ message: 'Erro ao carregar locais' });
  }
});

app.post('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

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
      RETURNING *
    `, [
      req.user.id, name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    ]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating attendance location:', error);
    res.status(500).json({ message: 'Erro ao criar local' });
  }
});

app.put('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const locationId = parseInt(req.params.id);
    const {
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default
    } = req.body;

    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1',
        [req.user.id]
      );
    }

    const result = await pool.query(`
      UPDATE attendance_locations 
      SET name = $1, address = $2, address_number = $3, address_complement = $4,
          neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9,
          is_default = $10, updated_at = CURRENT_TIMESTAMP
      WHERE id = $11 AND professional_id = $12
      RETURNING *
    `, [
      name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default, locationId, req.user.id
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating attendance location:', error);
    res.status(500).json({ message: 'Erro ao atualizar local' });
  }
});

app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const locationId = parseInt(req.params.id);

    const result = await pool.query(
      'DELETE FROM attendance_locations WHERE id = $1 AND professional_id = $2 RETURNING id',
      [locationId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    res.json({ message: 'Local excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting attendance location:', error);
    res.status(500).json({ message: 'Erro ao excluir local' });
  }
});

// Reports routes
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    const result = await pool.query(`
      SELECT 
        SUM(c.value) as total_revenue,
        COUNT(*) as total_consultations
      FROM consultations c
      WHERE c.date BETWEEN $1 AND $2
    `, [start_date, end_date]);

    const revenueByProfessional = await pool.query(`
      SELECT 
        u.name as professional_name,
        COALESCE(u.professional_percentage, 50) as professional_percentage,
        SUM(c.value) as revenue,
        COUNT(*) as consultation_count,
        SUM(c.value * (COALESCE(u.professional_percentage, 50) / 100.0)) as professional_payment,
        SUM(c.value * ((100 - COALESCE(u.professional_percentage, 50)) / 100.0)) as clinic_revenue
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.date BETWEEN $1 AND $2
      GROUP BY u.id, u.name, u.professional_percentage
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    const revenueByService = await pool.query(`
      SELECT 
        s.name as service_name,
        SUM(c.value) as revenue,
        COUNT(*) as consultation_count
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      WHERE c.date BETWEEN $1 AND $2
      GROUP BY s.id, s.name
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    res.json({
      total_revenue: result.rows[0].total_revenue || 0,
      revenue_by_professional: revenueByProfessional.rows,
      revenue_by_service: revenueByService.rows
    });
  } catch (error) {
    console.error('Error fetching revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const professionalId = req.user.id;

    const summaryResult = await pool.query(`
      SELECT 
        COALESCE(u.professional_percentage, 50) as professional_percentage,
        SUM(c.value) as total_revenue,
        COUNT(*) as consultation_count,
        SUM(c.value * ((100 - COALESCE(u.professional_percentage, 50)) / 100.0)) as amount_to_pay,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        COUNT(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.professional_id = $1 AND c.date BETWEEN $2 AND $3
      GROUP BY u.professional_percentage
    `, [professionalId, start_date, end_date]);

    const consultationsResult = await pool.query(`
      SELECT 
        c.date,
        COALESCE(u.name, d.name, pp.name) as client_name,
        s.name as service_name,
        c.value as total_value,
        c.value * ((100 - COALESCE(prof.professional_percentage, 50)) / 100.0) as amount_to_pay
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users prof ON c.professional_id = prof.id
      WHERE c.professional_id = $1 AND c.date BETWEEN $2 AND $3
      ORDER BY c.date DESC
    `, [professionalId, start_date, end_date]);

    const summary = summaryResult.rows[0] || {
      professional_percentage: 50,
      total_revenue: 0,
      consultation_count: 0,
      amount_to_pay: 0,
      convenio_revenue: 0,
      private_revenue: 0,
      convenio_consultations: 0,
      private_consultations: 0
    };

    res.json({
      summary,
      consultations: consultationsResult.rows
    });
  } catch (error) {
    console.error('Error fetching professional revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

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
      WHERE roles @> '["client"]' AND city IS NOT NULL AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching clients by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

app.get('/api/reports/professionals-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        city,
        state,
        COUNT(*) as total_professionals,
        json_agg(
          json_build_object(
            'category_name', COALESCE(category_name, 'Sem categoria'),
            'count', 1
          )
        ) as categories
      FROM users 
      WHERE roles @> '["professional"]' AND city IS NOT NULL AND city != ''
      GROUP BY city, state
      ORDER BY total_professionals DESC
    `);

    const processedResult = result.rows.map(row => ({
      ...row,
      categories: row.categories.reduce((acc, cat) => {
        const existing = acc.find(c => c.category_name === cat.category_name);
        if (existing) {
          existing.count += cat.count;
        } else {
          acc.push(cat);
        }
        return acc;
      }, [])
    }));

    res.json(processedResult);
  } catch (error) {
    console.error('Error fetching professionals by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

// Image upload route
app.post('/api/upload-image', authenticate, async (req, res) => {
  try {
    const upload = createUpload();
    
    upload.single('image')(req, res, async (err) => {
      if (err) {
        console.error('Upload error:', err);
        return res.status(400).json({ message: err.message });
      }

      if (!req.file) {
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      const imageUrl = req.file.path;

      // Update user photo_url
      await pool.query(
        'UPDATE users SET photo_url = $1 WHERE id = $2',
        [imageUrl, req.user.id]
      );

      res.json({ imageUrl });
    });
  } catch (error) {
    console.error('Error uploading image:', error);
    res.status(500).json({ message: 'Erro ao fazer upload da imagem' });
  }
});

// Admin: Grant scheduling access
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    await pool.query(`
      UPDATE users 
      SET has_scheduling_access = true,
          access_expires_at = $1,
          access_granted_by = $2,
          access_granted_at = CURRENT_TIMESTAMP
      WHERE id = $3 AND roles @> '["professional"]'
    `, [expires_at, req.user.name, professional_id]);

    res.json({ message: 'Acesso concedido com sucesso' });
  } catch (error) {
    console.error('Error granting scheduling access:', error);
    res.status(500).json({ message: 'Erro ao conceder acesso' });
  }
});

app.post('/api/admin/revoke-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id } = req.body;

    await pool.query(`
      UPDATE users 
      SET has_scheduling_access = false,
          access_expires_at = NULL,
          access_granted_by = NULL,
          access_granted_at = NULL
      WHERE id = $1 AND roles @> '["professional"]'
    `, [professional_id]);

    res.json({ message: 'Acesso revogado com sucesso' });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro ao revogar acesso' });
  }
});

app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, email, phone, category_name,
        has_scheduling_access, access_expires_at, access_granted_by, access_granted_at
      FROM users 
      WHERE roles @> '["professional"]'
      ORDER BY name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals scheduling access:', error);
    res.status(500).json({ message: 'Erro ao carregar dados' });
  }
});

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'dist', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ message: 'Erro interno do servidor' });
});

// Initialize database and start server
const startServer = async () => {
  try {
    await initializeTables();
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`💳 MercadoPago configured: ${process.env.MP_ACCESS_TOKEN ? '✅' : '❌'}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();