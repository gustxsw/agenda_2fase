import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import createUpload from './middleware/upload.js';
import { generateDocumentPDF } from './utils/documentGenerator.js';
import { MercadoPagoConfig, Preference } from 'mercadopago';

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
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('dist'));

// Initialize MercadoPago SDK v2
const client = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN,
  options: {
    timeout: 5000,
    idempotencyKey: 'abc'
  }
});

// Get base URL for redirects
const getBaseUrl = () => {
  if (process.env.NODE_ENV === 'production') {
    return 'https://www.cartaoquiroferreira.com.br';
  }
  return 'http://localhost:5173';
};

// ==================== AUTH ROUTES ====================

// Login route
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
      message: 'Login realizado com sucesso',
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

// Select role route
app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;

    if (!userId || !role) {
      return res.status(400).json({ message: 'ID do usuário e role são obrigatórios' });
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
      message: 'Role selecionada com sucesso',
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

    if (!req.user.roles || !req.user.roles.includes(role)) {
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
      message: 'Role alterada com sucesso',
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

// Register route
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

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles,
        subscription_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW())
      RETURNING id, name, cpf, roles`,
      [
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, hashedPassword,
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

// Logout route
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// ==================== PAYMENT ROUTES ====================

// Create subscription payment for clients
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { user_id, dependent_ids = [] } = req.body;
    const baseUrl = getBaseUrl();

    console.log('🔄 Creating subscription payment for user:', user_id);

    // Get user data
    const userResult = await pool.query(
      'SELECT name, email FROM users WHERE id = $1',
      [user_id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = userResult.rows[0];

    // Calculate total amount (R$250 for titular + R$50 per dependent)
    const dependentCount = dependent_ids.length;
    const totalAmount = 250 + (dependentCount * 50);

    console.log('💰 Subscription payment details:', {
      user_id,
      dependentCount,
      totalAmount
    });

    // Create preference using SDK v2
    const preference = new Preference(client);

    const preferenceData = {
      items: [
        {
          id: `subscription_${user_id}`,
          title: `Assinatura Cartão Quiro Ferreira - ${user.name}`,
          description: `Assinatura mensal (Titular + ${dependentCount} dependente(s))`,
          quantity: 1,
          unit_price: totalAmount,
          currency_id: 'BRL'
        }
      ],
      payer: {
        name: user.name,
        email: user.email || `user${user_id}@cartaoquiroferreira.com.br`
      },
      back_urls: {
        success: `${baseUrl}/client?payment=success`,
        failure: `${baseUrl}/client?payment=failure`,
        pending: `${baseUrl}/client?payment=pending`
      },
      auto_return: 'approved',
      external_reference: `subscription_${user_id}_${Date.now()}`,
      notification_url: `${baseUrl}/api/webhooks/mercadopago`,
      metadata: {
        user_id: user_id.toString(),
        payment_type: 'subscription',
        dependent_count: dependentCount.toString()
      }
    };

    const result = await preference.create({ body: preferenceData });

    console.log('✅ Subscription preference created:', result.id);

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point
    });

  } catch (error) {
    console.error('❌ Error creating subscription payment:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento de assinatura',
      error: error.message 
    });
  }
});

// Create professional payment
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;
    const baseUrl = getBaseUrl();

    console.log('🔄 Creating professional payment:', {
      professional_id: req.user.id,
      amount
    });

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor inválido' });
    }

    // Get professional data
    const userResult = await pool.query(
      'SELECT name, email FROM users WHERE id = $1',
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professional = userResult.rows[0];

    console.log('💰 Professional payment details:', {
      professional_id: req.user.id,
      professional_name: professional.name,
      amount
    });

    // Create preference using SDK v2
    const preference = new Preference(client);

    const preferenceData = {
      items: [
        {
          id: `professional_payment_${req.user.id}`,
          title: `Repasse ao Convênio - ${professional.name}`,
          description: `Pagamento referente às consultas realizadas`,
          quantity: 1,
          unit_price: Number(amount),
          currency_id: 'BRL'
        }
      ],
      payer: {
        name: professional.name,
        email: professional.email || `professional${req.user.id}@cartaoquiroferreira.com.br`
      },
      back_urls: {
        success: `${baseUrl}/professional?payment=success`,
        failure: `${baseUrl}/professional?payment=failure`,
        pending: `${baseUrl}/professional?payment=pending`
      },
      auto_return: 'approved',
      external_reference: `professional_${req.user.id}_${Date.now()}`,
      notification_url: `${baseUrl}/api/webhooks/mercadopago`,
      metadata: {
        professional_id: req.user.id.toString(),
        payment_type: 'professional_payment',
        amount: amount.toString()
      }
    };

    const result = await preference.create({ body: preferenceData });

    console.log('✅ Professional payment preference created:', result.id);

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point
    });

  } catch (error) {
    console.error('❌ Error creating professional payment:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento profissional',
      error: error.message 
    });
  }
});

// MercadoPago webhook handler
app.post('/api/webhooks/mercadopago', async (req, res) => {
  try {
    console.log('🔔 MercadoPago webhook received:', req.body);

    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      
      // Get payment details from MercadoPago
      const { Payment } = await import('mercadopago');
      const payment = new Payment(client);
      
      const paymentData = await payment.get({ id: paymentId });
      
      console.log('💳 Payment data:', paymentData);

      const externalReference = paymentData.external_reference;
      const status = paymentData.status;
      const metadata = paymentData.metadata;

      if (status === 'approved') {
        if (metadata.payment_type === 'subscription') {
          // Handle subscription payment
          const userId = parseInt(metadata.user_id);
          
          // Calculate expiry date (1 month from now)
          const expiryDate = new Date();
          expiryDate.setMonth(expiryDate.getMonth() + 1);
          
          await pool.query(
            'UPDATE users SET subscription_status = $1, subscription_expiry = $2 WHERE id = $3',
            ['active', expiryDate.toISOString(), userId]
          );
          
          console.log('✅ Subscription activated for user:', userId);
          
        } else if (metadata.payment_type === 'professional_payment') {
          // Handle professional payment
          const professionalId = parseInt(metadata.professional_id);
          const amount = parseFloat(metadata.amount);
          
          // Record the payment
          await pool.query(
            `INSERT INTO professional_payments (
              professional_id, amount, payment_id, external_reference, 
              status, paid_at, created_at
            ) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
            [professionalId, amount, paymentId, externalReference, 'paid']
          );
          
          console.log('✅ Professional payment recorded:', {
            professionalId,
            amount,
            paymentId
          });
        }
      }
    }

    res.status(200).json({ message: 'Webhook processed successfully' });
  } catch (error) {
    console.error('❌ Webhook processing error:', error);
    res.status(500).json({ message: 'Error processing webhook' });
  }
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
      return res.status(400).json({ message: 'Campos obrigatórios não preenchidos' });
    }

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles,
        percentage, category_id, subscription_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW())
      RETURNING id, name, cpf, roles`,
      [
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, hashedPassword, roles,
        percentage, category_id, roles.includes('client') ? 'pending' : null
      ]
    );

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

    // Check if user can edit this profile
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(id)) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    let updateQuery = `
      UPDATE users SET 
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, updated_at = NOW()
    `;
    let queryParams = [
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state
    ];
    let paramCount = 10;

    // Add admin-only fields
    if (req.user.currentRole === 'admin' && roles) {
      updateQuery += `, roles = $${++paramCount}, percentage = $${++paramCount}, category_id = $${++paramCount}`;
      queryParams.push(roles, percentage, category_id);
    }

    // Handle password change
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Senha atual é obrigatória' });
      }

      // Verify current password
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

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      updateQuery += `, password_hash = $${++paramCount}`;
      queryParams.push(hashedNewPassword);
    }

    updateQuery += ` WHERE id = $${++paramCount} RETURNING id, name, email`;
    queryParams.push(id);

    const result = await pool.query(updateQuery, queryParams);

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

// Activate client (admin only)
app.put('/api/users/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { expiry_date } = req.body;

    if (!expiry_date) {
      return res.status(400).json({ message: 'Data de expiração é obrigatória' });
    }

    const result = await pool.query(
      'UPDATE users SET subscription_status = $1, subscription_expiry = $2 WHERE id = $3 RETURNING id, name',
      ['active', expiry_date, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
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

// ==================== CLIENT LOOKUP ROUTES ====================

// Lookup client by CPF
app.get('/api/clients/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const result = await pool.query(
      `SELECT id, name, cpf, subscription_status, subscription_expiry 
       FROM users 
       WHERE cpf = $1 AND roles @> '["client"]'`,
      [cpf]
    );

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

    const result = await pool.query(
      'SELECT id, name, cpf, birth_date, created_at FROM dependents WHERE client_id = $1 ORDER BY name',
      [clientId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro ao buscar dependentes' });
  }
});

// Lookup dependent by CPF
app.get('/api/dependents/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const result = await pool.query(
      `SELECT 
        d.id, d.name, d.cpf, d.birth_date, d.client_id,
        u.name as client_name, u.subscription_status as client_subscription_status
       FROM dependents d
       JOIN users u ON d.client_id = u.id
       WHERE d.cpf = $1`,
      [cpf]
    );

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
app.post('/api/dependents', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    if (!client_id || !name || !cpf) {
      return res.status(400).json({ message: 'Campos obrigatórios não preenchidos' });
    }

    // Check if CPF already exists
    const existingDependent = await pool.query(
      'SELECT id FROM dependents WHERE cpf = $1',
      [cpf]
    );

    if (existingDependent.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    const result = await pool.query(
      `INSERT INTO dependents (client_id, name, cpf, birth_date, created_at)
       VALUES ($1, $2, $3, $4, NOW())
       RETURNING id, name, cpf, birth_date, created_at`,
      [client_id, name, cpf, birth_date]
    );

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
app.put('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    const result = await pool.query(
      `UPDATE dependents SET name = $1, birth_date = $2, updated_at = NOW()
       WHERE id = $3
       RETURNING id, name, cpf, birth_date`,
      [name, birth_date, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

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
app.delete('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM dependents WHERE id = $1 RETURNING id',
      [id]
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

// ==================== SERVICES ROUTES ====================

// Get all services
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
    res.status(500).json({ message: 'Erro ao buscar serviços' });
  }
});

// Create service (admin only)
app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !description || !base_price) {
      return res.status(400).json({ message: 'Campos obrigatórios não preenchidos' });
    }

    const result = await pool.query(
      `INSERT INTO services (name, description, base_price, category_id, is_base_service, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING id, name, description, base_price, category_id, is_base_service`,
      [name, description, base_price, category_id, is_base_service]
    );

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

    const result = await pool.query(
      `UPDATE services SET 
        name = $1, description = $2, base_price = $3, 
        category_id = $4, is_base_service = $5, updated_at = NOW()
       WHERE id = $6
       RETURNING id, name, description, base_price, category_id, is_base_service`,
      [name, description, base_price, category_id, is_base_service, id]
    );

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

// ==================== SERVICE CATEGORIES ROUTES ====================

// Get all service categories
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, description FROM service_categories ORDER BY name'
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro ao buscar categorias' });
  }
});

// Create service category (admin only)
app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name || !description) {
      return res.status(400).json({ message: 'Nome e descrição são obrigatórios' });
    }

    const result = await pool.query(
      `INSERT INTO service_categories (name, description, created_at)
       VALUES ($1, $2, NOW())
       RETURNING id, name, description`,
      [name, description]
    );

    res.status(201).json({
      message: 'Categoria criada com sucesso',
      category: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating service category:', error);
    res.status(500).json({ message: 'Erro ao criar categoria' });
  }
});

// ==================== CONSULTATIONS ROUTES ====================

// Get consultations
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id, c.date, c.value, c.status, c.notes,
        s.name as service_name,
        u.name as professional_name,
        COALESCE(u2.name, pp.name, d.name) as client_name,
        CASE 
          WHEN c.dependent_id IS NOT NULL THEN true
          ELSE false
        END as is_dependent
      FROM consultations c
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users u ON c.professional_id = u.id
      LEFT JOIN users u2 ON c.client_id = u2.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
    `;

    let queryParams = [];

    // Filter based on user role
    if (req.user.currentRole === 'client') {
      query += ` WHERE (c.client_id = $1 OR c.dependent_id IN (
        SELECT id FROM dependents WHERE client_id = $1
      ))`;
      queryParams.push(req.user.id);
    } else if (req.user.currentRole === 'professional') {
      query += ` WHERE c.professional_id = $1`;
      queryParams.push(req.user.id);
    }

    query += ` ORDER BY c.date DESC`;

    const result = await pool.query(query, queryParams);
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
        client_id, dependent_id, private_patient_id, professional_id,
        service_id, location_id, value, date, status, notes, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
      RETURNING id, date, value, status`,
      [
        client_id, dependent_id, private_patient_id, req.user.id,
        service_id, location_id, value, date, status, notes
      ]
    );

    res.status(201).json({
      message: 'Consulta registrada com sucesso',
      consultation: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro ao registrar consulta' });
  }
});

// Update consultation status
app.put('/api/consultations/:id/status', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ message: 'Status é obrigatório' });
    }

    const validStatuses = ['scheduled', 'confirmed', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Status inválido' });
    }

    const result = await pool.query(
      `UPDATE consultations SET status = $1, updated_at = NOW()
       WHERE id = $2 AND professional_id = $3
       RETURNING id, status`,
      [status, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Consulta não encontrada' });
    }

    res.json({
      message: 'Status atualizado com sucesso',
      consultation: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating consultation status:', error);
    res.status(500).json({ message: 'Erro ao atualizar status da consulta' });
  }
});

// ==================== PROFESSIONALS ROUTES ====================

// Get professionals for clients
app.get('/api/professionals', authenticate, authorize(['client']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.roles,
        u.address, u.address_number, u.address_complement,
        u.neighborhood, u.city, u.state, u.photo_url,
        sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.roles @> '["professional"]'
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
        sa.has_scheduling_access,
        sa.access_expires_at,
        sa.access_granted_by,
        sa.access_granted_at
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      LEFT JOIN scheduling_access sa ON u.id = sa.professional_id
      WHERE u.roles @> '["professional"]'
      ORDER BY u.name
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals scheduling access:', error);
    res.status(500).json({ message: 'Erro ao buscar acesso à agenda dos profissionais' });
  }
});

// Grant scheduling access (admin only)
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: 'ID do profissional e data de expiração são obrigatórios' });
    }

    // Insert or update scheduling access
    await pool.query(`
      INSERT INTO scheduling_access (
        professional_id, has_scheduling_access, access_expires_at,
        access_granted_by, access_granted_at, reason, created_at
      ) VALUES ($1, true, $2, $3, NOW(), $4, NOW())
      ON CONFLICT (professional_id) 
      DO UPDATE SET 
        has_scheduling_access = true,
        access_expires_at = $2,
        access_granted_by = $3,
        access_granted_at = NOW(),
        reason = $4,
        updated_at = NOW()
    `, [professional_id, expires_at, req.user.name, reason]);

    res.json({ message: 'Acesso à agenda concedido com sucesso' });
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

    await pool.query(`
      UPDATE scheduling_access 
      SET has_scheduling_access = false, updated_at = NOW()
      WHERE professional_id = $1
    `, [professional_id]);

    res.json({ message: 'Acesso à agenda revogado com sucesso' });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro ao revogar acesso à agenda' });
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

    // Check if CPF already exists for this professional
    const existingPatient = await pool.query(
      'SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2',
      [cpf, req.user.id]
    );

    if (existingPatient.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado para este profissional' });
    }

    const result = await pool.query(
      `INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date,
        address, address_number, address_complement, neighborhood,
        city, state, zip_code, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
      RETURNING id, name, cpf, email, phone, birth_date, created_at`,
      [
        req.user.id, name, cpf, email, phone, birth_date,
        address, address_number, address_complement, neighborhood,
        city, state, zip_code
      ]
    );

    res.status(201).json({
      message: 'Paciente particular criado com sucesso',
      patient: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating private patient:', error);
    res.status(500).json({ message: 'Erro ao criar paciente particular' });
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

    const result = await pool.query(
      `UPDATE private_patients SET 
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, zip_code = $11,
        updated_at = NOW()
       WHERE id = $12 AND professional_id = $13
       RETURNING id, name, cpf, email, phone, birth_date`,
      [
        name, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, zip_code,
        id, req.user.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente particular não encontrado' });
    }

    res.json({
      message: 'Paciente particular atualizado com sucesso',
      patient: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating private patient:', error);
    res.status(500).json({ message: 'Erro ao atualizar paciente particular' });
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
      return res.status(404).json({ message: 'Paciente particular não encontrado' });
    }

    res.json({ message: 'Paciente particular excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting private patient:', error);
    res.status(500).json({ message: 'Erro ao excluir paciente particular' });
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
      return res.status(400).json({ message: 'Paciente é obrigatório' });
    }

    const result = await pool.query(
      `INSERT INTO medical_records (
        professional_id, private_patient_id, chief_complaint,
        history_present_illness, past_medical_history, medications,
        allergies, physical_examination, diagnosis, treatment_plan,
        notes, vital_signs, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
      RETURNING id, created_at`,
      [
        req.user.id, private_patient_id, chief_complaint,
        history_present_illness, past_medical_history, medications,
        allergies, physical_examination, diagnosis, treatment_plan,
        notes, JSON.stringify(vital_signs)
      ]
    );

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

    const result = await pool.query(
      `UPDATE medical_records SET 
        chief_complaint = $1, history_present_illness = $2,
        past_medical_history = $3, medications = $4, allergies = $5,
        physical_examination = $6, diagnosis = $7, treatment_plan = $8,
        notes = $9, vital_signs = $10, updated_at = NOW()
       WHERE id = $11 AND professional_id = $12
       RETURNING id, updated_at`,
      [
        chief_complaint, history_present_illness, past_medical_history,
        medications, allergies, physical_examination, diagnosis,
        treatment_plan, notes, JSON.stringify(vital_signs), id, req.user.id
      ]
    );

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
        COALESCE(pp.name, d.name, u.name) as patient_name
      FROM medical_documents md
      LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
      LEFT JOIN dependents d ON md.dependent_id = d.id
      LEFT JOIN users u ON md.client_id = u.id
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
    const { title, document_type, private_patient_id, client_id, dependent_id, template_data } = req.body;

    if (!title || !document_type || !template_data) {
      return res.status(400).json({ message: 'Título, tipo de documento e dados do template são obrigatórios' });
    }

    // Generate document PDF
    const documentResult = await generateDocumentPDF(document_type, template_data);

    // Save document record
    const result = await pool.query(
      `INSERT INTO medical_documents (
        professional_id, private_patient_id, client_id, dependent_id,
        title, document_type, document_url, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      RETURNING id, title, document_url, created_at`,
      [
        req.user.id, private_patient_id, client_id, dependent_id,
        title, document_type, documentResult.url
      ]
    );

    res.status(201).json({
      message: 'Documento criado com sucesso',
      document: result.rows[0],
      title,
      documentUrl: documentResult.url
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

    const result = await pool.query(
      `INSERT INTO attendance_locations (
        professional_id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
      RETURNING id, name, is_default, created_at`,
      [
        req.user.id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default
      ]
    );

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

    const result = await pool.query(
      `UPDATE attendance_locations SET 
        name = $1, address = $2, address_number = $3, address_complement = $4,
        neighborhood = $5, city = $6, state = $7, zip_code = $8,
        phone = $9, is_default = $10, updated_at = NOW()
       WHERE id = $11 AND professional_id = $12
       RETURNING id, name, is_default`,
      [
        name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default,
        id, req.user.id
      ]
    );

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

// ==================== IMAGE UPLOAD ROUTE ====================

// Upload image route
app.post('/api/upload-image', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Image upload request received');
    
    const upload = createUpload();
    
    upload.single('image')(req, res, async (err) => {
      if (err) {
        console.error('❌ Upload error:', err);
        return res.status(400).json({ 
          message: err.message || 'Erro no upload da imagem' 
        });
      }

      if (!req.file) {
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      console.log('✅ Image uploaded successfully:', req.file);

      // Update user's photo_url in database
      await pool.query(
        'UPDATE users SET photo_url = $1, updated_at = NOW() WHERE id = $2',
        [req.file.path, req.user.id]
      );

      res.json({
        message: 'Imagem enviada com sucesso',
        imageUrl: req.file.path
      });
    });
  } catch (error) {
    console.error('❌ Error in upload route:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// ==================== REPORTS ROUTES ====================

// Revenue report (admin only)
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
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count,
        SUM(c.value * (u.percentage / 100.0)) as professional_payment,
        SUM(c.value * ((100 - u.percentage) / 100.0)) as clinic_revenue
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.date >= $1 AND c.date <= $2
        AND c.client_id IS NOT NULL
      GROUP BY u.id, u.name, u.percentage
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Get revenue by service
    const serviceRevenueResult = await pool.query(`
      SELECT 
        s.name as service_name,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      WHERE c.date >= $1 AND c.date <= $2
      GROUP BY s.id, s.name
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Calculate total revenue
    const totalRevenueResult = await pool.query(`
      SELECT SUM(value) as total_revenue
      FROM consultations
      WHERE date >= $1 AND date <= $2
    `, [start_date, end_date]);

    const totalRevenue = totalRevenueResult.rows[0]?.total_revenue || 0;

    res.json({
      total_revenue: Number(totalRevenue),
      revenue_by_professional: professionalRevenueResult.rows.map(row => ({
        ...row,
        revenue: Number(row.revenue),
        professional_payment: Number(row.professional_payment),
        clinic_revenue: Number(row.clinic_revenue)
      })),
      revenue_by_service: serviceRevenueResult.rows.map(row => ({
        ...row,
        revenue: Number(row.revenue)
      }))
    });
  } catch (error) {
    console.error('Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de receita' });
  }
});

// Professional revenue report
app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    // Get professional's percentage
    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    if (professionalResult.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professionalPercentage = professionalResult.rows[0].percentage || 50;

    // Get consultations for the period
    const consultationsResult = await pool.query(`
      SELECT 
        c.date, c.value,
        s.name as service_name,
        COALESCE(u.name, pp.name, d.name) as client_name,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN c.value
          ELSE c.value * ((100 - $3) / 100.0)
        END as amount_to_pay
      FROM consultations c
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      WHERE c.professional_id = $1 
        AND c.date >= $2 AND c.date <= $4
      ORDER BY c.date DESC
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    // Calculate summary
    const totalRevenue = consultationsResult.rows.reduce((sum, row) => sum + Number(row.value), 0);
    const totalAmountToPay = consultationsResult.rows.reduce((sum, row) => sum + Number(row.amount_to_pay), 0);

    res.json({
      summary: {
        professional_percentage: professionalPercentage,
        total_revenue: totalRevenue,
        consultation_count: consultationsResult.rows.length,
        amount_to_pay: totalAmountToPay
      },
      consultations: consultationsResult.rows.map(row => ({
        ...row,
        total_value: Number(row.value),
        amount_to_pay: Number(row.amount_to_pay)
      }))
    });
  } catch (error) {
    console.error('Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de receita do profissional' });
  }
});

// Professional detailed report
app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    // Get professional's percentage
    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = professionalResult.rows[0]?.percentage || 50;

    // Get consultation counts and revenue
    const summaryResult = await pool.query(`
      SELECT 
        COUNT(*) as total_consultations,
        COUNT(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        SUM(c.value) as total_revenue,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue
      FROM consultations c
      WHERE c.professional_id = $1 
        AND c.date >= $2 AND c.date <= $3
    `, [req.user.id, start_date, end_date]);

    const summary = summaryResult.rows[0];
    const convenioRevenue = Number(summary.convenio_revenue) || 0;
    const amountToPay = convenioRevenue * ((100 - professionalPercentage) / 100);

    res.json({
      summary: {
        total_consultations: Number(summary.total_consultations),
        convenio_consultations: Number(summary.convenio_consultations),
        private_consultations: Number(summary.private_consultations),
        total_revenue: Number(summary.total_revenue) || 0,
        convenio_revenue: convenioRevenue,
        private_revenue: Number(summary.private_revenue) || 0,
        professional_percentage: professionalPercentage,
        amount_to_pay: amountToPay
      }
    });
  } catch (error) {
    console.error('Error generating professional detailed report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório detalhado do profissional' });
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
      WHERE roles @> '["client"]' 
        AND city IS NOT NULL 
        AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC, city
    `);
    
    res.json(result.rows);
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
      WHERE u.roles @> '["professional"]' 
        AND u.city IS NOT NULL 
        AND u.city != ''
      GROUP BY u.city, u.state
      ORDER BY total_professionals DESC, u.city
    `);

    // Process the categories to group by category name
    const processedResult = result.rows.map(row => {
      const categoryMap = new Map();
      
      row.categories.forEach((cat: any) => {
        const name = cat.category_name;
        if (categoryMap.has(name)) {
          categoryMap.set(name, categoryMap.get(name) + cat.count);
        } else {
          categoryMap.set(name, cat.count);
        }
      });

      return {
        ...row,
        categories: Array.from(categoryMap.entries()).map(([category_name, count]) => ({
          category_name,
          count
        }))
      };
    });
    
    res.json(processedResult);
  } catch (error) {
    console.error('Error generating professionals by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório de profissionais por cidade' });
  }
});

// ==================== STATIC FILES ====================

// Serve static files from dist directory
app.get('*', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'dist', 'index.html'));
});

// ==================== SERVER START ====================

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`💳 MercadoPago configured: ${process.env.MP_ACCESS_TOKEN ? '✅' : '❌'}`);
});