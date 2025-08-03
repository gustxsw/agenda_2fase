// Load environment variables FIRST
import dotenv from 'dotenv';
dotenv.config();

// Debug environment variables
console.log('🔍 Environment check:');
console.log('NODE_ENV:', process.env.NODE_ENV || 'NOT DEFINED');
console.log('PORT:', process.env.PORT || 'NOT DEFINED');
console.log('DATABASE_URL:', process.env.DATABASE_URL ? 'DEFINED' : 'NOT DEFINED');

import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { MercadoPagoConfig, Preference } from 'mercadopago';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import createUpload from './middleware/upload.js';

// Import route modules
import attendanceLocationsRoutes from './routes/attendanceLocations.js';
import medicalRecordsRoutes from './routes/medicalRecords.js';
import privatePatientsRoutes from './routes/privatePatients.js';
import schedulingRoutes from './routes/scheduling.js';
import schedulingPaymentRoutes from './routes/schedulingPayment.js';

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize MercadoPago
const client = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN,
});

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3000',
      'https://www.cartaoquiroferreira.com.br',
      'https://cartaoquiroferreira.com.br'
    ];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static('dist'));

// Use route modules
app.use('/api/attendance-locations', attendanceLocationsRoutes);
app.use('/api/medical-records', medicalRecordsRoutes);
app.use('/api/private-patients', privatePatientsRoutes);
app.use('/api/scheduling', schedulingRoutes);
app.use('/api/scheduling-payment', schedulingPaymentRoutes);

// Create test professional function
async function createTestProfessional() {
  try {
    console.log('🧪 Creating test professional...');
    
    // Check if test professional already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      ['12345678901']
    );
    
    if (existingUser.rows.length > 0) {
      console.log('✅ Test professional already exists');
      return;
    }
    
    // First, ensure we have a service category
    let categoryResult = await pool.query(
      'SELECT id FROM service_categories WHERE name = $1',
      ['Fisioterapia']
    );
    
    let categoryId;
    if (categoryResult.rows.length === 0) {
      // Create test category
      categoryResult = await pool.query(
        `INSERT INTO service_categories (name, description)
         VALUES ($1, $2)
         RETURNING id`,
        ['Fisioterapia', 'Serviços de fisioterapia e reabilitação']
      );
      categoryId = categoryResult.rows[0].id;
      console.log('✅ Test category created with ID:', categoryId);
    } else {
      categoryId = categoryResult.rows[0].id;
    }
    
    // Ensure we have a test service
    let serviceResult = await pool.query(
      'SELECT id FROM services WHERE name = $1',
      ['Consulta Fisioterapêutica']
    );
    
    let serviceId;
    if (serviceResult.rows.length === 0) {
      serviceResult = await pool.query(
        `INSERT INTO services (name, description, base_price, category_id, is_base_service)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id`,
        ['Consulta Fisioterapêutica', 'Avaliação e tratamento fisioterapêutico', 150.00, categoryId, true]
      );
      serviceId = serviceResult.rows[0].id;
      console.log('✅ Test service created with ID:', serviceId);
    } else {
      serviceId = serviceResult.rows[0].id;
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash('123456', 10);
    
    // Create user with professional role
    const userResult = await pool.query(
      `INSERT INTO users (name, cpf, email, phone, birth_date, address, address_number, 
                         address_complement, neighborhood, city, state, password, roles, 
                         percentage, category_id, subscription_status, subscription_expiry)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
       RETURNING id`,
      [
        'Dr. João Silva (TESTE)',
        '12345678901',
        'joao.teste@quiroferreira.com',
        '64981249199',
        '1985-03-15',
        'Rua das Flores',
        '123',
        'Sala 101',
        'Centro',
        'Goiânia',
        'GO',
        hashedPassword,
        ['professional'],
        70,
        categoryId,
        'active',
        '2025-12-31'
      ]
    );
    
    const professionalId = userResult.rows[0].id;
    console.log('✅ Test professional created with ID:', professionalId);
    
    // Create scheduling subscription
    await pool.query(
      `INSERT INTO professional_scheduling_subscriptions 
       (professional_id, status, expires_at, payment_id)
       VALUES ($1, 'active', '2025-12-31', 'test_payment_123')
       ON CONFLICT (professional_id) DO UPDATE SET
         status = 'active',
         expires_at = '2025-12-31',
         payment_id = 'test_payment_123'`,
      [professionalId]
    );
    
    // Create schedule settings
    await pool.query(
      `INSERT INTO professional_schedule_settings 
       (professional_id, work_days, work_start_time, work_end_time, 
        break_start_time, break_end_time, consultation_duration, has_scheduling_subscription)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (professional_id) DO UPDATE SET
         work_days = $2,
         work_start_time = $3,
         work_end_time = $4,
         break_start_time = $5,
         break_end_time = $6,
         consultation_duration = $7,
         has_scheduling_subscription = $8`,
      [professionalId, [1,2,3,4,5], '08:00', '18:00', '12:00', '13:00', 60, true]
    );
    
    // Create attendance location
    await pool.query(
      `INSERT INTO attendance_locations 
       (professional_id, name, address, address_number, neighborhood, city, state, 
        zip_code, phone, is_default)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (professional_id, name) DO UPDATE SET
         address = $3,
         address_number = $4,
         neighborhood = $5,
         city = $6,
         state = $7,
         zip_code = $8,
         phone = $9,
         is_default = $10`,
      [professionalId, 'Clínica Principal - TESTE', 'Rua das Flores', '123', 
       'Centro', 'Goiânia', 'GO', '74000000', '6432221234', true]
    );
    
    // Create private patients
    const patient1Result = await pool.query(
      `INSERT INTO private_patients 
       (professional_id, name, cpf, email, phone, birth_date, address, city, state)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (professional_id, cpf) DO UPDATE SET
         name = $2,
         email = $4,
         phone = $5
       RETURNING id`,
      [professionalId, 'Maria Santos (TESTE)', '98765432100', 'maria.teste@email.com', 
       '64987654321', '1990-05-20', 'Rua das Palmeiras, 456', 'Goiânia', 'GO']
    );
    
    const patient2Result = await pool.query(
      `INSERT INTO private_patients 
       (professional_id, name, cpf, email, phone, birth_date, address, city, state)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (professional_id, cpf) DO UPDATE SET
         name = $2,
         email = $4,
         phone = $5
       RETURNING id`,
      [professionalId, 'Carlos Oliveira (TESTE)', '11122233344', 'carlos.teste@email.com', 
       '64912345678', '1988-12-10', 'Avenida Central, 789', 'Goiânia', 'GO']
    );
    
    const patient1Id = patient1Result.rows[0].id;
    const patient2Id = patient2Result.rows[0].id;
    
    // Get location ID
    const locationResult = await pool.query(
      'SELECT id FROM attendance_locations WHERE professional_id = $1 AND is_default = true',
      [professionalId]
    );
    const locationId = locationResult.rows[0]?.id;
    
    // Create test appointments for this week
    const today = new Date();
    const appointments = [
      {
        date: today.toISOString().split('T')[0],
        time: '14:00',
        patient_id: patient1Id,
        notes: 'Consulta de avaliação inicial'
      },
      {
        date: new Date(today.getTime() + 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        time: '10:00',
        patient_id: patient2Id,
        notes: 'Sessão de fisioterapia'
      },
      {
        date: new Date(today.getTime() + 2 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        time: '16:00',
        patient_id: patient1Id,
        notes: 'Retorno - evolução do tratamento'
      }
    ];
    
    for (const appointment of appointments) {
      await pool.query(
        `INSERT INTO appointments 
         (professional_id, private_patient_id, service_id, appointment_date, 
          appointment_time, location_id, value, status, notes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT DO NOTHING`,
        [professionalId, appointment.patient_id, serviceId, appointment.date, 
         appointment.time, locationId, 150.00, 'scheduled', appointment.notes]
      );
    }
    
    // Create medical records
    await pool.query(
      `INSERT INTO medical_records 
       (professional_id, private_patient_id, chief_complaint, history_present_illness,
        physical_examination, diagnosis, treatment_plan, vital_signs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT DO NOTHING`,
      [professionalId, patient1Id, 
       'Dor nas costas há 3 dias', 
       'Paciente relata dor lombar após esforço físico no trabalho. Dor de intensidade moderada (6/10), piora com movimento e melhora com repouso.',
       'Tensão muscular na região lombar, sem sinais neurológicos. Amplitude de movimento limitada por dor.',
       'Lombalgia mecânica aguda',
       'Repouso relativo por 48h, aplicação de calor local, fisioterapia para fortalecimento e alongamento, analgésicos se necessário.',
       JSON.stringify({
         blood_pressure: '120/80',
         heart_rate: '72',
         temperature: '36.5',
         respiratory_rate: '16',
         oxygen_saturation: '98',
         weight: '70',
         height: '1.75'
       })]
    );
    
    await pool.query(
      `INSERT INTO medical_records 
       (professional_id, private_patient_id, chief_complaint, history_present_illness,
        physical_examination, diagnosis, treatment_plan, vital_signs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT DO NOTHING`,
      [professionalId, patient2Id, 
       'Dor no ombro direito', 
       'Paciente praticante de tênis relata dor no ombro direito há 1 semana após jogo. Dor ao elevar o braço.',
       'Dor à palpação do tendão supraespinhal, teste de Neer positivo, força muscular preservada.',
       'Tendinopatia do manguito rotador',
       'Crioterapia nas primeiras 48h, fisioterapia para fortalecimento excêntrico, evitar movimentos repetitivos acima da cabeça.',
       JSON.stringify({
         blood_pressure: '118/75',
         heart_rate: '68',
         temperature: '36.3',
         respiratory_rate: '14',
         oxygen_saturation: '99',
         weight: '75',
         height: '1.80'
       })]
    );
    
    console.log('🎉 Test professional setup completed successfully!');
    console.log('📋 Login credentials:');
    console.log('   CPF: 123.456.789-01');
    console.log('   Password: 123456');
    console.log('📅 Test appointments created for this week');
    console.log('📋 Medical records created for both patients');
    
  } catch (error) {
    console.error('❌ Error creating test professional:', error);
  }
}

// Authentication routes
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
      password,
    } = req.body;

    console.log('📝 Registration request received for:', name);

    // Validate required fields
    if (!name || !cpf || !password) {
      return res.status(400).json({ message: 'Nome, CPF e senha são obrigatórios' });
    }

    // Clean CPF
    const cleanCpf = cpf.replace(/\D/g, '');

    // Validate CPF format
    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'Usuário já cadastrado com este CPF' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with client role and pending subscription
    const result = await pool.query(
      `INSERT INTO users (name, cpf, email, phone, birth_date, address, address_number, 
                         address_complement, neighborhood, city, state, password, roles, 
                         subscription_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
       RETURNING id, name, cpf, roles`,
      [
        name,
        cleanCpf,
        email,
        phone,
        birth_date,
        address,
        address_number,
        address_complement,
        neighborhood,
        city,
        state,
        hashedPassword,
        ['client'],
        'pending'
      ]
    );

    const user = result.rows[0];

    console.log('✅ User registered successfully:', user.id);

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

app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: 'CPF e senha são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    const result = await pool.query(
      'SELECT id, name, cpf, password, roles FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles || []
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

    const userData = {
      id: req.user.id,
      name: req.user.name,
      cpf: req.user.cpf,
      roles: req.user.roles,
      currentRole: role
    };

    res.json({
      message: 'Role alterada com sucesso',
      user: userData,
      token
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

// User routes
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.name, u.cpf, u.email, u.phone, u.birth_date, u.address, 
             u.address_number, u.address_complement, u.neighborhood, u.city, u.state, 
             u.roles, u.percentage, u.category_id, u.subscription_status, u.subscription_expiry, 
             u.created_at, sc.name as category_name
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

app.post('/api/users', authenticate, authorize(['admin']), async (req, res) => {
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
      password,
      roles,
      percentage,
      category_id,
    } = req.body;

    // Validate required fields
    if (!name || !cpf || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Nome, CPF, senha e pelo menos uma role são obrigatórios' });
    }

    // Clean CPF
    const cleanCpf = cpf.replace(/\D/g, '');

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'Usuário já cadastrado com este CPF' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Set subscription status based on roles
    let subscriptionStatus = 'pending';
    if (roles.includes('client')) {
      subscriptionStatus = 'pending';
    } else {
      subscriptionStatus = 'active';
    }

    // Create user
    const result = await pool.query(
      `INSERT INTO users (name, cpf, email, phone, birth_date, address, address_number, 
                         address_complement, neighborhood, city, state, password, roles, 
                         percentage, category_id, subscription_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
       RETURNING id, name, cpf, roles`,
      [
        name,
        cleanCpf,
        email,
        phone,
        birth_date,
        address,
        address_number,
        address_complement,
        neighborhood,
        city,
        state,
        hashedPassword,
        roles,
        percentage,
        category_id,
        subscriptionStatus
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
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.put('/api/users/:id', authenticate, async (req, res) => {
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
      roles,
      percentage,
      category_id,
      currentPassword,
      newPassword
    } = req.body;

    // Check if user exists and user has permission
    if (req.user.currentRole !== 'admin' && req.user.id !== parseInt(id)) {
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

    // Add roles, percentage, category_id if admin is updating
    if (req.user.currentRole === 'admin' && roles) {
      paramCount++;
      updateQuery += `, roles = $${paramCount}`;
      queryParams.push(roles);

      if (percentage !== undefined) {
        paramCount++;
        updateQuery += `, percentage = $${paramCount}`;
        queryParams.push(percentage);
      }

      if (category_id !== undefined) {
        paramCount++;
        updateQuery += `, category_id = $${paramCount}`;
        queryParams.push(category_id);
      }
    }

    // Handle password change
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Senha atual é obrigatória para alterar a senha' });
      }

      // Verify current password
      const userResult = await pool.query('SELECT password FROM users WHERE id = $1', [id]);
      if (userResult.rows.length === 0) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
      }

      const isValidPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password);
      if (!isValidPassword) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      paramCount++;
      updateQuery += `, password = $${paramCount}`;
      queryParams.push(hashedNewPassword);
    }

    paramCount++;
    updateQuery += ` WHERE id = $${paramCount} RETURNING id, name, cpf, email, roles`;
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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// 🔥 NEW: Activate client endpoint
app.put('/api/users/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { expiry_date } = req.body;

    if (!expiry_date) {
      return res.status(400).json({ message: 'Data de expiração é obrigatória' });
    }

    // Validate that the user exists and is a client
    const userCheck = await pool.query(
      'SELECT id, roles FROM users WHERE id = $1',
      [id]
    );

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = userCheck.rows[0];
    if (!user.roles || !user.roles.includes('client')) {
      return res.status(400).json({ message: 'Apenas clientes podem ser ativados' });
    }

    // Update subscription status and expiry
    const result = await pool.query(
      `UPDATE users 
       SET subscription_status = 'active', 
           subscription_expiry = $1,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING id, name, subscription_status, subscription_expiry`,
      [expiry_date, id]
    );

    res.json({
      message: 'Cliente ativado com sucesso',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Error activating client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Service categories routes
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM service_categories ORDER BY name'
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Nome da categoria é obrigatório' });
    }

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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !description || !base_price) {
      return res.status(400).json({ message: 'Nome, descrição e preço base são obrigatórios' });
    }

    const result = await pool.query(
      'INSERT INTO services (name, description, base_price, category_id, is_base_service) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, description, base_price, category_id, is_base_service || false]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(
      'UPDATE services SET name = $1, description = $2, base_price = $3, category_id = $4, is_base_service = $5 WHERE id = $6 RETURNING *',
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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Professionals route
app.get('/api/professionals', authenticate, authorize(['client', 'admin']), async (req, res) => {
  try {
    console.log('🔄 Fetching professionals for user role:', req.user.currentRole);
    
    const result = await pool.query(`
      SELECT u.id, u.name, u.email, u.phone, u.address, u.address_number, 
             u.address_complement, u.neighborhood, u.city, u.state, u.roles,
             u.photo_url, sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.roles @> '["professional"]'
      ORDER BY u.name
    `);
    
    console.log('✅ Found professionals:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Consultations routes
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT c.*, s.name as service_name, u.name as professional_name,
             COALESCE(client.name, dep.name, pp.name) as client_name,
             CASE 
               WHEN c.dependent_id IS NOT NULL THEN true 
               ELSE false 
             END as is_dependent
      FROM consultations c
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users u ON c.professional_id = u.id
      LEFT JOIN users client ON c.client_id = client.id
      LEFT JOIN dependents dep ON c.dependent_id = dep.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
    `;
    
    let queryParams = [];
    
    if (req.user.currentRole === 'client') {
      // Clients see their own consultations and their dependents'
      query += ` WHERE (c.client_id = $1 OR dep.client_id = $1)`;
      queryParams.push(req.user.id);
    } else if (req.user.currentRole === 'professional') {
      // Professionals see their own consultations
      query += ` WHERE c.professional_id = $1`;
      queryParams.push(req.user.id);
    }
    // Admins see all consultations (no WHERE clause)
    
    query += ` ORDER BY c.date DESC`;
    
    const result = await pool.query(query, queryParams);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching consultations:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

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
      date,
    } = req.body;

    console.log('🔄 Creating consultation:', {
      client_id,
      dependent_id,
      private_patient_id,
      professional_id,
      service_id,
      location_id,
      value,
      date
    });

    // Validate that professional_id matches authenticated user
    if (professional_id !== req.user.id) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    // Validate required fields
    if (!service_id || !value || !date) {
      return res.status(400).json({ message: 'Serviço, valor e data são obrigatórios' });
    }

    // Validate that at least one patient type is specified
    if (!client_id && !dependent_id && !private_patient_id) {
      return res.status(400).json({ message: 'É necessário especificar um cliente, dependente ou paciente particular' });
    }

    // If it's a client or dependent, validate subscription status
    if (client_id || dependent_id) {
      let subscriptionQuery;
      let subscriptionParams;
      
      if (dependent_id) {
        // Check dependent's client subscription
        subscriptionQuery = `
          SELECT u.subscription_status 
          FROM dependents d 
          JOIN users u ON d.client_id = u.id 
          WHERE d.id = $1
        `;
        subscriptionParams = [dependent_id];
      } else {
        // Check client subscription
        subscriptionQuery = 'SELECT subscription_status FROM users WHERE id = $1';
        subscriptionParams = [client_id];
      }
      
      const subscriptionResult = await pool.query(subscriptionQuery, subscriptionParams);
      
      if (subscriptionResult.rows.length === 0) {
        return res.status(404).json({ message: 'Cliente não encontrado' });
      }
      
      if (subscriptionResult.rows[0].subscription_status !== 'active') {
        return res.status(400).json({ message: 'Cliente não possui assinatura ativa' });
      }
    }

    const result = await pool.query(
      `INSERT INTO consultations (client_id, dependent_id, private_patient_id, professional_id, service_id, location_id, value, date)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [client_id, dependent_id, private_patient_id, professional_id, service_id, location_id, value, date]
    );

    console.log('✅ Consultation created:', result.rows[0]);

    res.status(201).json({
      message: 'Consulta registrada com sucesso',
      consultation: result.rows[0]
    });
  } catch (error) {
    console.error('❌ Error creating consultation:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Dependents routes
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;
    
    // Check if user has permission to view these dependents
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

app.get('/api/dependents/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;
    
    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }
    
    const cleanCpf = cpf.replace(/\D/g, '');
    
    const result = await pool.query(`
      SELECT d.*, u.name as client_name, u.subscription_status as client_subscription_status
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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/dependents', authenticate, authorize(['client', 'admin']), async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    // Check if user has permission to add dependents for this client
    if (req.user.currentRole === 'client' && req.user.id !== client_id) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    // Validate required fields
    if (!client_id || !name || !cpf) {
      return res.status(400).json({ message: 'ID do cliente, nome e CPF são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    // Check if CPF already exists
    const existingDependent = await pool.query(
      'SELECT id FROM dependents WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingDependent.rows.length > 0) {
      return res.status(400).json({ message: 'Já existe um dependente cadastrado com este CPF' });
    }

    // Check if CPF belongs to an existing user
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'Este CPF já está cadastrado como usuário' });
    }

    // Check dependent limit (max 10 per client)
    const dependentCount = await pool.query(
      'SELECT COUNT(*) FROM dependents WHERE client_id = $1',
      [client_id]
    );

    if (parseInt(dependentCount.rows[0].count) >= 10) {
      return res.status(400).json({ message: 'Limite máximo de 10 dependentes atingido' });
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

app.put('/api/dependents/:id', authenticate, authorize(['client', 'admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    // Check if user has permission to edit this dependent
    if (req.user.currentRole === 'client') {
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
    }

    const result = await pool.query(
      'UPDATE dependents SET name = $1, birth_date = $2 WHERE id = $3 RETURNING *',
      [name, birth_date, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.delete('/api/dependents/:id', authenticate, authorize(['client', 'admin']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if user has permission to delete this dependent
    if (req.user.currentRole === 'client') {
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
    }

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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Client lookup route
app.get('/api/clients/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;
    
    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }
    
    const cleanCpf = cpf.replace(/\D/g, '');
    
    const result = await pool.query(
      'SELECT id, name, cpf, subscription_status FROM users WHERE cpf = $1 AND roles @> \'["client"]\'',
      [cleanCpf]
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

// Reports routes
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    // Get total revenue
    const totalRevenueResult = await pool.query(
      'SELECT COALESCE(SUM(value), 0) as total_revenue FROM consultations WHERE date >= $1 AND date <= $2',
      [start_date, end_date]
    );

    // Get revenue by professional
    const revenueByProfessionalResult = await pool.query(`
      SELECT 
        u.name as professional_name,
        u.percentage as professional_percentage,
        COALESCE(SUM(c.value), 0) as revenue,
        COUNT(c.id) as consultation_count,
        COALESCE(SUM(c.value * (u.percentage / 100.0)), 0) as professional_payment,
        COALESCE(SUM(c.value * ((100 - u.percentage) / 100.0)), 0) as clinic_revenue
      FROM users u
      LEFT JOIN consultations c ON u.id = c.professional_id 
        AND c.date >= $1 AND c.date <= $2
      WHERE u.roles @> '["professional"]'
      GROUP BY u.id, u.name, u.percentage
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Get revenue by service
    const revenueByServiceResult = await pool.query(`
      SELECT 
        s.name as service_name,
        COALESCE(SUM(c.value), 0) as revenue,
        COUNT(c.id) as consultation_count
      FROM services s
      LEFT JOIN consultations c ON s.id = c.service_id 
        AND c.date >= $1 AND c.date <= $2
      GROUP BY s.id, s.name
      HAVING COUNT(c.id) > 0
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    res.json({
      total_revenue: parseFloat(totalRevenueResult.rows[0].total_revenue),
      revenue_by_professional: revenueByProfessionalResult.rows.map(row => ({
        professional_name: row.professional_name,
        professional_percentage: parseInt(row.professional_percentage),
        revenue: parseFloat(row.revenue),
        consultation_count: parseInt(row.consultation_count),
        professional_payment: parseFloat(row.professional_payment),
        clinic_revenue: parseFloat(row.clinic_revenue)
      })),
      revenue_by_service: revenueByServiceResult.rows.map(row => ({
        service_name: row.service_name,
        revenue: parseFloat(row.revenue),
        consultation_count: parseInt(row.consultation_count)
      }))
    });
  } catch (error) {
    console.error('Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    console.log('🔄 Generating professional revenue report for user:', req.user.id);
    console.log('🔄 Date range:', start_date, 'to', end_date);

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
        c.date,
        c.value as total_value,
        s.name as service_name,
        COALESCE(client.name, dep.name, pp.name) as client_name,
        (c.value * ((100 - $3) / 100.0)) as amount_to_pay
      FROM consultations c
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users client ON c.client_id = client.id
      LEFT JOIN dependents dep ON c.dependent_id = dep.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      WHERE c.professional_id = $1 
        AND c.date >= $2 
        AND c.date <= $4
      ORDER BY c.date DESC
    `, [req.user.id, start_date, professionalPercentage, end_date]);

    // Calculate summary
    const totalRevenue = consultationsResult.rows.reduce((sum, row) => sum + parseFloat(row.total_value), 0);
    const totalAmountToPay = consultationsResult.rows.reduce((sum, row) => sum + parseFloat(row.amount_to_pay), 0);

    const response = {
      summary: {
        professional_percentage: professionalPercentage,
        total_revenue: totalRevenue,
        consultation_count: consultationsResult.rows.length,
        amount_to_pay: totalAmountToPay
      },
      consultations: consultationsResult.rows.map(row => ({
        date: row.date,
        client_name: row.client_name,
        service_name: row.service_name,
        total_value: parseFloat(row.total_value),
        amount_to_pay: parseFloat(row.amount_to_pay)
      }))
    };

    console.log('✅ Professional revenue report generated:', response);
    res.json(response);
  } catch (error) {
    console.error('❌ Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Data inicial e final são obrigatórias' });
    }

    // Get professional's percentage
    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = professionalResult.rows[0]?.percentage || 50;

    // Get consultations breakdown
    const consultationsResult = await pool.query(`
      SELECT 
        COUNT(*) as total_consultations,
        COUNT(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        COALESCE(SUM(c.value), 0) as total_revenue,
        COALESCE(SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value ELSE 0 END), 0) as convenio_revenue,
        COALESCE(SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END), 0) as private_revenue
      FROM consultations c
      WHERE c.professional_id = $1 
        AND c.date >= $2 
        AND c.date <= $3
    `, [req.user.id, start_date, end_date]);

    const data = consultationsResult.rows[0];
    const convenioRevenue = parseFloat(data.convenio_revenue);
    const amountToPay = convenioRevenue * ((100 - professionalPercentage) / 100);

    res.json({
      summary: {
        total_consultations: parseInt(data.total_consultations),
        convenio_consultations: parseInt(data.convenio_consultations),
        private_consultations: parseInt(data.private_consultations),
        total_revenue: parseFloat(data.total_revenue),
        convenio_revenue: convenioRevenue,
        private_revenue: parseFloat(data.private_revenue),
        professional_percentage: professionalPercentage,
        amount_to_pay: amountToPay
      }
    });
  } catch (error) {
    console.error('Error generating detailed professional report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Payment routes
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { user_id, dependent_ids } = req.body;

    // Validate that user_id matches authenticated user
    if (user_id !== req.user.id) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    // Get user data
    const userResult = await pool.query(
      'SELECT name, email FROM users WHERE id = $1',
      [user_id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const user = userResult.rows[0];

    // Get dependents count
    const dependentsResult = await pool.query(
      'SELECT COUNT(*) FROM dependents WHERE client_id = $1',
      [user_id]
    );

    const dependentCount = parseInt(dependentsResult.rows[0].count);

    // Calculate total amount (R$250 for titular + R$50 per dependent)
    const totalAmount = 250 + (dependentCount * 50);

    const preference = new Preference(client);

    const items = [
      {
        title: 'Assinatura Cartão Quiro Ferreira - Titular',
        description: 'Assinatura mensal do cartão de convênio',
        quantity: 1,
        unit_price: 250,
        currency_id: 'BRL',
      }
    ];

    if (dependentCount > 0) {
      items.push({
        title: `Dependentes (${dependentCount})`,
        description: 'Taxa adicional por dependente',
        quantity: dependentCount,
        unit_price: 50,
        currency_id: 'BRL',
      });
    }

    const preferenceData = {
      items,
      payer: {
        name: user.name,
        email: user.email || `user${user_id}@quiroferreira.com.br`,
      },
      back_urls: {
        success: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client/payment-success`,
        failure: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client/payment-failure`,
        pending: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client/payment-pending`,
      },
      auto_return: 'approved',
      external_reference: `subscription_${user_id}_${Date.now()}`,
      notification_url: `${process.env.API_URL || 'http://localhost:3001'}/api/webhook`,
      statement_descriptor: 'QUIRO FERREIRA',
    };

    console.log('🔄 Creating MercadoPago preference:', preferenceData);

    const result = await preference.create({ body: preferenceData });

    console.log('✅ MercadoPago preference created:', result);

    // Store the payment intent in database
    await pool.query(
      `INSERT INTO subscription_payments 
       (user_id, mp_preference_id, amount, status, external_reference)
       VALUES ($1, $2, $3, 'pending', $4)`,
      [user_id, result.id, totalAmount, preferenceData.external_reference]
    );

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point,
    });
  } catch (error) {
    console.error('❌ Error creating subscription:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento da assinatura',
      error: error.message 
    });
  }
});

app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor inválido' });
    }

    // Get professional data
    const professionalResult = await pool.query(
      'SELECT name, email FROM users WHERE id = $1',
      [req.user.id]
    );

    if (professionalResult.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    const professional = professionalResult.rows[0];

    const preference = new Preference(client);

    const preferenceData = {
      items: [
        {
          title: 'Repasse ao Convênio Quiro Ferreira',
          description: 'Valor a ser repassado ao convênio referente às consultas realizadas',
          quantity: 1,
          unit_price: amount,
          currency_id: 'BRL',
        }
      ],
      payer: {
        name: professional.name,
        email: professional.email || `professional${req.user.id}@quiroferreira.com.br`,
      },
      back_urls: {
        success: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/payment-success`,
        failure: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/payment-failure`,
        pending: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/payment-pending`,
      },
      auto_return: 'approved',
      external_reference: `professional_payment_${req.user.id}_${Date.now()}`,
      notification_url: `${process.env.API_URL || 'http://localhost:3001'}/api/professional-payment-webhook`,
      statement_descriptor: 'QUIRO FERREIRA',
    };

    console.log('🔄 Creating professional payment preference:', preferenceData);

    const result = await preference.create({ body: preferenceData });

    console.log('✅ Professional payment preference created:', result);

    // Store the payment intent in database
    await pool.query(
      `INSERT INTO professional_payments 
       (professional_id, mp_preference_id, amount, status, external_reference)
       VALUES ($1, $2, $3, 'pending', $4)`,
      [req.user.id, result.id, amount, preferenceData.external_reference]
    );

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point,
    });
  } catch (error) {
    console.error('❌ Error creating professional payment:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento profissional',
      error: error.message 
    });
  }
});

// Image upload route
app.post('/api/upload-image', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Image upload request received');
    
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
      
      console.log('✅ Image uploaded successfully:', req.file);
      
      try {
        // Update user's photo_url in database
        await pool.query(
          'UPDATE users SET photo_url = $1 WHERE id = $2',
          [req.file.path, req.user.id]
        );
        
        console.log('✅ User photo_url updated in database');
        
        res.json({
          message: 'Imagem enviada com sucesso',
          imageUrl: req.file.path,
          filename: req.file.filename
        });
      } catch (dbError) {
        console.error('❌ Database error:', dbError);
        res.status(500).json({ message: 'Erro ao salvar URL da imagem no banco de dados' });
      }
    });
  } catch (error) {
    console.error('❌ Upload route error:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor no upload',
      error: error.message 
    });
  }
});

// Medical documents routes
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT md.*, 
             COALESCE(pp.name, c.name, d.name) as patient_name
      FROM medical_documents md
      LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
      LEFT JOIN users c ON md.client_id = c.id
      LEFT JOIN dependents d ON md.dependent_id = d.id
      WHERE md.professional_id = $1
      ORDER BY md.created_at DESC
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

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

    // Generate document content based on type and template_data
    let documentContent = '';
    
    switch (document_type) {
      case 'certificate':
        documentContent = `
          ATESTADO MÉDICO
          
          Atesto para os devidos fins que o(a) paciente ${template_data.patientName}, 
          portador(a) do CPF ${template_data.patientCpf}, esteve sob meus cuidados médicos 
          e necessita de afastamento de suas atividades por ${template_data.days} dia(s).
          
          Descrição: ${template_data.description}
          ${template_data.cid ? `CID: ${template_data.cid}` : ''}
          
          ${template_data.professionalName}
          ${template_data.professionalSpecialty || ''}
          CRM: ${template_data.crm}
        `;
        break;
      case 'prescription':
        documentContent = `
          RECEITUÁRIO MÉDICO
          
          Paciente: ${template_data.patientName}
          CPF: ${template_data.patientCpf}
          
          ${template_data.prescription}
          
          ${template_data.professionalName}
          ${template_data.professionalSpecialty || ''}
          CRM: ${template_data.crm}
        `;
        break;
      default:
        documentContent = template_data.content || '';
    }

    // For now, we'll store the content directly
    // In a real implementation, you would generate a PDF and store it
    const result = await pool.query(`
      INSERT INTO medical_documents 
      (professional_id, private_patient_id, client_id, dependent_id, document_type, title, document_url, template_data)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `, [req.user.id, private_patient_id, client_id, dependent_id, document_type, title, 
        `data:text/plain;base64,${Buffer.from(documentContent).toString('base64')}`, template_data]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating medical document:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Webhook routes
app.post('/api/webhook', async (req, res) => {
  try {
    console.log('🔔 Webhook received:', req.body);

    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      
      // Here you would typically verify the payment with MercadoPago API
      // For now, we'll simulate payment approval
      
      // Find the payment record
      const paymentResult = await pool.query(
        `SELECT * FROM subscription_payments WHERE mp_payment_id = $1`,
        [paymentId]
      );

      if (paymentResult.rows.length > 0) {
        const payment = paymentResult.rows[0];
        
        // Update payment status
        await pool.query(
          `UPDATE subscription_payments 
           SET status = 'approved', updated_at = CURRENT_TIMESTAMP
           WHERE id = $1`,
          [payment.id]
        );

        // Update user subscription status
        const expiryDate = new Date();
        expiryDate.setMonth(expiryDate.getMonth() + 1); // 1 month from now

        await pool.query(
          `UPDATE users 
           SET subscription_status = 'active', subscription_expiry = $1
           WHERE id = $2`,
          [expiryDate, payment.user_id]
        );

        console.log('✅ Subscription activated for user:', payment.user_id);
      }
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error('❌ Error processing webhook:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

app.post('/api/professional-payment-webhook', async (req, res) => {
  try {
    console.log('🔔 Professional payment webhook received:', req.body);

    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      
      // Find the payment record
      const paymentResult = await pool.query(
        `SELECT * FROM professional_payments WHERE mp_payment_id = $1`,
        [paymentId]
      );

      if (paymentResult.rows.length > 0) {
        const payment = paymentResult.rows[0];
        
        // Update payment status
        await pool.query(
          `UPDATE professional_payments 
           SET status = 'approved', updated_at = CURRENT_TIMESTAMP
           WHERE id = $1`,
          [payment.id]
        );

        console.log('✅ Professional payment processed for:', payment.professional_id);
      }
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error('❌ Error processing professional payment webhook:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Appointments routes (for scheduling system)
app.get('/api/appointments', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    const result = await pool.query(`
      SELECT a.*, 
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
      ORDER BY a.appointment_date, a.appointment_time
    `, [req.user.id, start_date, end_date]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Catch-all route for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'dist', 'index.html'));
});

// Start server and create test data
async function startServer() {
  try {
    // Test database connection
    await pool.query('SELECT NOW()');
    console.log('✅ Database connected successfully');
    
    // Create test professional
    await createTestProfessional();
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();