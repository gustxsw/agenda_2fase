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
        1, // Assuming category 1 exists
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
       ON CONFLICT (professional_id) DO NOTHING`,
      [professionalId]
    );
    
    // Create schedule settings
    await pool.query(
      `INSERT INTO professional_schedule_settings 
       (professional_id, work_days, work_start_time, work_end_time, 
        break_start_time, break_end_time, consultation_duration, has_scheduling_subscription)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (professional_id) DO NOTHING`,
      [professionalId, [1,2,3,4,5], '08:00', '18:00', '12:00', '13:00', 60, true]
    );
    
    // Create attendance location
    await pool.query(
      `INSERT INTO attendance_locations 
       (professional_id, name, address, address_number, neighborhood, city, state, 
        zip_code, phone, is_default)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT DO NOTHING`,
      [professionalId, 'Clínica Principal - TESTE', 'Rua das Flores', '123', 
       'Centro', 'Goiânia', 'GO', '74000000', '6432221234', true]
    );
    
    // Create private patients
    const patient1Result = await pool.query(
      `INSERT INTO private_patients 
       (professional_id, name, cpf, email, phone, birth_date, address, city, state)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id`,
      [professionalId, 'Maria Santos (TESTE)', '98765432100', 'maria.teste@email.com', 
       '64987654321', '1990-05-20', 'Rua das Palmeiras, 456', 'Goiânia', 'GO']
    );
    
    const patient2Result = await pool.query(
      `INSERT INTO private_patients 
       (professional_id, name, cpf, email, phone, birth_date, address, city, state)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id`,
      [professionalId, 'Carlos Oliveira (TESTE)', '11122233344', 'carlos.teste@email.com', 
       '64912345678', '1988-12-10', 'Avenida Central, 789', 'Goiânia', 'GO']
    );
    
    const patient1Id = patient1Result.rows[0].id;
    
    // Create test appointment for today
    const today = new Date();
    const appointmentDate = today.toISOString().split('T')[0];
    
    await pool.query(
      `INSERT INTO appointments 
       (professional_id, private_patient_id, service_id, appointment_date, 
        appointment_time, value, status, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT DO NOTHING`,
      [professionalId, patient1Id, 1, appointmentDate, '14:00', 150.00, 'scheduled', 
       'Consulta de teste agendada automaticamente']
    );
    
    // Create medical record
    await pool.query(
      `INSERT INTO medical_records 
       (professional_id, private_patient_id, chief_complaint, history_present_illness,
        physical_examination, diagnosis, treatment_plan, vital_signs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT DO NOTHING`,
      [professionalId, patient1Id, 
       'Dor nas costas há 3 dias', 
       'Paciente relata dor lombar após esforço físico',
       'Tensão muscular na região lombar, sem sinais neurológicos',
       'Lombalgia mecânica',
       'Repouso relativo, fisioterapia, analgésicos se necessário',
       JSON.stringify({
         blood_pressure: '120/80',
         heart_rate: '72',
         temperature: '36.5',
         weight: '70',
         height: '1.75'
       })]
    );
    
    console.log('🎉 Test professional setup completed successfully!');
    console.log('📋 Login credentials:');
    console.log('   CPF: 123.456.789-01');
    console.log('   Password: 123456');
    
  } catch (error) {
    console.error('❌ Error creating test professional:', error);
  }
}

// Authentication routes
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