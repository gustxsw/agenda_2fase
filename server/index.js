import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import { pool } from './db.js';

// Import routes
import authRoutes from './routes/auth.js';
import usersRoutes from './routes/users.js';
import clientsRoutes from './routes/clients.js';
import professionalsRoutes from './routes/professionals.js';
import consultationsRoutes from './routes/consultations.js';
import reportsRoutes from './routes/reports.js';
import servicesRoutes from './routes/services.js';
import serviceCategoriesRoutes from './routes/serviceCategories.js';
import privatePatientsRoutes from './routes/privatePatients.js';
import attendanceLocationsRoutes from './routes/attendanceLocations.js';
import schedulingRoutes from './routes/scheduling.js';
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

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/clients', clientsRoutes);
app.use('/api/professionals', professionalsRoutes);
app.use('/api/consultations', consultationsRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/api/services', servicesRoutes);
app.use('/api/service-categories', serviceCategoriesRoutes);
app.use('/api/private-patients', privatePatientsRoutes);
app.use('/api/attendance-locations', attendanceLocationsRoutes);
app.use('/api/scheduling', schedulingRoutes);
app.use('/api/dependents', dependentsRoutes);

// Serve static files from React build
app.use(express.static(distPath));

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

// Start server
const PORT = process.env.PORT || 3001;

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
    console.log('🎉 Setup completo! Use CPF: 123.456.789-01 e senha: teste123');

  } catch (error) {
    console.error('❌ Erro ao criar profissional de teste:', error);
  }
}

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Frontend: http://localhost:${PORT}`);
  console.log(`🔗 API: http://localhost:${PORT}/api`);
  
  // Create test professional on startup
  setTimeout(() => {
    createTestProfessional();
  }, 2000);
});