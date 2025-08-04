import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'https://www.cartaoquiroferreira.com.br', 'https://cartaoquiroferreira.com.br'],
  credentials: true
}));
app.use(express.json());

// Auth middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Token não fornecido' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const result = await pool.query('SELECT id, name, cpf, roles FROM users WHERE id = $1', [decoded.id]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Usuário não encontrado' });
    }

    req.user = {
      id: result.rows[0].id,
      name: result.rows[0].name,
      cpf: result.rows[0].cpf,
      roles: result.rows[0].roles || [],
      currentRole: decoded.currentRole
    };

    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido' });
  }
};

// Create tables
const createTables = async () => {
  try {
    console.log('🔄 Creating database tables...');

    // Users table
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
        has_scheduling_access BOOLEAN DEFAULT FALSE,
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
        is_base_service BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Private patients
    await pool.query(`
      CREATE TABLE IF NOT EXISTS private_patients (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id),
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
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Dependents
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dependents (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) NOT NULL,
        birth_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Attendance locations
    await pool.query(`
      CREATE TABLE IF NOT EXISTS attendance_locations (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id),
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

    // Appointments
    await pool.query(`
      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        service_id INTEGER REFERENCES services(id),
        location_id INTEGER REFERENCES attendance_locations(id),
        appointment_date DATE NOT NULL,
        appointment_time TIME NOT NULL,
        value DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'scheduled',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Consultations
    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        professional_id INTEGER REFERENCES users(id),
        service_id INTEGER REFERENCES services(id),
        location_id INTEGER REFERENCES attendance_locations(id),
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Medical records
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_records (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id),
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

    console.log('✅ Database tables created successfully');
  } catch (error) {
    console.error('❌ Error creating tables:', error);
  }
};

// Create test data
const createTestData = async () => {
  try {
    console.log('🔄 Creating test data...');

    // Create category
    const categoryResult = await pool.query(`
      INSERT INTO service_categories (name, description) 
      VALUES ('Fisioterapia', 'Serviços de fisioterapia e reabilitação')
      ON CONFLICT DO NOTHING
      RETURNING id
    `);

    let categoryId;
    if (categoryResult.rows.length > 0) {
      categoryId = categoryResult.rows[0].id;
    } else {
      const existingCategory = await pool.query(`SELECT id FROM service_categories WHERE name = 'Fisioterapia'`);
      categoryId = existingCategory.rows[0].id;
    }

    // Create service
    await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service) 
      VALUES ('Consulta Fisioterapêutica', 'Consulta completa de fisioterapia', 150.00, $1, true)
      ON CONFLICT DO NOTHING
    `, [categoryId]);

    // Check if test professional exists
    const existingProfessional = await pool.query(`SELECT id FROM users WHERE cpf = '12345678901'`);
    
    if (existingProfessional.rows.length === 0) {
      // Create test professional
      const hashedPassword = await bcrypt.hash('123456', 10);
      
      const professionalResult = await pool.query(`
        INSERT INTO users (
          name, cpf, email, phone, password_hash, roles, 
          category_id, percentage, has_scheduling_access
        ) VALUES (
          'Dr. João Silva', '12345678901', 'joao@teste.com', '64981249199',
          $1, ARRAY['professional'], $2, 70, TRUE
        ) RETURNING id
      `, [hashedPassword, categoryId]);

      const professionalId = professionalResult.rows[0].id;

      // Create attendance location
      const locationResult = await pool.query(`
        INSERT INTO attendance_locations (
          professional_id, name, address, address_number, 
          neighborhood, city, state, phone, is_default
        ) VALUES (
          $1, 'Clínica Principal', 'Rua das Flores', '123',
          'Centro', 'Goiânia', 'GO', '6432221234', TRUE
        ) RETURNING id
      `, [professionalId]);

      const locationId = locationResult.rows[0].id;

      // Create private patients
      const patient1Result = await pool.query(`
        INSERT INTO private_patients (
          professional_id, name, cpf, email, phone, birth_date
        ) VALUES (
          $1, 'Maria Santos', '11111111111', 'maria@teste.com', '64987654321', '1985-05-15'
        ) RETURNING id
      `, [professionalId]);

      const patient2Result = await pool.query(`
        INSERT INTO private_patients (
          professional_id, name, cpf, email, phone, birth_date
        ) VALUES (
          $1, 'Carlos Oliveira', '22222222222', 'carlos@teste.com', '64912345678', '1978-12-03'
        ) RETURNING id
      `, [professionalId]);

      const patient1Id = patient1Result.rows[0].id;
      const patient2Id = patient2Result.rows[0].id;

      // Get service ID
      const serviceResult = await pool.query(`SELECT id FROM services WHERE name = 'Consulta Fisioterapêutica'`);
      const serviceId = serviceResult.rows[0].id;

      // Create appointments for next few days
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);
      
      const dayAfter = new Date();
      dayAfter.setDate(dayAfter.getDate() + 2);
      
      const dayAfter2 = new Date();
      dayAfter2.setDate(dayAfter2.getDate() + 3);

      await pool.query(`
        INSERT INTO appointments (
          professional_id, private_patient_id, service_id, location_id,
          appointment_date, appointment_time, value, status, notes
        ) VALUES 
        ($1, $2, $3, $4, $5, '09:00', 150.00, 'scheduled', 'Primeira consulta'),
        ($1, $6, $3, $4, $7, '14:30', 150.00, 'scheduled', 'Consulta de retorno'),
        ($1, $2, $3, $4, $8, '10:15', 150.00, 'scheduled', 'Segunda sessão')
      `, [
        professionalId, patient1Id, serviceId, locationId, 
        tomorrow.toISOString().split('T')[0],
        patient2Id,
        dayAfter.toISOString().split('T')[0],
        dayAfter2.toISOString().split('T')[0]
      ]);

      // Create medical records
      await pool.query(`
        INSERT INTO medical_records (
          professional_id, private_patient_id, chief_complaint, 
          diagnosis, treatment_plan, notes
        ) VALUES 
        ($1, $2, 'Dor lombar há 2 semanas', 'Lombalgia mecânica', 'Fisioterapia 3x/semana', 'Paciente colaborativo'),
        ($1, $3, 'Dor no ombro direito', 'Tendinite do supraespinhal', 'Exercícios específicos', 'Melhora gradual')
      `, [professionalId, patient1Id, patient2Id]);

      console.log('✅ Test professional created successfully!');
      console.log('📋 Login: CPF 123.456.789-01 | Senha: 123456');
    } else {
      console.log('ℹ️ Test professional already exists');
    }
  } catch (error) {
    console.error('❌ Error creating test data:', error);
  }
};

// Routes

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;
    
    const result = await pool.query('SELECT * FROM users WHERE cpf = $1', [cpf.replace(/\D/g, '')]);
    
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
      user: userData,
      needsRoleSelection: userData.roles.length > 1
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;
    
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    const user = result.rows[0];
    
    if (!user.roles.includes(role)) {
      return res.status(403).json({ message: 'Role não autorizada' });
    }
    
    const token = jwt.sign(
      { id: user.id, currentRole: role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles,
      currentRole: role
    };
    
    res.json({ token, user: userData });
  } catch (error) {
    console.error('Role selection error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Users routes
app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    const user = result.rows[0];
    delete user.password_hash;
    
    res.json(user);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Service categories
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM service_categories ORDER BY name');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Services
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.*, sc.name as category_name 
      FROM services s 
      LEFT JOIN service_categories sc ON s.category_id = sc.id 
      ORDER BY s.name
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Private patients
app.get('/api/private-patients', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM private_patients WHERE professional_id = $1 ORDER BY name',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Attendance locations
app.get('/api/attendance-locations', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM attendance_locations WHERE professional_id = $1 ORDER BY is_default DESC, name',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching locations:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Appointments
app.get('/api/appointments', authenticate, async (req, res) => {
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

// Check scheduling access
app.get('/api/scheduling-payment/subscription-status', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT has_scheduling_access FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    const hasAccess = result.rows[0].has_scheduling_access;
    
    res.json({
      has_subscription: hasAccess,
      status: hasAccess ? 'active' : 'inactive',
      expires_at: hasAccess ? '2025-12-31T23:59:59.000Z' : null
    });
  } catch (error) {
    console.error('Error checking subscription:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Consultations
app.post('/api/consultations', authenticate, async (req, res) => {
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

    const result = await pool.query(`
      INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id,
        service_id, location_id, value, date
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `, [client_id, dependent_id, private_patient_id, professional_id, service_id, location_id, value, date]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Professional revenue report
app.get('/api/reports/professional-revenue', authenticate, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    const result = await pool.query(`
      SELECT 
        c.date,
        COALESCE(pp.name, u.name, d.name) as client_name,
        s.name as service_name,
        c.value as total_value,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN 0
          ELSE ROUND(c.value * (100 - COALESCE(prof.percentage, 50)) / 100.0, 2)
        END as amount_to_pay
      FROM consultations c
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users prof ON c.professional_id = prof.id
      WHERE c.professional_id = $1
      AND c.date >= $2
      AND c.date <= $3
      ORDER BY c.date DESC
    `, [req.user.id, start_date, end_date]);

    const consultations = result.rows;
    
    // Get professional percentage
    const profResult = await pool.query('SELECT percentage FROM users WHERE id = $1', [req.user.id]);
    const professionalPercentage = profResult.rows[0]?.percentage || 50;
    
    const summary = {
      professional_percentage: professionalPercentage,
      total_revenue: consultations.reduce((sum, c) => sum + parseFloat(c.total_value), 0),
      consultation_count: consultations.length,
      amount_to_pay: consultations.reduce((sum, c) => sum + parseFloat(c.amount_to_pay), 0)
    };

    res.json({ summary, consultations });
  } catch (error) {
    console.error('Error fetching professional revenue:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Admin route to activate scheduling access
app.put('/api/users/:id/activate-scheduling', authenticate, async (req, res) => {
  try {
    // Check if user is admin
    if (!req.user.roles.includes('admin')) {
      return res.status(403).json({ message: 'Acesso negado' });
    }
    
    const { id } = req.params;
    
    await pool.query(
      'UPDATE users SET has_scheduling_access = TRUE WHERE id = $1',
      [id]
    );
    
    res.json({ message: 'Acesso à agenda ativado com sucesso' });
  } catch (error) {
    console.error('Error activating scheduling:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Initialize database and start server
const startServer = async () => {
  try {
    await createTables();
    await createTestData();
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log('📋 Test Professional: CPF 123.456.789-01 | Password: 123456');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();