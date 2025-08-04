import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';

// Import route modules
import schedulingRoutes from './routes/scheduling.js';
import privatePatientRoutes from './routes/privatePatients.js';
import medicalRecordsRoutes from './routes/medicalRecords.js';
import attendanceLocationRoutes from './routes/attendanceLocations.js';
import schedulingPaymentRoutes from './routes/schedulingPayment.js';

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
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static('dist'));

// Create database tables
const createTables = async () => {
  try {
    console.log('🔄 Creating database tables...');

    // Users table with scheduling access control
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
        scheduling_expires_at TIMESTAMP,
        photo_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Service categories
    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
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
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(professional_id, cpf)
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
        zip_code VARCHAR(8),
        phone VARCHAR(20),
        is_default BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Professional schedule settings
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_schedule_settings (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        work_days INTEGER[] DEFAULT ARRAY[1,2,3,4,5],
        work_start_time TIME DEFAULT '08:00',
        work_end_time TIME DEFAULT '18:00',
        break_start_time TIME DEFAULT '12:00',
        break_end_time TIME DEFAULT '13:00',
        consultation_duration INTEGER DEFAULT 60,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Appointments
    await pool.query(`
      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
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
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
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

    // Professional scheduling payments (for MercadoPago integration)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_scheduling_payments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        mp_preference_id VARCHAR(255),
        mp_payment_id VARCHAR(255),
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        external_reference VARCHAR(255),
        payment_date TIMESTAMP,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Client subscription payments
    await pool.query(`
      CREATE TABLE IF NOT EXISTS client_subscription_payments (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        mp_preference_id VARCHAR(255),
        mp_payment_id VARCHAR(255),
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        external_reference VARCHAR(255),
        payment_date TIMESTAMP,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('✅ Database tables created successfully');
  } catch (error) {
    console.error('❌ Error creating tables:', error);
  }
};

// Create basic test data (without appointments)
const createBasicTestData = async () => {
  try {
    console.log('🔄 Creating basic test data...');

    // Create category
    const categoryResult = await pool.query(`
      INSERT INTO service_categories (name, description) 
      VALUES ('Fisioterapia', 'Serviços de fisioterapia e reabilitação')
      ON CONFLICT (name) DO NOTHING
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
      // Create test professional with scheduling access
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
      await pool.query(`
        INSERT INTO attendance_locations (
          professional_id, name, address, address_number, 
          neighborhood, city, state, phone, is_default
        ) VALUES (
          $1, 'Clínica Principal', 'Rua das Flores', '123',
          'Centro', 'Goiânia', 'GO', '6432221234', TRUE
        )
      `, [professionalId]);

      // Create schedule settings
      await pool.query(`
        INSERT INTO professional_schedule_settings (
          professional_id, work_days, work_start_time, work_end_time,
          break_start_time, break_end_time, consultation_duration
        ) VALUES (
          $1, ARRAY[1,2,3,4,5], '08:00', '18:00', '12:00', '13:00', 60
        )
      `, [professionalId]);

      // Create private patients
      await pool.query(`
        INSERT INTO private_patients (
          professional_id, name, cpf, email, phone, birth_date
        ) VALUES 
        ($1, 'Maria Santos', '11111111111', 'maria@teste.com', '64987654321', '1985-05-15'),
        ($1, 'Carlos Oliveira', '22222222222', 'carlos@teste.com', '64912345678', '1978-12-03')
      `, [professionalId]);

      console.log('✅ Test professional created successfully!');
      console.log('📋 Login: CPF 123.456.789-01 | Senha: 123456');
      console.log('📅 Acesso à agenda: ATIVO');
    } else {
      console.log('ℹ️ Test professional already exists');
    }

    // Create admin user if doesn't exist
    const existingAdmin = await pool.query(`SELECT id FROM users WHERE cpf = '00000000000'`);
    
    if (existingAdmin.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      
      await pool.query(`
        INSERT INTO users (
          name, cpf, email, password_hash, roles
        ) VALUES (
          'Administrador', '00000000000', 'admin@quiroferreira.com',
          $1, ARRAY['admin']
        )
      `, [hashedPassword]);

      console.log('✅ Admin user created!');
      console.log('📋 Admin Login: CPF 000.000.000-00 | Senha: admin123');
    }
  } catch (error) {
    console.error('❌ Error creating test data:', error);
  }
};

// Auth Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;
    
    console.log('🔄 Login attempt for CPF:', cpf);
    
    const result = await pool.query('SELECT * FROM users WHERE cpf = $1', [cpf.replace(/\D/g, '')]);
    
    if (result.rows.length === 0) {
      console.log('❌ User not found');
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }
    
    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
      console.log('❌ Invalid password');
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }
    
    console.log('✅ Login successful for user:', user.name);
    
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
    console.error('❌ Login error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/select-role', async (req, res) => {
  try {
    const { userId, role } = req.body;
    
    console.log('🎯 Role selection:', { userId, role });
    
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
    
    console.log('✅ Role selected successfully:', role);
    
    res.json({ token, user: userData });
  } catch (error) {
    console.error('❌ Role selection error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/switch-role', authenticate, async (req, res) => {
  try {
    const { role } = req.body;
    
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
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
    console.error('Error switching role:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, password
    } = req.body;

    // Check if user already exists
    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cpf.replace(/\D/g, '')]);
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(`
      INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, ARRAY['client'])
      RETURNING id, name, cpf, roles
    `, [
      name, cpf.replace(/\D/g, ''), email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, hashedPassword
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

// Users Routes
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.*, sc.name as category_name 
      FROM users u 
      LEFT JOIN service_categories sc ON u.category_id = sc.id 
      ORDER BY u.created_at DESC
    `);
    
    const users = result.rows.map(user => {
      delete user.password_hash;
      return user;
    });
    
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

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

app.post('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, password, roles,
      percentage, category_id
    } = req.body;

    // Check if user already exists
    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cpf]);
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(`
      INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles,
        percentage, category_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING id, name, cpf, roles
    `, [
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, hashedPassword, roles,
      percentage, category_id
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
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, roles,
      percentage, category_id, currentPassword, newPassword
    } = req.body;

    // Check authorization
    if (req.user.id !== parseInt(id) && !req.user.roles.includes('admin')) {
      return res.status(403).json({ message: 'Não autorizado' });
    }

    let updateQuery = `
      UPDATE users SET 
        name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
        address_number = $6, address_complement = $7, neighborhood = $8,
        city = $9, state = $10, updated_at = CURRENT_TIMESTAMP
    `;
    let queryParams = [name, email, phone, birth_date, address, address_number, address_complement, neighborhood, city, state];
    let paramCount = 10;

    // Add admin-only fields
    if (req.user.roles.includes('admin')) {
      updateQuery += `, roles = $${paramCount + 1}, percentage = $${paramCount + 2}, category_id = $${paramCount + 3}`;
      queryParams.push(roles, percentage, category_id);
      paramCount += 3;
    }

    // Handle password change
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Senha atual é obrigatória' });
      }

      // Verify current password
      const userResult = await pool.query('SELECT password_hash FROM users WHERE id = $1', [id]);
      const isValidPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
      
      if (!isValidPassword) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updateQuery += `, password_hash = $${paramCount + 1}`;
      queryParams.push(hashedPassword);
      paramCount++;
    }

    updateQuery += ` WHERE id = $${paramCount + 1} RETURNING id, name, cpf, roles`;
    queryParams.push(id);

    const result = await pool.query(updateQuery, queryParams);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({ message: 'Usuário atualizado com sucesso', user: result.rows[0] });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

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

// Activate client subscription
app.put('/api/users/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { expiry_date } = req.body;

    const result = await pool.query(`
      UPDATE users 
      SET subscription_status = 'active', subscription_expiry = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2 AND 'client' = ANY(roles)
      RETURNING id, name, subscription_status, subscription_expiry
    `, [expiry_date, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    res.json({ 
      message: 'Cliente ativado com sucesso', 
      user: result.rows[0] 
    });
  } catch (error) {
    console.error('Error activating client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Activate/Deactivate professional scheduling access
app.put('/api/users/:id/scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { has_access, expires_at } = req.body;

    const result = await pool.query(`
      UPDATE users 
      SET has_scheduling_access = $1, scheduling_expires_at = $2, updated_at = CURRENT_TIMESTAMP
      WHERE id = $3 AND 'professional' = ANY(roles)
      RETURNING id, name, has_scheduling_access, scheduling_expires_at
    `, [has_access, expires_at, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    res.json({ 
      message: has_access ? 'Acesso à agenda ativado' : 'Acesso à agenda desativado', 
      user: result.rows[0] 
    });
  } catch (error) {
    console.error('Error updating scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Service Categories Routes
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM service_categories ORDER BY name');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
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
    console.error('Error creating category:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Services Routes
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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(`
      UPDATE services 
      SET name = $1, description = $2, base_price = $3, category_id = $4, is_base_service = $5
      WHERE id = $6 
      RETURNING *
    `, [name, description, base_price, category_id, is_base_service, id]);

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

// Professionals Routes
app.get('/api/professionals', authenticate, async (req, res) => {
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

// Clients lookup
app.get('/api/clients/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;
    
    const result = await pool.query(`
      SELECT id, name, cpf, subscription_status 
      FROM users 
      WHERE cpf = $1 AND 'client' = ANY(roles)
    `, [cpf.replace(/\D/g, '')]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error looking up client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Dependents Routes
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;
    
    const result = await pool.query(`
      SELECT d.*, u.subscription_status as client_subscription_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.client_id = $1 
      ORDER BY d.name
    `, [clientId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.get('/api/dependents/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;
    
    const result = await pool.query(`
      SELECT d.*, u.name as client_name, u.subscription_status as client_subscription_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.cpf = $1
    `, [cpf.replace(/\D/g, '')]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error looking up dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/dependents', authenticate, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    // Check if dependent already exists
    const existingDependent = await pool.query('SELECT id FROM dependents WHERE cpf = $1', [cpf]);
    
    if (existingDependent.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    const result = await pool.query(`
      INSERT INTO dependents (client_id, name, cpf, birth_date) 
      VALUES ($1, $2, $3, $4) 
      RETURNING *
    `, [client_id, name, cpf, birth_date]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.put('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    const result = await pool.query(`
      UPDATE dependents 
      SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP
      WHERE id = $3 
      RETURNING *
    `, [name, birth_date, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.delete('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query('DELETE FROM dependents WHERE id = $1 RETURNING *', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Consultations Routes
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
      query += ` WHERE (c.client_id = $1 OR d.client_id = $1)`;
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
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/consultations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      client_id, dependent_id, private_patient_id, service_id,
      location_id, value, date
    } = req.body;

    const result = await pool.query(`
      INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id,
        service_id, location_id, value, date
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `, [client_id, dependent_id, private_patient_id, req.user.id, service_id, location_id, value, date]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Reports Routes
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    const result = await pool.query(`
      SELECT 
        prof.name as professional_name,
        prof.percentage as professional_percentage,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count,
        SUM(ROUND(c.value * prof.percentage / 100.0, 2)) as professional_payment,
        SUM(ROUND(c.value * (100 - prof.percentage) / 100.0, 2)) as clinic_revenue
      FROM consultations c
      JOIN users prof ON c.professional_id = prof.id
      WHERE c.date >= $1 AND c.date <= $2
      AND c.private_patient_id IS NULL
      GROUP BY prof.id, prof.name, prof.percentage
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    const revenue_by_professional = result.rows;
    
    const serviceResult = await pool.query(`
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

    const revenue_by_service = serviceResult.rows;
    
    const total_revenue = revenue_by_professional.reduce((sum, item) => sum + parseFloat(item.revenue), 0);

    res.json({
      total_revenue,
      revenue_by_professional,
      revenue_by_service
    });
  } catch (error) {
    console.error('Error fetching revenue report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
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

app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    const result = await pool.query(`
      SELECT 
        COUNT(*) as total_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        SUM(c.value) as total_revenue,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        prof.percentage as professional_percentage,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN ROUND(c.value * (100 - prof.percentage) / 100.0, 2) ELSE 0 END) as amount_to_pay
      FROM consultations c
      JOIN users prof ON c.professional_id = prof.id
      WHERE c.professional_id = $1
      AND c.date >= $2
      AND c.date <= $3
      GROUP BY prof.percentage
    `, [req.user.id, start_date, end_date]);

    const summary = result.rows[0] || {
      total_consultations: 0,
      convenio_consultations: 0,
      private_consultations: 0,
      total_revenue: 0,
      convenio_revenue: 0,
      private_revenue: 0,
      professional_percentage: 50,
      amount_to_pay: 0
    };

    res.json({ summary });
  } catch (error) {
    console.error('Error fetching detailed report:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Scheduling access check
app.get('/api/scheduling-payment/subscription-status', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT has_scheduling_access, scheduling_expires_at 
      FROM users 
      WHERE id = $1
    `, [req.user.id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    const user = result.rows[0];
    const hasAccess = user.has_scheduling_access;
    const expiresAt = user.scheduling_expires_at;
    
    // Check if access is still valid
    const isActive = hasAccess && (!expiresAt || new Date(expiresAt) > new Date());
    
    res.json({
      has_subscription: hasAccess,
      status: isActive ? 'active' : 'expired',
      expires_at: expiresAt
    });
  } catch (error) {
    console.error('Error checking subscription:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// MercadoPago payment creation for scheduling
app.post('/api/create-scheduling-subscription', authenticate, authorize(['professional']), async (req, res) => {
  try {
    // For MVP, we'll simulate the payment creation
    // In production, you would integrate with MercadoPago SDK here
    
    const paymentData = {
      preference_id: `test_pref_${Date.now()}`,
      init_point: `https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=test_pref_${Date.now()}`,
      sandbox_init_point: `https://sandbox.mercadopago.com.br/checkout/v1/redirect?pref_id=test_pref_${Date.now()}`
    };

    // Store payment record
    await pool.query(`
      INSERT INTO professional_scheduling_payments 
      (professional_id, mp_preference_id, amount, status, external_reference)
      VALUES ($1, $2, $3, 'pending', $4)
    `, [req.user.id, paymentData.preference_id, 49.90, `scheduling_${req.user.id}_${Date.now()}`]);

    res.json(paymentData);
  } catch (error) {
    console.error('Error creating scheduling payment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Professional payment to clinic
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;
    
    // For MVP, we'll simulate the payment creation
    const paymentData = {
      preference_id: `prof_payment_${Date.now()}`,
      init_point: `https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=prof_payment_${Date.now()}`,
      sandbox_init_point: `https://sandbox.mercadopago.com.br/checkout/v1/redirect?pref_id=prof_payment_${Date.now()}`
    };

    res.json(paymentData);
  } catch (error) {
    console.error('Error creating professional payment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Client subscription payment
app.post('/api/create-subscription', authenticate, async (req, res) => {
  try {
    const { user_id } = req.body;
    
    // For MVP, we'll simulate the payment creation
    const paymentData = {
      preference_id: `client_sub_${Date.now()}`,
      init_point: `https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=client_sub_${Date.now()}`,
      sandbox_init_point: `https://sandbox.mercadopago.com.br/checkout/v1/redirect?pref_id=client_sub_${Date.now()}`
    };

    // Store payment record
    await pool.query(`
      INSERT INTO client_subscription_payments 
      (client_id, mp_preference_id, amount, status, external_reference)
      VALUES ($1, $2, $3, 'pending', $4)
    `, [user_id, paymentData.preference_id, 250.00, `client_sub_${user_id}_${Date.now()}`]);

    res.json(paymentData);
  } catch (error) {
    console.error('Error creating subscription payment:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Use route modules
app.use('/api/scheduling', schedulingRoutes);
app.use('/api/private-patients', privatePatientRoutes);
app.use('/api/medical-records', medicalRecordsRoutes);
app.use('/api/attendance-locations', attendanceLocationRoutes);
app.use('/api/scheduling-payment', schedulingPaymentRoutes);

// Catch-all handler for React Router
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('❌ Server error:', error);
  res.status(500).json({ message: 'Erro interno do servidor' });
});

// Initialize database and start server
const startServer = async () => {
  try {
    await createTables();
    await createBasicTestData();
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log('');
      console.log('🧪 TEST ACCOUNTS:');
      console.log('📋 Professional: CPF 123.456.789-01 | Password: 123456 | Scheduling: ✅ ACTIVE');
      console.log('📋 Admin: CPF 000.000.000-00 | Password: admin123');
      console.log('');
      console.log('🔧 MANUAL SCHEDULING ACCESS:');
      console.log('   UPDATE users SET has_scheduling_access = TRUE WHERE id = [PROFESSIONAL_ID];');
      console.log('   UPDATE users SET scheduling_expires_at = \'2025-12-31 23:59:59\' WHERE id = [PROFESSIONAL_ID];');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();