import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';
import createUpload from './middleware/upload.js';
import { generateDocumentPDF } from './utils/documentGenerator.js';

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

// Serve static files from dist directory
app.use(express.static('dist'));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, password
    } = req.body;

    // Check if user already exists
    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cpf]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with client role and pending subscription
    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles,
        subscription_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW())
      RETURNING id, name, cpf, email, roles, subscription_status`,
      [name, cpf, email, phone, birth_date, address, address_number,
       address_complement, neighborhood, city, state, hashedPassword, ['client'], 'pending']
    );

    const user = result.rows[0];
    res.status(201).json({ message: 'Usuário criado com sucesso', user });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { cpf, password } = req.body;

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

    const needsRoleSelection = userData.roles.length > 1;

    res.json({ user: userData, needsRoleSelection });
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
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });

    const userData = {
      ...req.user,
      currentRole: role
    };

    res.json({ user: userData, token });
  } catch (error) {
    console.error('Role switch error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// User management routes
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date, u.address,
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
    res.status(500).json({ message: 'Erro ao buscar usuários' });
  }
});

app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date, u.address,
        u.address_number, u.address_complement, u.neighborhood, u.city, u.state,
        u.roles, u.percentage, u.category_id, u.subscription_status, u.subscription_expiry,
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

app.post('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, password, roles,
      percentage, category_id
    } = req.body;

    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cpf]);
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
      RETURNING id, name, cpf, email, roles`,
      [name, cpf, email, phone, birth_date, address, address_number,
       address_complement, neighborhood, city, state, hashedPassword, roles,
       percentage, category_id, roles.includes('client') ? 'pending' : null]
    );

    res.status(201).json({ message: 'Usuário criado com sucesso', user: result.rows[0] });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Erro ao criar usuário' });
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

    // Check if user exists
    const userResult = await pool.query('SELECT password_hash FROM users WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    let updateQuery = `
      UPDATE users SET 
        name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
        address_number = $6, address_complement = $7, neighborhood = $8,
        city = $9, state = $10, roles = $11, percentage = $12, category_id = $13,
        updated_at = NOW()
    `;
    let queryParams = [name, email, phone, birth_date, address, address_number,
                      address_complement, neighborhood, city, state, roles, percentage, category_id];

    // Handle password change
    if (newPassword && currentPassword) {
      const isValidPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
      if (!isValidPassword) {
        return res.status(400).json({ message: 'Senha atual incorreta' });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updateQuery += ', password_hash = $14';
      queryParams.push(hashedPassword);
    }

    updateQuery += ' WHERE id = $' + (queryParams.length + 1) + ' RETURNING id, name, email, roles';
    queryParams.push(id);

    const result = await pool.query(updateQuery, queryParams);
    res.json({ message: 'Usuário atualizado com sucesso', user: result.rows[0] });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Erro ao atualizar usuário' });
  }
});

app.put('/api/users/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { expiry_date } = req.body;

    const result = await pool.query(
      `UPDATE users SET 
        subscription_status = 'active',
        subscription_expiry = $1,
        updated_at = NOW()
      WHERE id = $2 AND 'client' = ANY(roles)
      RETURNING id, name, subscription_status, subscription_expiry`,
      [expiry_date, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cliente não encontrado' });
    }

    res.json({ message: 'Cliente ativado com sucesso', user: result.rows[0] });
  } catch (error) {
    console.error('Error activating user:', error);
    res.status(500).json({ message: 'Erro ao ativar cliente' });
  }
});

app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ message: 'Usuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Erro ao excluir usuário' });
  }
});

// Client lookup routes
app.get('/api/clients/lookup', authenticate, authorize(['professional', 'admin']), async (req, res) => {
  try {
    const { cpf } = req.query;

    const result = await pool.query(`
      SELECT id, name, cpf, subscription_status, subscription_expiry
      FROM users 
      WHERE cpf = $1 AND 'client' = ANY(roles)
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

// Dependents routes
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

app.get('/api/dependents/lookup', authenticate, authorize(['professional', 'admin']), async (req, res) => {
  try {
    const { cpf } = req.query;

    const result = await pool.query(`
      SELECT 
        d.id, d.name, d.cpf, d.birth_date,
        u.id as client_id, u.name as client_name, u.subscription_status as client_subscription_status
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

app.post('/api/dependents', authenticate, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    const existingDependent = await pool.query('SELECT id FROM dependents WHERE cpf = $1', [cpf]);
    if (existingDependent.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado como dependente' });
    }

    const result = await pool.query(
      'INSERT INTO dependents (client_id, name, cpf, birth_date, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING *',
      [client_id, name, cpf, birth_date]
    );

    res.status(201).json({ message: 'Dependente criado com sucesso', dependent: result.rows[0] });
  } catch (error) {
    console.error('Error creating dependent:', error);
    res.status(500).json({ message: 'Erro ao criar dependente' });
  }
});

app.put('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    const result = await pool.query(
      'UPDATE dependents SET name = $1, birth_date = $2, updated_at = NOW() WHERE id = $3 RETURNING *',
      [name, birth_date, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json({ message: 'Dependente atualizado com sucesso', dependent: result.rows[0] });
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro ao atualizar dependente' });
  }
});

app.delete('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM dependents WHERE id = $1', [id]);
    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro ao excluir dependente' });
  }
});

// Service categories routes
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM service_categories ORDER BY name');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Erro ao buscar categorias' });
  }
});

app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;
    const result = await pool.query(
      'INSERT INTO service_categories (name, description, created_at) VALUES ($1, $2, NOW()) RETURNING *',
      [name, description]
    );
    res.status(201).json({ message: 'Categoria criada com sucesso', category: result.rows[0] });
  } catch (error) {
    console.error('Error creating category:', error);
    res.status(500).json({ message: 'Erro ao criar categoria' });
  }
});

// Services routes
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
    res.status(500).json({ message: 'Erro ao buscar serviços' });
  }
});

app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;
    const result = await pool.query(
      'INSERT INTO services (name, description, base_price, category_id, is_base_service, created_at) VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *',
      [name, description, base_price, category_id, is_base_service]
    );
    res.status(201).json({ message: 'Serviço criado com sucesso', service: result.rows[0] });
  } catch (error) {
    console.error('Error creating service:', error);
    res.status(500).json({ message: 'Erro ao criar serviço' });
  }
});

app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(
      'UPDATE services SET name = $1, description = $2, base_price = $3, category_id = $4, is_base_service = $5, updated_at = NOW() WHERE id = $6 RETURNING *',
      [name, description, base_price, category_id, is_base_service, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Serviço não encontrado' });
    }

    res.json({ message: 'Serviço atualizado com sucesso', service: result.rows[0] });
  } catch (error) {
    console.error('Error updating service:', error);
    res.status(500).json({ message: 'Erro ao atualizar serviço' });
  }
});

app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM services WHERE id = $1', [id]);
    res.json({ message: 'Serviço excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting service:', error);
    res.status(500).json({ message: 'Erro ao excluir serviço' });
  }
});

// Professionals routes
app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.address, u.address_number,
        u.address_complement, u.neighborhood, u.city, u.state, u.roles,
        u.photo_url, sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals:', error);
    res.status(500).json({ message: 'Erro ao buscar profissionais' });
  }
});

// Private patients routes
app.get('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM private_patients 
      WHERE professional_id = $1 
      ORDER BY name
    `, [req.user.id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching private patients:', error);
    res.status(500).json({ message: 'Erro ao buscar pacientes' });
  }
});

app.post('/api/private-patients', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    const existingPatient = await pool.query(
      'SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2',
      [cpf, req.user.id]
    );

    if (existingPatient.rows.length > 0) {
      return res.status(400).json({ message: 'Paciente já cadastrado' });
    }

    const result = await pool.query(`
      INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW()) RETURNING *
    `, [req.user.id, name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, zip_code]);

    res.status(201).json({ message: 'Paciente criado com sucesso', patient: result.rows[0] });
  } catch (error) {
    console.error('Error creating private patient:', error);
    res.status(500).json({ message: 'Erro ao criar paciente' });
  }
});

app.put('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code
    } = req.body;

    const result = await pool.query(`
      UPDATE private_patients SET 
        name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
        address_number = $6, address_complement = $7, neighborhood = $8,
        city = $9, state = $10, zip_code = $11, updated_at = NOW()
      WHERE id = $12 AND professional_id = $13 RETURNING *
    `, [name, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, zip_code, id, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Paciente não encontrado' });
    }

    res.json({ message: 'Paciente atualizado com sucesso', patient: result.rows[0] });
  } catch (error) {
    console.error('Error updating private patient:', error);
    res.status(500).json({ message: 'Erro ao atualizar paciente' });
  }
});

app.delete('/api/private-patients/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM private_patients WHERE id = $1 AND professional_id = $2', [id, req.user.id]);
    res.json({ message: 'Paciente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting private patient:', error);
    res.status(500).json({ message: 'Erro ao excluir paciente' });
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
    console.error('Error fetching locations:', error);
    res.status(500).json({ message: 'Erro ao buscar locais' });
  }
});

app.post('/api/attendance-locations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      name, address, address_number, address_complement, neighborhood,
      city, state, zip_code, phone, is_default
    } = req.body;

    // If this is set as default, remove default from others
    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1',
        [req.user.id]
      );
    }

    const result = await pool.query(`
      INSERT INTO attendance_locations (
        professional_id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW()) RETURNING *
    `, [req.user.id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default]);

    res.status(201).json({ message: 'Local criado com sucesso', location: result.rows[0] });
  } catch (error) {
    console.error('Error creating location:', error);
    res.status(500).json({ message: 'Erro ao criar local' });
  }
});

app.put('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, address, address_number, address_complement, neighborhood,
      city, state, zip_code, phone, is_default
    } = req.body;

    // If this is set as default, remove default from others
    if (is_default) {
      await pool.query(
        'UPDATE attendance_locations SET is_default = false WHERE professional_id = $1 AND id != $2',
        [req.user.id, id]
      );
    }

    const result = await pool.query(`
      UPDATE attendance_locations SET 
        name = $1, address = $2, address_number = $3, address_complement = $4,
        neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9,
        is_default = $10, updated_at = NOW()
      WHERE id = $11 AND professional_id = $12 RETURNING *
    `, [name, address, address_number, address_complement, neighborhood,
        city, state, zip_code, phone, is_default, id, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Local não encontrado' });
    }

    res.json({ message: 'Local atualizado com sucesso', location: result.rows[0] });
  } catch (error) {
    console.error('Error updating location:', error);
    res.status(500).json({ message: 'Erro ao atualizar local' });
  }
});

app.delete('/api/attendance-locations/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM attendance_locations WHERE id = $1 AND professional_id = $2', [id, req.user.id]);
    res.json({ message: 'Local excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting location:', error);
    res.status(500).json({ message: 'Erro ao excluir local' });
  }
});

// Consultations routes
app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id, c.date, c.value,
        s.name as service_name,
        u.name as professional_name,
        COALESCE(u2.name, d.name, pp.name) as client_name,
        CASE 
          WHEN c.dependent_id IS NOT NULL THEN true
          ELSE false
        END as is_dependent
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      JOIN users u ON c.professional_id = u.id
      LEFT JOIN users u2 ON c.client_id = u2.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
    `;

    const params = [];

    if (req.user.currentRole === 'client') {
      query += ' WHERE (c.client_id = $1 OR d.client_id = $1)';
      params.push(req.user.id);
    } else if (req.user.currentRole === 'professional') {
      query += ' WHERE c.professional_id = $1';
      params.push(req.user.id);
    }

    query += ' ORDER BY c.date DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching consultations:', error);
    res.status(500).json({ message: 'Erro ao buscar consultas' });
  }
});

app.post('/api/consultations', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      client_id, dependent_id, private_patient_id, service_id, location_id,
      value, date, appointment_date, appointment_time, create_appointment
    } = req.body;

    // Create consultation
    const consultationResult = await pool.query(`
      INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id, service_id,
        location_id, value, date, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) RETURNING *
    `, [client_id, dependent_id, private_patient_id, req.user.id, service_id, location_id, value, date]);

    const consultation = consultationResult.rows[0];
    let appointment = null;

    // Create appointment if requested
    if (create_appointment && appointment_date && appointment_time) {
      const appointmentResult = await pool.query(`
        INSERT INTO appointments (
          professional_id, private_patient_id, client_id, dependent_id,
          service_id, appointment_date, appointment_time, location_id,
          value, status, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'scheduled', NOW()) RETURNING *
      `, [req.user.id, private_patient_id, client_id, dependent_id, service_id,
          appointment_date, appointment_time, location_id, value]);

      appointment = appointmentResult.rows[0];
    }

    res.status(201).json({
      message: 'Consulta registrada com sucesso',
      consultation,
      appointment
    });
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro ao registrar consulta' });
  }
});

// Scheduling/Appointments routes
app.get('/api/scheduling/appointments', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    let query = `
      SELECT 
        a.id, a.appointment_date, a.appointment_time, a.value, a.status, a.notes,
        COALESCE(u.name, d.name, pp.name) as patient_name,
        COALESCE(u.cpf, d.cpf, pp.cpf) as patient_cpf,
        s.name as service_name,
        al.name as location_name,
        al.address as location_address,
        a.private_patient_id, a.client_id, a.dependent_id
      FROM appointments a
      LEFT JOIN users u ON a.client_id = u.id
      LEFT JOIN dependents d ON a.dependent_id = d.id
      LEFT JOIN private_patients pp ON a.private_patient_id = pp.id
      LEFT JOIN services s ON a.service_id = s.id
      LEFT JOIN attendance_locations al ON a.location_id = al.id
      WHERE a.professional_id = $1
    `;

    const params = [req.user.id];

    if (start_date && end_date) {
      query += ' AND a.appointment_date BETWEEN $2 AND $3';
      params.push(start_date, end_date);
    }

    query += ' ORDER BY a.appointment_date DESC, a.appointment_time DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).json({ message: 'Erro ao buscar agendamentos' });
  }
});

app.post('/api/scheduling/appointments', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const {
      private_patient_id, service_id, appointment_date, appointment_time,
      location_id, notes, value
    } = req.body;

    const result = await pool.query(`
      INSERT INTO appointments (
        professional_id, private_patient_id, service_id, appointment_date,
        appointment_time, location_id, notes, value, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'scheduled', NOW()) RETURNING *
    `, [req.user.id, private_patient_id, service_id, appointment_date,
        appointment_time, location_id, notes, value]);

    res.status(201).json({ message: 'Agendamento criado com sucesso', appointment: result.rows[0] });
  } catch (error) {
    console.error('Error creating appointment:', error);
    res.status(500).json({ message: 'Erro ao criar agendamento' });
  }
});

app.put('/api/scheduling/appointments/:id/status', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status, notes } = req.body;

    // Get appointment details first
    const appointmentResult = await pool.query(`
      SELECT 
        a.*,
        COALESCE(u.name, d.name, pp.name) as patient_name,
        s.name as service_name
      FROM appointments a
      LEFT JOIN users u ON a.client_id = u.id
      LEFT JOIN dependents d ON a.dependent_id = d.id
      LEFT JOIN private_patients pp ON a.private_patient_id = pp.id
      LEFT JOIN services s ON a.service_id = s.id
      WHERE a.id = $1 AND a.professional_id = $2
    `, [id, req.user.id]);

    if (appointmentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Agendamento não encontrado' });
    }

    const appointment = appointmentResult.rows[0];

    // Update appointment status
    await pool.query(`
      UPDATE appointments SET 
        status = $1, notes = $2, updated_at = NOW()
      WHERE id = $3 AND professional_id = $4
    `, [status, notes, id, req.user.id]);

    // If status is 'completed', create consultation record
    if (status === 'completed') {
      // Check if consultation already exists for this appointment
      const existingConsultation = await pool.query(
        'SELECT id FROM consultations WHERE appointment_id = $1',
        [id]
      );

      if (existingConsultation.rows.length === 0) {
        // Create consultation record
        const consultationDate = new Date(`${appointment.appointment_date}T${appointment.appointment_time}`);
        
        await pool.query(`
          INSERT INTO consultations (
            client_id, dependent_id, private_patient_id, professional_id,
            service_id, location_id, value, date, appointment_id, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
        `, [
          appointment.client_id,
          appointment.dependent_id,
          appointment.private_patient_id,
          appointment.professional_id,
          appointment.service_id,
          appointment.location_id,
          appointment.value,
          consultationDate.toISOString(),
          id
        ]);
      }
    }

    res.json({ 
      message: status === 'completed' 
        ? 'Status atualizado e consulta registrada nos relatórios!'
        : 'Status atualizado com sucesso!'
    });
  } catch (error) {
    console.error('Error updating appointment status:', error);
    res.status(500).json({ message: 'Erro ao atualizar status' });
  }
});

app.delete('/api/scheduling/appointments/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM appointments WHERE id = $1 AND professional_id = $2', [id, req.user.id]);
    res.json({ message: 'Agendamento excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting appointment:', error);
    res.status(500).json({ message: 'Erro ao excluir agendamento' });
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
      WHERE mr.professional_id = $1
      ORDER BY mr.created_at DESC
    `, [req.user.id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical records:', error);
    res.status(500).json({ message: 'Erro ao buscar prontuários' });
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
        professional_id, private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, vital_signs, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW()) RETURNING *
    `, [req.user.id, private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, JSON.stringify(vital_signs)]);

    res.status(201).json({ message: 'Prontuário criado com sucesso', record: result.rows[0] });
  } catch (error) {
    console.error('Error creating medical record:', error);
    res.status(500).json({ message: 'Erro ao criar prontuário' });
  }
});

app.put('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      chief_complaint, history_present_illness, past_medical_history,
      medications, allergies, physical_examination, diagnosis,
      treatment_plan, notes, vital_signs
    } = req.body;

    const result = await pool.query(`
      UPDATE medical_records SET 
        chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
        medications = $4, allergies = $5, physical_examination = $6,
        diagnosis = $7, treatment_plan = $8, notes = $9, vital_signs = $10,
        updated_at = NOW()
      WHERE id = $11 AND professional_id = $12 RETURNING *
    `, [chief_complaint, history_present_illness, past_medical_history,
        medications, allergies, physical_examination, diagnosis,
        treatment_plan, notes, JSON.stringify(vital_signs), id, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }

    res.json({ message: 'Prontuário atualizado com sucesso', record: result.rows[0] });
  } catch (error) {
    console.error('Error updating medical record:', error);
    res.status(500).json({ message: 'Erro ao atualizar prontuário' });
  }
});

app.delete('/api/medical-records/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM medical_records WHERE id = $1 AND professional_id = $2', [id, req.user.id]);
    res.json({ message: 'Prontuário excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting medical record:', error);
    res.status(500).json({ message: 'Erro ao excluir prontuário' });
  }
});

// Medical documents routes
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        md.*,
        pp.name as patient_name
      FROM medical_documents md
      LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
      WHERE md.professional_id = $1
      ORDER BY md.created_at DESC
    `, [req.user.id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro ao buscar documentos' });
  }
});

app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { title, document_type, private_patient_id, template_data } = req.body;

    // Generate document
    const documentResult = await generateDocumentPDF(document_type, template_data);

    // Save document record
    const result = await pool.query(`
      INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type,
        document_url, created_at
      ) VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *
    `, [req.user.id, private_patient_id, title, document_type, documentResult.url]);

    res.status(201).json({
      message: 'Documento criado com sucesso',
      document: result.rows[0],
      title,
      documentUrl: documentResult.url
    });
  } catch (error) {
    console.error('Error creating medical document:', error);
    res.status(500).json({ message: 'Erro ao criar documento' });
  }
});

// Image upload route
app.post('/api/upload-image', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const upload = createUpload();
    
    upload.single('image')(req, res, async (err) => {
      if (err) {
        console.error('Upload error:', err);
        return res.status(400).json({ message: err.message || 'Erro no upload da imagem' });
      }

      if (!req.file) {
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      const imageUrl = req.file.path;

      // Update user's photo_url
      await pool.query(
        'UPDATE users SET photo_url = $1, updated_at = NOW() WHERE id = $2',
        [imageUrl, req.user.id]
      );

      res.json({
        message: 'Imagem enviada com sucesso',
        imageUrl: imageUrl
      });
    });
  } catch (error) {
    console.error('Error in upload route:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Reports routes
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    // Get total revenue
    const totalResult = await pool.query(`
      SELECT COALESCE(SUM(value), 0) as total_revenue
      FROM consultations
      WHERE date BETWEEN $1 AND $2
    `, [start_date, end_date]);

    // Get revenue by professional
    const professionalResult = await pool.query(`
      SELECT 
        u.name as professional_name,
        u.percentage as professional_percentage,
        COALESCE(SUM(c.value), 0) as revenue,
        COUNT(c.id) as consultation_count,
        COALESCE(SUM(c.value * (u.percentage / 100.0)), 0) as professional_payment,
        COALESCE(SUM(c.value * ((100 - u.percentage) / 100.0)), 0) as clinic_revenue
      FROM users u
      LEFT JOIN consultations c ON u.id = c.professional_id 
        AND c.date BETWEEN $1 AND $2
      WHERE 'professional' = ANY(u.roles)
      GROUP BY u.id, u.name, u.percentage
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    // Get revenue by service
    const serviceResult = await pool.query(`
      SELECT 
        s.name as service_name,
        COALESCE(SUM(c.value), 0) as revenue,
        COUNT(c.id) as consultation_count
      FROM services s
      LEFT JOIN consultations c ON s.id = c.service_id 
        AND c.date BETWEEN $1 AND $2
      GROUP BY s.id, s.name
      HAVING COUNT(c.id) > 0
      ORDER BY revenue DESC
    `, [start_date, end_date]);

    res.json({
      total_revenue: parseFloat(totalResult.rows[0].total_revenue),
      revenue_by_professional: professionalResult.rows.map(row => ({
        ...row,
        revenue: parseFloat(row.revenue),
        professional_payment: parseFloat(row.professional_payment),
        clinic_revenue: parseFloat(row.clinic_revenue)
      })),
      revenue_by_service: serviceResult.rows.map(row => ({
        ...row,
        revenue: parseFloat(row.revenue)
      }))
    });
  } catch (error) {
    console.error('Error generating revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    // Get professional's percentage
    const userResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = userResult.rows[0]?.percentage || 50;

    // Get consultations for the professional
    const consultationsResult = await pool.query(`
      SELECT 
        c.date, c.value as total_value,
        COALESCE(u.name, d.name, pp.name) as client_name,
        s.name as service_name,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN c.value
          ELSE c.value * ($3 / 100.0)
        END as amount_to_pay
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN services s ON c.service_id = s.id
      WHERE c.professional_id = $1 AND c.date BETWEEN $2 AND $4
      ORDER BY c.date DESC
    `, [req.user.id, start_date, 100 - professionalPercentage, end_date]);

    // Calculate summary
    const totalConsultations = consultationsResult.rows.length;
    const convenioConsultations = consultationsResult.rows.filter(c => !c.client_name || c.client_name !== 'Private').length;
    const privateConsultations = consultationsResult.rows.filter(c => c.client_name === 'Private').length;
    const totalRevenue = consultationsResult.rows.reduce((sum, c) => sum + parseFloat(c.total_value), 0);
    const amountToPay = consultationsResult.rows.reduce((sum, c) => sum + parseFloat(c.amount_to_pay), 0);

    res.json({
      summary: {
        professional_percentage: professionalPercentage,
        total_revenue: totalRevenue,
        consultation_count: totalConsultations,
        amount_to_pay: amountToPay
      },
      consultations: consultationsResult.rows.map(row => ({
        ...row,
        total_value: parseFloat(row.total_value),
        amount_to_pay: parseFloat(row.amount_to_pay)
      }))
    });
  } catch (error) {
    console.error('Error generating professional revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

app.get('/api/reports/professional-detailed', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    // Get professional's percentage
    const userResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [req.user.id]
    );

    const professionalPercentage = userResult.rows[0]?.percentage || 50;

    // Get detailed consultation data
    const consultationsResult = await pool.query(`
      SELECT 
        c.value,
        CASE 
          WHEN c.private_patient_id IS NOT NULL THEN 'private'
          ELSE 'convenio'
        END as consultation_type
      FROM consultations c
      WHERE c.professional_id = $1 AND c.date BETWEEN $2 AND $3
    `, [req.user.id, start_date, end_date]);

    const consultations = consultationsResult.rows;
    
    // Calculate metrics
    const totalConsultations = consultations.length;
    const convenioConsultations = consultations.filter(c => c.consultation_type === 'convenio').length;
    const privateConsultations = consultations.filter(c => c.consultation_type === 'private').length;
    
    const convenioRevenue = consultations
      .filter(c => c.consultation_type === 'convenio')
      .reduce((sum, c) => sum + parseFloat(c.value), 0);
    
    const privateRevenue = consultations
      .filter(c => c.consultation_type === 'private')
      .reduce((sum, c) => sum + parseFloat(c.value), 0);
    
    const totalRevenue = convenioRevenue + privateRevenue;
    const amountToPay = convenioRevenue * ((100 - professionalPercentage) / 100);

    res.json({
      summary: {
        total_consultations: totalConsultations,
        convenio_consultations: convenioConsultations,
        private_consultations: privateConsultations,
        total_revenue: totalRevenue,
        convenio_revenue: convenioRevenue,
        private_revenue: privateRevenue,
        professional_percentage: professionalPercentage,
        amount_to_pay: amountToPay
      }
    });
  } catch (error) {
    console.error('Error generating detailed professional report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório detalhado' });
  }
});

app.get('/api/reports/clients-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        city, state,
        COUNT(*) as client_count,
        COUNT(CASE WHEN subscription_status = 'active' THEN 1 END) as active_clients,
        COUNT(CASE WHEN subscription_status = 'pending' THEN 1 END) as pending_clients,
        COUNT(CASE WHEN subscription_status = 'expired' THEN 1 END) as expired_clients
      FROM users 
      WHERE 'client' = ANY(roles) AND city IS NOT NULL AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error generating clients by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

app.get('/api/reports/professionals-by-city', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.city, u.state,
        COUNT(u.id) as total_professionals,
        json_agg(
          json_build_object(
            'category_name', COALESCE(sc.name, 'Sem categoria'),
            'count', 1
          )
        ) as categories
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles) AND u.city IS NOT NULL AND u.city != ''
      GROUP BY u.city, u.state
      ORDER BY total_professionals DESC
    `);

    // Process the aggregated data
    const processedResult = result.rows.map(row => {
      const categoryMap = new Map();
      
      row.categories.forEach(cat => {
        const name = cat.category_name;
        categoryMap.set(name, (categoryMap.get(name) || 0) + 1);
      });

      return {
        city: row.city,
        state: row.state,
        total_professionals: parseInt(row.total_professionals),
        categories: Array.from(categoryMap.entries()).map(([name, count]) => ({
          category_name: name,
          count: count
        }))
      };
    });

    res.json(processedResult);
  } catch (error) {
    console.error('Error generating professionals by city report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

// Admin scheduling access routes
app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone,
        sc.name as category_name,
        sa.has_access as has_scheduling_access,
        sa.expires_at as access_expires_at,
        sa.granted_by as access_granted_by,
        sa.granted_at as access_granted_at
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      LEFT JOIN scheduling_access sa ON u.id = sa.professional_id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals scheduling access:', error);
    res.status(500).json({ message: 'Erro ao buscar dados de acesso' });
  }
});

app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    // Upsert scheduling access
    await pool.query(`
      INSERT INTO scheduling_access (professional_id, has_access, expires_at, granted_by, granted_at, reason)
      VALUES ($1, true, $2, $3, NOW(), $4)
      ON CONFLICT (professional_id) 
      DO UPDATE SET 
        has_access = true,
        expires_at = $2,
        granted_by = $3,
        granted_at = NOW(),
        reason = $4
    `, [professional_id, expires_at, req.user.name, reason]);

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
      UPDATE scheduling_access 
      SET has_access = false, revoked_at = NOW(), revoked_by = $1
      WHERE professional_id = $2
    `, [req.user.name, professional_id]);

    res.json({ message: 'Acesso revogado com sucesso' });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro ao revogar acesso' });
  }
});

// Payment routes
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    // This would integrate with MercadoPago for subscription payments
    res.json({
      message: 'Subscription payment created',
      init_point: 'https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=example'
    });
  } catch (error) {
    console.error('Error creating subscription:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
  }
});

app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;
    
    // This would integrate with MercadoPago for professional payments
    res.json({
      message: 'Professional payment created',
      init_point: 'https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=example'
    });
  } catch (error) {
    console.error('Error creating professional payment:', error);
    res.status(500).json({ message: 'Erro ao criar pagamento' });
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

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Environment: ${process.env.NODE_ENV || 'development'}`);
});