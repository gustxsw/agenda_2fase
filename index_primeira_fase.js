import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import { pool } from './db.js';
import { authenticate, authorize } from './middleware/auth.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Get __dirname equivalent for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3000',
      'https://www.cartaoquiroferreira.com.br',
      'https://cartaoquiroferreira.com.br'
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// 🔥 HEALTH CHECK ROUTE
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    message: 'Server is running properly',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Serve static files from dist directory
app.use(express.static(path.join(__dirname, '../dist')));

// Initialize database tables
const initDatabase = async () => {
  try {
    console.log('🔥 Initializing database...');
    
    // Create users table with roles array and photo_url
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
        address_complement TEXT,
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        password VARCHAR(255) NOT NULL,
        roles TEXT[] NOT NULL DEFAULT '{}',
        percentage DECIMAL(5,2),
        category_id INTEGER,
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry DATE,
        photo_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add photo_url column if it doesn't exist
    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'users' AND column_name = 'photo_url'
        ) THEN
          ALTER TABLE users ADD COLUMN photo_url TEXT;
        END IF;
      END $$;
    `);

    // Create service categories table FIRST
    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 🔥 Insert default service category BEFORE creating services table
    const categoryExists = await pool.query('SELECT id FROM service_categories WHERE name = $1', ['Fisioterapia']);
    let categoryId = 1;
    
    if (categoryExists.rows.length === 0) {
      const categoryResult = await pool.query(`
        INSERT INTO service_categories (name, description) 
        VALUES ($1, $2)
        RETURNING id
      `, ['Fisioterapia', 'Serviços de fisioterapia e reabilitação']);
      categoryId = categoryResult.rows[0].id;
      console.log('✅ Default service category created with ID:', categoryId);
    } else {
      categoryId = categoryExists.rows[0].id;
      console.log('✅ Default service category already exists with ID:', categoryId);
    }

    // Create services table with proper foreign key reference
    await pool.query(`
      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        base_price DECIMAL(10,2) NOT NULL,
        category_id INTEGER REFERENCES service_categories(id) ON DELETE SET NULL,
        is_base_service BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create dependents table
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

    // Create consultations table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        professional_id INTEGER REFERENCES users(id) NOT NULL,
        service_id INTEGER REFERENCES services(id) NOT NULL,
        date TIMESTAMP NOT NULL,
        value DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create payment tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS client_payments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) NOT NULL,
        external_reference VARCHAR(255) UNIQUE NOT NULL,
        preference_id VARCHAR(255),
        payment_id VARCHAR(255),
        status VARCHAR(50) DEFAULT 'pending',
        amount DECIMAL(10,2) NOT NULL,
        description TEXT,
        payment_method VARCHAR(100),
        payment_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_payments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) NOT NULL,
        external_reference VARCHAR(255) UNIQUE NOT NULL,
        preference_id VARCHAR(255),
        payment_id VARCHAR(255),
        status VARCHAR(50) DEFAULT 'pending',
        amount DECIMAL(10,2) NOT NULL,
        description TEXT,
        payment_method VARCHAR(100),
        payment_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Insert default admin user if not exists
    const adminExists = await pool.query('SELECT id FROM users WHERE cpf = $1', ['00000000000']);
    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.query(`
        INSERT INTO users (name, cpf, password, roles) 
        VALUES ($1, $2, $3, $4)
      `, ['Administrador', '00000000000', hashedPassword, ['admin']]);
      console.log('✅ Default admin user created');
    }

    // 🔥 Insert default service with proper category reference
    const serviceExists = await pool.query('SELECT id FROM services WHERE name = $1', ['Consulta Fisioterapia']);
    if (serviceExists.rows.length === 0) {
      await pool.query(`
        INSERT INTO services (name, description, base_price, category_id, is_base_service) 
        VALUES ($1, $2, $3, $4, $5)
      `, ['Consulta Fisioterapia', 'Consulta básica de fisioterapia', 80.00, categoryId, true]);
      console.log('✅ Default service created with category ID:', categoryId);
    }

    // 🔥 Add foreign key constraint for users.category_id if it doesn't exist
    try {
      await pool.query(`
        DO $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM information_schema.table_constraints 
            WHERE constraint_name = 'users_category_id_fkey'
          ) THEN
            ALTER TABLE users 
            ADD CONSTRAINT users_category_id_fkey 
            FOREIGN KEY (category_id) REFERENCES service_categories(id) ON DELETE SET NULL;
          END IF;
        END $$;
      `);
      console.log('✅ Foreign key constraint for users.category_id ensured');
    } catch (error) {
      console.log('⚠️ Foreign key constraint already exists or could not be added:', error.message);
    }

    console.log('✅ Database initialized successfully!');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    throw error; // Re-throw to prevent server from starting with broken DB
  }
};

// Helper function to get base URL
const getBaseUrl = (req) => {
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers['x-forwarded-host'] || req.get('host');
  return `${protocol}://${host}`;
};

// 🔥 FIXED: Image upload route with better error handling and validation
app.post('/api/upload-image', authenticate, authorize(['professional']), async (req, res) => {
  try {
    console.log('🔄 Starting image upload process...');
    
    // Check Cloudinary environment variables
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;
    
    console.log('🔍 Environment variables check:');
    console.log('CLOUDINARY_CLOUD_NAME:', cloudName ? '✅ Found' : '❌ Missing');
    console.log('CLOUDINARY_API_KEY:', apiKey ? '✅ Found' : '❌ Missing');
    console.log('CLOUDINARY_API_SECRET:', apiSecret ? '✅ Found' : '❌ Missing');
    
    if (!cloudName || !apiKey || !apiSecret) {
      return res.status(500).json({ 
        message: 'Configuração do Cloudinary não encontrada',
        error: 'Verifique as variáveis de ambiente CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY e CLOUDINARY_API_SECRET'
      });
    }
    
    // Import upload middleware dynamically
    const { default: createUpload } = await import('./middleware/upload.js');
    
    let upload;
    try {
      upload = createUpload();
    } catch (uploadError) {
      console.error('❌ Error creating upload middleware:', uploadError);
      return res.status(500).json({ 
        message: 'Erro na configuração do upload',
        error: uploadError.message 
      });
    }
    
    // Use multer middleware
    upload.single('image')(req, res, async (err) => {
      try {
        if (err) {
          console.error('❌ Multer error:', err);
          return res.status(400).json({ 
            message: 'Erro no upload da imagem',
            error: err.message 
          });
        }

        if (!req.file) {
          console.error('❌ No file received');
          return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
        }

        console.log('✅ File uploaded to Cloudinary:', req.file.path);
        
        const imageUrl = req.file.path; // Cloudinary URL
        const userId = req.user.id;

        console.log('🔄 Updating database with image URL:', imageUrl);

        // Update user's photo_url in database
        const result = await pool.query(
          'UPDATE users SET photo_url = $1, updated_at = NOW() WHERE id = $2 RETURNING photo_url',
          [imageUrl, userId]
        );

        if (result.rows.length === 0) {
          throw new Error('Usuário não encontrado');
        }

        console.log('✅ Database updated successfully');

        res.json({
          message: 'Imagem enviada com sucesso',
          imageUrl: imageUrl
        });

      } catch (dbError) {
        console.error('❌ Database error:', dbError);
        res.status(500).json({ 
          message: 'Erro ao salvar imagem no banco de dados',
          error: dbError.message 
        });
      }
    });

  } catch (error) {
    console.error('❌ General upload error:', error);
    res.status(500).json({ 
      message: 'Erro interno do servidor',
      error: error.message 
    });
  }
});

// MercadoPago routes
app.post('/api/create-subscription', authenticate, async (req, res) => {
  try {
    const { user_id, dependent_ids = [] } = req.body;
    const accessToken = process.env.MP_ACCESS_TOKEN;
    
    if (!accessToken) {
      throw new Error('MercadoPago access token not configured');
    }

    // Calculate amount (R$250 titular + R$50 per dependent)
    const titularPrice = 250;
    const dependentPrice = 50;
    const totalPeople = 1 + dependent_ids.length;
    const amount = titularPrice + (dependent_ids.length * dependentPrice);
    
    const externalReference = `subscription_${user_id}_${Date.now()}`;
    const baseUrl = getBaseUrl(req);
    
    const preferenceData = {
      items: [
        {
          id: 'subscription',
          title: `Assinatura Convênio Quiro Ferreira - ${totalPeople} pessoa(s)`,
          description: `Assinatura mensal - Titular (R$ ${titularPrice}) + ${dependent_ids.length} dependente(s) (R$ ${dependentPrice} cada)`,
          quantity: 1,
          unit_price: amount,
          currency_id: 'BRL'
        }
      ],
      payer: {
        name: req.user.name,
        email: 'cliente@cartaoquiroferreira.com.br'
      },
      payment_methods: {
        excluded_payment_types: [],
        excluded_payment_methods: [],
        installments: 12
      },
      back_urls: {
        success: `${baseUrl}/client?payment=success`,
        failure: `${baseUrl}/client?payment=failure`, 
        pending: `${baseUrl}/client?payment=pending`
      },
      auto_return: 'approved',
      external_reference: externalReference,
      notification_url: `${baseUrl}/api/webhooks/payment-success`,
      statement_descriptor: 'QUIRO FERREIRA',
      expires: false
    };

    const response = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(preferenceData)
    });

    if (!response.ok) {
      const errorData = await response.text();
      throw new Error(`MercadoPago API Error: ${response.status} - ${errorData}`);
    }

    const preference = await response.json();

    await pool.query(`
      INSERT INTO client_payments (user_id, external_reference, preference_id, amount, description, status)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [
      user_id,
      externalReference,
      preference.id,
      amount,
      `Assinatura mensal - ${totalPeople} pessoa(s)`,
      'pending'
    ]);

    res.json({
      preference_id: preference.id,
      init_point: preference.init_point,
      sandbox_init_point: preference.sandbox_init_point,
      external_reference: externalReference
    });

  } catch (error) {
    console.error('Error creating subscription:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento',
      error: error.message 
    });
  }
});

app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;
    const accessToken = process.env.MP_ACCESS_TOKEN;
    
    if (!accessToken) {
      throw new Error('MercadoPago access token not configured');
    }

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor inválido' });
    }

    const externalReference = `professional_${req.user.id}_${Date.now()}`;
    const baseUrl = getBaseUrl(req);
    
    const preferenceData = {
      items: [
        {
          id: 'professional_payment',
          title: `Pagamento ao Convênio - ${req.user.name}`,
          description: `Repasse ao convênio referente às consultas realizadas`,
          quantity: 1,
          unit_price: parseFloat(amount),
          currency_id: 'BRL'
        }
      ],
      payer: {
        name: req.user.name,
        email: 'profissional@cartaoquiroferreira.com.br'
      },
      payment_methods: {
        excluded_payment_types: [],
        excluded_payment_methods: [],
        installments: 12
      },
      back_urls: {
        success: `${baseUrl}/professional?payment=success`,
        failure: `${baseUrl}/professional?payment=failure`,
        pending: `${baseUrl}/professional?payment=pending`
      },
      auto_return: 'approved',
      external_reference: externalReference,
      notification_url: `${baseUrl}/api/webhooks/payment-success`,
      statement_descriptor: 'QUIRO FERREIRA',
      expires: false
    };

    const response = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(preferenceData)
    });

    if (!response.ok) {
      const errorData = await response.text();
      throw new Error(`MercadoPago API Error: ${response.status} - ${errorData}`);
    }

    const preference = await response.json();

    await pool.query(`
      INSERT INTO professional_payments (professional_id, external_reference, preference_id, amount, description, status)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [
      req.user.id,
      externalReference,
      preference.id,
      amount,
      'Repasse ao convênio',
      'pending'
    ]);

    res.json({
      preference_id: preference.id,
      init_point: preference.init_point,
      sandbox_init_point: preference.sandbox_init_point,
      external_reference: externalReference
    });

  } catch (error) {
    console.error('Error creating professional payment:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento',
      error: error.message 
    });
  }
});

// Webhook routes
app.post('/api/webhooks/payment-success', async (req, res) => {
  try {
    const { type, data } = req.body;
    
    if (type === 'payment') {
      const paymentId = data.id;
      
      const accessToken = process.env.MP_ACCESS_TOKEN;
      const paymentResponse = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });
      
      if (paymentResponse.ok) {
        const paymentData = await paymentResponse.json();
        const externalReference = paymentData.external_reference;
        const status = paymentData.status;
        
        if (status === 'approved') {
          if (externalReference.startsWith('subscription_')) {
            await pool.query(`
              UPDATE client_payments 
              SET status = $1, payment_id = $2, payment_method = $3, payment_date = NOW(), updated_at = NOW()
              WHERE external_reference = $4
            `, ['approved', paymentId, paymentData.payment_method_id, externalReference]);
            
            const userId = externalReference.split('_')[1];
            const expiryDate = new Date();
            expiryDate.setMonth(expiryDate.getMonth() + 1);
            
            await pool.query(`
              UPDATE users 
              SET subscription_status = 'active', subscription_expiry = $1, updated_at = NOW()
              WHERE id = $2
            `, [expiryDate, userId]);
            
          } else if (externalReference.startsWith('professional_')) {
            await pool.query(`
              UPDATE professional_payments 
              SET status = $1, payment_id = $2, payment_method = $3, payment_date = NOW(), updated_at = NOW()
              WHERE external_reference = $4
            `, ['approved', paymentId, paymentData.payment_method_id, externalReference]);
          }
        }
      }
    }
    
    res.status(200).json({ received: true });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Auth routes
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
      return res.status(401).json({ message: 'CPF ou senha inválidos' });
    }

    const user = result.rows[0];

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ message: 'CPF ou senha inválidos' });
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
      { 
        id: user.id, 
        cpf: user.cpf,
        currentRole: role,
        roles: user.roles
      },
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
      token,
      user: userData
    });

  } catch (error) {
    console.error('Role selection error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/switch-role', authenticate, async (req, res) => {
  try {
    const { role } = req.body;
    const userId = req.user.id;

    if (!role) {
      return res.status(400).json({ message: 'Role é obrigatória' });
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
      { 
        id: user.id, 
        cpf: user.cpf,
        currentRole: role,
        roles: user.roles
      },
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
      message: 'Role alterada com sucesso',
      token,
      user: userData
    });

  } catch (error) {
    console.error('Role switch error:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date,
      address, address_number, address_complement,
      neighborhood, city, state, password
    } = req.body;

    if (!name || !cpf || !password) {
      return res.status(400).json({ message: 'Nome, CPF e senha são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    if (cleanCpf.length !== 11) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
    }

    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'CPF já cadastrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(`
      INSERT INTO users (
        name, cpf, email, phone, birth_date,
        address, address_number, address_complement,
        neighborhood, city, state, password, roles
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id, name, cpf, roles
    `, [
      name.trim(),
      cleanCpf,
      email?.trim() || null,
      phone?.replace(/\D/g, '') || null,
      birth_date || null,
      address?.trim() || null,
      address_number?.trim() || null,
      address_complement?.trim() || null,
      neighborhood?.trim() || null,
      city?.trim() || null,
      state || null,
      hashedPassword,
      ['client']
    ]);

    const newUser = result.rows[0];

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: {
        id: newUser.id,
        name: newUser.name,
        cpf: newUser.cpf,
        roles: newUser.roles
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === '23505') {
      res.status(409).json({ message: 'CPF já cadastrado' });
    } else {
      res.status(500).json({ message: 'Erro interno do servidor' });
    }
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout realizado com sucesso' });
});

// Protected routes
app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date,
        u.address, u.address_number, u.address_complement,
        u.neighborhood, u.city, u.state, u.roles, u.percentage,
        u.category_id, u.created_at, u.subscription_status, u.subscription_expiry,
        u.photo_url, sc.name as category_name
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

// 🔥 UPDATED: Route to activate client subscription with custom expiry date
app.put('/api/users/:id/activate', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { expiry_date } = req.body;
    
    // Validate expiry date
    if (!expiry_date) {
      return res.status(400).json({ message: 'Data de expiração é obrigatória' });
    }
    
    const expiryDate = new Date(expiry_date);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    if (expiryDate <= today) {
      return res.status(400).json({ message: 'Data de expiração deve ser posterior à data atual' });
    }
    
    // Check if user exists and is a client
    const userResult = await pool.query(
      'SELECT id, name, roles FROM users WHERE id = $1',
      [id]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    const user = userResult.rows[0];
    
    if (!user.roles || !user.roles.includes('client')) {
      return res.status(400).json({ message: 'Apenas clientes podem ter assinatura ativada' });
    }
    
    // Set subscription as active with custom expiry date
    const result = await pool.query(`
      UPDATE users 
      SET subscription_status = 'active', 
          subscription_expiry = $1, 
          updated_at = NOW()
      WHERE id = $2
      RETURNING id, name, subscription_status, subscription_expiry
    `, [expiryDate, id]);
    
    res.json({
      message: 'Cliente ativado com sucesso',
      user: result.rows[0]
    });
    
  } catch (error) {
    console.error('Error activating client:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// 🔥 FIXED: Add missing CRUD routes for users
app.post('/api/users', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const {
      name, cpf, email, phone, birth_date,
      address, address_number, address_complement,
      neighborhood, city, state, password, roles,
      percentage, category_id
    } = req.body;

    if (!name || !cpf || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Nome, CPF, senha e pelo menos uma role são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    if (cleanCpf.length !== 11) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos' });
    }

    const existingUser = await pool.query('SELECT id FROM users WHERE cpf = $1', [cleanCpf]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'CPF já cadastrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(`
      INSERT INTO users (
        name, cpf, email, phone, birth_date,
        address, address_number, address_complement,
        neighborhood, city, state, password, roles,
        percentage, category_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING id, name, cpf, roles
    `, [
      name.trim(),
      cleanCpf,
      email?.trim() || null,
      phone?.replace(/\D/g, '') || null,
      birth_date || null,
      address?.trim() || null,
      address_number?.trim() || null,
      address_complement?.trim() || null,
      neighborhood?.trim() || null,
      city?.trim() || null,
      state || null,
      hashedPassword,
      roles,
      percentage || null,
      category_id || null
    ]);

    const newUser = result.rows[0];

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      user: newUser
    });

  } catch (error) {
    console.error('Error creating user:', error);
    if (error.code === '23505') {
      res.status(409).json({ message: 'CPF já cadastrado' });
    } else {
      res.status(500).json({ message: 'Erro interno do servidor' });
    }
  }
});

app.put('/api/users/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, email, phone, birth_date,
      address, address_number, address_complement,
      neighborhood, city, state, roles,
      percentage, category_id
    } = req.body;

    if (!name || !roles || roles.length === 0) {
      return res.status(400).json({ message: 'Nome e pelo menos uma role são obrigatórios' });
    }

    const result = await pool.query(`
      UPDATE users SET
        name = $1, email = $2, phone = $3, birth_date = $4,
        address = $5, address_number = $6, address_complement = $7,
        neighborhood = $8, city = $9, state = $10, roles = $11,
        percentage = $12, category_id = $13, updated_at = NOW()
      WHERE id = $14
      RETURNING id, name, cpf, roles
    `, [
      name.trim(),
      email?.trim() || null,
      phone?.replace(/\D/g, '') || null,
      birth_date || null,
      address?.trim() || null,
      address_number?.trim() || null,
      address_complement?.trim() || null,
      neighborhood?.trim() || null,
      city?.trim() || null,
      state || null,
      roles,
      percentage || null,
      category_id || null,
      id
    ]);

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

    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({ message: 'Usuário excluído com sucesso' });

  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

app.get('/api/professionals', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone,
        u.address, u.address_number, u.address_complement,
        u.neighborhood, u.city, u.state, u.roles,
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

app.get('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Erro ao buscar usuário' });
  }
});

// Service categories routes
app.get('/api/service-categories', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM service_categories ORDER BY name');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching service categories:', error);
    res.status(500).json({ message: 'Erro ao buscar categorias' });
  }
});

app.post('/api/service-categories', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description } = req.body;
    
    if (!name) {
      return res.status(400).json({ message: 'Nome é obrigatório' });
    }
    
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
    res.status(500).json({ message: 'Erro ao buscar serviços' });
  }
});

app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;
    
    if (!name || !base_price) {
      return res.status(400).json({ message: 'Nome e preço base são obrigatórios' });
    }
    
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
    res.status(500).json({ message: 'Erro ao atualizar serviço' });
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
    res.status(500).json({ message: 'Erro ao excluir serviço' });
  }
});

// Client lookup route - 🔥 UPDATED: Check subscription status
app.get('/api/clients/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;
    
    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }
    
    const cleanCpf = cpf.replace(/\D/g, '');
    
    const result = await pool.query(
      'SELECT id, name, cpf, subscription_status FROM users WHERE cpf = $1 AND $2 = ANY(roles)',
      [cleanCpf, 'client']
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

// 🔥 NEW: Dependent lookup route
app.get('/api/dependents/lookup', authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;
    
    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }
    
    const cleanCpf = cpf.replace(/\D/g, '');
    
    const result = await pool.query(`
      SELECT 
        d.id, d.name, d.cpf, d.client_id,
        u.name as client_name, u.subscription_status as client_subscription_status
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
    res.status(500).json({ message: 'Erro ao buscar dependente' });
  }
});

// Dependents routes
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;
    const result = await pool.query(
      'SELECT * FROM dependents WHERE client_id = $1 ORDER BY name',
      [clientId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching dependents:', error);
    res.status(500).json({ message: 'Erro ao buscar dependentes' });
  }
});

app.post('/api/dependents', authenticate, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;
    
    if (!client_id || !name || !cpf) {
      return res.status(400).json({ message: 'client_id, name e cpf são obrigatórios' });
    }
    
    const cleanCpf = cpf.replace(/\D/g, '');
    
    const result = await pool.query(`
      INSERT INTO dependents (client_id, name, cpf, birth_date)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `, [client_id, name, cleanCpf, birth_date]);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating dependent:', error);
    if (error.code === '23505') {
      res.status(409).json({ message: 'CPF já cadastrado' });
    } else {
      res.status(500).json({ message: 'Erro ao criar dependente' });
    }
  }
});

app.put('/api/dependents/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;
    
    const result = await pool.query(`
      UPDATE dependents 
      SET name = $1, birth_date = $2
      WHERE id = $3
      RETURNING *
    `, [name, birth_date, id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro ao atualizar dependente' });
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
    res.status(500).json({ message: 'Erro ao excluir dependente' });
  }
});

// Consultations routes
app.post('/api/consultations', authenticate, async (req, res) => {
  try {
    const { client_id, dependent_id, professional_id, service_id, value, date } = req.body;
    
    if (!professional_id || !service_id || !value || !date) {
      return res.status(400).json({ message: 'professional_id, service_id, value e date são obrigatórios' });
    }
    
    // 🔥 BACKEND VALIDATION: Check subscription status before allowing consultation
    let subscriptionStatus = null;
    
    if (dependent_id) {
      // Check dependent's client subscription status
      const dependentResult = await pool.query(`
        SELECT u.subscription_status 
        FROM dependents d 
        JOIN users u ON d.client_id = u.id 
        WHERE d.id = $1
      `, [dependent_id]);
      
      if (dependentResult.rows.length === 0) {
        return res.status(404).json({ message: 'Dependente não encontrado' });
      }
      
      subscriptionStatus = dependentResult.rows[0].subscription_status;
    } else if (client_id) {
      // Check client subscription status
      const clientResult = await pool.query(`
        SELECT subscription_status FROM users WHERE id = $1
      `, [client_id]);
      
      if (clientResult.rows.length === 0) {
        return res.status(404).json({ message: 'Cliente não encontrado' });
      }
      
      subscriptionStatus = clientResult.rows[0].subscription_status;
    }
    
    if (subscriptionStatus !== 'active') {
      return res.status(403).json({ 
        message: 'Não é possível registrar consulta para cliente sem assinatura ativa' 
      });
    }
    
    const result = await pool.query(`
      INSERT INTO consultations (client_id, dependent_id, professional_id, service_id, value, date)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [client_id, dependent_id, professional_id, service_id, value, date]);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating consultation:', error);
    res.status(500).json({ message: 'Erro ao criar consulta' });
  }
});

app.get('/api/consultations', authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id, c.date, c.value,
        s.name as service_name,
        u_prof.name as professional_name,
        COALESCE(d.name, u_client.name) as client_name
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      JOIN users u_prof ON c.professional_id = u_prof.id
      LEFT JOIN users u_client ON c.client_id = u_client.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
    `;
    
    const params = [];
    
    if (req.user.currentRole === 'client') {
      query += ' WHERE (c.client_id = $1 OR c.dependent_id IN (SELECT id FROM dependents WHERE client_id = $1))';
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

// Reports routes
app.get('/api/reports/revenue', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Datas de início e fim são obrigatórias' });
    }

    const professionalRevenueQuery = `
      SELECT 
        u.name as professional_name,
        u.percentage as professional_percentage,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count,
        SUM(c.value * u.percentage / 100) as professional_payment,
        SUM(c.value * (100 - u.percentage) / 100) as clinic_revenue
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.date >= $1 AND c.date <= $2
      GROUP BY u.id, u.name, u.percentage
      ORDER BY revenue DESC
    `;

    const serviceRevenueQuery = `
      SELECT 
        s.name as service_name,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      WHERE c.date >= $1 AND c.date <= $2
      GROUP BY s.id, s.name
      ORDER BY revenue DESC
    `;

    const totalRevenueQuery = `
      SELECT SUM(value) as total_revenue
      FROM consultations
      WHERE date >= $1 AND date <= $2
    `;

    const [professionalResult, serviceResult, totalResult] = await Promise.all([
      pool.query(professionalRevenueQuery, [start_date, end_date]),
      pool.query(serviceRevenueQuery, [start_date, end_date]),
      pool.query(totalRevenueQuery, [start_date, end_date])
    ]);

    res.json({
      total_revenue: parseFloat(totalResult.rows[0]?.total_revenue || 0),
      revenue_by_professional: professionalResult.rows.map(row => ({
        professional_name: row.professional_name,
        professional_percentage: parseFloat(row.professional_percentage || 0),
        revenue: parseFloat(row.revenue || 0),
        consultation_count: parseInt(row.consultation_count || 0),
        professional_payment: parseFloat(row.professional_payment || 0),
        clinic_revenue: parseFloat(row.clinic_revenue || 0)
      })),
      revenue_by_service: serviceResult.rows.map(row => ({
        service_name: row.service_name,
        revenue: parseFloat(row.revenue || 0),
        consultation_count: parseInt(row.consultation_count || 0)
      }))
    });
  } catch (error) {
    console.error('Error fetching revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

app.get('/api/reports/professional-revenue', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const professionalId = req.user.id;
    
    // Get professional percentage
    const professionalResult = await pool.query(
      'SELECT percentage FROM users WHERE id = $1',
      [professionalId]
    );
    
    const professionalPercentage = professionalResult.rows[0]?.percentage || 50;
    
    // Get all consultations for this professional
    const allConsultationsResult = await pool.query(`
      SELECT 
        c.id,
        c.date,
        COALESCE(cl.name, d.name) as client_name,
        s.name as service_name,
        c.value as total_value,
        ROUND(c.value * (100 - COALESCE(u.percentage, 50)) / 100, 2) as amount_to_pay
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      LEFT JOIN users cl ON c.client_id = cl.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN users u ON c.professional_id = u.id
      WHERE c.professional_id = $1
      ORDER BY c.date DESC
    `, [professionalId]);
    
    // Get pending payments (accumulated from previous periods)
    const pendingPaymentsResult = await pool.query(`
      SELECT COALESCE(SUM(amount), 0) as total_pending
      FROM professional_payments 
      WHERE professional_id = $1 AND status = 'pending'
    `, [professionalId]);
    
    const pendingAmount = parseFloat(pendingPaymentsResult.rows[0]?.total_pending || 0);
    const consultations = allConsultationsResult.rows;
    
    // Calculate totals
    const totalRevenue = consultations.reduce((sum, consultation) => {
      return sum + parseFloat(consultation.total_value || 0);
    }, 0);
    
    const professionalEarnings = consultations.reduce((sum, consultation) => {
      const professionalShare = consultation.total_value * (professionalPercentage / 100);
      return sum + professionalShare;
    }, 0);
    
    // Calculate amount to pay (clinic's share + pending amounts)
    const totalAmountToPay = consultations.reduce((sum, consultation) => {
      const clinicShare = consultation.total_value * ((100 - professionalPercentage) / 100);
      return sum + clinicShare;
    }, 0);
    
    const result = {
      summary: {
        professional_percentage: professionalPercentage,
        total_revenue: totalRevenue,
        consultation_count: consultations.length || 0,
        amount_to_pay: totalAmountToPay
      },
      consultations: consultations
    };
    
    res.json(result);
  } catch (error) {
    console.error('Error fetching professional revenue report:', error);
    res.status(500).json({ message: 'Erro ao gerar relatório' });
  }
});

// 🔥 CATCH-ALL ROUTE - SERVE REACT APP
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Erro interno do servidor' });
});

// Start server
const startServer = async () => {
  try {
    await initDatabase();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log('🔥 LOGIN NA URL RAIZ IMPLEMENTADO!');
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();