import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './db.js';

// Import routes
import authRoutes from './routes/auth.js';
import usersRoutes from './routes/users.js';
import clientsRoutes from './routes/clients.js';
import professionalsRoutes from './routes/professionals.js';
import consultationsRoutes from './routes/consultations.js';
import schedulingRoutes from './routes/scheduling.js';
import medicalRecordsRoutes from './routes/medicalRecords.js';
import privatePatientsRoutes from './routes/privatePatients.js';
import attendanceLocationsRoutes from './routes/attendanceLocations.js';
import reportsRoutes from './routes/reports.js';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// =============================================================================
// CLOUDINARY CONFIGURATION
// =============================================================================

// Configure Cloudinary
const configureCloudinary = () => {
  try {
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;
    
    console.log('🔍 Cloudinary credentials check:');
    console.log('Cloud Name:', cloudName ? '✅ Found' : '❌ Missing');
    console.log('API Key:', apiKey ? '✅ Found' : '❌ Missing');
    console.log('API Secret:', apiSecret ? '✅ Found' : '❌ Missing');
    
    if (!cloudName || !apiKey || !apiSecret) {
      console.warn('⚠️ Cloudinary credentials missing - image upload will be disabled');
      return false;
    }
    
    cloudinary.config({
      cloud_name: cloudName,
      api_key: apiKey,
      api_secret: apiSecret,
      secure: true
    });

    console.log('✅ Cloudinary configured successfully');
    return true;
  } catch (error) {
    console.error('❌ Error configuring Cloudinary:', error);
    return false;
  }
};

const isCloudinaryConfigured = configureCloudinary();

// Configure Cloudinary storage for multer
let storage;
if (isCloudinaryConfigured) {
  storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
      folder: 'quiro-ferreira/professionals',
      allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
      transformation: [
        {
          width: 400,
          height: 400,
          crop: 'fill',
          gravity: 'face',
          quality: 'auto:good'
        }
      ]
    },
  });
} else {
  // Fallback to memory storage if Cloudinary is not configured
  storage = multer.memoryStorage();
}

// Create multer instance
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    console.log('🔄 File filter - File type:', file.mimetype);
    
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Apenas arquivos de imagem são permitidos'), false);
    }
  },
});

// =============================================================================
// MIDDLEWARE CONFIGURATION
// =============================================================================

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3000',
      'http://localhost:4173',
      'https://cartaoquiroferreira.com.br',
      'https://www.cartaoquiroferreira.com.br',
      'https://convenioquiroferreira.onrender.com'
    ];
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn('🚫 CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
  exposedHeaders: ['Set-Cookie']
};

app.use(cors(corsOptions));

// Body parsing middleware
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf);
    } catch (e) {
      console.error('❌ Invalid JSON received:', buf.toString().substring(0, 100));
      throw new Error('Invalid JSON');
    }
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb' 
}));

app.use(cookieParser());

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`📡 ${timestamp} - ${req.method} ${req.path}`);
  
  // Log request body for POST/PUT requests (excluding sensitive data)
  if ((req.method === 'POST' || req.method === 'PUT') && req.body) {
    const logBody = { ...req.body };
    if (logBody.password) logBody.password = '[REDACTED]';
    if (logBody.currentPassword) logBody.currentPassword = '[REDACTED]';
    if (logBody.newPassword) logBody.newPassword = '[REDACTED]';
    console.log('📝 Request body:', JSON.stringify(logBody, null, 2));
  }
  
  next();
});

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  
  next();
});

// =============================================================================
// AUTHENTICATION MIDDLEWARE
// =============================================================================

const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'Token de acesso não fornecido' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');

    const result = await pool.query(
      'SELECT id, name, cpf, email, roles FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Usuário não encontrado' });
    }

    const user = result.rows[0];
    let userRoles = [];
    
    try {
      userRoles = typeof user.roles === 'string' ? JSON.parse(user.roles) : user.roles || [];
    } catch (e) {
      userRoles = Array.isArray(user.roles) ? user.roles : [user.roles].filter(Boolean);
    }

    req.user = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      email: user.email,
      roles: userRoles,
      currentRole: decoded.currentRole || userRoles[0]
    };

    next();
  } catch (error) {
    console.error('❌ Authentication error:', error);
    return res.status(401).json({ message: 'Token inválido ou expirado' });
  }
};

const authorize = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.currentRole) {
      return res.status(403).json({ message: 'Acesso não autorizado - role não definida' });
    }

    if (!allowedRoles.includes(req.user.currentRole)) {
      return res.status(403).json({ 
        message: `Acesso não autorizado. Requer: ${allowedRoles.join(' ou ')}. Atual: ${req.user.currentRole}` 
      });
    }

    next();
  };
};

// =============================================================================
// STATIC FILES AND FRONTEND
// =============================================================================

// Serve static files from dist directory
app.use(express.static(path.join(__dirname, '../dist'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1y' : '0',
  etag: true,
  lastModified: true
}));

// Serve public assets
app.use('/public', express.static(path.join(__dirname, '../public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1y' : '0'
}));

// =============================================================================
// IMAGE UPLOAD ENDPOINTS
// =============================================================================

// Upload professional image
app.post('/api/upload-image', authenticate, authorize(['professional']), upload.single('image'), async (req, res) => {
  try {
    console.log('🔄 Processing image upload for user:', req.user.id);
    
    if (!req.file) {
      return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
    }

    let imageUrl;
    
    if (isCloudinaryConfigured && req.file.path) {
      // Cloudinary upload successful
      imageUrl = req.file.path;
      console.log('✅ Image uploaded to Cloudinary:', imageUrl);
    } else {
      // Fallback - return a placeholder or handle differently
      console.warn('⚠️ Cloudinary not configured, using fallback');
      return res.status(500).json({ message: 'Serviço de upload não configurado' });
    }

    // Update user's photo_url in database
    const updateResult = await pool.query(
      'UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING photo_url',
      [imageUrl, req.user.id]
    );

    if (updateResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    res.json({ 
      message: 'Imagem atualizada com sucesso',
      imageUrl: imageUrl
    });
  } catch (error) {
    console.error('❌ Error uploading image:', error);
    res.status(500).json({ 
      message: 'Erro ao fazer upload da imagem',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// =============================================================================
// SERVICE CATEGORIES ENDPOINTS
// =============================================================================

// Get all service categories
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

// Create service category (admin only)
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
    if (error.code === '23505') {
      res.status(400).json({ message: 'Já existe uma categoria com este nome' });
    } else {
      res.status(500).json({ message: 'Erro interno do servidor' });
    }
  }
});

// =============================================================================
// SERVICES ENDPOINTS
// =============================================================================

// Get all services
app.get('/api/services', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.*, sc.name as category_name 
       FROM services s
       LEFT JOIN service_categories sc ON s.category_id = sc.id
       ORDER BY sc.name, s.name`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create service (admin only)
app.post('/api/services', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !description || !base_price) {
      return res.status(400).json({ message: 'Nome, descrição e preço base são obrigatórios' });
    }

    const result = await pool.query(
      `INSERT INTO services (name, description, base_price, category_id, is_base_service)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [name, description, base_price, category_id, is_base_service || false]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating service:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update service (admin only)
app.put('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(
      `UPDATE services 
       SET name = $1, description = $2, base_price = $3, category_id = $4, 
           is_base_service = $5, updated_at = CURRENT_TIMESTAMP
       WHERE id = $6 RETURNING *`,
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

// Delete service (admin only)
app.delete('/api/services/:id', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    // Check if service has consultations
    const consultationsCheck = await pool.query(
      'SELECT COUNT(*) FROM consultations WHERE service_id = $1',
      [id]
    );

    if (parseInt(consultationsCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir serviço que possui consultas registradas' 
      });
    }

    const result = await pool.query(
      'DELETE FROM services WHERE id = $1 RETURNING *',
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

// =============================================================================
// DEPENDENTS ENDPOINTS
// =============================================================================

// Get dependents for a client
app.get('/api/dependents/:clientId', authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    // Verify access - clients can only see their own dependents
    if (req.user.currentRole === 'client' && req.user.id !== parseInt(clientId)) {
      return res.status(403).json({ message: 'Acesso não autorizado' });
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

// Lookup dependent by CPF (for professionals)
app.get('/api/dependents/lookup', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: 'CPF é obrigatório' });
    }

    const cleanCpf = cpf.toString().replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    const result = await pool.query(
      `SELECT d.*, u.name as client_name, u.subscription_status as client_subscription_status
       FROM dependents d
       JOIN users u ON d.client_id = u.id
       WHERE d.cpf = $1`,
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error looking up dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create dependent
app.post('/api/dependents', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    // Verify client can only create dependents for themselves
    if (req.user.currentRole === 'client' && req.user.id !== client_id) {
      return res.status(403).json({ message: 'Você só pode adicionar dependentes para sua própria conta' });
    }

    if (!name || !cpf) {
      return res.status(400).json({ message: 'Nome e CPF são obrigatórios' });
    }

    const cleanCpf = cpf.replace(/\D/g, '');

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: 'CPF deve conter 11 dígitos numéricos' });
    }

    // Check if CPF already exists
    const existingDependent = await pool.query(
      'SELECT id FROM dependents WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingDependent.rows.length > 0) {
      return res.status(400).json({ message: 'CPF já cadastrado como dependente' });
    }

    // Check if CPF exists as a client
    const existingClient = await pool.query(
      'SELECT id FROM users WHERE cpf = $1',
      [cleanCpf]
    );

    if (existingClient.rows.length > 0) {
      return res.status(400).json({ message: 'Este CPF já está cadastrado como cliente' });
    }

    // Check dependent limit (max 10 per client)
    const dependentCount = await pool.query(
      'SELECT COUNT(*) FROM dependents WHERE client_id = $1',
      [client_id]
    );

    if (parseInt(dependentCount.rows[0].count) >= 10) {
      return res.status(400).json({ message: 'Limite máximo de 10 dependentes por cliente' });
    }

    const result = await pool.query(
      `INSERT INTO dependents (client_id, name, cpf, birth_date)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [client_id, name, cleanCpf, birth_date]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Update dependent
app.put('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    // Verify ownership
    const dependentCheck = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [id]
    );

    if (dependentCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    if (req.user.currentRole === 'client' && req.user.id !== dependentCheck.rows[0].client_id) {
      return res.status(403).json({ message: 'Você só pode editar seus próprios dependentes' });
    }

    const result = await pool.query(
      `UPDATE dependents 
       SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $3 RETURNING *`,
      [name, birth_date, id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Delete dependent
app.delete('/api/dependents/:id', authenticate, authorize(['client']), async (req, res) => {
  try {
    const { id } = req.params;

    // Verify ownership
    const dependentCheck = await pool.query(
      'SELECT client_id FROM dependents WHERE id = $1',
      [id]
    );

    if (dependentCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Dependente não encontrado' });
    }

    if (req.user.currentRole === 'client' && req.user.id !== dependentCheck.rows[0].client_id) {
      return res.status(403).json({ message: 'Você só pode excluir seus próprios dependentes' });
    }

    // Check if dependent has consultations
    const consultationsCheck = await pool.query(
      'SELECT COUNT(*) FROM consultations WHERE dependent_id = $1',
      [id]
    );

    if (parseInt(consultationsCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        message: 'Não é possível excluir dependente que possui consultas registradas' 
      });
    }

    await pool.query('DELETE FROM dependents WHERE id = $1', [id]);

    res.json({ message: 'Dependente excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting dependent:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// ADMIN ENDPOINTS
// =============================================================================

// Get professionals with scheduling access (admin only)
app.get('/api/admin/professionals-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         u.id,
         u.name,
         u.email,
         u.phone,
         sc.name as category_name,
         COALESCE(pss.status = 'active' AND pss.expires_at > NOW(), false) as has_scheduling_access,
         pss.expires_at as access_expires_at,
         pss.granted_by as access_granted_by,
         pss.granted_at as access_granted_at,
         pss.status as subscription_status
       FROM users u
       LEFT JOIN service_categories sc ON u.category_id = sc.id
       LEFT JOIN professional_scheduling_subscriptions pss ON u.id = pss.professional_id
       WHERE u.roles::jsonb ? 'professional'
       ORDER BY u.name`
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching professionals scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Grant scheduling access (admin only)
app.post('/api/admin/grant-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: 'ID do profissional e data de expiração são obrigatórios' });
    }

    // Check if professional exists
    const professionalCheck = await pool.query(
      `SELECT id FROM users WHERE id = $1 AND roles::jsonb ? 'professional'`,
      [professional_id]
    );

    if (professionalCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Profissional não encontrado' });
    }

    // Grant or update access
    const result = await pool.query(
      `INSERT INTO professional_scheduling_subscriptions 
       (professional_id, status, expires_at, granted_by, granted_at, reason, is_admin_granted)
       VALUES ($1, 'active', $2, $3, CURRENT_TIMESTAMP, $4, true)
       ON CONFLICT (professional_id) 
       DO UPDATE SET 
         status = 'active',
         expires_at = $2,
         granted_by = $3,
         granted_at = CURRENT_TIMESTAMP,
         reason = $4,
         is_admin_granted = true,
         updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [professional_id, expires_at, req.user.name, reason]
    );

    res.json({
      message: 'Acesso à agenda concedido com sucesso',
      subscription: result.rows[0]
    });
  } catch (error) {
    console.error('Error granting scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Revoke scheduling access (admin only)
app.post('/api/admin/revoke-scheduling-access', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { professional_id } = req.body;

    if (!professional_id) {
      return res.status(400).json({ message: 'ID do profissional é obrigatório' });
    }

    // Update subscription status
    await pool.query(
      `UPDATE professional_scheduling_subscriptions 
       SET status = 'revoked', 
           revoked_by = $1,
           revoked_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE professional_id = $2`,
      [req.user.name, professional_id]
    );

    res.json({ message: 'Acesso à agenda revogado com sucesso' });
  } catch (error) {
    console.error('Error revoking scheduling access:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// PAYMENT ENDPOINTS
// =============================================================================

// Create subscription payment for clients
app.post('/api/create-subscription', authenticate, authorize(['client']), async (req, res) => {
  try {
    console.log('🔄 Creating subscription for client:', req.user.id);

    // Check if client already has active subscription
    const existingSubscription = await pool.query(
      `SELECT * FROM client_subscriptions 
       WHERE client_id = $1 AND status = 'active' AND expires_at > NOW()`,
      [req.user.id]
    );

    if (existingSubscription.rows.length > 0) {
      return res.status(400).json({ 
        message: 'Você já possui uma assinatura ativa' 
      });
    }

    // Get dependents count for pricing
    const dependentsResult = await pool.query(
      `SELECT COUNT(*) as count FROM dependents WHERE client_id = $1`,
      [req.user.id]
    );

    const dependentCount = parseInt(dependentsResult.rows[0].count) || 0;
    const basePrice = 250; // R$ 250 for titular
    const dependentPrice = 50; // R$ 50 per dependent
    const totalAmount = basePrice + (dependentCount * dependentPrice);

    // For MVP, we'll simulate payment creation
    const externalReference = `subscription_${req.user.id}_${Date.now()}`;

    // Store the payment intent in database
    await pool.query(
      `INSERT INTO client_payments 
       (client_id, amount, status, external_reference, dependent_count)
       VALUES ($1, $2, 'pending', $3, $4)`,
      [req.user.id, totalAmount, externalReference, dependentCount]
    );

    // Return mock payment data for development
    res.json({
      preference_id: `mock_${externalReference}`,
      init_point: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client/payment-success`,
      total_amount: totalAmount,
      dependent_count: dependentCount
    });
  } catch (error) {
    console.error('❌ Error creating subscription:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento da assinatura',
      error: error.message 
    });
  }
});

// Create professional payment
app.post('/api/professional/create-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor inválido' });
    }

    console.log('🔄 Creating professional payment for:', req.user.id, 'Amount:', amount);

    const externalReference = `professional_${req.user.id}_${Date.now()}`;

    // Store the payment intent in database
    await pool.query(
      `INSERT INTO professional_payments 
       (professional_id, amount, status, external_reference)
       VALUES ($1, $2, 'pending', $3)`,
      [req.user.id, amount, externalReference]
    );

    // Return mock payment data for development
    res.json({
      preference_id: `mock_${externalReference}`,
      init_point: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/payment-success`,
    });
  } catch (error) {
    console.error('❌ Error creating professional payment:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento',
      error: error.message 
    });
  }
});

// =============================================================================
// MEDICAL DOCUMENTS ENDPOINTS
// =============================================================================

// Get medical documents for current professional
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT md.*, 
              COALESCE(pp.name, c.name, d.name) as patient_name
       FROM medical_documents md
       LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
       LEFT JOIN users c ON md.client_id = c.id
       LEFT JOIN dependents d ON md.dependent_id = d.id
       WHERE md.professional_id = $1
       ORDER BY md.created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create medical document
app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { private_patient_id, client_id, dependent_id, document_type, title, template_data } = req.body;

    if (!document_type || !title) {
      return res.status(400).json({ message: 'Tipo de documento e título são obrigatórios' });
    }

    // Generate document URL (in production, this would generate a PDF)
    const documentUrl = `${process.env.API_URL || 'http://localhost:3001'}/documents/${Date.now()}_${title.replace(/\s+/g, '_')}.pdf`;

    const result = await pool.query(
      `INSERT INTO medical_documents 
       (professional_id, private_patient_id, client_id, dependent_id, document_type, title, document_url, template_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [req.user.id, private_patient_id, client_id, dependent_id, document_type, title, documentUrl, JSON.stringify(template_data)]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating medical document:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// API ROUTES
// =============================================================================

app.use('/api/auth', authRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/clients', clientsRoutes);
app.use('/api/professionals', professionalsRoutes);
app.use('/api/consultations', consultationsRoutes);
app.use('/api/scheduling', schedulingRoutes);
app.use('/api/medical-records', medicalRecordsRoutes);
app.use('/api/private-patients', privatePatientsRoutes);
app.use('/api/attendance-locations', attendanceLocationsRoutes);
app.use('/api/reports', reportsRoutes);

// =============================================================================
// HEALTH CHECK AND SYSTEM INFO
// =============================================================================

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: '1.0.0',
    services: {
      database: 'connected',
      cloudinary: isCloudinaryConfigured ? 'configured' : 'not configured'
    }
  });
});

// System info endpoint (admin only)
app.get('/api/system-info', authenticate, authorize(['admin']), async (req, res) => {
  try {
    // Get database stats
    const userStats = await pool.query(
      `SELECT 
         COUNT(*) as total_users,
         COUNT(CASE WHEN roles::jsonb ? 'client' THEN 1 END) as total_clients,
         COUNT(CASE WHEN roles::jsonb ? 'professional' THEN 1 END) as total_professionals,
         COUNT(CASE WHEN roles::jsonb ? 'admin' THEN 1 END) as total_admins
       FROM users`
    );

    const consultationStats = await pool.query(
      `SELECT 
         COUNT(*) as total_consultations,
         COUNT(CASE WHEN date >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as consultations_last_30_days,
         COALESCE(SUM(value), 0) as total_revenue
       FROM consultations`
    );

    res.json({
      system: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        node_version: process.version,
        environment: process.env.NODE_ENV || 'development'
      },
      database: {
        users: userStats.rows[0],
        consultations: consultationStats.rows[0]
      },
      services: {
        cloudinary: isCloudinaryConfigured
      }
    });
  } catch (error) {
    console.error('Error fetching system info:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// DATABASE UTILITIES
// =============================================================================

// Database connection test
app.get('/api/db-test', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as current_time, version() as postgres_version');
    res.json({
      status: 'connected',
      ...result.rows[0]
    });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).json({ 
      status: 'error',
      message: 'Falha na conexão com o banco de dados' 
    });
  }
});

// =============================================================================
// ERROR HANDLING
// =============================================================================

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  console.warn(`🚫 API route not found: ${req.method} ${req.path}`);
  res.status(404).json({ 
    message: 'Endpoint não encontrado',
    path: req.path,
    method: req.method
  });
});

// Serve React app for all other routes
app.get('*', (req, res) => {
  try {
    const indexPath = path.join(__dirname, '../dist/index.html');
    res.sendFile(indexPath);
  } catch (error) {
    console.error('Error serving index.html:', error);
    res.status(500).send('Erro interno do servidor');
  }
});

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error('🚨 Server error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });

  // Handle specific error types
  if (err.name === 'ValidationError') {
    return res.status(400).json({ 
      message: 'Dados inválidos',
      details: err.message 
    });
  }

  if (err.name === 'UnauthorizedError' || err.name === 'JsonWebTokenError') {
    return res.status(401).json({ 
      message: 'Token inválido ou expirado' 
    });
  }

  if (err.code === '23505') { // PostgreSQL unique violation
    return res.status(400).json({ 
      message: 'Dados duplicados - registro já existe' 
    });
  }

  if (err.code === '23503') { // PostgreSQL foreign key violation
    return res.status(400).json({ 
      message: 'Referência inválida - dados relacionados não encontrados' 
    });
  }

  // Default error response
  res.status(err.status || 500).json({ 
    message: err.message || 'Erro interno do servidor',
    error: process.env.NODE_ENV === 'development' ? {
      message: err.message,
      stack: err.stack
    } : undefined
  });
});

// =============================================================================
// GRACEFUL SHUTDOWN
// =============================================================================

const gracefulShutdown = (signal) => {
  console.log(`\n🛑 Received ${signal}. Starting graceful shutdown...`);
  
  // Close database connections
  pool.end(() => {
    console.log('📊 Database connections closed');
  });
  
  // Close server
  process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('🚨 Uncaught Exception:', err);
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown('unhandledRejection');
});

// =============================================================================
// SERVER STARTUP
// =============================================================================

const startServer = async () => {
  try {
    // Test database connection
    await pool.query('SELECT NOW()');
    console.log('✅ Database connection established');
    
    // Start server
    app.listen(PORT, () => {
      console.log('\n🚀 ===== CONVÊNIO QUIRO FERREIRA SERVER =====');
      console.log(`📱 Frontend: http://localhost:5173`);
      console.log(`🔗 API: http://localhost:${PORT}/api`);
      console.log(`🏥 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`📊 Database: ${process.env.DATABASE_URL ? 'Connected' : 'Local'}`);
      console.log(`☁️ Cloudinary: ${isCloudinaryConfigured ? 'Configured' : 'Not configured'}`);
      console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Using default'}`);
      console.log('============================================\n');
      
      // Log available routes
      console.log('📋 Available API routes:');
      console.log('  🔐 /api/auth/* - Authentication');
      console.log('  👥 /api/users/* - User management');
      console.log('  🏥 /api/clients/* - Client operations');
      console.log('  👨‍⚕️ /api/professionals/* - Professional operations');
      console.log('  📅 /api/consultations/* - Consultation management');
      console.log('  🗓️ /api/scheduling/* - Appointment scheduling');
      console.log('  📋 /api/medical-records/* - Medical records');
      console.log('  👤 /api/private-patients/* - Private patients');
      console.log('  📍 /api/attendance-locations/* - Attendance locations');
      console.log('  📊 /api/reports/* - Reports and analytics');
      console.log('  🏗️ /api/services/* - Service management');
      console.log('  📂 /api/service-categories/* - Service categories');
      console.log('  👶 /api/dependents/* - Dependent management');
      console.log('  🖼️ /api/upload-image - Image upload');
      console.log('  ❤️ /api/health - Health check');
      console.log('');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
startServer();

export default app;