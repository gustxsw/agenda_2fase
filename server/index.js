import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { pool } from "./db.js";
import { MercadoPagoConfig, Preference, Payment } from "mercadopago";
import createUpload from "./middleware/upload.js";
import { generateDocumentPDF } from "./utils/documentGenerator.js";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// 🔥 MERCADOPAGO SDK V2 CONFIGURATION
const createTables = async () => {
  try {
    console.log("🔄 Creating database tables...");

    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) UNIQUE,
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
        password VARCHAR(255) NOT NULL,
        roles TEXT[] DEFAULT ARRAY['client'],
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry TIMESTAMP,
        professional_percentage INTEGER DEFAULT 50,
        photo_url TEXT,
        has_scheduling_access BOOLEAN DEFAULT false,
        scheduling_access_expires_at TIMESTAMP,
        scheduling_access_granted_by INTEGER,
        scheduling_access_granted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create service_categories table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create services table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        base_price DECIMAL(10,2) NOT NULL,
        category_id INTEGER REFERENCES service_categories(id) ON DELETE SET NULL,
        is_base_service BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create dependents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dependents (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) NOT NULL UNIQUE,
        birth_date DATE,
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry TIMESTAMP,
        billing_amount DECIMAL(10,2) DEFAULT 50.00,
        payment_reference VARCHAR(255),
        activated_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create private_patients table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS private_patients (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11),
        email VARCHAR(255),
        phone VARCHAR(20),
        birth_date DATE,
        address TEXT,
        address_number VARCHAR(20),
        address_complement VARCHAR(100),
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        zip_code VARCHAR(10),
        scheduling_access_expires_at TIMESTAMP,
        scheduling_access_granted_by VARCHAR(255),
        scheduling_access_granted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create attendance_locations table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS attendance_locations (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        address TEXT,
        address_number VARCHAR(20),
        address_complement VARCHAR(100),
        neighborhood VARCHAR(100),
        city VARCHAR(100),
        state VARCHAR(2),
        zip_code VARCHAR(8),
        phone VARCHAR(20),
        is_default BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create consultations table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        dependent_id INTEGER REFERENCES dependents(id) ON DELETE SET NULL,
        private_patient_id INTEGER REFERENCES private_patients(id) ON DELETE SET NULL,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE RESTRICT,
        location_id INTEGER REFERENCES attendance_locations(id) ON DELETE SET NULL,
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        status VARCHAR(20) DEFAULT 'completed',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create medical_records table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_records (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER NOT NULL REFERENCES private_patients(id) ON DELETE CASCADE,
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

    // Create medical_documents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_documents (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id) ON DELETE SET NULL,
        title VARCHAR(255) NOT NULL,
        document_type VARCHAR(50) NOT NULL,
        document_url TEXT NOT NULL,
        template_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create payments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS client_payments (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL(10,2) NOT NULL,
        payment_status VARCHAR(20) DEFAULT 'pending',
        payment_method VARCHAR(50),
        external_payment_id VARCHAR(255),
        payment_reference VARCHAR(255),
        subscription_months INTEGER DEFAULT 12,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 🔥 DEPENDENT PAYMENTS TABLE
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dependent_payments (
        id SERIAL PRIMARY KEY,
        dependent_id INTEGER NOT NULL REFERENCES dependents(id) ON DELETE CASCADE,
        client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL(10,2) NOT NULL DEFAULT 50.00,
        payment_status VARCHAR(20) DEFAULT 'pending',
        mp_payment_id VARCHAR(255),
        mp_preference_id VARCHAR(255),
        activated_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 🔥 PROFESSIONAL PAYMENTS TABLE (Contas a Pagar)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS professional_payments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL(10,2) NOT NULL,
        payment_status VARCHAR(20) DEFAULT 'pending',
        mp_payment_id VARCHAR(255),
        mp_preference_id VARCHAR(255),
        period_start DATE NOT NULL,
        period_end DATE NOT NULL,
        consultation_count INTEGER DEFAULT 0,
        total_revenue DECIMAL(10,2) DEFAULT 0,
        professional_percentage INTEGER DEFAULT 50,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 🔥 AGENDA ACCESS PAYMENTS TABLE
    await pool.query(`
      CREATE TABLE IF NOT EXISTS agenda_payments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL(10,2) NOT NULL DEFAULT 100.00,
        payment_status VARCHAR(20) DEFAULT 'pending',
        mp_payment_id VARCHAR(255),
        mp_preference_id VARCHAR(255),
        access_months INTEGER DEFAULT 1,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create audit_logs table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(100) NOT NULL,
        table_name VARCHAR(100),
        record_id INTEGER,
        old_values JSONB,
        new_values JSONB,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create notifications table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        type VARCHAR(50) DEFAULT 'info',
        is_read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create system_settings table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS system_settings (
        id SERIAL PRIMARY KEY,
        key VARCHAR(100) NOT NULL UNIQUE,
        value TEXT,
        description TEXT,
        updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_users_cpf ON users(cpf);
      CREATE INDEX IF NOT EXISTS idx_users_roles ON users USING GIN(roles);
      CREATE INDEX IF NOT EXISTS idx_users_subscription_status ON users(subscription_status);
      CREATE INDEX IF NOT EXISTS idx_dependents_client_id ON dependents(client_id);
      CREATE INDEX IF NOT EXISTS idx_dependents_cpf ON dependents(cpf);
      CREATE INDEX IF NOT EXISTS idx_consultations_client_id ON consultations(client_id);
      CREATE INDEX IF NOT EXISTS idx_consultations_professional_id ON consultations(professional_id);
      CREATE INDEX IF NOT EXISTS idx_consultations_date ON consultations(date);
      CREATE INDEX IF NOT EXISTS idx_consultations_status ON consultations(status);
      CREATE INDEX IF NOT EXISTS idx_medical_records_professional_id ON medical_records(professional_id);
      CREATE INDEX IF NOT EXISTS idx_medical_records_patient_id ON medical_records(private_patient_id);
      CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
      CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
      CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
      CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read);
    `);

    // Insert default service categories
    await pool.query(`
      INSERT INTO service_categories (name, description) VALUES
      ('Fisioterapia', 'Serviços de fisioterapia e reabilitação'),
      ('Psicologia', 'Atendimento psicológico e terapias'),
      ('Nutrição', 'Consultas nutricionais e acompanhamento'),
      ('Medicina Geral', 'Consultas médicas gerais'),
      ('Odontologia', 'Serviços odontológicos'),
      ('Estética', 'Procedimentos estéticos e bem-estar'),
      ('Educação Física', 'Personal training e atividades físicas'),
      ('Outros', 'Outros serviços de saúde e bem-estar')
      ON CONFLICT (name) DO NOTHING
    `);

    // Insert default services
    await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      SELECT 
        'Consulta de Fisioterapia', 
        'Consulta inicial de fisioterapia com avaliação completa', 
        120.00, 
        sc.id, 
        true
      FROM service_categories sc WHERE sc.name = 'Fisioterapia'
      ON CONFLICT DO NOTHING;
      
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      SELECT 
        'Sessão de Fisioterapia', 
        'Sessão de fisioterapia para tratamento', 
        80.00, 
        sc.id, 
        false
      FROM service_categories sc WHERE sc.name = 'Fisioterapia'
      ON CONFLICT DO NOTHING;
      
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      SELECT 
        'Consulta Psicológica', 
        'Sessão de psicoterapia individual', 
        150.00, 
        sc.id, 
        true
      FROM service_categories sc WHERE sc.name = 'Psicologia'
      ON CONFLICT DO NOTHING;
      
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      SELECT 
        'Consulta Nutricional', 
        'Consulta com nutricionista e plano alimentar', 
        100.00, 
        sc.id, 
        true
      FROM service_categories sc WHERE sc.name = 'Nutrição'
      ON CONFLICT DO NOTHING;
      
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      SELECT 
        'Consulta Médica', 
        'Consulta médica geral', 
        200.00, 
        sc.id, 
        true
      FROM service_categories sc WHERE sc.name = 'Medicina Geral'
      ON CONFLICT DO NOTHING;
    `);

    // Insert default system settings
    await pool.query(`
      INSERT INTO system_settings (key, value, description) VALUES
      ('subscription_price', '250', 'Preço da assinatura mensal do titular'),
      ('dependent_price', '50', 'Preço da assinatura mensal do dependente'),
      ('default_professional_percentage', '50', 'Porcentagem padrão do profissional'),
      ('max_dependents_per_client', '10', 'Número máximo de dependentes por cliente'),
      ('system_maintenance_mode', 'false', 'Modo de manutenção do sistema'),
      ('backup_enabled', 'true', 'Backup automático habilitado'),
      ('notification_email', 'admin@quiroferreira.com.br', 'Email para notificações do sistema')
      ON CONFLICT (key) DO NOTHING
    `);

    // Create admin user if not exists
    const adminExists = await pool.query(
      "SELECT id FROM users WHERE roles @> ARRAY['admin'] LIMIT 1"
    );

    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash("admin123", 10);
      await pool.query(
        `
        INSERT INTO users (
          name, 
          cpf, 
          email, 
          password, 
          roles, 
          subscription_status,
          professional_percentage
        ) VALUES (
          'Administrador do Sistema',
          '00000000000',
          'admin@quiroferreira.com.br',
          $1,
          ARRAY['admin'],
          'active',
          0
        )
      `,
        [hashedPassword]
      );

      console.log("✅ Admin user created with credentials:");
      console.log("   CPF: 000.000.000-00");
      console.log("   Password: admin123");
    }

    console.log("✅ Database tables created successfully");
  } catch (error) {
    console.error("❌ Error creating tables:", error);
    throw error;
  }
};

// Helper function to process subscription payments
async function processSubscriptionPayment(payment, paymentId) {
  try {
    console.log('🔄 Processing subscription payment:', payment);
    
    // Update payment status
    await pool.query(
      'UPDATE client_payments SET status = $1, updated_at = NOW() WHERE mp_payment_id = $2',
      ['approved', paymentId]
    );
    
    // Activate user subscription
    const expiryDate = new Date();
    expiryDate.setMonth(expiryDate.getMonth() + 1);
    
    await pool.query(
      'UPDATE users SET subscription_status = $1, subscription_expiry = $2 WHERE id = $3',
      ['active', expiryDate.toISOString(), payment.user_id]
    );
    
    console.log('✅ Subscription activated for user:', payment.user_id);
  } catch (error) {
    console.error('❌ Error processing subscription payment:', error);
  }
}

// Helper function to process dependent payments
async function processDependentPayment(payment, paymentId) {
  try {
    console.log('🔄 Processing dependent payment:', payment);
    
    // Update payment status
    await pool.query(
      'UPDATE dependent_payments SET status = $1, updated_at = NOW() WHERE mp_payment_id = $2',
      ['approved', paymentId]
    );
    
    // Activate dependent subscription
    const expiryDate = new Date();
    expiryDate.setMonth(expiryDate.getMonth() + 1);
    
    await pool.query(
      'UPDATE dependents SET subscription_status = $1, subscription_expiry = $2, activated_at = NOW() WHERE id = $3',
      ['active', expiryDate.toISOString(), payment.dependent_id]
    );
    
    console.log('✅ Dependent subscription activated:', payment.dependent_id);
  } catch (error) {
    console.error('❌ Error processing dependent payment:', error);
  }
}

// Helper function to process professional payments
async function processProfessionalPayment(payment, paymentId) {
  try {
    console.log('🔄 Processing professional payment:', payment);
    
    // Update payment status
    await pool.query(
      'UPDATE professional_payments SET status = $1, updated_at = NOW() WHERE mp_payment_id = $2',
      ['approved', paymentId]
    );
    
    console.log('✅ Professional payment processed:', payment.user_id);
  } catch (error) {
    console.error('❌ Error processing professional payment:', error);
  }
}

// Helper function to process agenda payments
async function processAgendaPayment(payment, paymentId) {
  try {
    console.log('🔄 Processing agenda payment:', payment);
    
    // Update payment status
    await pool.query(
      'UPDATE agenda_payments SET status = $1, updated_at = NOW() WHERE mp_payment_id = $2',
      ['approved', paymentId]
    );
    
    console.log('✅ Agenda payment processed:', payment.user_id);
  } catch (error) {
    console.error('❌ Error processing agenda payment:', error);
  }
}

// 🔥 CORS CONFIGURATION FOR PRODUCTION
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      "http://localhost:5173",
      "http://localhost:3000",
      "https://cartaoquiroferreira.com.br",
      "https://www.cartaoquiroferreira.com.br",
      "https://convenioquiroferreira.onrender.com",
    ];

    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log("❌ CORS blocked origin:", origin);
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(cookieParser());

// 🔥 MERCADOPAGO V2 CONFIGURATION
const mercadoPagoClient = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN || "",
  options: {
    timeout: 5000,
    idempotencyKey: "abc",
  },
});

// 🔥 AUTHENTICATION MIDDLEWARE
const payment = new Payment(mercadoPagoClient);
const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res
        .status(401)
        .json({ message: "Não autorizado - token não fornecido" });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "your-secret-key"
    );

    const result = await pool.query(
      "SELECT id, name, cpf, roles, subscription_status, subscription_expiry FROM users WHERE id = $1",
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Usuário não encontrado" });
    }

    const user = result.rows[0];

    req.user = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles || [],
      currentRole: decoded.currentRole || (user.roles && user.roles[0]),
      subscription_status: user.subscription_status,
      subscription_expiry: user.subscription_expiry,
    };

    next();
  } catch (error) {
    console.error("❌ Auth error:", error);
    return res.status(401).json({ message: "Token inválido" });
  }
};

// 🔥 AUTHORIZATION MIDDLEWARE
const authorize = (roles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.currentRole) {
      return res
        .status(403)
        .json({ message: "Acesso não autorizado - role não definida" });
    }

    if (!roles.includes(req.user.currentRole)) {
      return res
        .status(403)
        .json({ message: "Acesso não autorizado para esta role" });
    }

    next();
  };
};

// 🔥 SUBSCRIPTION STATUS VERIFICATION MIDDLEWARE
const verifyActiveSubscription = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: "Usuário não autenticado" });
    }

    // Get fresh subscription status from database
    const result = await pool.query(
      "SELECT subscription_status, subscription_expiry FROM users WHERE id = $1",
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const { subscription_status, subscription_expiry } = result.rows[0];

    console.log("🔍 VERIFICAÇÃO DE ASSINATURA:", {
      userId: req.user.id,
      status: subscription_status,
      expiry: subscription_expiry,
    });

    if (subscription_status !== "active") {
      return res.status(403).json({
        message: "Assinatura inativa. Realize o pagamento para continuar.",
        subscription_status,
        subscription_expiry,
      });
    }

    // Check if subscription is expired
    if (subscription_expiry && new Date(subscription_expiry) < new Date()) {
      // Update status to expired
      await pool.query(
        "UPDATE users SET subscription_status = $1 WHERE id = $2",
        ["expired", req.user.id]
      );

      return res.status(403).json({
        message: "Assinatura expirada. Renove para continuar.",
        subscription_status: "expired",
        subscription_expiry,
      });
    }

    next();
  } catch (error) {
    console.error("❌ Erro na verificação de assinatura:", error);
    return res.status(500).json({ message: "Erro interno do servidor" });
  }
};

// 🔥 PREVENT PAYMENT FOR ACTIVE CLIENTS MIDDLEWARE
const preventPaymentForActiveClients = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: "Usuário não autenticado" });
    }

    // Get fresh subscription status from database
    const result = await pool.query(
      "SELECT subscription_status, subscription_expiry FROM users WHERE id = $1",
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const { subscription_status } = result.rows[0];

    console.log("🚫 VERIFICAÇÃO ANTI-PAGAMENTO:", {
      userId: req.user.id,
      userName: req.user.name,
      status: subscription_status,
      action: "BLOCKED_PAYMENT_ATTEMPT",
    });

    if (subscription_status === "active") {
      console.error("🚫 BLOQUEADO: Cliente ativo tentou fazer pagamento!", {
        userId: req.user.id,
        userName: req.user.name,
        timestamp: new Date().toISOString(),
      });

      return res.status(400).json({
        message:
          "Sua assinatura já está ativa. Não é necessário realizar pagamento.",
        subscription_status,
        blocked: true,
      });
    }

    next();
  } catch (error) {
    console.error("❌ Erro na verificação anti-pagamento:", error);
    return res.status(500).json({ message: "Erro interno do servidor" });
  }
};

// 🔥 HEALTH CHECK
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

// 🔥 AUTH ROUTES
app.post("/api/auth/login", async (req, res) => {
  try {
    const { cpf, password } = req.body;

    console.log("🔄 Login attempt for CPF:", cpf?.substring(0, 3) + "***");

    if (!cpf || !password) {
      return res.status(400).json({ message: "CPF e senha são obrigatórios" });
    }

    const cleanCpf = cpf.replace(/\D/g, "");

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: "CPF deve conter 11 dígitos" });
    }

    const result = await pool.query(
      "SELECT id, name, cpf, password, roles, subscription_status, subscription_expiry FROM users WHERE cpf = $1",
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      console.log(
        "❌ User not found for CPF:",
        cleanCpf.substring(0, 3) + "***"
      );
      return res.status(401).json({ message: "Credenciais inválidas" });
    }

    const user = result.rows[0];

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      console.log("❌ Invalid password for user:", user.id);
      return res.status(401).json({ message: "Credenciais inválidas" });
    }

    console.log("✅ Login successful for user:", user.id, "roles:", user.roles);

    const userResponse = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles || [],
      subscription_status: user.subscription_status,
      subscription_expiry: user.subscription_expiry,
    };

    res.json({
      message: "Login realizado com sucesso",
      user: userResponse,
    });
  } catch (error) {
    console.error("❌ Login error:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post("/api/auth/select-role", async (req, res) => {
  try {
    const { userId, role } = req.body;

    console.log("🎯 Role selection:", { userId, role });

    if (!userId || !role) {
      return res
        .status(400)
        .json({ message: "UserId e role são obrigatórios" });
    }

    const result = await pool.query(
      "SELECT id, name, cpf, roles, subscription_status, subscription_expiry FROM users WHERE id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const user = result.rows[0];

    if (!user.roles || !user.roles.includes(role)) {
      return res
        .status(403)
        .json({ message: "Role não autorizada para este usuário" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        currentRole: role,
        name: user.name,
      },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "24h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    });

    const userResponse = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles,
      currentRole: role,
      subscription_status: user.subscription_status,
      subscription_expiry: user.subscription_expiry,
    };

    console.log("✅ Role selected successfully:", { userId, role });

    res.json({
      message: "Role selecionada com sucesso",
      user: userResponse,
      token,
    });
  } catch (error) {
    console.error("❌ Role selection error:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post("/api/auth/switch-role", authenticate, async (req, res) => {
  try {
    const { role } = req.body;

    if (!role) {
      return res.status(400).json({ message: "Role é obrigatória" });
    }

    if (!req.user.roles.includes(role)) {
      return res
        .status(403)
        .json({ message: "Role não autorizada para este usuário" });
    }

    const token = jwt.sign(
      {
        id: req.user.id,
        currentRole: role,
        name: req.user.name,
      },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "24h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    });

    const userResponse = {
      ...req.user,
      currentRole: role,
    };

    res.json({
      message: "Role alterada com sucesso",
      user: userResponse,
      token,
    });
  } catch (error) {
    console.error("❌ Role switch error:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post("/api/auth/register", async (req, res) => {
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
      zip_code,
      password,
    } = req.body;

    console.log("🔄 Registration attempt for:", name);

    if (!name || !password) {
      return res.status(400).json({ message: "Nome e senha são obrigatórios" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Senha deve ter pelo menos 6 caracteres" });
    }

    let cleanCpf = null;
    if (cpf) {
      cleanCpf = cpf.replace(/\D/g, "");
      if (!/^\d{11}$/.test(cleanCpf)) {
        return res.status(400).json({ message: "CPF deve conter 11 dígitos" });
      }

      const existingUser = await pool.query(
        "SELECT id FROM users WHERE cpf = $1",
        [cleanCpf]
      );

      if (existingUser.rows.length > 0) {
        return res.status(400).json({ message: "CPF já cadastrado" });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, zip_code, password, roles, 
        subscription_status, professional_percentage
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) 
      RETURNING id, name, cpf, email, roles, subscription_status, subscription_expiry`,
      [
        name.trim(),
        cleanCpf,
        email?.trim() || null,
        phone?.replace(/\D/g, "") || null,
        birth_date || null,
        address?.trim() || null,
        address_number?.trim() || null,
        address_complement?.trim() || null,
        neighborhood?.trim() || null,
        city?.trim() || null,
        state || null,
        zip_code?.replace(/\D/g, "") || null,
        hashedPassword,
        ["client"],
        "pending",
        parseInt("50"), // Default percentage as integer
      ]
    );

    const newUser = result.rows[0];

    console.log("✅ User registered successfully:", newUser.id);

    res.status(201).json({
      message: "Usuário criado com sucesso",
      user: newUser,
    });
  } catch (error) {
    console.error("❌ Registration error:", error);

    if (error.code === "23505") {
      return res.status(400).json({ message: "CPF já cadastrado" });
    }

    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout realizado com sucesso" });
});

// 🔥 SUBSCRIPTION STATUS VERIFICATION ROUTE
app.get(
  "/api/users/:id/subscription-status",
  authenticate,
  async (req, res) => {
    try {
      const userId = parseInt(req.params.id);

      console.log("🔍 VERIFICAÇÃO DE STATUS DE ASSINATURA:", {
        requestedUserId: userId,
        authenticatedUserId: req.user.id,
        userRole: req.user.currentRole,
      });

      // Only allow users to check their own status or admins to check any status
      if (req.user.id !== userId && req.user.currentRole !== "admin") {
        return res.status(403).json({ message: "Acesso negado" });
      }

      const result = await pool.query(
        "SELECT subscription_status, subscription_expiry FROM users WHERE id = $1",
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Usuário não encontrado" });
      }

      const { subscription_status, subscription_expiry } = result.rows[0];

      console.log("✅ STATUS VERIFICADO:", {
        userId,
        subscription_status,
        subscription_expiry,
        isActive: subscription_status === "active",
      });

      res.json({
        subscription_status,
        subscription_expiry,
        is_active: subscription_status === "active",
      });
    } catch (error) {
      console.error("❌ Erro ao verificar status de assinatura:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// 🔥 USER ROUTES
app.get("/api/users", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    console.log("🔄 Fetching all users for admin");

    const result = await pool.query(
      `SELECT id, name, cpf, email, phone, roles, subscription_status, 
       subscription_expiry, created_at 
       FROM users 
       ORDER BY created_at DESC`
    );

    console.log("✅ Users fetched:", result.rows.length);

    res.json(result.rows);
  } catch (error) {
    console.error("❌ Error fetching users:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.get("/api/users/:id", authenticate, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    console.log("🔄 Fetching user data for ID:", userId);

    // Only allow users to get their own data or admins to get any user data
    if (req.user.id !== userId && req.user.currentRole !== "admin") {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const result = await pool.query(
      `SELECT id, name, cpf, email, phone, birth_date, address, address_number,
       address_complement, neighborhood, city, state, zip_code, roles, subscription_status,
       subscription_expiry, professional_percentage, photo_url, created_at
       FROM users WHERE id = $1`,
      [userId]
    );

    if (result.rows.length === 0) {
      console.log("❌ User not found:", userId);
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const user = result.rows[0];

    console.log("✅ User data fetched:", {
      id: user.id,
      name: user.name,
      subscription_status: user.subscription_status,
      subscription_expiry: user.subscription_expiry,
    });

    res.json(user);
  } catch (error) {
    console.error("❌ Error fetching user:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post("/api/users", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const { name, cpf, email, phone, password, roles } = req.body;

    if (!name || !password || !roles || roles.length === 0) {
      return res.status(400).json({
        message: "Nome, senha e pelo menos uma role são obrigatórios",
      });
    }

    let cleanCpf = null;
    if (cpf) {
      cleanCpf = cpf.replace(/\D/g, "");
      if (!/^\d{11}$/.test(cleanCpf)) {
        return res.status(400).json({ message: "CPF deve conter 11 dígitos" });
      }

      const existingUser = await pool.query(
        "SELECT id FROM users WHERE cpf = $1",
        [cleanCpf]
      );

      if (existingUser.rows.length > 0) {
        return res.status(400).json({ message: "CPF já cadastrado" });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, password, roles, subscription_status, professional_percentage
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
      RETURNING id, name, cpf, email, phone, roles, subscription_status, subscription_expiry, created_at`,
      [
        name.trim(),
        cleanCpf,
        email?.trim() || null,
        phone?.replace(/\D/g, "") || null,
        hashedPassword,
        roles,
        roles.includes("client") ? "pending" : "active",
        parseInt("50"), // Default percentage as integer
      ]
    );

    console.log("✅ User created by admin:", result.rows[0].id);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Error creating user:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.put("/api/users/:id", authenticate, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const {
      name,
      email,
      phone,
      roles,
      currentPassword,
      newPassword,
      professional_percentage,
    } = req.body;
    const zip_code = req.body.zip_code || null;

    // Only allow users to update their own data or admins to update any user data
    if (req.user.id !== userId && req.user.currentRole !== "admin") {
      return res.status(403).json({ message: "Acesso negado" });
    }

    // Get current user data
    const currentUser = await pool.query(
      "SELECT password FROM users WHERE id = $1",
      [userId]
    );

    if (currentUser.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    let updateFields = [];
    let updateValues = [];
    let paramCount = 1;

    if (name) {
      updateFields.push(`name = $${paramCount}`);
      updateValues.push(name.trim());
      paramCount++;
    }

    if (email !== undefined) {
      updateFields.push(`email = $${paramCount}`);
      updateValues.push(email?.trim() || null);
      paramCount++;
    }

    if (phone !== undefined) {
      updateFields.push(`phone = $${paramCount}`);
      updateValues.push(phone?.replace(/\D/g, "") || null);
      paramCount++;
    }

    if (roles && req.user.currentRole === "admin") {
      updateFields.push(`roles = $${paramCount}`);
      updateValues.push(roles);
      paramCount++;
    }

    if (
      professional_percentage !== undefined &&
      req.user.currentRole === "admin"
    ) {
      updateFields.push(`professional_percentage = $${paramCount}`);
      updateValues.push(parseInt(professional_percentage)); // Convert to integer
      paramCount++;
    }

    // Handle password change
    if (newPassword) {
      if (!currentPassword) {
        return res
          .status(400)
          .json({ message: "Senha atual é obrigatória para alterar a senha" });
      }

      const isValidPassword = await bcrypt.compare(
        currentPassword,
        currentUser.rows[0].password
      );
      if (!isValidPassword) {
        return res.status(400).json({ message: "Senha atual incorreta" });
      }

      if (newPassword.length < 6) {
        return res
          .status(400)
          .json({ message: "Nova senha deve ter pelo menos 6 caracteres" });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updateFields.push(`password = $${paramCount}`);
      updateValues.push(hashedPassword);
      paramCount++;
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ message: "Nenhum campo para atualizar" });
    }

    updateValues.push(userId);

    const result = await pool.query(
      `UPDATE users SET ${updateFields.join(
        ", "
      )}, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $${paramCount} 
       RETURNING id, name, cpf, email, phone, roles, subscription_status, subscription_expiry`,
      updateValues
    );

    console.log("✅ User updated:", userId);

    res.json(result.rows[0]);
  } catch (error) {
    console.error("❌ Error updating user:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.delete(
  "/api/users/:id",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const userId = parseInt(req.params.id);

      const result = await pool.query(
        "DELETE FROM users WHERE id = $1 RETURNING id",
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Usuário não encontrado" });
      }

      console.log("✅ User deleted:", userId);

      res.json({ message: "Usuário excluído com sucesso" });
    } catch (error) {
      console.error("❌ Error deleting user:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// 🔥 CLIENT LOOKUP ROUTES
app.get("/api/clients/lookup", authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: "CPF é obrigatório" });
    }

    const cleanCpf = cpf.replace(/\D/g, "");

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: "CPF deve conter 11 dígitos" });
    }

    const result = await pool.query(
      `SELECT id, name, cpf, subscription_status, subscription_expiry 
       FROM users 
       WHERE cpf = $1 AND 'client' = ANY(roles)`,
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Cliente não encontrado" });
    }

    const client = result.rows[0];

    console.log("✅ Client found:", {
      id: client.id,
      name: client.name,
      subscription_status: client.subscription_status,
    });

    res.json(client);
  } catch (error) {
    console.error("❌ Error looking up client:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// 🔥 DEPENDENTS ROUTES
app.get("/api/dependents/:clientId", authenticate, async (req, res) => {
  try {
    const clientId = parseInt(req.params.clientId);

    console.log("🔄 Fetching dependents for client:", clientId);

    // Verify access
    if (req.user.id !== clientId && req.user.currentRole !== "admin") {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const result = await pool.query(
      `SELECT id, name, cpf, birth_date, subscription_status, subscription_expiry,
       billing_amount, payment_reference, activated_at, created_at,
       subscription_status as current_status
       FROM dependents 
       WHERE client_id = $1 
       ORDER BY created_at DESC`,
      [clientId]
    );

    console.log("✅ Dependents fetched:", result.rows.length);

    res.json(result.rows);
  } catch (error) {
    console.error("❌ Error fetching dependents:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.get("/api/dependents/lookup", authenticate, async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: "CPF é obrigatório" });
    }

    const cleanCpf = cpf.replace(/\D/g, "");

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: "CPF deve conter 11 dígitos" });
    }

    const result = await pool.query(
      `SELECT d.id, d.name, d.cpf, d.client_id, d.subscription_status as dependent_subscription_status,
       u.name as client_name, u.subscription_status as client_subscription_status
       FROM dependents d
       JOIN users u ON d.client_id = u.id
       WHERE d.cpf = $1`,
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Dependente não encontrado" });
    }

    const dependent = result.rows[0];

    console.log("✅ Dependent found:", {
      id: dependent.id,
      name: dependent.name,
      dependent_status: dependent.dependent_subscription_status,
      client_status: dependent.client_subscription_status,
    });

    res.json(dependent);
  } catch (error) {
    console.error("❌ Error looking up dependent:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post("/api/dependents", authenticate, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    console.log("🔄 Creating dependent:", { client_id, name });

    if (!client_id || !name || !cpf) {
      return res
        .status(400)
        .json({ message: "Client ID, nome e CPF são obrigatórios" });
    }

    // Verify access
    if (req.user.id !== client_id && req.user.currentRole !== "admin") {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const cleanCpf = cpf.replace(/\D/g, "");

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: "CPF deve conter 11 dígitos" });
    }

    // Check if CPF already exists
    const existingCpf = await pool.query(
      "SELECT id FROM users WHERE cpf = $1 UNION SELECT id FROM dependents WHERE cpf = $1",
      [cleanCpf]
    );

    if (existingCpf.rows.length > 0) {
      return res.status(400).json({ message: "CPF já cadastrado" });
    }

    // Check dependent limit (10 per client)
    const dependentCount = await pool.query(
      "SELECT COUNT(*) as count FROM dependents WHERE client_id = $1",
      [client_id]
    );

    if (parseInt(dependentCount.rows[0].count) >= 10) {
      return res
        .status(400)
        .json({ message: "Limite máximo de 10 dependentes atingido" });
    }

    const result = await pool.query(
      `INSERT INTO dependents (client_id, name, cpf, birth_date, subscription_status, billing_amount)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, cpf, birth_date, subscription_status, billing_amount, created_at`,
      [client_id, name.trim(), cleanCpf, birth_date || null, "pending", 50]
    );

    console.log("✅ Dependent created:", result.rows[0].id);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Error creating dependent:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.put("/api/dependents/:id", authenticate, async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);
    const { name, birth_date } = req.body;

    // Get dependent to verify ownership
    const dependent = await pool.query(
      "SELECT client_id FROM dependents WHERE id = $1",
      [dependentId]
    );

    if (dependent.rows.length === 0) {
      return res.status(404).json({ message: "Dependente não encontrado" });
    }

    // Verify access
    if (
      req.user.id !== dependent.rows[0].client_id &&
      req.user.currentRole !== "admin"
    ) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const result = await pool.query(
      `UPDATE dependents 
       SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $3
       RETURNING id, name, cpf, birth_date, subscription_status, billing_amount, created_at`,
      [name.trim(), birth_date || null, dependentId]
    );

    console.log("✅ Dependent updated:", dependentId);

    res.json(result.rows[0]);
  } catch (error) {
    console.error("❌ Error updating dependent:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.delete("/api/dependents/:id", authenticate, async (req, res) => {
  try {
    const dependentId = parseInt(req.params.id);

    // Get dependent to verify ownership
    const dependent = await pool.query(
      "SELECT client_id FROM dependents WHERE id = $1",
      [dependentId]
    );

    if (dependent.rows.length === 0) {
      return res.status(404).json({ message: "Dependente não encontrado" });
    }

    // Verify access
    if (
      req.user.id !== dependent.rows[0].client_id &&
      req.user.currentRole !== "admin"
    ) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    await pool.query("DELETE FROM dependents WHERE id = $1", [dependentId]);

    console.log("✅ Dependent deleted:", dependentId);

    res.json({ message: "Dependente excluído com sucesso" });
  } catch (error) {
    console.error("❌ Error deleting dependent:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// 🔥 ADMIN DEPENDENTS ROUTES
app.get(
  "/api/admin/dependents",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      console.log("🔄 Fetching all dependents for admin");

      const result = await pool.query(
        `SELECT d.id, d.client_id, d.name, d.cpf, d.birth_date, d.subscription_status,
       d.subscription_expiry, d.billing_amount, d.activated_at, d.created_at,
       u.name as client_name, u.subscription_status as client_status,
       d.subscription_status as current_status
       FROM dependents d
       JOIN users u ON d.client_id = u.id
       ORDER BY d.created_at DESC`
      );

      console.log("✅ All dependents fetched:", result.rows.length);

      res.json(result.rows);
    } catch (error) {
      console.error("❌ Error fetching all dependents:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.post(
  "/api/admin/dependents/:id/activate",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const dependentId = parseInt(req.params.id);

      console.log("🔄 Admin activating dependent:", dependentId);

      // Calculate expiry date (1 year from now)
      const expiryDate = new Date();
      expiryDate.setFullYear(expiryDate.getFullYear() + 1);

      // Update dependent status
      await pool.query(
        `
      UPDATE dependents 
      SET 
        subscription_status = 'active',
        subscription_expiry = $2,
        activated_at = NOW(),
        updated_at = NOW()
      WHERE id = $1
    `,
        [dependentId, expiryDate]
      );

      // Get dependent and client info
      const dependentResult = await pool.query(
        `
      SELECT d.*, u.id as client_id 
      FROM dependents d 
      JOIN users u ON d.client_id = u.id 
      WHERE d.id = $1
    `,
        [dependentId]
      );

      if (dependentResult.rows.length === 0) {
        throw new Error("Dependent not found");
      }

      const dependent = dependentResult.rows[0];

      // Insert payment record
      await pool.query(
        `
      INSERT INTO dependent_payments (dependent_id, client_id, mp_payment_id, mp_preference_id, amount, status, payment_method, activated_at, processed_at)
      VALUES ($1, $2, $3, $4, 50.00, 'approved', $5, NOW(), NOW())
      ON CONFLICT (mp_payment_id) DO NOTHING
    `,
        [
          dependentId,
          dependent.client_id,
          paymentId,
          preferenceId,
          paymentMethod,
        ]
      );

      const result = await pool.query(
        `UPDATE dependents 
       SET subscription_status = 'active', 
           subscription_expiry = $1,
           activated_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING id, name, subscription_status, subscription_expiry`,
        [expiryDate, dependentId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Dependente não encontrado" });
      }

      console.log("✅ Dependent activated by admin:", dependentId);

      res.json({
        message: "Dependente ativado com sucesso",
        dependent: result.rows[0],
      });
    } catch (error) {
      console.error("❌ Error activating dependent:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// 🔥 SERVICE CATEGORIES ROUTES
app.get("/api/service-categories", authenticate, async (req, res) => {
  try {
    console.log("🔄 Fetching service categories");

    const result = await pool.query(
      "SELECT id, name, description, created_at FROM service_categories ORDER BY name"
    );

    console.log("✅ Service categories fetched:", result.rows.length);

    res.json(result.rows);
  } catch (error) {
    console.error("❌ Error fetching service categories:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post(
  "/api/service-categories",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { name, description } = req.body;

      if (!name) {
        return res.status(400).json({ message: "Nome é obrigatório" });
      }

      const result = await pool.query(
        `INSERT INTO service_categories (name, description)
       VALUES ($1, $2)
       RETURNING id, name, description, created_at`,
        [name.trim(), description?.trim() || null]
      );

      console.log("✅ Service category created:", result.rows[0].id);

      res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error("❌ Error creating service category:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// 🔥 SERVICES ROUTES
app.get("/api/services", authenticate, async (req, res) => {
  try {
    console.log("🔄 Fetching services");

    const result = await pool.query(
      `SELECT s.id, s.name, s.description, s.base_price, s.category_id, s.is_base_service,
       sc.name as category_name
       FROM services s
       LEFT JOIN service_categories sc ON s.category_id = sc.id
       ORDER BY sc.name, s.name`
    );

    console.log("✅ Services fetched:", result.rows.length);

    res.json(result.rows);
  } catch (error) {
    console.error("❌ Error fetching services:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post(
  "/api/services",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { name, description, base_price, category_id, is_base_service } =
        req.body;

      if (!name || !description || !base_price) {
        return res
          .status(400)
          .json({ message: "Nome, descrição e preço base são obrigatórios" });
      }

      if (isNaN(base_price) || base_price <= 0) {
        return res
          .status(400)
          .json({ message: "Preço base deve ser um número maior que zero" });
      }

      const result = await pool.query(
        `INSERT INTO services (name, description, base_price, category_id, is_base_service)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, description, base_price, category_id, is_base_service`,
        [
          name.trim(),
          description.trim(),
          parseFloat(base_price),
          category_id || null,
          is_base_service || false,
        ]
      );

      console.log("✅ Service created:", result.rows[0].id);

      res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error("❌ Error creating service:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.put(
  "/api/services/:id",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const serviceId = parseInt(req.params.id);
      const { name, description, base_price, category_id, is_base_service } =
        req.body;

      if (!name || !description || !base_price) {
        return res
          .status(400)
          .json({ message: "Nome, descrição e preço base são obrigatórios" });
      }

      if (isNaN(base_price) || base_price <= 0) {
        return res
          .status(400)
          .json({ message: "Preço base deve ser um número maior que zero" });
      }

      const result = await pool.query(
        `UPDATE services 
       SET name = $1, description = $2, base_price = $3, category_id = $4, is_base_service = $5, updated_at = CURRENT_TIMESTAMP
       WHERE id = $6
       RETURNING id, name, description, base_price, category_id, is_base_service`,
        [
          name.trim(),
          description.trim(),
          parseFloat(base_price),
          category_id || null,
          is_base_service || false,
          serviceId,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Serviço não encontrado" });
      }

      console.log("✅ Service updated:", serviceId);

      res.json(result.rows[0]);
    } catch (error) {
      console.error("❌ Error updating service:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.delete(
  "/api/services/:id",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const serviceId = parseInt(req.params.id);

      const result = await pool.query(
        "DELETE FROM services WHERE id = $1 RETURNING id",
        [serviceId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Serviço não encontrado" });
      }

      console.log("✅ Service deleted:", serviceId);

      res.json({ message: "Serviço excluído com sucesso" });
    } catch (error) {
      console.error("❌ Error deleting service:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// 🔥 PROFESSIONALS ROUTES
app.get("/api/professionals", authenticate, async (req, res) => {
  try {
    console.log("🔄 Fetching professionals");

    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.phone, u.address, u.address_number,
       u.address_complement, u.neighborhood, u.city, u.state, u.roles, u.photo_url,
       COALESCE(sc.name, 'Sem categoria') as category_name
       FROM users u
       LEFT JOIN service_categories sc ON CAST(u.professional_percentage AS INTEGER) = sc.id
       WHERE 'professional' = ANY(u.roles)
       ORDER BY u.name`
    );

    console.log("✅ Professionals fetched:", result.rows.length);

    res.json(result.rows);
  } catch (error) {
    console.error("❌ Error fetching professionals:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// 🔥 CONSULTATIONS ROUTES
app.get("/api/consultations", authenticate, async (req, res) => {
  try {
    console.log(
      "🔄 Fetching consultations for user:",
      req.user.id,
      "role:",
      req.user.currentRole
    );

    let query;
    let params;

    if (req.user.currentRole === "admin") {
      // Admin sees all consultations
      query = `
        SELECT c.id, c.date, c.value, c.notes, c.status,
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
        ORDER BY c.date DESC
      `;
      params = [];
    } else if (req.user.currentRole === "professional") {
      // Professional sees their consultations
      query = `
        SELECT c.id, c.date, c.value, c.notes, c.status,
        COALESCE(u.name, d.name, pp.name) as client_name,
        s.name as service_name,
        prof.name as professional_name,
        CASE WHEN c.dependent_id IS NOT NULL THEN true ELSE false END as is_dependent
        FROM consultations c
        LEFT JOIN users u ON c.client_id = u.id
        LEFT JOIN dependents d ON c.dependent_id = d.id
        LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
        LEFT JOIN services s ON c.service_id = s.id
        LEFT JOIN users prof ON c.professional_id = prof.id
        WHERE c.professional_id = $1
        ORDER BY c.date DESC
      `;
      params = [req.user.id];
    } else {
      // Client sees their consultations
      query = `
        SELECT c.id, c.date, c.value, c.notes, c.status,
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
      `;
      params = [req.user.id];
    }

    const result = await pool.query(query, params);

    console.log("✅ Consultations fetched:", result.rows.length);

    res.json(result.rows);
  } catch (error) {
    console.error("❌ Error fetching consultations:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.get(
  "/api/consultations/client/:clientId",
  authenticate,
  async (req, res) => {
    try {
      const clientId = parseInt(req.params.clientId);

      console.log("🔄 Fetching consultations for client:", clientId);

      // Verify access
      if (req.user.id !== clientId && req.user.currentRole !== "admin") {
        return res.status(403).json({ message: "Acesso negado" });
      }

      const result = await pool.query(
        `SELECT c.id, c.date, c.value, c.notes, c.status,
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
       ORDER BY c.date DESC`,
        [clientId]
      );

      console.log("✅ Client consultations fetched:", result.rows.length);

      res.json(result.rows);
    } catch (error) {
      console.error("❌ Error fetching client consultations:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.post("/api/consultations", authenticate, async (req, res) => {
  try {
    const {
      client_id,
      dependent_id,
      private_patient_id,
      service_id,
      location_id,
      value,
      date,
      status,
      notes,
    } = req.body;

    console.log("🔄 Creating consultation:", {
      client_id,
      dependent_id,
      private_patient_id,
      service_id,
      professional_id: req.user.id,
    });

    if (!service_id || !value || !date) {
      return res
        .status(400)
        .json({ message: "Serviço, valor e data são obrigatórios" });
    }

    if (isNaN(value) || value <= 0) {
      return res
        .status(400)
        .json({ message: "Valor deve ser um número maior que zero" });
    }

    // Verify that either client_id, dependent_id, or private_patient_id is provided
    if (!client_id && !dependent_id && !private_patient_id) {
      return res.status(400).json({
        message:
          "Cliente, dependente ou paciente particular deve ser especificado",
      });
    }

    const result = await pool.query(
      `INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id, service_id,
        location_id, value, date, status, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING id, date, value, status, notes`,
      [
        client_id || null,
        dependent_id || null,
        private_patient_id || null,
        req.user.id,
        service_id,
        location_id || null,
        parseFloat(value),
        new Date(date),
        status || "completed",
        notes?.trim() || null,
      ]
    );

    console.log("✅ Consultation created:", result.rows[0].id);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Error creating consultation:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.put("/api/consultations/:id/status", authenticate, async (req, res) => {
  try {
    const consultationId = parseInt(req.params.id);
    const { status } = req.body;

    console.log("🔄 Updating consultation status:", { consultationId, status });

    if (!status) {
      return res.status(400).json({ message: "Status é obrigatório" });
    }

    const validStatuses = ["scheduled", "confirmed", "completed", "cancelled"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: "Status inválido" });
    }

    // Verify consultation belongs to professional or user is admin
    const consultation = await pool.query(
      "SELECT professional_id FROM consultations WHERE id = $1",
      [consultationId]
    );

    if (consultation.rows.length === 0) {
      return res.status(404).json({ message: "Consulta não encontrada" });
    }

    if (
      req.user.currentRole !== "admin" &&
      consultation.rows[0].professional_id !== req.user.id
    ) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const result = await pool.query(
      `UPDATE consultations 
       SET status = $1, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING id, status`,
      [status, consultationId]
    );

    console.log("✅ Consultation status updated:", consultationId);

    res.json(result.rows[0]);
  } catch (error) {
    console.error("❌ Error updating consultation status:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// 🔥 PRIVATE PATIENTS ROUTES
app.get(
  "/api/private-patients",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      console.log(
        "🔄 Fetching private patients for professional:",
        req.user.id
      );

      let query;
      let params;

      if (req.user.currentRole === "admin") {
        query = `
        SELECT pp.id, pp.name, pp.cpf, pp.email, pp.phone, pp.birth_date,
        pp.address, pp.address_number, pp.address_complement, pp.neighborhood,
        pp.city, pp.state, pp.zip_code, pp.created_at,
        u.name as professional_name
        FROM private_patients pp
        LEFT JOIN users u ON pp.professional_id = u.id
        ORDER BY pp.created_at DESC
      `;
        params = [];
      } else {
        query = `
        SELECT id, name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, zip_code, created_at
        FROM private_patients 
        WHERE professional_id = $1 
        ORDER BY created_at DESC
      `;
        params = [req.user.id];
      }

      const result = await pool.query(query, params);

      console.log("✅ Private patients fetched:", result.rows.length);

      res.json(result.rows);
    } catch (error) {
      console.error("❌ Error fetching private patients:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.post(
  "/api/private-patients",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
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
        zip_code,
      } = req.body;

      if (!name) {
        return res.status(400).json({ message: "Nome é obrigatório" });
      }

      let cleanCpf = null;
      if (cpf) {
        cleanCpf = cpf.replace(/\D/g, "");
        if (!/^\d{11}$/.test(cleanCpf)) {
          return res
            .status(400)
            .json({ message: "CPF deve conter 11 dígitos" });
        }

        // Check if CPF already exists
        const existingCpf = await pool.query(
          "SELECT id FROM users WHERE cpf = $1 UNION SELECT id FROM dependents WHERE cpf = $1 UNION SELECT id FROM private_patients WHERE cpf = $1",
          [cleanCpf]
        );

        if (existingCpf.rows.length > 0) {
          return res.status(400).json({ message: "CPF já cadastrado" });
        }
      }

      const result = await pool.query(
        `INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id, name, cpf, email, phone, birth_date, address, address_number,
      address_complement, neighborhood, city, state, zip_code, created_at`,
        [
          req.user.id,
          name.trim(),
          cleanCpf,
          email?.trim() || null,
          phone?.replace(/\D/g, "") || null,
          birth_date || null,
          address?.trim() || null,
          address_number?.trim() || null,
          address_complement?.trim() || null,
          neighborhood?.trim() || null,
          city?.trim() || null,
          state || null,
          zip_code?.replace(/\D/g, "") || null,
        ]
      );

      console.log("✅ Private patient created:", result.rows[0].id);

      res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error("❌ Error creating private patient:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.put(
  "/api/private-patients/:id",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      const patientId = parseInt(req.params.id);
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
        zip_code,
      } = req.body;

      if (!name) {
        return res.status(400).json({ message: "Nome é obrigatório" });
      }

      // Verify ownership for professionals
      if (req.user.currentRole === "professional") {
        const patient = await pool.query(
          "SELECT professional_id FROM private_patients WHERE id = $1",
          [patientId]
        );

        if (patient.rows.length === 0) {
          return res.status(404).json({ message: "Paciente não encontrado" });
        }

        if (patient.rows[0].professional_id !== req.user.id) {
          return res.status(403).json({ message: "Acesso negado" });
        }
      }

      const result = await pool.query(
        `UPDATE private_patients 
       SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
       address_number = $6, address_complement = $7, neighborhood = $8,
       city = $9, state = $10, zip_code = $11, updated_at = CURRENT_TIMESTAMP
       WHERE id = $12
       RETURNING id, name, cpf, email, phone, birth_date, address, address_number,
       address_complement, neighborhood, city, state, zip_code, created_at`,
        [
          name.trim(),
          email?.trim() || null,
          phone?.replace(/\D/g, "") || null,
          birth_date || null,
          address?.trim() || null,
          address_number?.trim() || null,
          address_complement?.trim() || null,
          neighborhood?.trim() || null,
          city?.trim() || null,
          state || null,
          zip_code?.replace(/\D/g, "") || null,
          patientId,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Paciente não encontrado" });
      }

      console.log("✅ Private patient updated:", patientId);

      res.json(result.rows[0]);
    } catch (error) {
      console.error("❌ Error updating private patient:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.delete(
  "/api/private-patients/:id",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      const patientId = parseInt(req.params.id);

      // Verify ownership for professionals
      if (req.user.currentRole === "professional") {
        const patient = await pool.query(
          "SELECT professional_id FROM private_patients WHERE id = $1",
          [patientId]
        );

        if (patient.rows.length === 0) {
          return res.status(404).json({ message: "Paciente não encontrado" });
        }

        if (patient.rows[0].professional_id !== req.user.id) {
          return res.status(403).json({ message: "Acesso negado" });
        }
      }

      const result = await pool.query(
        "DELETE FROM private_patients WHERE id = $1 RETURNING id",
        [patientId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Paciente não encontrado" });
      }

      console.log("✅ Private patient deleted:", patientId);

      res.json({ message: "Paciente excluído com sucesso" });
    } catch (error) {
      console.error("❌ Error deleting private patient:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// 🔥 ATTENDANCE LOCATIONS ROUTES
app.get(
  "/api/attendance-locations",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      console.log(
        "🔄 Fetching attendance locations for professional:",
        req.user.id
      );

      let query;
      let params;

      if (req.user.currentRole === "admin") {
        query = `
        SELECT al.id, al.name, al.address, al.address_number, al.address_complement,
        al.neighborhood, al.city, al.state, al.zip_code, al.phone, al.is_default,
        al.created_at, u.name as professional_name
        FROM attendance_locations al
        LEFT JOIN users u ON al.professional_id = u.id
        ORDER BY al.created_at DESC
      `;
        params = [];
      } else {
        query = `
        SELECT id, name, address, address_number, address_complement, neighborhood,
        city, state, zip_code, phone, is_default, created_at
        FROM attendance_locations 
        WHERE professional_id = $1 
        ORDER BY is_default DESC, created_at DESC
      `;
        params = [req.user.id];
      }

      const result = await pool.query(query, params);

      console.log("✅ Attendance locations fetched:", result.rows.length);

      res.json(result.rows);
    } catch (error) {
      console.error("❌ Error fetching attendance locations:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.post(
  "/api/attendance-locations",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      const {
        name,
        address,
        address_number,
        address_complement,
        neighborhood,
        city,
        state,
        zip_code,
        phone,
        is_default,
      } = req.body;

      if (!name) {
        return res.status(400).json({ message: "Nome é obrigatório" });
      }

      // If setting as default, remove default from other locations
      if (is_default) {
        await pool.query(
          "UPDATE attendance_locations SET is_default = false WHERE professional_id = $1",
          [req.user.id]
        );
      }

      const result = await pool.query(
        `INSERT INTO attendance_locations (
        professional_id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id, name, address, address_number, address_complement,
      neighborhood, city, state, zip_code, phone, is_default, created_at`,
        [
          req.user.id,
          name.trim(),
          address?.trim() || null,
          address_number?.trim() || null,
          address_complement?.trim() || null,
          neighborhood?.trim() || null,
          city?.trim() || null,
          state || null,
          zip_code?.replace(/\D/g, "") || null,
          phone?.replace(/\D/g, "") || null,
          is_default || false,
        ]
      );

      console.log("✅ Attendance location created:", result.rows[0].id);

      res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error("❌ Error creating attendance location:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.put(
  "/api/attendance-locations/:id",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      const locationId = parseInt(req.params.id);
      const {
        name,
        address,
        address_number,
        address_complement,
        neighborhood,
        city,
        state,
        zip_code,
        phone,
        is_default,
      } = req.body;

      if (!name) {
        return res.status(400).json({ message: "Nome é obrigatório" });
      }

      // Verify ownership for professionals
      if (req.user.currentRole === "professional") {
        const location = await pool.query(
          "SELECT professional_id FROM attendance_locations WHERE id = $1",
          [locationId]
        );

        if (location.rows.length === 0) {
          return res.status(404).json({ message: "Local não encontrado" });
        }

        if (location.rows[0].professional_id !== req.user.id) {
          return res.status(403).json({ message: "Acesso negado" });
        }
      }

      // If setting as default, remove default from other locations
      if (is_default) {
        const professionalId =
          req.user.currentRole === "admin"
            ? (
                await pool.query(
                  "SELECT professional_id FROM attendance_locations WHERE id = $1",
                  [locationId]
                )
              ).rows[0]?.professional_id
            : req.user.id;

        if (professionalId) {
          await pool.query(
            "UPDATE attendance_locations SET is_default = false WHERE professional_id = $1 AND id != $2",
            [professionalId, locationId]
          );
        }
      }

      const result = await pool.query(
        `UPDATE attendance_locations 
       SET name = $1, address = $2, address_number = $3, address_complement = $4,
       neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9,
       is_default = $10, updated_at = CURRENT_TIMESTAMP
       WHERE id = $11
       RETURNING id, name, address, address_number, address_complement,
       neighborhood, city, state, zip_code, phone, is_default, created_at`,
        [
          name.trim(),
          address?.trim() || null,
          address_number?.trim() || null,
          address_complement?.trim() || null,
          neighborhood?.trim() || null,
          city?.trim() || null,
          state || null,
          zip_code?.replace(/\D/g, "") || null,
          phone?.replace(/\D/g, "") || null,
          is_default || false,
          locationId,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Local não encontrado" });
      }

      console.log("✅ Attendance location updated:", locationId);

      res.json(result.rows[0]);
    } catch (error) {
      console.error("❌ Error updating attendance location:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.delete(
  "/api/attendance-locations/:id",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      const locationId = parseInt(req.params.id);

      // Verify ownership for professionals
      if (req.user.currentRole === "professional") {
        const location = await pool.query(
          "SELECT professional_id FROM attendance_locations WHERE id = $1",
          [locationId]
        );

        if (location.rows.length === 0) {
          return res.status(404).json({ message: "Local não encontrado" });
        }

        if (location.rows[0].professional_id !== req.user.id) {
          return res.status(403).json({ message: "Acesso negado" });
        }
      }

      const result = await pool.query(
        "DELETE FROM attendance_locations WHERE id = $1 RETURNING id",
        [locationId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Local não encontrado" });
      }

      console.log("✅ Attendance location deleted:", locationId);

      res.json({ message: "Local excluído com sucesso" });
    } catch (error) {
      console.error("❌ Error deleting attendance location:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// 🔥 MEDICAL RECORDS ROUTES
app.get(
  "/api/medical-records",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      console.log("🔄 Fetching medical records for professional:", req.user.id);

      let query;
      let params;

      if (req.user.currentRole === "admin") {
        query = `
        SELECT mr.id, mr.chief_complaint, mr.history_present_illness, mr.past_medical_history,
        mr.medications, mr.allergies, mr.physical_examination, mr.diagnosis,
        mr.treatment_plan, mr.notes, mr.vital_signs, mr.created_at, mr.updated_at,
        pp.name as patient_name, u.name as professional_name
        FROM medical_records mr
        LEFT JOIN private_patients pp ON mr.private_patient_id = pp.id
        LEFT JOIN users u ON mr.professional_id = u.id
        ORDER BY mr.created_at DESC
      `;
        params = [];
      } else {
        query = `
        SELECT mr.id, mr.chief_complaint, mr.history_present_illness, mr.past_medical_history,
        mr.medications, mr.allergies, mr.physical_examination, mr.diagnosis,
        mr.treatment_plan, mr.notes, mr.vital_signs, mr.created_at, mr.updated_at,
        pp.name as patient_name
        FROM medical_records mr
        LEFT JOIN private_patients pp ON mr.private_patient_id = pp.id
        WHERE mr.professional_id = $1
        ORDER BY mr.created_at DESC
      `;
        params = [req.user.id];
      }

      const result = await pool.query(query, params);

      console.log("✅ Medical records fetched:", result.rows.length);

      res.json(result.rows);
    } catch (error) {
      console.error("❌ Error fetching medical records:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.post(
  "/api/medical-records",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      const {
        private_patient_id,
        chief_complaint,
        history_present_illness,
        past_medical_history,
        medications,
        allergies,
        physical_examination,
        diagnosis,
        treatment_plan,
        notes,
        vital_signs,
      } = req.body;

      if (!private_patient_id) {
        return res.status(400).json({ message: "Paciente é obrigatório" });
      }

      // Verify patient belongs to professional
      if (req.user.currentRole === "professional") {
        const patient = await pool.query(
          "SELECT professional_id FROM private_patients WHERE id = $1",
          [private_patient_id]
        );

        if (patient.rows.length === 0) {
          return res.status(404).json({ message: "Paciente não encontrado" });
        }

        if (patient.rows[0].professional_id !== req.user.id) {
          return res.status(403).json({ message: "Acesso negado" });
        }
      }

      const result = await pool.query(
        `INSERT INTO medical_records (
        professional_id, private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, vital_signs
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING id, chief_complaint, diagnosis, created_at`,
        [
          req.user.id,
          private_patient_id,
          chief_complaint?.trim() || null,
          history_present_illness?.trim() || null,
          past_medical_history?.trim() || null,
          medications?.trim() || null,
          allergies?.trim() || null,
          physical_examination?.trim() || null,
          diagnosis?.trim() || null,
          treatment_plan?.trim() || null,
          notes?.trim() || null,
          vital_signs || null,
        ]
      );

      console.log("✅ Medical record created:", result.rows[0].id);

      res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error("❌ Error creating medical record:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.put(
  "/api/medical-records/:id",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      const recordId = parseInt(req.params.id);
      const {
        chief_complaint,
        history_present_illness,
        past_medical_history,
        medications,
        allergies,
        physical_examination,
        diagnosis,
        treatment_plan,
        notes,
        vital_signs,
      } = req.body;

      // Verify ownership for professionals
      if (req.user.currentRole === "professional") {
        const record = await pool.query(
          "SELECT professional_id FROM medical_records WHERE id = $1",
          [recordId]
        );

        if (record.rows.length === 0) {
          return res.status(404).json({ message: "Prontuário não encontrado" });
        }

        if (record.rows[0].professional_id !== req.user.id) {
          return res.status(403).json({ message: "Acesso negado" });
        }
      }

      const result = await pool.query(
        `UPDATE medical_records 
       SET chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
       medications = $4, allergies = $5, physical_examination = $6, diagnosis = $7,
       treatment_plan = $8, notes = $9, vital_signs = $10, updated_at = CURRENT_TIMESTAMP
       WHERE id = $11
       RETURNING id, chief_complaint, diagnosis, updated_at`,
        [
          chief_complaint?.trim() || null,
          history_present_illness?.trim() || null,
          past_medical_history?.trim() || null,
          medications?.trim() || null,
          allergies?.trim() || null,
          physical_examination?.trim() || null,
          diagnosis?.trim() || null,
          treatment_plan?.trim() || null,
          notes?.trim() || null,
          vital_signs || null,
          recordId,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Prontuário não encontrado" });
      }

      console.log("✅ Medical record updated:", recordId);

      res.json(result.rows[0]);
    } catch (error) {
      console.error("❌ Error updating medical record:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.delete(
  "/api/medical-records/:id",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      const recordId = parseInt(req.params.id);

      // Verify ownership for professionals
      if (req.user.currentRole === "professional") {
        const record = await pool.query(
          "SELECT professional_id FROM medical_records WHERE id = $1",
          [recordId]
        );

        if (record.rows.length === 0) {
          return res.status(404).json({ message: "Prontuário não encontrado" });
        }

        if (record.rows[0].professional_id !== req.user.id) {
          return res.status(403).json({ message: "Acesso negado" });
        }
      }

      const result = await pool.query(
        "DELETE FROM medical_records WHERE id = $1 RETURNING id",
        [recordId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Prontuário não encontrado" });
      }

      console.log("✅ Medical record deleted:", recordId);

      res.json({ message: "Prontuário excluído com sucesso" });
    } catch (error) {
      console.error("❌ Error deleting medical record:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.post(
  "/api/medical-records/generate-document",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      const { record_id, template_data } = req.body;

      console.log("🔄 Generating medical record document:", record_id);

      if (!record_id || !template_data) {
        return res.status(400).json({
          message: "ID do prontuário e dados do template são obrigatórios",
        });
      }

      // Verify record ownership for professionals
      if (req.user.currentRole === "professional") {
        const record = await pool.query(
          "SELECT professional_id FROM medical_records WHERE id = $1",
          [record_id]
        );

        if (record.rows.length === 0) {
          return res.status(404).json({ message: "Prontuário não encontrado" });
        }

        if (record.rows[0].professional_id !== req.user.id) {
          return res.status(403).json({ message: "Acesso negado" });
        }
      }

      const documentResult = await generateDocumentPDF(
        "medical_record",
        template_data
      );

      console.log("✅ Medical record document generated:", documentResult.url);

      res.json({
        message: "Documento gerado com sucesso",
        documentUrl: documentResult.url,
        publicId: documentResult.public_id,
      });
    } catch (error) {
      console.error("❌ Error generating medical record document:", error);
      res.status(500).json({ message: "Erro ao gerar documento" });
    }
  }
);

// 🔥 MEDICAL DOCUMENTS ROUTES
app.get(
  "/api/medical-documents",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      console.log(
        "🔄 Fetching medical documents for professional:",
        req.user.id
      );

      let query;
      let params;

      if (req.user.currentRole === "admin") {
        query = `
        SELECT md.id, md.title, md.document_type, md.document_url, md.created_at,
        pp.name as patient_name, u.name as professional_name
        FROM medical_documents md
        LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
        LEFT JOIN users u ON md.professional_id = u.id
        ORDER BY md.created_at DESC
      `;
        params = [];
      } else {
        query = `
        SELECT md.id, md.title, md.document_type, md.document_url, md.created_at,
        pp.name as patient_name
        FROM medical_documents md
        LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
        WHERE md.professional_id = $1
        ORDER BY md.created_at DESC
      `;
        params = [req.user.id];
      }

      const result = await pool.query(query, params);

      console.log("✅ Medical documents fetched:", result.rows.length);

      res.json(result.rows);
    } catch (error) {
      console.error("❌ Error fetching medical documents:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.post(
  "/api/medical-documents",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      const { title, document_type, private_patient_id, template_data } =
        req.body;

      console.log("🔄 Creating medical document:", { title, document_type });

      if (!title || !document_type || !template_data) {
        return res.status(400).json({
          message:
            "Título, tipo de documento e dados do template são obrigatórios",
        });
      }

      // Verify patient belongs to professional
      if (private_patient_id && req.user.currentRole === "professional") {
        const patient = await pool.query(
          "SELECT professional_id FROM private_patients WHERE id = $1",
          [private_patient_id]
        );

        if (patient.rows.length === 0) {
          return res.status(404).json({ message: "Paciente não encontrado" });
        }

        if (patient.rows[0].professional_id !== req.user.id) {
          return res.status(403).json({ message: "Acesso negado" });
        }
      }

      // Generate document
      const documentResult = await generateDocumentPDF(
        document_type,
        template_data
      );

      // Save document record
      const result = await pool.query(
        `INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type, document_url, template_data
      ) VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, title, document_type, document_url, created_at`,
        [
          req.user.id,
          private_patient_id || null,
          title.trim(),
          document_type,
          documentResult.url,
          template_data,
        ]
      );

      console.log("✅ Medical document created:", result.rows[0].id);

      res.status(201).json({
        ...result.rows[0],
        title: title.trim(),
        documentUrl: documentResult.url,
      });
    } catch (error) {
      console.error("❌ Error creating medical document:", error);
      res.status(500).json({ message: "Erro ao criar documento" });
    }
  }
);

// 🔥 REPORTS ROUTES
app.get(
  "/api/reports/revenue",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { start_date, end_date } = req.query;

      console.log("🔄 Generating revenue report:", { start_date, end_date });

      if (!start_date || !end_date) {
        return res
          .status(400)
          .json({ message: "Data inicial e final são obrigatórias" });
      }

      // Get total revenue
      const totalResult = await pool.query(
        `SELECT COALESCE(SUM(value), 0) as total_revenue
       FROM consultations 
       WHERE date >= $1 AND date <= $2`,
        [start_date, end_date]
      );

      const totalRevenue = parseFloat(totalResult.rows[0].total_revenue) || 0;

      // Get revenue by professional
      const professionalResult = await pool.query(
        `SELECT u.name as professional_name,
       COALESCE(u.professional_percentage, 50) as professional_percentage,
       COALESCE(SUM(c.value), 0) as revenue,
       COUNT(c.id) as consultation_count,
       COALESCE(SUM(c.value * (COALESCE(u.professional_percentage, 50) / 100.0)), 0) as professional_payment,
       COALESCE(SUM(c.value * ((100 - COALESCE(u.professional_percentage, 50)) / 100.0)), 0) as clinic_revenue
       FROM users u
       LEFT JOIN consultations c ON u.id = c.professional_id 
         AND c.date >= $1 AND c.date <= $2
       WHERE 'professional' = ANY(u.roles)
       GROUP BY u.id, u.name, u.professional_percentage
       ORDER BY revenue DESC`,
        [start_date, end_date]
      );

      // Convert percentages to integers
      const revenueByProfessional = professionalResult.rows.map((row) => ({
        ...row,
        professional_percentage: parseInt(row.professional_percentage) || 50,
        revenue: parseFloat(row.revenue) || 0,
        consultation_count: parseInt(row.consultation_count) || 0,
        professional_payment: parseFloat(row.professional_payment) || 0,
        clinic_revenue: parseFloat(row.clinic_revenue) || 0,
      }));

      // Get revenue by service
      const serviceResult = await pool.query(
        `SELECT s.name as service_name,
       COALESCE(SUM(c.value), 0) as revenue,
       COUNT(c.id) as consultation_count
       FROM services s
       LEFT JOIN consultations c ON s.id = c.service_id 
         AND c.date >= $1 AND c.date <= $2
       GROUP BY s.id, s.name
       HAVING COUNT(c.id) > 0
       ORDER BY revenue DESC`,
        [start_date, end_date]
      );

      const revenueByService = serviceResult.rows.map((row) => ({
        service_name: row.service_name,
        revenue: parseFloat(row.revenue) || 0,
        consultation_count: parseInt(row.consultation_count) || 0,
      }));

      const report = {
        total_revenue: totalRevenue,
        revenue_by_professional: revenueByProfessional,
        revenue_by_service: revenueByService,
      };

      console.log("✅ Revenue report generated:", {
        total_revenue: totalRevenue,
        professionals: revenueByProfessional.length,
        services: revenueByService.length,
      });

      res.json(report);
    } catch (error) {
      console.error("❌ Error generating revenue report:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.get(
  "/api/reports/professional-revenue",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { start_date, end_date } = req.query;

      console.log(
        "🔄 Generating professional revenue report for user:",
        req.user.id
      );

      if (!start_date || !end_date) {
        return res
          .status(400)
          .json({ message: "Data inicial e final são obrigatórias" });
      }

      // Get professional percentage from database
      const professionalData = await pool.query(
        "SELECT professional_percentage FROM users WHERE id = $1",
        [req.user.id]
      );

      const professionalPercentage =
        parseInt(professionalData.rows[0]?.professional_percentage) || 50;

      console.log(
        "🔍 Professional percentage from DB:",
        professionalPercentage
      );

      // Get consultations for the professional
      const result = await pool.query(
        `SELECT c.date, c.value,
       COALESCE(u.name, d.name, pp.name) as client_name,
       s.name as service_name,
       c.value * ($3 / 100.0) as amount_to_pay
       FROM consultations c
       LEFT JOIN users u ON c.client_id = u.id
       LEFT JOIN dependents d ON c.dependent_id = d.id
       LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
       LEFT JOIN services s ON c.service_id = s.id
       WHERE c.professional_id = $1 AND c.date >= $2 AND c.date <= $4
       ORDER BY c.date DESC`,
        [req.user.id, start_date, 100 - professionalPercentage, end_date]
      );

      // Calculate summary
      const consultations = result.rows.map((row) => ({
        date: row.date,
        client_name: row.client_name,
        service_name: row.service_name,
        total_value: parseFloat(row.value) || 0,
        amount_to_pay: parseFloat(row.amount_to_pay) || 0,
      }));

      const summary = {
        professional_percentage: professionalPercentage,
        total_revenue: consultations.reduce((sum, c) => sum + c.total_value, 0),
        consultation_count: consultations.length,
        amount_to_pay: consultations.reduce(
          (sum, c) => sum + c.amount_to_pay,
          0
        ),
      };

      const report = {
        summary,
        consultations,
      };

      console.log("✅ Professional revenue report generated:", {
        consultation_count: summary.consultation_count,
        total_revenue: summary.total_revenue,
        amount_to_pay: summary.amount_to_pay,
      });

      res.json(report);
    } catch (error) {
      console.error("❌ Error generating professional revenue report:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.get(
  "/api/reports/professional-detailed",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { start_date, end_date } = req.query;

      console.log(
        "🔄 Generating detailed professional report for user:",
        req.user.id
      );

      if (!start_date || !end_date) {
        return res
          .status(400)
          .json({ message: "Data inicial e final são obrigatórias" });
      }

      // Get professional percentage
      const professionalData = await pool.query(
        "SELECT professional_percentage FROM users WHERE id = $1",
        [req.user.id]
      );

      const professionalPercentage =
        parseInt(professionalData.rows[0]?.professional_percentage) || 50;

      // Get consultations breakdown
      const consultationsResult = await pool.query(
        `SELECT 
       COUNT(*) as total_consultations,
       COUNT(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 1 END) as convenio_consultations,
       COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
       COALESCE(SUM(c.value), 0) as total_revenue,
       COALESCE(SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value ELSE 0 END), 0) as convenio_revenue,
       COALESCE(SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END), 0) as private_revenue
       FROM consultations c
       WHERE c.professional_id = $1 AND c.date >= $2 AND c.date <= $3`,
        [req.user.id, start_date, end_date]
      );

      const data = consultationsResult.rows[0];
      const convenioRevenue = parseFloat(data.convenio_revenue) || 0;
      const amountToPay =
        convenioRevenue * ((100 - professionalPercentage) / 100);

      const summary = {
        total_consultations: parseInt(data.total_consultations) || 0,
        convenio_consultations: parseInt(data.convenio_consultations) || 0,
        private_consultations: parseInt(data.private_consultations) || 0,
        total_revenue: parseFloat(data.total_revenue) || 0,
        convenio_revenue: convenioRevenue,
        private_revenue: parseFloat(data.private_revenue) || 0,
        professional_percentage: professionalPercentage,
        amount_to_pay: amountToPay,
      };

      console.log("✅ Detailed professional report generated:", summary);

      res.json({ summary });
    } catch (error) {
      console.error("❌ Error generating detailed professional report:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.get(
  "/api/reports/clients-by-city",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      console.log("🔄 Generating clients by city report");

      const result = await pool.query(
        `SELECT 
       city,
       state,
       COUNT(*) as client_count,
       COUNT(CASE WHEN subscription_status = 'active' THEN 1 END) as active_clients,
       COUNT(CASE WHEN subscription_status = 'pending' THEN 1 END) as pending_clients,
       COUNT(CASE WHEN subscription_status = 'expired' THEN 1 END) as expired_clients
       FROM users 
       WHERE 'client' = ANY(roles) AND city IS NOT NULL AND city != ''
       GROUP BY city, state
       ORDER BY client_count DESC, city`
      );

      const report = result.rows.map((row) => ({
        city: row.city,
        state: row.state,
        client_count: parseInt(row.client_count) || 0,
        active_clients: parseInt(row.active_clients) || 0,
        pending_clients: parseInt(row.pending_clients) || 0,
        expired_clients: parseInt(row.expired_clients) || 0,
      }));

      console.log("✅ Clients by city report generated:", report.length);

      res.json(report);
    } catch (error) {
      console.error("❌ Error generating clients by city report:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.get(
  "/api/reports/professionals-by-city",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      console.log("🔄 Generating professionals by city report");

      const result = await pool.query(
        `SELECT 
       u.city,
       u.state,
       COUNT(*) as total_professionals,
       json_agg(
         json_build_object(
           'category_name', COALESCE(sc.name, 'Sem categoria'),
           'count', 1
         )
       ) as categories
       FROM users u
       LEFT JOIN service_categories sc ON CAST(u.professional_percentage AS INTEGER) = sc.id
       WHERE 'professional' = ANY(u.roles) AND u.city IS NOT NULL AND u.city != ''
       GROUP BY u.city, u.state
       ORDER BY total_professionals DESC, u.city`
      );

      const report = result.rows.map((row) => ({
        city: row.city,
        state: row.state,
        total_professionals: parseInt(row.total_professionals) || 0,
        categories: row.categories || [],
      }));

      console.log("✅ Professionals by city report generated:", report.length);

      res.json(report);
    } catch (error) {
      console.error("❌ Error generating professionals by city report:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// 🔥 SCHEDULING ACCESS MANAGEMENT
app.get(
  "/api/admin/professionals-scheduling-access",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      console.log("🔄 Fetching professionals scheduling access");

      const result = await pool.query(
        `SELECT u.id, u.name, u.email, u.phone,
       COALESCE(sc.name, 'Sem categoria') as category_name,
       COALESCE(sa.has_access, false) as has_scheduling_access,
        CASE 
          WHEN u.scheduling_access_expires_at IS NOT NULL AND u.scheduling_access_expires_at > NOW() THEN true
          ELSE false
        END as has_scheduling_access,
        u.scheduling_access_expires_at as access_expires_at,
        u.scheduling_access_granted_by as access_granted_by,
        u.scheduling_access_granted_at as access_granted_at
       LEFT JOIN service_categories sc ON CAST(u.professional_percentage AS INTEGER) = sc.id
       WHERE 'professional' = ANY(u.roles)
       ORDER BY u.name`
      );

      console.log(
        "✅ Professionals scheduling access fetched:",
        result.rows.length
      );

      res.json(result.rows);
    } catch (error) {
      console.error(
        "❌ Error fetching professionals scheduling access:",
        error
      );
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.post(
  "/api/admin/grant-scheduling-access",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { professional_id, expires_at, reason } = req.body;

      console.log("🔄 Granting scheduling access:", {
        professional_id,
        expires_at,
      });

      if (!professional_id || !expires_at) {
        return res.status(400).json({
          message: "ID do profissional e data de expiração são obrigatórios",
        });
      }

      // Upsert scheduling access
      await pool.query(
        `INSERT INTO scheduling_access (professional_id, has_access, expires_at, granted_by, granted_at, reason)
       VALUES ($1, true, $2, $3, CURRENT_TIMESTAMP, $4)
       ON CONFLICT (professional_id) 
       DO UPDATE SET 
         has_access = true,
         expires_at = $2,
         granted_by = $3,
         granted_at = CURRENT_TIMESTAMP,
         reason = $4`,
        [professional_id, expires_at, req.user.name, reason]
      );

      console.log(
        "✅ Scheduling access granted to professional:",
        professional_id
      );

      res.json({ message: "Acesso à agenda concedido com sucesso" });
    } catch (error) {
      console.error("❌ Error granting scheduling access:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.post(
  "/api/admin/revoke-scheduling-access",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { professional_id } = req.body;

      console.log(
        "🔄 Revoking scheduling access for professional:",
        professional_id
      );

      if (!professional_id) {
        return res
          .status(400)
          .json({ message: "ID do profissional é obrigatório" });
      }

      await pool.query(
        `UPDATE scheduling_access 
       SET has_access = false, revoked_at = CURRENT_TIMESTAMP, revoked_by = $1
       WHERE professional_id = $2`,
        [req.user.name, professional_id]
      );

      console.log(
        "✅ Scheduling access revoked for professional:",
        professional_id
      );

      res.json({ message: "Acesso à agenda revogado com sucesso" });
    } catch (error) {
      console.error("❌ Error revoking scheduling access:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// 🔥 IMAGE UPLOAD ROUTE
app.post("/api/upload-image", authenticate, async (req, res) => {
  try {
    console.log("🔄 Image upload request for user:", req.user.id);

    const upload = createUpload();

    upload.single("image")(req, res, async (err) => {
      if (err) {
        console.error("❌ Upload error:", err);
        return res
          .status(400)
          .json({ message: err.message || "Erro no upload da imagem" });
      }

      if (!req.file) {
        return res.status(400).json({ message: "Nenhuma imagem foi enviada" });
      }

      console.log("✅ Image uploaded to Cloudinary:", req.file.path);

      // Update user photo URL in database
      await pool.query(
        "UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
        [req.file.path, req.user.id]
      );

      console.log("✅ User photo URL updated in database");

      res.json({
        message: "Imagem enviada com sucesso",
        imageUrl: req.file.path,
        publicId: req.file.filename,
      });
    });
  } catch (error) {
    console.error("❌ Error in image upload route:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// 🔥 MERCADOPAGO PAYMENT ROUTES

// 🚫 SUBSCRIPTION PAYMENT WITH TRIPLE VERIFICATION
app.post(
  "/api/create-subscription",
  authenticate,
  preventPaymentForActiveClients,
  async (req, res) => {
    try {
      const { user_id } = req.body;

      console.log("🔄 Creating subscription payment for user:", user_id);

      if (!user_id) {
        return res.status(400).json({ message: "User ID é obrigatório" });
      }

      // VERIFICATION 1: Check if user exists and get current status
      const userResult = await pool.query(
        "SELECT id, name, cpf, subscription_status FROM users WHERE id = $1",
        [user_id]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({ message: "Usuário não encontrado" });
      }

      const user = userResult.rows[0];

      // VERIFICATION 2: Block if already active
      if (user.subscription_status === "active") {
        console.error("🚫 BLOCKED: Active client tried to pay!", {
          userId: user_id,
          userName: user.name,
          status: user.subscription_status,
          timestamp: new Date().toISOString(),
        });

        return res.status(400).json({
          message:
            "Sua assinatura já está ativa. Não é necessário realizar pagamento.",
          blocked: true,
          current_status: user.subscription_status,
        });
      }

      // VERIFICATION 3: Only allow if status is pending or expired
      if (!["pending", "expired"].includes(user.subscription_status)) {
        return res.status(400).json({
          message: "Status de assinatura inválido para pagamento.",
          current_status: user.subscription_status,
        });
      }

      console.log("✅ PAYMENT ALLOWED for user:", {
        userId: user_id,
        userName: user.name,
        status: user.subscription_status,
      });

      const preference = new Preference(mercadoPagoClient);

      const preferenceData = {
        items: [
          {
            id: `subscription_${user_id}`,
            title: "Assinatura Convênio Quiro Ferreira",
            description: "Assinatura mensal do convênio de saúde",
            quantity: 1,
            unit_price: 250,
            currency_id: "BRL",
          },
        ],
        payer: {
          name: user.name,
          identification: {
            type: "CPF",
            number: user.cpf,
          },
        },
        back_urls: {
          success: `${req.protocol}://${req.get(
            "host"
          )}/api/payment/success?type=subscription&user_id=${user_id}`,
          failure: `${req.protocol}://${req.get(
            "host"
          )}/api/payment/failure?type=subscription&user_id=${user_id}`,
          pending: `${req.protocol}://${req.get(
            "host"
          )}/api/payment/pending?type=subscription&user_id=${user_id}`,
        },
        auto_return: "approved",
        external_reference: `subscription_${user_id}_${Date.now()}`,
        notification_url: `${req.protocol}://${req.get(
          "host"
        )}/api/webhooks/mercadopago`,
      };

      const result = await preference.create({ body: preferenceData });

      console.log("✅ Subscription payment preference created:", result.id);

      res.json({
        id: result.id,
        init_point: result.init_point,
        sandbox_init_point: result.sandbox_init_point,
      });
    } catch (error) {
      console.error("❌ Error creating subscription payment:", error);
      res.status(500).json({ message: "Erro ao criar pagamento" });
    }
  }
);

// DEPENDENT PAYMENT
app.post(
  "/api/dependents/:id/create-payment",
  authenticate,
  async (req, res) => {
    try {
      const dependentId = parseInt(req.params.id);

      console.log("🔄 Creating dependent payment for:", dependentId);

      // Get dependent data
      const dependentResult = await pool.query(
        `SELECT d.id, d.name, d.cpf, d.client_id, d.subscription_status, d.billing_amount,
       u.name as client_name
       FROM dependents d
       JOIN users u ON d.client_id = u.id
       WHERE d.id = $1`,
        [dependentId]
      );

      if (dependentResult.rows.length === 0) {
        return res.status(404).json({ message: "Dependente não encontrado" });
      }

      const dependent = dependentResult.rows[0];

      // Verify access
      if (
        req.user.id !== dependent.client_id &&
        req.user.currentRole !== "admin"
      ) {
        return res.status(403).json({ message: "Acesso negado" });
      }

      // Check if already active
      if (dependent.subscription_status === "active") {
        return res.status(400).json({ message: "Dependente já está ativo" });
      }

      const preference = new Preference(mercadoPagoClient);

      // 🔥 MERCADOPAGO SDK V2 - Create preference for dependent
      const preferenceData = {
        items: [
          {
            id: `dependent_${dependentId}`,
            title: `Ativação de Dependente - ${dependent.name}`,
            description: "Ativação de dependente no convênio de saúde",
            quantity: 1,
            unit_price: dependent.billing_amount || 50,
            currency_id: "BRL",
          },
        ],
        payer: {
          name: dependent.client_name,
          identification: {
            type: "CPF",
            number: dependent.cpf,
          },
        },
        back_urls: {
          success:
            "https://cartaoquiroferreira.com.br/client?payment=success&type=dependent",
          failure:
            "https://cartaoquiroferreira.com.br/client?payment=failure&type=dependent",
          pending:
            "https://cartaoquiroferreira.com.br/client?payment=pending&type=dependent",
          success: `${req.protocol}://${req.get(
            "host"
          )}/api/payment/success?type=dependent&dependent_id=${dependentId}`,
          failure: `${req.protocol}://${req.get(
            "host"
          )}/api/payment/failure?type=dependent&dependent_id=${dependentId}`,
          pending: `${req.protocol}://${req.get(
            "host"
          )}/api/payment/pending?type=dependent&dependent_id=${dependentId}`,
        },
        auto_return: "approved",
        external_reference: `dependent_${dependentId}_${Date.now()}`,
        notification_url: `${req.protocol}://${req.get(
          "host"
        )}/api/webhooks/mercadopago`,
      };

      const result = await preference.create({ body: preferenceData });

      // 🔥 Save to dependent_payments table
      const paymentResult = await pool.query(
        "INSERT INTO dependent_payments (dependent_id, client_id, amount, mp_preference_id) VALUES ($1, $2, $3, $4) RETURNING id",
        [
          dependentId,
          dependent.client_id,
          dependent.billing_amount || 50,
          result.id,
        ]
      );

      console.log(
        "✅ Dependent payment record created:",
        paymentResult.rows[0].id
      );

      console.log("✅ Dependent payment preference created:", result.id);

      res.json({
        id: result.id,
        init_point: result.init_point,
        sandbox_init_point: result.sandbox_init_point,
      });
    } catch (error) {
      console.error("❌ Error creating dependent payment:", error);
      res.status(500).json({ message: "Erro ao criar pagamento" });
    }
  }
);

// PROFESSIONAL PAYMENT
app.post(
  "/api/professional/create-payment",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { amount } = req.body;

      console.log(
        "🔄 Creating professional payment for user:",
        req.user.id,
        "amount:",
        amount
      );

      if (!amount || isNaN(amount) || amount <= 0) {
        return res.status(400).json({ message: "Valor inválido" });
      }

      const preference = new Preference(mercadoPagoClient);

      const preferenceData = {
        items: [
          {
            id: `professional_payment_${req.user.id}`,
            title: "Repasse ao Convênio Quiro Ferreira",
            description:
              "Pagamento de repasse ao convênio referente às consultas realizadas",
            quantity: 1,
            unit_price: parseFloat(amount),
            currency_id: "BRL",
          },
        ],
        payer: {
          name: req.user.name,
          identification: {
            type: "CPF",
            number: req.user.cpf || "00000000000",
          },
        },
        back_urls: {
          success: `${req.protocol}://${req.get(
            "host"
          )}/api/payment/success?type=professional&professional_id=${
            req.user.id
          }`,
          failure: `${req.protocol}://${req.get(
            "host"
          )}/api/payment/failure?type=professional&professional_id=${
            req.user.id
          }`,
          pending: `${req.protocol}://${req.get(
            "host"
          )}/api/payment/pending?type=professional&professional_id=${
            req.user.id
          }`,
        },
        auto_return: "approved",
        external_reference: `professional_${req.user.id}_${Date.now()}`,
        notification_url: `${req.protocol}://${req.get(
          "host"
        )}/api/webhooks/mercadopago`,
      };

      const result = await preference.create({ body: preferenceData });

      console.log("✅ Professional payment preference created:", result.id);

      res.json({
        id: result.id,
        init_point: result.init_point,
        sandbox_init_point: result.sandbox_init_point,
      });
    } catch (error) {
      console.error("❌ Error creating professional payment:", error);
      res.status(500).json({ message: "Erro ao criar pagamento" });
    }
  }
);

// 🔥 PAYMENT CALLBACK ROUTES
app.get("/api/payment/success", async (req, res) => {
  try {
    const { type, user_id, dependent_id, professional_id } = req.query;

    console.log("✅ Payment success callback:", {
      type,
      user_id,
      dependent_id,
      professional_id,
    });

    let redirectUrl =
      process.env.NODE_ENV === "production"
        ? "https://www.cartaoquiroferreira.com.br"
        : "http://localhost:5173";

    if (type === "subscription" && user_id) {
      redirectUrl += `/client?payment=success&type=subscription`;
    } else if (type === "dependent" && dependent_id) {
      redirectUrl += `/client?payment=success&type=dependent`;
    } else if (type === "professional" && professional_id) {
      redirectUrl += `/professional?payment=success&type=professional`;
    } else {
      redirectUrl += `/?payment=success`;
    }

    res.redirect(redirectUrl);
  } catch (error) {
    console.error("❌ Error in payment success callback:", error);
    res.redirect(
      process.env.NODE_ENV === "production"
        ? "https://www.cartaoquiroferreira.com.br/?payment=error"
        : "http://localhost:5173/?payment=error"
    );
  }
});

app.get("/api/payment/failure", async (req, res) => {
  try {
    const { type, user_id, dependent_id, professional_id } = req.query;

    console.log("❌ Payment failure callback:", {
      type,
      user_id,
      dependent_id,
      professional_id,
    });

    let redirectUrl =
      process.env.NODE_ENV === "production"
        ? "https://www.cartaoquiroferreira.com.br"
        : "http://localhost:5173";

    if (type === "subscription" && user_id) {
      redirectUrl += `/client?payment=failure&type=subscription`;
    } else if (type === "dependent" && dependent_id) {
      redirectUrl += `/client?payment=failure&type=dependent`;
    } else if (type === "professional" && professional_id) {
      redirectUrl += `/professional?payment=failure&type=professional`;
    } else {
      redirectUrl += `/?payment=failure`;
    }

    res.redirect(redirectUrl);
  } catch (error) {
    console.error("❌ Error in payment failure callback:", error);
    res.redirect(
      process.env.NODE_ENV === "production"
        ? "https://www.cartaoquiroferreira.com.br/?payment=error"
        : "http://localhost:5173/?payment=error"
    );
  }
});

app.get("/api/payment/pending", async (req, res) => {
  try {
    const { type, user_id, dependent_id, professional_id } = req.query;

    console.log("⏳ Payment pending callback:", {
      type,
      user_id,
      dependent_id,
      professional_id,
    });

    let redirectUrl =
      process.env.NODE_ENV === "production"
        ? "https://www.cartaoquiroferreira.com.br"
        : "http://localhost:5173";

    if (type === "subscription" && user_id) {
      redirectUrl += `/client?payment=pending&type=subscription`;
    } else if (type === "dependent" && dependent_id) {
      redirectUrl += `/client?payment=pending&type=dependent`;
    } else if (type === "professional" && professional_id) {
      redirectUrl += `/professional?payment=pending&type=professional`;
    } else {
      redirectUrl += `/?payment=pending`;
    }

    res.redirect(redirectUrl);
  } catch (error) {
    console.error("❌ Error in payment pending callback:", error);
    res.redirect(
      process.env.NODE_ENV === "production"
        ? "https://www.cartaoquiroferreira.com.br/?payment=error"
        : "http://localhost:5173/?payment=error"
    );
  }
});

// 🔥 MERCADOPAGO WEBHOOK
app.post("/api/webhooks/mercadopago", async (req, res) => {
  try {
    console.log("🔔 MercadoPago webhook received:", req.body);

    const { type, data } = req.body;

    if (type === "payment") {
      const paymentId = data.id;

      console.log("💳 Processing payment webhook for payment ID:", paymentId);

      // Here you would typically:
      // 1. Fetch payment details from MercadoPago API
      // 2. Verify payment status
      // 3. Update database accordingly
      // 4. Send notifications

      // For now, we'll just log and acknowledge
      console.log("✅ Payment webhook processed successfully");
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error("❌ Error processing webhook:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// 🔥 SYSTEM STATISTICS ROUTE
app.get(
  "/api/system/stats",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      console.log("🔄 Fetching system statistics");

      const stats = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM users WHERE 'client' = ANY(roles)) as total_clients,
        (SELECT COUNT(*) FROM users WHERE 'professional' = ANY(roles)) as total_professionals,
        (SELECT COUNT(*) FROM users WHERE 'admin' = ANY(roles)) as total_admins,
        (SELECT COUNT(*) FROM dependents) as total_dependents,
        (SELECT COUNT(*) FROM consultations) as total_consultations,
        (SELECT COUNT(*) FROM services) as total_services,
        (SELECT COUNT(*) FROM service_categories) as total_categories,
        (SELECT COUNT(*) FROM private_patients) as total_private_patients,
        (SELECT COUNT(*) FROM medical_records) as total_medical_records,
        (SELECT COUNT(*) FROM medical_documents) as total_medical_documents,
        (SELECT COALESCE(SUM(value), 0) FROM consultations) as total_revenue,
        (SELECT COUNT(*) FROM users WHERE subscription_status = 'active' AND 'client' = ANY(roles)) as active_clients,
        (SELECT COUNT(*) FROM users WHERE subscription_status = 'pending' AND 'client' = ANY(roles)) as pending_clients,
        (SELECT COUNT(*) FROM users WHERE subscription_status = 'expired' AND 'client' = ANY(roles)) as expired_clients,
        (SELECT COUNT(*) FROM dependents WHERE subscription_status = 'active') as active_dependents,
        (SELECT COUNT(*) FROM dependents WHERE subscription_status = 'pending') as pending_dependents
    `);

      const systemStats = {
        users: {
          total_clients: parseInt(stats.rows[0].total_clients) || 0,
          total_professionals: parseInt(stats.rows[0].total_professionals) || 0,
          total_admins: parseInt(stats.rows[0].total_admins) || 0,
          active_clients: parseInt(stats.rows[0].active_clients) || 0,
          pending_clients: parseInt(stats.rows[0].pending_clients) || 0,
          expired_clients: parseInt(stats.rows[0].expired_clients) || 0,
        },
        dependents: {
          total_dependents: parseInt(stats.rows[0].total_dependents) || 0,
          active_dependents: parseInt(stats.rows[0].active_dependents) || 0,
          pending_dependents: parseInt(stats.rows[0].pending_dependents) || 0,
        },
        consultations: {
          total_consultations: parseInt(stats.rows[0].total_consultations) || 0,
          total_revenue: parseFloat(stats.rows[0].total_revenue) || 0,
        },
        services: {
          total_services: parseInt(stats.rows[0].total_services) || 0,
          total_categories: parseInt(stats.rows[0].total_categories) || 0,
        },
        medical: {
          total_private_patients:
            parseInt(stats.rows[0].total_private_patients) || 0,
          total_medical_records:
            parseInt(stats.rows[0].total_medical_records) || 0,
          total_medical_documents:
            parseInt(stats.rows[0].total_medical_documents) || 0,
        },
      };

      console.log("✅ System statistics generated");

      res.json(systemStats);
    } catch (error) {
      console.error("❌ Error fetching system statistics:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// 🔥 AUDIT LOG ROUTE
app.get(
  "/api/audit-logs",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { limit = 100, offset = 0 } = req.query;

      console.log("🔄 Fetching audit logs");

      const result = await pool.query(
        `SELECT id, user_id, action, table_name, record_id, old_values, new_values, 
       ip_address, user_agent, created_at
       FROM audit_logs 
       ORDER BY created_at DESC 
       LIMIT $1 OFFSET $2`,
        [parseInt(limit), parseInt(offset)]
      );

      console.log("✅ Audit logs fetched:", result.rows.length);

      res.json(result.rows);
    } catch (error) {
      console.error("❌ Error fetching audit logs:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// 🔥 BACKUP ROUTE
app.post(
  "/api/system/backup",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      console.log("🔄 Creating system backup");

      const tables = [
        "users",
        "dependents",
        "services",
        "service_categories",
        "consultations",
        "private_patients",
        "medical_records",
        "medical_documents",
        "attendance_locations",
        "scheduling_access",
      ];

      const backup = {};

      for (const table of tables) {
        try {
          const result = await pool.query(`SELECT * FROM ${table}`);
          backup[table] = result.rows;
        } catch (error) {
          console.warn(`⚠️ Could not backup table ${table}:`, error.message);
          backup[table] = [];
        }
      }

      const backupData = {
        timestamp: new Date().toISOString(),
        version: "1.0",
        tables: backup,
      };

      console.log("✅ System backup created successfully");

      res.json({
        message: "Backup criado com sucesso",
        timestamp: backupData.timestamp,
        tables: Object.keys(backup),
        total_records: Object.values(backup).reduce(
          (sum, records) => sum + records.length,
          0
        ),
      });
    } catch (error) {
      console.error("❌ Error creating backup:", error);
      res.status(500).json({ message: "Erro ao criar backup" });
    }
  }
);

// 🔥 CLEANUP ROUTE
app.post(
  "/api/system/cleanup",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      console.log("🔄 Running system cleanup");

      const { days_old = 90 } = req.body;
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - parseInt(days_old));

      let cleanupResults = {
        expired_tokens: 0,
        old_audit_logs: 0,
        orphaned_records: 0,
      };

      // Clean old audit logs
      try {
        const auditResult = await pool.query(
          "DELETE FROM audit_logs WHERE created_at < $1",
          [cutoffDate]
        );
        cleanupResults.old_audit_logs = auditResult.rowCount || 0;
        console.log(
          `✅ Cleaned ${cleanupResults.old_audit_logs} old audit logs`
        );
      } catch (error) {
        console.warn("⚠️ Could not clean audit logs:", error.message);
      }

      // Clean orphaned dependents (where client no longer exists)
      try {
        const orphanResult = await pool.query(
          `DELETE FROM dependents 
         WHERE client_id NOT IN (SELECT id FROM users WHERE 'client' = ANY(roles))`
        );
        cleanupResults.orphaned_records = orphanResult.rowCount || 0;
        console.log(
          `✅ Cleaned ${cleanupResults.orphaned_records} orphaned dependents`
        );
      } catch (error) {
        console.warn("⚠️ Could not clean orphaned records:", error.message);
      }

      console.log("✅ System cleanup completed:", cleanupResults);

      res.json({
        message: "Limpeza do sistema concluída",
        results: cleanupResults,
      });
    } catch (error) {
      console.error("❌ Error during system cleanup:", error);
      res.status(500).json({ message: "Erro durante limpeza do sistema" });
    }
  }
);

// 🔥 NOTIFICATION SYSTEM
app.get("/api/notifications", authenticate, async (req, res) => {
  try {
    console.log("🔄 Fetching notifications for user:", req.user.id);

    const result = await pool.query(
      `SELECT id, title, message, type, is_read, created_at
       FROM notifications 
       WHERE user_id = $1 OR user_id IS NULL
       ORDER BY created_at DESC 
       LIMIT 50`,
      [req.user.id]
    );

    console.log("✅ Notifications fetched:", result.rows.length);

    res.json(result.rows);
  } catch (error) {
    console.error("❌ Error fetching notifications:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post(
  "/api/notifications",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { title, message, type, user_id, role_filter } = req.body;

      console.log("🔄 Creating notification:", {
        title,
        type,
        user_id,
        role_filter,
      });

      if (!title || !message) {
        return res
          .status(400)
          .json({ message: "Título e mensagem são obrigatórios" });
      }

      if (user_id) {
        // Send to specific user
        const result = await pool.query(
          `INSERT INTO notifications (user_id, title, message, type, created_by)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, title, message, type, created_at`,
          [user_id, title.trim(), message.trim(), type || "info", req.user.id]
        );

        console.log("✅ Notification created for user:", user_id);

        res.status(201).json(result.rows[0]);
      } else if (role_filter) {
        // Send to all users with specific role
        const users = await pool.query(
          "SELECT id FROM users WHERE $1 = ANY(roles)",
          [role_filter]
        );

        const notifications = [];
        for (const user of users.rows) {
          const result = await pool.query(
            `INSERT INTO notifications (user_id, title, message, type, created_by)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id`,
            [user.id, title.trim(), message.trim(), type || "info", req.user.id]
          );
          notifications.push(result.rows[0]);
        }

        console.log(
          "✅ Notifications created for role:",
          role_filter,
          "count:",
          notifications.length
        );

        res.status(201).json({
          message: `${notifications.length} notificações criadas`,
          count: notifications.length,
        });
      } else {
        // Send to all users
        const result = await pool.query(
          `INSERT INTO notifications (title, message, type, created_by)
         VALUES ($1, $2, $3, $4)
         RETURNING id, title, message, type, created_at`,
          [title.trim(), message.trim(), type || "info", req.user.id]
        );

        console.log("✅ Global notification created");

        res.status(201).json(result.rows[0]);
      }
    } catch (error) {
      console.error("❌ Error creating notification:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

app.put("/api/notifications/:id/read", authenticate, async (req, res) => {
  try {
    const notificationId = parseInt(req.params.id);

    const result = await pool.query(
      `UPDATE notifications 
       SET is_read = true, read_at = CURRENT_TIMESTAMP
       WHERE id = $1 AND (user_id = $2 OR user_id IS NULL)
       RETURNING id`,
      [notificationId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Notificação não encontrada" });
    }

    console.log("✅ Notification marked as read:", notificationId);

    res.json({ message: "Notificação marcada como lida" });
  } catch (error) {
    console.error("❌ Error marking notification as read:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// 🔥 ERROR HANDLING MIDDLEWARE
app.use((error, req, res, next) => {
  console.error("❌ Unhandled error:", error);

  if (error.type === "entity.parse.failed") {
    return res.status(400).json({ message: "Dados JSON inválidos" });
  }

  if (error.type === "entity.too.large") {
    return res.status(413).json({ message: "Arquivo muito grande" });
  }

  res.status(500).json({
    message: "Erro interno do servidor",
    error: process.env.NODE_ENV === "development" ? error.message : undefined,
  });
});

// 🔥 404 HANDLER
app.use("*", (req, res) => {
  console.log("❌ Route not found:", req.method, req.originalUrl);
  res.status(404).json({ message: "Rota não encontrada" });
});

// 🔥 GRACEFUL SHUTDOWN
process.on("SIGTERM", () => {
  console.log("🔄 SIGTERM received, shutting down gracefully");
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("🔄 SIGINT received, shutting down gracefully");
  process.exit(0);
});

// Initialize database tables on startup
createTables().catch((error) => {
  console.error("❌ Failed to create database tables:", error);
  process.exit(1);
});

// 🔥 START SERVER
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/health`);
});

export default app;