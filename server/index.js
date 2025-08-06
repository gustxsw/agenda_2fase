import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { pool } from "./db.js";
import createUpload from "./middleware/upload.js";

// Import routes
import authRoutes from './routes/auth.js';
import usersRoutes from './routes/users.js';
import professionalsRoutes from './routes/professionals.js';
import clientsRoutes from './routes/clients.js';
import consultationRoutes from './routes/consultations.js';
import dependentRoutes from './routes/dependents.js';
import serviceRoutes from './routes/services.js';

// Create all necessary tables
const createTables = async () => {
  try {
    console.log("🔄 Creating database tables...");

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
        photo_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Service categories table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Services table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        base_price DECIMAL(10,2) NOT NULL,
        category_id INTEGER REFERENCES service_categories(id),
        is_base_service BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Dependents table
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

    // Consultations table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        private_patient_id INTEGER,
        professional_id INTEGER REFERENCES users(id),
        service_id INTEGER REFERENCES services(id),
        location_id INTEGER,
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Attendance locations table
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
        is_default BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Private patients table
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
        UNIQUE(professional_id, cpf)
      )
    `);

    // Medical records table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_records (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id) ON DELETE CASCADE,
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

    // Medical documents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_documents (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id),
        document_type VARCHAR(50) NOT NULL,
        title VARCHAR(255) NOT NULL,
        document_url TEXT NOT NULL,
        template_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Professional schedule settings table
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
        has_scheduling_subscription BOOLEAN DEFAULT false,
        subscription_expires_at TIMESTAMP,
        expires_at TIMESTAMP,
        granted_by VARCHAR(255),
        granted_at TIMESTAMP,
        grant_reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Appointments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id),
        appointment_date DATE NOT NULL,
        appointment_time TIME NOT NULL,
        service_name VARCHAR(255),
        location_id INTEGER REFERENCES attendance_locations(id),
        value DECIMAL(10,2),
        status VARCHAR(20) DEFAULT 'scheduled',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Insert default service categories if they don't exist
    await pool.query(`
      INSERT INTO service_categories (name, description) 
      SELECT * FROM (VALUES 
        ('Fisioterapia', 'Serviços de fisioterapia e reabilitação'),
        ('Psicologia', 'Atendimento psicológico e terapias'),
        ('Nutrição', 'Consultas nutricionais e acompanhamento'),
        ('Medicina Geral', 'Consultas médicas gerais'),
        ('Odontologia', 'Serviços odontológicos'),
        ('Outros', 'Outros serviços de saúde')
      ) AS v(name, description)
      WHERE NOT EXISTS (SELECT 1 FROM service_categories WHERE service_categories.name = v.name)
    `);

    // Insert default services if they don't exist
    await pool.query(`
      INSERT INTO services (name, description, base_price, category_id, is_base_service)
      SELECT v.name, v.description, v.base_price, sc.id, v.is_base_service
      FROM (VALUES 
        ('Consulta Fisioterapêutica', 'Avaliação e tratamento fisioterapêutico', 80.00, 'Fisioterapia', true),
        ('Sessão de Fisioterapia', 'Sessão de tratamento fisioterapêutico', 60.00, 'Fisioterapia', false),
        ('Consulta Psicológica', 'Atendimento psicológico individual', 100.00, 'Psicologia', true),
        ('Consulta Nutricional', 'Avaliação e orientação nutricional', 90.00, 'Nutrição', true),
        ('Consulta Médica', 'Consulta médica geral', 120.00, 'Medicina Geral', true),
        ('Consulta Odontológica', 'Avaliação odontológica', 80.00, 'Odontologia', true)
      ) AS v(name, description, base_price, category_name, is_base_service)
      JOIN service_categories sc ON sc.name = v.category_name
      WHERE NOT EXISTS (SELECT 1 FROM services WHERE services.name = v.name)
    `);

    // Insert default admin user
    try {
      const hashedPassword = await bcrypt.hash("admin123", 10);

      await pool.query(
        `
        INSERT INTO users (name, cpf, password_hash, roles, subscription_status, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
        ON CONFLICT (cpf) DO NOTHING
      `,
        [
          "Administrador Sistema",
          "00000000000",
          hashedPassword,
          ["admin"],
          "active",
        ]
      );

      console.log("✅ Default admin user created successfully");
      console.log("📋 Admin credentials:");
      console.log("   CPF: 000.000.000-00");
      console.log("   Senha: admin123");
    } catch (error) {
      console.log(
        "ℹ️ Default admin user already exists or error creating:",
        error.message
      );
    }

    console.log("✅ Database tables created successfully");
  } catch (error) {
    console.error("❌ Error creating tables:", error);
  }
};

// Initialize database tables
createTables();

// ES module compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://www.cartaoquiroferreira.com.br",
      "https://cartaoquiroferreira.com.br",
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static(path.join(__dirname, "../dist")));

// Auth middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ message: "Não autorizado" });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "your-secret-key"
    );

    const result = await pool.query(
      "SELECT id, name, cpf, roles FROM users WHERE id = $1",
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
    };

    next();
  } catch (error) {
    console.error("Auth error:", error);
    return res.status(401).json({ message: "Token inválido" });
  }
};

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

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/professionals', professionalsRoutes);
app.use('/api/clients', clientsRoutes);
app.use('/api/consultations', consultationRoutes);

// ==================== AUTH ROUTES ====================

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: "CPF e senha são obrigatórios" });
    }

    const result = await pool.query(
      "SELECT id, name, cpf, email, password_hash, roles FROM users WHERE cpf = $1",
      [cpf]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Credenciais inválidas" });
    }

    const user = result.rows[0];

    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ message: "Credenciais inválidas" });
    }

    const userRoles = user.roles || [];
    const needsRoleSelection = userRoles.length > 1;

    res.json({
      message: "Login realizado com sucesso",
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        email: user.email,
        roles: userRoles,
      },
      needsRoleSelection,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Register
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
      password,
    } = req.body;

    if (!name || !cpf || !password) {
      return res
        .status(400)
        .json({ message: "Nome, CPF e senha são obrigatórios" });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      "SELECT id FROM users WHERE cpf = $1",
      [cpf]
    );
    if (existingUser.rows.length > 0) {
      return res
        .status(400)
        .json({ message: "Usuário já existe com este CPF" });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user with client role and pending subscription
    const result = await pool.query(
      `
      INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles,
        subscription_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, CURRENT_TIMESTAMP)
      RETURNING id, name, cpf, email, roles
    `,
      [
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
        passwordHash,
        JSON.stringify(["client"]),
        "pending",
      ]
    );

    const user = result.rows[0];

    res.status(201).json({
      message: "Usuário criado com sucesso",
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        email: user.email,
        roles: user.roles,
      },
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Select role
app.post("/api/auth/select-role", async (req, res) => {
  try {
    const { userId, role } = req.body;

    if (!userId || !role) {
      return res
        .status(400)
        .json({ message: "ID do usuário e role são obrigatórios" });
    }

    const result = await pool.query(
      "SELECT id, name, cpf, email, roles FROM users WHERE id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const user = result.rows[0];
    const userRoles = user.roles || [];

    if (!userRoles.includes(role)) {
      return res
        .status(403)
        .json({ message: "Role não autorizada para este usuário" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        currentRole: role,
      },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "24h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json({
      message: "Role selecionada com sucesso",
      token,
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        email: user.email,
        roles: userRoles,
        currentRole: role,
      },
    });
  } catch (error) {
    console.error("Role selection error:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Switch role
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
      },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "24h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json({
      message: "Role alterada com sucesso",
      token,
      user: {
        id: req.user.id,
        name: req.user.name,
        cpf: req.user.cpf,
        roles: req.user.roles,
        currentRole: role,
      },
    });
  } catch (error) {
    console.error("Switch role error:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout realizado com sucesso" });
});

// ==================== USER ROUTES ====================

// Get all users (admin only)
app.get("/api/users", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, roles, percentage,
        category_id, subscription_status, subscription_expiry, created_at
      FROM users 
      ORDER BY created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Get user by ID
app.get("/api/users/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Users can only access their own data unless they're admin
    if (req.user.currentRole !== "admin" && req.user.id !== parseInt(id)) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const result = await pool.query(
      `
      SELECT 
        id, name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, roles, percentage,
        category_id, subscription_status, subscription_expiry, photo_url, created_at
      FROM users 
      WHERE id = $1
    `,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Create user (admin only)
app.post("/api/users", authenticate, authorize(["admin"]), async (req, res) => {
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

    if (!name || !cpf || !password || !roles || roles.length === 0) {
      return res
        .status(400)
        .json({
          message: "Nome, CPF, senha e pelo menos uma role são obrigatórios",
        });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      "SELECT id FROM users WHERE cpf = $1",
      [cpf]
    );
    if (existingUser.rows.length > 0) {
      return res
        .status(400)
        .json({ message: "Usuário já existe com este CPF" });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Set subscription status based on roles
    const subscriptionStatus = roles.includes("client") ? "pending" : null;

    const result = await pool.query(
      `
      INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number,
        address_complement, neighborhood, city, state, password_hash, roles,
        percentage, category_id, subscription_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, CURRENT_TIMESTAMP)
      RETURNING id, name, cpf, email, roles
    `,
      [
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
        passwordHash,
        JSON.stringify(roles),
        percentage,
        category_id,
        subscriptionStatus,
      ]
    );

    res.status(201).json({
      message: "Usuário criado com sucesso",
      user: result.rows[0],
    });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Update user
app.put("/api/users/:id", authenticate, async (req, res) => {
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
      newPassword,
    } = req.body;

    // Users can only update their own data unless they're admin
    if (req.user.currentRole !== "admin" && req.user.id !== parseInt(id)) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    let updateQuery = `
      UPDATE users SET 
        name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
        address_number = $6, address_complement = $7, neighborhood = $8,
        city = $9, state = $10, updated_at = CURRENT_TIMESTAMP
    `;
    let queryParams = [
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
    ];
    let paramCount = 10;

    // Only admin can update roles, percentage, and category
    if (req.user.currentRole === "admin" && roles) {
      updateQuery += `, roles = $${++paramCount}, percentage = $${++paramCount}, category_id = $${++paramCount}`;
      queryParams.push(JSON.stringify(roles), percentage, category_id);
    }

    // Handle password change
    if (newPassword) {
      if (!currentPassword) {
        return res
          .status(400)
          .json({ message: "Senha atual é obrigatória para alterar a senha" });
      }

      // Verify current password
      const userResult = await pool.query(
        "SELECT password_hash FROM users WHERE id = $1",
        [id]
      );
      if (userResult.rows.length === 0) {
        return res.status(404).json({ message: "Usuário não encontrado" });
      }

      const isValidPassword = await bcrypt.compare(
        currentPassword,
        userResult.rows[0].password_hash
      );
      if (!isValidPassword) {
        return res.status(400).json({ message: "Senha atual incorreta" });
      }

      const newPasswordHash = await bcrypt.hash(newPassword, 10);
      updateQuery += `, password_hash = $${++paramCount}`;
      queryParams.push(newPasswordHash);
    }

    updateQuery += ` WHERE id = $${++paramCount} RETURNING id, name, cpf, email, roles`;
    queryParams.push(id);

    const result = await pool.query(updateQuery, queryParams);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    res.json({
      message: "Usuário atualizado com sucesso",
      user: result.rows[0],
    });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Delete user (admin only)
app.delete(
  "/api/users/:id",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { id } = req.params;

      const result = await pool.query(
        "DELETE FROM users WHERE id = $1 RETURNING id",
        [id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Usuário não encontrado" });
      }

      res.json({ message: "Usuário excluído com sucesso" });
    } catch (error) {
      console.error("Error deleting user:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Activate client (admin only)
app.put(
  "/api/users/:id/activate",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { expiry_date } = req.body;

      if (!expiry_date) {
        return res
          .status(400)
          .json({ message: "Data de expiração é obrigatória" });
      }

      const result = await pool.query(
        `
      UPDATE users 
      SET subscription_status = 'active', subscription_expiry = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2 AND roles @> '["client"]'
      RETURNING id, name, subscription_status, subscription_expiry
    `,
        [expiry_date, id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Cliente não encontrado" });
      }

      res.json({
        message: "Cliente ativado com sucesso",
        user: result.rows[0],
      });
    } catch (error) {
      console.error("Error activating client:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// ==================== SERVICE CATEGORIES ROUTES ====================

// Get all service categories
app.get("/api/service-categories", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM service_categories ORDER BY name"
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching service categories:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Create service category (admin only)
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
        `
      INSERT INTO service_categories (name, description, created_at)
      VALUES ($1, $2, CURRENT_TIMESTAMP)
      RETURNING *
    `,
        [name, description]
      );

      res.status(201).json({
        message: "Categoria criada com sucesso",
        category: result.rows[0],
      });
    } catch (error) {
      console.error("Error creating service category:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// ==================== SERVICES ROUTES ====================

// Get all services
app.get("/api/services", authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.*, sc.name as category_name
      FROM services s
      LEFT JOIN service_categories sc ON s.category_id = sc.id
      ORDER BY s.name
    `);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching services:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Create service (admin only)
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

      const result = await pool.query(
        `
      INSERT INTO services (name, description, base_price, category_id, is_base_service, created_at)
      VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
      RETURNING *
    `,
        [name, description, base_price, category_id, is_base_service || false]
      );

      res.status(201).json({
        message: "Serviço criado com sucesso",
        service: result.rows[0],
      });
    } catch (error) {
      console.error("Error creating service:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Update service (admin only)
app.put(
  "/api/services/:id",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name, description, base_price, category_id, is_base_service } =
        req.body;

      const result = await pool.query(
        `
      UPDATE services 
      SET name = $1, description = $2, base_price = $3, category_id = $4, 
          is_base_service = $5, updated_at = CURRENT_TIMESTAMP
      WHERE id = $6
      RETURNING *
    `,
        [name, description, base_price, category_id, is_base_service, id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Serviço não encontrado" });
      }

      res.json({
        message: "Serviço atualizado com sucesso",
        service: result.rows[0],
      });
    } catch (error) {
      console.error("Error updating service:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Delete service (admin only)
app.delete(
  "/api/services/:id",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { id } = req.params;

      const result = await pool.query(
        "DELETE FROM services WHERE id = $1 RETURNING id",
        [id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Serviço não encontrado" });
      }

      res.json({ message: "Serviço excluído com sucesso" });
    } catch (error) {
      console.error("Error deleting service:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// ==================== CONSULTATIONS ROUTES ====================

// Get consultations
app.get("/api/consultations", authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id, c.date, c.value, c.created_at,
        s.name as service_name,
        u_prof.name as professional_name,
        COALESCE(u_client.name, d.name, pp.name) as client_name,
        CASE 
          WHEN d.id IS NOT NULL THEN true 
          ELSE false 
        END as is_dependent
      FROM consultations c
      LEFT JOIN services s ON c.service_id = s.id
      LEFT JOIN users u_prof ON c.professional_id = u_prof.id
      LEFT JOIN users u_client ON c.client_id = u_client.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
    `;

    const queryParams = [];

    // Filter based on user role
    if (req.user.currentRole === "client") {
      query += ` WHERE (c.client_id = $1 OR d.client_id = $1)`;
      queryParams.push(req.user.id);
    } else if (req.user.currentRole === "professional") {
      query += ` WHERE c.professional_id = $1`;
      queryParams.push(req.user.id);
    }

    query += ` ORDER BY c.date DESC`;

    const result = await pool.query(query, queryParams);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching consultations:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Create consultation (professional only)
app.post(
  "/api/consultations",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const {
        client_id,
        dependent_id,
        private_patient_id,
        service_id,
        location_id,
        value,
        date,
      } = req.body;

      if (!service_id || !value || !date) {
        return res
          .status(400)
          .json({ message: "Serviço, valor e data são obrigatórios" });
      }

      // Must have either client_id, dependent_id, or private_patient_id
      if (!client_id && !dependent_id && !private_patient_id) {
        return res
          .status(400)
          .json({
            message: "Cliente, dependente ou paciente particular é obrigatório",
          });
      }

      const result = await pool.query(
        `
      INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id, service_id, 
        location_id, value, date, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
      RETURNING *
    `,
        [
          client_id,
          dependent_id,
          private_patient_id,
          req.user.id,
          service_id,
          location_id,
          value,
          date,
        ]
      );

      res.status(201).json({
        message: "Consulta registrada com sucesso",
        consultation: result.rows[0],
      });
    } catch (error) {
      console.error("Error creating consultation:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// ==================== DEPENDENTS ROUTES ====================

// Get dependents by client ID
app.get("/api/dependents/:clientId", authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    // Clients can only access their own dependents
    if (
      req.user.currentRole === "client" &&
      req.user.id !== parseInt(clientId)
    ) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const result = await pool.query(
      `
      SELECT id, name, cpf, birth_date, created_at
      FROM dependents 
      WHERE client_id = $1
      ORDER BY name
    `,
      [clientId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching dependents:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Lookup dependent by CPF (professional only)
app.get(
  "/api/dependents/lookup",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { cpf } = req.query;

      if (!cpf) {
        return res.status(400).json({ message: "CPF é obrigatório" });
      }

      const result = await pool.query(
        `
      SELECT 
        d.id, d.name, d.cpf, d.client_id,
        u.name as client_name, u.subscription_status as client_subscription_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.cpf = $1
    `,
        [cpf]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Dependente não encontrado" });
      }

      res.json(result.rows[0]);
    } catch (error) {
      console.error("Error looking up dependent:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Create dependent (client only)
app.post(
  "/api/dependents",
  authenticate,
  authorize(["client"]),
  async (req, res) => {
    try {
      const { client_id, name, cpf, birth_date } = req.body;

      if (!client_id || !name || !cpf) {
        return res
          .status(400)
          .json({ message: "ID do cliente, nome e CPF são obrigatórios" });
      }

      // Clients can only create dependents for themselves
      if (req.user.id !== client_id) {
        return res.status(403).json({ message: "Acesso negado" });
      }

      // Check if CPF already exists
      const existingDependent = await pool.query(
        "SELECT id FROM dependents WHERE cpf = $1",
        [cpf]
      );
      if (existingDependent.rows.length > 0) {
        return res
          .status(400)
          .json({ message: "Já existe um dependente com este CPF" });
      }

      const result = await pool.query(
        `
      INSERT INTO dependents (client_id, name, cpf, birth_date, created_at)
      VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
      RETURNING *
    `,
        [client_id, name, cpf, birth_date]
      );

      res.status(201).json({
        message: "Dependente criado com sucesso",
        dependent: result.rows[0],
      });
    } catch (error) {
      console.error("Error creating dependent:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Update dependent
app.put("/api/dependents/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    // Get dependent to check ownership
    const dependentResult = await pool.query(
      "SELECT client_id FROM dependents WHERE id = $1",
      [id]
    );
    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: "Dependente não encontrado" });
    }

    // Clients can only update their own dependents
    if (
      req.user.currentRole === "client" &&
      req.user.id !== dependentResult.rows[0].client_id
    ) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const result = await pool.query(
      `
      UPDATE dependents 
      SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP
      WHERE id = $3
      RETURNING *
    `,
      [name, birth_date, id]
    );

    res.json({
      message: "Dependente atualizado com sucesso",
      dependent: result.rows[0],
    });
  } catch (error) {
    console.error("Error updating dependent:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Delete dependent
app.delete("/api/dependents/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Get dependent to check ownership
    const dependentResult = await pool.query(
      "SELECT client_id FROM dependents WHERE id = $1",
      [id]
    );
    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: "Dependente não encontrado" });
    }

    // Clients can only delete their own dependents
    if (
      req.user.currentRole === "client" &&
      req.user.id !== dependentResult.rows[0].client_id
    ) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    await pool.query("DELETE FROM dependents WHERE id = $1", [id]);

    res.json({ message: "Dependente excluído com sucesso" });
  } catch (error) {
    console.error("Error deleting dependent:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// ==================== PROFESSIONALS ROUTES ====================

// Get all professionals (for clients)
app.get(
  "/api/professionals",
  authenticate,
  authorize(["client"]),
  async (req, res) => {
    try {
      const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.address, u.address_number,
        u.address_complement, u.neighborhood, u.city, u.state, u.photo_url,
        sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.roles @> '["professional"]'
      ORDER BY u.name
    `);

      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching professionals:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Lookup client by CPF (professional only)
app.get(
  "/api/clients/lookup",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { cpf } = req.query;

      if (!cpf) {
        return res.status(400).json({ message: "CPF é obrigatório" });
      }

      const result = await pool.query(
        `
      SELECT id, name, cpf, subscription_status
      FROM users 
      WHERE cpf = $1 AND roles @> '["client"]'
    `,
        [cpf]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Cliente não encontrado" });
      }

      res.json(result.rows[0]);
    } catch (error) {
      console.error("Error looking up client:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// ==================== REPORTS ROUTES ====================

// Revenue report (admin only)
app.get(
  "/api/reports/revenue",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { start_date, end_date } = req.query;

      if (!start_date || !end_date) {
        return res
          .status(400)
          .json({ message: "Data inicial e final são obrigatórias" });
      }

      // Get revenue by professional
      const professionalRevenue = await pool.query(
        `
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
        AND c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL
      GROUP BY u.id, u.name, u.percentage
      ORDER BY revenue DESC
    `,
        [start_date, end_date]
      );

      // Get revenue by service
      const serviceRevenue = await pool.query(
        `
      SELECT 
        s.name as service_name,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      WHERE c.date >= $1 AND c.date <= $2
        AND c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL
      GROUP BY s.id, s.name
      ORDER BY revenue DESC
    `,
        [start_date, end_date]
      );

      // Calculate total revenue
      const totalRevenue = professionalRevenue.rows.reduce(
        (sum, row) => sum + parseFloat(row.revenue),
        0
      );

      res.json({
        total_revenue: totalRevenue,
        revenue_by_professional: professionalRevenue.rows,
        revenue_by_service: serviceRevenue.rows,
      });
    } catch (error) {
      console.error("Error generating revenue report:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Professional revenue report
app.get(
  "/api/reports/professional-revenue",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { start_date, end_date } = req.query;

      if (!start_date || !end_date) {
        return res
          .status(400)
          .json({ message: "Data inicial e final são obrigatórias" });
      }

      // Get professional's percentage
      const professionalResult = await pool.query(
        "SELECT percentage FROM users WHERE id = $1",
        [req.user.id]
      );

      if (professionalResult.rows.length === 0) {
        return res.status(404).json({ message: "Profissional não encontrado" });
      }

      const professionalPercentage =
        professionalResult.rows[0].percentage || 50;

      // Get consultations for this professional
      const consultationsResult = await pool.query(
        `
      SELECT 
        c.date, c.value,
        COALESCE(u.name, d.name) as client_name,
        s.name as service_name
      FROM consultations c
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN services s ON c.service_id = s.id
      WHERE c.professional_id = $1 
        AND c.date >= $2 AND c.date <= $3
        AND (c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL)
      ORDER BY c.date DESC
    `,
        [req.user.id, start_date, end_date]
      );

      const consultations = consultationsResult.rows;
      const totalRevenue = consultations.reduce(
        (sum, c) => sum + parseFloat(c.value),
        0
      );
      const amountToPay = totalRevenue * ((100 - professionalPercentage) / 100);

      // Format consultations with payment details
      const formattedConsultations = consultations.map((c) => ({
        date: c.date,
        client_name: c.client_name,
        service_name: c.service_name,
        total_value: parseFloat(c.value),
        amount_to_pay:
          parseFloat(c.value) * ((100 - professionalPercentage) / 100),
      }));

      res.json({
        summary: {
          professional_percentage: professionalPercentage,
          total_revenue: totalRevenue,
          consultation_count: consultations.length,
          amount_to_pay: amountToPay,
        },
        consultations: formattedConsultations,
      });
    } catch (error) {
      console.error("Error generating professional revenue report:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Professional detailed report
app.get(
  "/api/reports/professional-detailed",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { start_date, end_date } = req.query;

      if (!start_date || !end_date) {
        return res
          .status(400)
          .json({ message: "Data inicial e final são obrigatórias" });
      }

      // Get professional's percentage
      const professionalResult = await pool.query(
        "SELECT percentage FROM users WHERE id = $1",
        [req.user.id]
      );

      const professionalPercentage =
        professionalResult.rows[0]?.percentage || 50;

      // Get convenio consultations
      const convenioResult = await pool.query(
        `
      SELECT COUNT(*) as count, SUM(value) as revenue
      FROM consultations 
      WHERE professional_id = $1 
        AND date >= $2 AND date <= $3
        AND (client_id IS NOT NULL OR dependent_id IS NOT NULL)
    `,
        [req.user.id, start_date, end_date]
      );

      // Get private consultations
      const privateResult = await pool.query(
        `
      SELECT COUNT(*) as count, SUM(value) as revenue
      FROM consultations 
      WHERE professional_id = $1 
        AND date >= $2 AND date <= $3
        AND private_patient_id IS NOT NULL
    `,
        [req.user.id, start_date, end_date]
      );

      const convenioData = convenioResult.rows[0];
      const privateData = privateResult.rows[0];

      const convenioRevenue = parseFloat(convenioData.revenue) || 0;
      const privateRevenue = parseFloat(privateData.revenue) || 0;
      const totalRevenue = convenioRevenue + privateRevenue;
      const amountToPay =
        convenioRevenue * ((100 - professionalPercentage) / 100);

      res.json({
        summary: {
          total_consultations:
            parseInt(convenioData.count) + parseInt(privateData.count),
          convenio_consultations: parseInt(convenioData.count),
          private_consultations: parseInt(privateData.count),
          total_revenue: totalRevenue,
          convenio_revenue: convenioRevenue,
          private_revenue: privateRevenue,
          professional_percentage: professionalPercentage,
          amount_to_pay: amountToPay,
        },
      });
    } catch (error) {
      console.error("Error generating detailed professional report:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// ==================== PRIVATE PATIENTS ROUTES ====================

// Get private patients (professional only)
app.get(
  "/api/private-patients",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        `
      SELECT *
      FROM private_patients 
      WHERE professional_id = $1
      ORDER BY name
    `,
        [req.user.id]
      );

      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching private patients:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Create private patient (professional only)
app.post(
  "/api/private-patients",
  authenticate,
  authorize(["professional"]),
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

      if (!name || !cpf) {
        return res.status(400).json({ message: "Nome e CPF são obrigatórios" });
      }

      // Check if CPF already exists for this professional
      const existingPatient = await pool.query(
        "SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2",
        [cpf, req.user.id]
      );

      if (existingPatient.rows.length > 0) {
        return res
          .status(400)
          .json({ message: "Já existe um paciente com este CPF" });
      }

      const result = await pool.query(
        `
      INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, CURRENT_TIMESTAMP)
      RETURNING *
    `,
        [
          req.user.id,
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
        ]
      );

      res.status(201).json({
        message: "Paciente criado com sucesso",
        patient: result.rows[0],
      });
    } catch (error) {
      console.error("Error creating private patient:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Update private patient (professional only)
app.put(
  "/api/private-patients/:id",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
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
        zip_code,
      } = req.body;

      const result = await pool.query(
        `
      UPDATE private_patients 
      SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
          address_number = $6, address_complement = $7, neighborhood = $8,
          city = $9, state = $10, zip_code = $11, updated_at = CURRENT_TIMESTAMP
      WHERE id = $12 AND professional_id = $13
      RETURNING *
    `,
        [
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
          id,
          req.user.id,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Paciente não encontrado" });
      }

      res.json({
        message: "Paciente atualizado com sucesso",
        patient: result.rows[0],
      });
    } catch (error) {
      console.error("Error updating private patient:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Delete private patient (professional only)
app.delete(
  "/api/private-patients/:id",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { id } = req.params;

      const result = await pool.query(
        "DELETE FROM private_patients WHERE id = $1 AND professional_id = $2 RETURNING id",
        [id, req.user.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Paciente não encontrado" });
      }

      res.json({ message: "Paciente excluído com sucesso" });
    } catch (error) {
      console.error("Error deleting private patient:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// ==================== ATTENDANCE LOCATIONS ROUTES ====================

// Get attendance locations (professional only)
app.get(
  "/api/attendance-locations",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        `
      SELECT *
      FROM attendance_locations 
      WHERE professional_id = $1
      ORDER BY is_default DESC, name
    `,
        [req.user.id]
      );

      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching attendance locations:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Create attendance location (professional only)
app.post(
  "/api/attendance-locations",
  authenticate,
  authorize(["professional"]),
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
        `
      INSERT INTO attendance_locations (
        professional_id, name, address, address_number, address_complement,
        neighborhood, city, state, zip_code, phone, is_default, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP)
      RETURNING *
    `,
        [
          req.user.id,
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
        ]
      );

      res.status(201).json({
        message: "Local criado com sucesso",
        location: result.rows[0],
      });
    } catch (error) {
      console.error("Error creating attendance location:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Update attendance location (professional only)
app.put(
  "/api/attendance-locations/:id",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { id } = req.params;
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

      // If setting as default, remove default from other locations
      if (is_default) {
        await pool.query(
          "UPDATE attendance_locations SET is_default = false WHERE professional_id = $1 AND id != $2",
          [req.user.id, id]
        );
      }

      const result = await pool.query(
        `
      UPDATE attendance_locations 
      SET name = $1, address = $2, address_number = $3, address_complement = $4,
          neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9,
          is_default = $10, updated_at = CURRENT_TIMESTAMP
      WHERE id = $11 AND professional_id = $12
      RETURNING *
    `,
        [
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
          id,
          req.user.id,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Local não encontrado" });
      }

      res.json({
        message: "Local atualizado com sucesso",
        location: result.rows[0],
      });
    } catch (error) {
      console.error("Error updating attendance location:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Delete attendance location (professional only)
app.delete(
  "/api/attendance-locations/:id",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { id } = req.params;

      const result = await pool.query(
        "DELETE FROM attendance_locations WHERE id = $1 AND professional_id = $2 RETURNING id",
        [id, req.user.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Local não encontrado" });
      }

      res.json({ message: "Local excluído com sucesso" });
    } catch (error) {
      console.error("Error deleting attendance location:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// ==================== SCHEDULING ROUTES ====================

// Get scheduling settings (professional only)
app.get(
  "/api/scheduling/settings",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        `
      SELECT *
      FROM professional_schedule_settings 
      WHERE professional_id = $1
    `,
        [req.user.id]
      );

      if (result.rows.length === 0) {
        // Return default settings
        res.json({
          professional_id: req.user.id,
          work_days: [1, 2, 3, 4, 5],
          work_start_time: "08:00",
          work_end_time: "18:00",
          break_start_time: "12:00",
          break_end_time: "13:00",
          consultation_duration: 60,
          has_scheduling_subscription: false,
        });
      } else {
        res.json(result.rows[0]);
      }
    } catch (error) {
      console.error("Error fetching scheduling settings:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Update scheduling settings (professional only)
app.put(
  "/api/scheduling/settings",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const {
        work_days,
        work_start_time,
        work_end_time,
        break_start_time,
        break_end_time,
        consultation_duration,
      } = req.body;

      const result = await pool.query(
        `
      INSERT INTO professional_schedule_settings (
        professional_id, work_days, work_start_time, work_end_time,
        break_start_time, break_end_time, consultation_duration, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
      ON CONFLICT (professional_id) 
      DO UPDATE SET 
        work_days = $2, work_start_time = $3, work_end_time = $4,
        break_start_time = $5, break_end_time = $6, consultation_duration = $7,
        updated_at = CURRENT_TIMESTAMP
      RETURNING *
    `,
        [
          req.user.id,
          JSON.stringify(work_days),
          work_start_time,
          work_end_time,
          break_start_time,
          break_end_time,
          consultation_duration,
        ]
      );

      res.json({
        message: "Configurações salvas com sucesso",
        settings: result.rows[0],
      });
    } catch (error) {
      console.error("Error updating scheduling settings:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Get subscription status for scheduling (professional only)
app.get(
  "/api/scheduling-payment/subscription-status",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        `
      SELECT 
        COALESCE(has_scheduling_subscription, false) as has_subscription,
        CASE 
          WHEN has_scheduling_subscription = true AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) THEN 'active'
          WHEN has_scheduling_subscription = true AND expires_at <= CURRENT_TIMESTAMP THEN 'expired'
          ELSE 'inactive'
        END as status,
        expires_at
      FROM professional_schedule_settings 
      WHERE professional_id = $1
    `,
        [req.user.id]
      );

      if (result.rows.length === 0) {
        res.json({
          has_subscription: false,
          status: "inactive",
          expires_at: null,
        });
      } else {
        res.json(result.rows[0]);
      }
    } catch (error) {
      console.error("Error fetching subscription status:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Get appointments (professional only)
app.get(
  "/api/appointments",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { start_date, end_date } = req.query;

      let query = `
      SELECT 
        a.id, a.appointment_date, a.appointment_time, a.value, a.status, a.notes,
        pp.name as patient_name, pp.cpf as patient_cpf,
        s.name as service_name,
        al.name as location_name, al.address as location_address
      FROM appointments a
      LEFT JOIN private_patients pp ON a.private_patient_id = pp.id
      LEFT JOIN services s ON a.service_id = s.id
      LEFT JOIN attendance_locations al ON a.location_id = al.id
      WHERE a.professional_id = $1
    `;

      const queryParams = [req.user.id];

      if (start_date && end_date) {
        query += ` AND a.appointment_date >= $2 AND a.appointment_date <= $3`;
        queryParams.push(start_date, end_date);
      }

      query += ` ORDER BY a.appointment_date, a.appointment_time`;

      const result = await pool.query(query, queryParams);
      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching appointments:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// ==================== MEDICAL DOCUMENTS ROUTES ====================

// Get medical documents (professional only)
app.get(
  "/api/medical-documents",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        `
      SELECT 
        md.id, md.title, md.document_type, md.document_url, md.created_at,
        pp.name as patient_name
      FROM medical_documents md
      LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
      WHERE md.professional_id = $1
      ORDER BY md.created_at DESC
    `,
        [req.user.id]
      );

      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching medical documents:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Create medical document (professional only)
app.post(
  "/api/medical-documents",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { private_patient_id, document_type, title, template_data } =
        req.body;

      if (!document_type || !title) {
        return res
          .status(400)
          .json({ message: "Tipo de documento e título são obrigatórios" });
      }

      // For now, we'll create a simple document URL (in production, this would generate a PDF)
      const documentUrl = `${req.protocol}://${req.get(
        "host"
      )}/documents/${Date.now()}-${title.replace(/\s+/g, "-")}.pdf`;

      const result = await pool.query(
        `
      INSERT INTO medical_documents (
        professional_id, private_patient_id, document_type, title, 
        template_data, document_url, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
      RETURNING *
    `,
        [
          req.user.id,
          private_patient_id,
          document_type,
          title,
          JSON.stringify(template_data),
          documentUrl,
        ]
      );

      res.status(201).json({
        message: "Documento criado com sucesso",
        document: result.rows[0],
      });
    } catch (error) {
      console.error("Error creating medical document:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// ==================== IMAGE UPLOAD ROUTE ====================

// Upload image (professional only)
app.post(
  "/api/upload-image",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      // Create upload middleware instance
      const upload = createUpload();

      // Use multer middleware
      upload.single("image")(req, res, async (err) => {
        if (err) {
          console.error("Upload error:", err);
          return res
            .status(400)
            .json({ message: err.message || "Erro no upload da imagem" });
        }

        if (!req.file) {
          return res
            .status(400)
            .json({ message: "Nenhuma imagem foi enviada" });
        }

        try {
          // Update user's photo_url in database
          await pool.query("UPDATE users SET photo_url = $1 WHERE id = $2", [
            req.file.path,
            req.user.id,
          ]);

          res.json({
            message: "Imagem enviada com sucesso",
            imageUrl: req.file.path,
          });
        } catch (dbError) {
          console.error("Database error after upload:", dbError);
          res
            .status(500)
            .json({
              message: "Erro ao salvar URL da imagem no banco de dados",
            });
        }
      });
    } catch (error) {
      console.error("Error in upload route:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// ==================== PAYMENT ROUTES ====================

// Create subscription payment (client only)
app.post(
  "/api/create-subscription",
  authenticate,
  authorize(["client"]),
  async (req, res) => {
    try {
      // For MVP, just return a mock payment URL
      const mockPaymentUrl =
        "https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=mock-preference-id";

      res.json({
        message: "Preferência de pagamento criada",
        init_point: mockPaymentUrl,
        preference_id: "mock-preference-id",
      });
    } catch (error) {
      console.error("Error creating subscription payment:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Create professional payment
app.post(
  "/api/professional/create-payment",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { amount } = req.body;

      if (!amount || amount <= 0) {
        return res.status(400).json({ message: "Valor inválido" });
      }

      // For MVP, just return a mock payment URL
      const mockPaymentUrl =
        "https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=mock-professional-payment";

      res.json({
        message: "Preferência de pagamento criada",
        init_point: mockPaymentUrl,
        preference_id: "mock-professional-payment",
      });
    } catch (error) {
      console.error("Error creating professional payment:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Create scheduling subscription payment (professional only)
app.post(
  "/api/create-scheduling-subscription",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      // For MVP, just return a mock payment URL
      const mockPaymentUrl =
        "https://www.mercadopago.com.br/checkout/v1/redirect?pref_id=mock-scheduling-subscription";

      res.json({
        message: "Preferência de pagamento criada",
        init_point: mockPaymentUrl,
        preference_id: "mock-scheduling-subscription",
      });
    } catch (error) {
      console.error("Error creating scheduling subscription payment:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// ==================== ADMIN SCHEDULING ACCESS ROUTES ====================

// Get all professionals with scheduling access status (admin only)
app.get(
  "/api/admin/professionals-scheduling-access",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const result = await pool.query(`
      SELECT 
        u.id,
        u.name,
        u.email,
        u.phone,
        sc.name as category_name,
        COALESCE(pss.has_scheduling_subscription, false) as has_scheduling_access,
        pss.expires_at as access_expires_at,
        pss.granted_by as access_granted_by,
        pss.granted_at as access_granted_at
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      LEFT JOIN professional_schedule_settings pss ON u.id = pss.professional_id
      WHERE u.roles @> '["professional"]'
      ORDER BY u.name
    `);

      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching professionals scheduling access:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Grant scheduling access to professional (admin only)
app.post(
  "/api/admin/grant-scheduling-access",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { professional_id, expires_at, reason } = req.body;

      if (!professional_id || !expires_at) {
        return res
          .status(400)
          .json({
            message: "ID do profissional e data de expiração são obrigatórios",
          });
      }

      // Check if professional exists
      const professionalCheck = await pool.query(
        `SELECT id, name, roles FROM users WHERE id = $1 AND roles @> '["professional"]'`,
        [professional_id]
      );

      if (professionalCheck.rows.length === 0) {
        return res.status(404).json({ message: "Profissional não encontrado" });
      }

      // Insert or update professional schedule settings
      const result = await pool.query(
        `
      INSERT INTO professional_schedule_settings 
      (professional_id, work_days, work_start_time, work_end_time, break_start_time, break_end_time, 
       consultation_duration, has_scheduling_subscription, expires_at, granted_by, granted_at, grant_reason)
      VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8, $9, CURRENT_TIMESTAMP, $10)
      ON CONFLICT (professional_id) 
      DO UPDATE SET 
        has_scheduling_subscription = true,
        expires_at = $8,
        granted_by = $9,
        granted_at = CURRENT_TIMESTAMP,
        grant_reason = $10,
        updated_at = CURRENT_TIMESTAMP
      RETURNING *
    `,
        [
          professional_id,
          JSON.stringify([1, 2, 3, 4, 5]), // Default work days
          "08:00", // Default start time
          "18:00", // Default end time
          "12:00", // Default break start
          "13:00", // Default break end
          60, // Default consultation duration
          expires_at,
          req.user.name, // Admin name
          reason,
        ]
      );

      res.json({
        message: "Acesso à agenda concedido com sucesso",
        data: result.rows[0],
      });
    } catch (error) {
      console.error("Error granting scheduling access:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Revoke scheduling access (admin only)
app.post(
  "/api/admin/revoke-scheduling-access",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const { professional_id } = req.body;

      if (!professional_id) {
        return res
          .status(400)
          .json({ message: "ID do profissional é obrigatório" });
      }

      const result = await pool.query(
        `
      UPDATE professional_schedule_settings 
      SET 
        has_scheduling_subscription = false,
        expires_at = NULL,
        granted_by = NULL,
        granted_at = NULL,
        grant_reason = NULL,
        updated_at = CURRENT_TIMESTAMP
      WHERE professional_id = $1
      RETURNING *
    `,
        [professional_id]
      );

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({ message: "Configurações do profissional não encontradas" });
      }

      res.json({
        message: "Acesso à agenda revogado com sucesso",
      });
    } catch (error) {
      console.error("Error revoking scheduling access:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Serve React app for all other routes
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../dist/index.html"));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({
    message: "Erro interno do servidor",
    error: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(
    `📱 Frontend URL: ${process.env.FRONTEND_URL || "http://localhost:5173"}`
  );
});