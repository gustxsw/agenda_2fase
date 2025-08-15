import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { pool } from "./db.js";
import { authenticate, authorize } from "./middleware/auth.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import { MercadoPagoConfig, Preference } from "mercadopago";
import cookieParser from "cookie-parser";
import createUpload from "./middleware/upload.js";
import { generateDocumentPDF } from "./utils/documentGenerator.js";
import dotenv from "dotenv";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

// Database migration function to ensure status column exists
const ensureStatusColumn = async () => {
  try {
    console.log(
      "🔄 Checking if status column exists in consultations table..."
    );

    // Check if status column exists
    const checkColumnQuery = `
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'consultations' AND column_name = 'status'
    `;

    const columnCheck = await pool.query(checkColumnQuery);

    if (columnCheck.rows.length === 0) {
      console.log("❌ Status column not found, creating it...");

      // Add status column with default value
      const addColumnQuery = `
        ALTER TABLE consultations 
        ADD COLUMN status VARCHAR(20) DEFAULT 'completed' NOT NULL
      `;

      await pool.query(addColumnQuery);
      console.log(
        '✅ Status column added successfully with default value "completed"'
      );

      // Update existing records to have 'completed' status
      const updateExistingQuery = `
        UPDATE consultations 
        SET status = 'completed' 
        WHERE status IS NULL
      `;

      await pool.query(updateExistingQuery);
      console.log('✅ Existing consultations updated with "completed" status');
    } else {
      console.log("✅ Status column already exists");
    }
  } catch (error) {
    console.error("❌ Error ensuring status column:", error);
    // Don't throw error to prevent server from crashing
  }
};

// Function to ensure updated_at column exists
const ensureUpdatedAtColumn = async () => {
  try {
    console.log(
      "🔄 Checking if updated_at column exists in consultations table..."
    );

    // Check if updated_at column exists
    const checkColumnQuery = `
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'consultations' 
      AND column_name = 'updated_at'
    `;

    const columnResult = await pool.query(checkColumnQuery);

    if (columnResult.rows.length === 0) {
      console.log("❌ updated_at column does not exist. Creating...");

      // Add updated_at column
      await pool.query(`
        ALTER TABLE consultations 
        ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      `);

      // Update existing records to have current timestamp
      await pool.query(`
        UPDATE consultations 
        SET updated_at = CURRENT_TIMESTAMP 
        WHERE updated_at IS NULL
      `);

      console.log("✅ updated_at column created and populated successfully");
    } else {
      console.log("✅ updated_at column already exists");
    }
  } catch (error) {
    console.error("❌ Error ensuring updated_at column:", error);
    throw error;
  }
};

// 🔥 CONFIGURE MERCADOPAGO SDK V2
let mercadopagoClient = null;
let preferenceClient = null;

const initializeMercadoPago = () => {
  try {
    const accessToken = process.env.MP_ACCESS_TOKEN;

    if (!accessToken) {
      console.warn(
        "⚠️  MercadoPago access token not found. Payment features will be disabled."
      );
      return false;
    }

    console.log("🔄 Initializing MercadoPago SDK v2...");

    // Initialize MercadoPago client
    mercadopagoClient = new MercadoPagoConfig({
      accessToken: accessToken,
      options: {
        timeout: 5000,
        idempotencyKey: "abc",
      },
    });

    // Initialize Preference client
    preferenceClient = new Preference(mercadopagoClient);

    console.log("✅ MercadoPago SDK v2 initialized successfully");
    return true;
  } catch (error) {
    console.error("❌ Error initializing MercadoPago:", error);
    return false;
  }
};

// Initialize MercadoPago
const mercadopagoEnabled = initializeMercadoPago();

const app = express();
const PORT = process.env.PORT || 3001;

// 🔥 CORS CONFIGURATION FOR PRODUCTION
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      "http://localhost:5173",
      "http://localhost:3000",
      "http://localhost:3001",
      "https://cartaoquiroferreira.com.br",
      "https://www.cartaoquiroferreira.com.br",
      "https://convenioquiroferreira.onrender.com",
    ];

    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log("❌ CORS blocked origin:", origin);
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
  exposedHeaders: ["Set-Cookie"],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static(path.join(process.cwd(), "dist")));

// 🔥 DATABASE SETUP FUNCTION
const setupDatabase = async () => {
  try {
    console.log("🔄 Setting up database...");

    // Create tables if they don't exist
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
        password VARCHAR(255) NOT NULL,
        roles TEXT[] DEFAULT ARRAY['client'],
        percentage INTEGER DEFAULT 50,
        category_id INTEGER,
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry DATE,
        photo_url TEXT,
        has_scheduling_access BOOLEAN DEFAULT FALSE,
        access_expires_at TIMESTAMP,
        access_granted_by VARCHAR(255),
        access_granted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        base_price DECIMAL(10,2) NOT NULL,
        category_id INTEGER REFERENCES service_categories(id),
        is_base_service BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(name, category_id)
      )
    `);

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
        UNIQUE(cpf, professional_id)
      )
    `);

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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        professional_id INTEGER REFERENCES users(id) NOT NULL,
        service_id INTEGER REFERENCES services(id) NOT NULL,
        location_id INTEGER REFERENCES attendance_locations(id),
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) NOT NULL,
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        private_patient_id INTEGER REFERENCES private_patients(id),
        service_id INTEGER REFERENCES services(id) NOT NULL,
        location_id INTEGER REFERENCES attendance_locations(id),
        appointment_date DATE NOT NULL,
        appointment_time TIME NOT NULL,
        status VARCHAR(20) DEFAULT 'scheduled',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_records (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) NOT NULL,
        private_patient_id INTEGER REFERENCES private_patients(id) NOT NULL,
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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_documents (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) NOT NULL,
        private_patient_id INTEGER REFERENCES private_patients(id),
        title VARCHAR(255) NOT NULL,
        document_type VARCHAR(50) NOT NULL,
        document_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 🔥 ALWAYS ensure private_patient_id column exists in consultations table
    console.log(
      "🔄 Checking if private_patient_id column exists in consultations..."
    );

    const columnCheckResult = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'consultations' 
      AND column_name = 'private_patient_id'
    `);

    if (columnCheckResult.rows.length === 0) {
      console.log(
        "➕ Adding private_patient_id column to consultations table..."
      );

      await pool.query(`
        ALTER TABLE consultations 
        ADD COLUMN private_patient_id INTEGER REFERENCES private_patients(id)
      `);

      console.log("✅ private_patient_id column added successfully");
    } else {
      console.log("✅ private_patient_id column already exists");
    }

    // 🔥 Update the constraint to include private_patient_id
    console.log("🔄 Updating consultation patient constraint...");

    // Drop existing constraint if it exists
    await pool.query(`
      ALTER TABLE consultations 
      DROP CONSTRAINT IF EXISTS consultation_patient_check
    `);

    // Add updated constraint
    await pool.query(`
      ALTER TABLE consultations 
      ADD CONSTRAINT consultation_patient_check CHECK (
        (client_id IS NOT NULL AND dependent_id IS NULL AND private_patient_id IS NULL) OR
        (client_id IS NULL AND dependent_id IS NOT NULL AND private_patient_id IS NULL) OR
        (client_id IS NULL AND dependent_id IS NULL AND private_patient_id IS NOT NULL)
      )
    `);

    console.log("✅ Consultation patient constraint updated successfully");

    // 🔥 ALWAYS ensure notes column exists in consultations table
    console.log("🔄 Checking if notes column exists in consultations...");

    const notesColumnCheckResult = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'consultations' 
      AND column_name = 'notes'
    `);

    if (notesColumnCheckResult.rows.length === 0) {
      console.log("➕ Adding notes column to consultations table...");

      await pool.query(`
        ALTER TABLE consultations 
        ADD COLUMN notes TEXT
      `);

      console.log("✅ notes column added successfully");
    } else {
      console.log("✅ notes column already exists");
    }

    // Handle duplicates and create unique constraints
    console.log("🔄 Checking for duplicates and creating constraints...");

    // Fix duplicate CPFs in users table
    try {
      const duplicateCpfs = await pool.query(`
        SELECT cpf, array_agg(id ORDER BY created_at) as ids
        FROM users 
        GROUP BY cpf 
        HAVING COUNT(*) > 1
      `);

      for (const row of duplicateCpfs.rows) {
        const [keepId, ...duplicateIds] = row.ids;
        console.log(
          `🔧 Found duplicate CPF ${
            row.cpf
          }, keeping ID ${keepId}, removing ${duplicateIds.join(", ")}`
        );

        // Update duplicate CPFs to make them unique
        for (let i = 0; i < duplicateIds.length; i++) {
          const newCpf = `${row.cpf.slice(0, -2)}${String(i + 1).padStart(
            2,
            "0"
          )}`;
          await pool.query("UPDATE users SET cpf = $1 WHERE id = $2", [
            newCpf,
            duplicateIds[i],
          ]);
        }
      }
    } catch (error) {
      console.log("ℹ️  No duplicate CPFs found in users table");
    }

    // Fix duplicate category names
    try {
      const duplicateCategories = await pool.query(`
        SELECT name, array_agg(id ORDER BY created_at) as ids
        FROM service_categories 
        GROUP BY name 
        HAVING COUNT(*) > 1
      `);

      for (const row of duplicateCategories.rows) {
        const [keepId, ...duplicateIds] = row.ids;
        console.log(
          `🔧 Found duplicate category ${
            row.name
          }, keeping ID ${keepId}, removing ${duplicateIds.join(", ")}`
        );

        // Update duplicate names
        for (let i = 0; i < duplicateIds.length; i++) {
          const newName = `${row.name} (${i + 1})`;
          await pool.query(
            "UPDATE service_categories SET name = $1 WHERE id = $2",
            [newName, duplicateIds[i]]
          );
        }
      }
    } catch (error) {
      console.log("ℹ️  No duplicate category names found");
    }

    // Fix duplicate service names within same category
    try {
      const duplicateServices = await pool.query(`
        SELECT name, category_id, array_agg(id ORDER BY created_at) as ids
        FROM services 
        GROUP BY name, category_id 
        HAVING COUNT(*) > 1
      `);

      for (const row of duplicateServices.rows) {
        const [keepId, ...duplicateIds] = row.ids;
        console.log(
          `🔧 Found duplicate service ${row.name} in category ${row.category_id}, keeping ID ${keepId}`
        );

        // Update duplicate names
        for (let i = 0; i < duplicateIds.length; i++) {
          const newName = `${row.name} (${i + 1})`;
          await pool.query("UPDATE services SET name = $1 WHERE id = $2", [
            newName,
            duplicateIds[i],
          ]);
        }
      }
    } catch (error) {
      console.log("ℹ️  No duplicate service names found");
    }

    // Fix duplicate dependent CPFs
    try {
      const duplicateDependentCpfs = await pool.query(`
        SELECT cpf, array_agg(id ORDER BY created_at) as ids
        FROM dependents 
        GROUP BY cpf 
        HAVING COUNT(*) > 1
      `);

      for (const row of duplicateDependentCpfs.rows) {
        const [keepId, ...duplicateIds] = row.ids;
        console.log(
          `🔧 Found duplicate dependent CPF ${row.cpf}, keeping ID ${keepId}`
        );

        // Update duplicate CPFs
        for (let i = 0; i < duplicateIds.length; i++) {
          const newCpf = `${row.cpf.slice(0, -2)}${String(i + 1).padStart(
            2,
            "0"
          )}`;
          await pool.query("UPDATE dependents SET cpf = $1 WHERE id = $2", [
            newCpf,
            duplicateIds[i],
          ]);
        }
      }
    } catch (error) {
      console.log("ℹ️  No duplicate dependent CPFs found");
    }

    // Fix duplicate private patient CPFs per professional
    try {
      const duplicatePrivatePatients = await pool.query(`
        SELECT cpf, professional_id, array_agg(id ORDER BY created_at) as ids
        FROM private_patients 
        GROUP BY cpf, professional_id 
        HAVING COUNT(*) > 1
      `);

      for (const row of duplicatePrivatePatients.rows) {
        const [keepId, ...duplicateIds] = row.ids;
        console.log(
          `🔧 Found duplicate private patient CPF ${row.cpf} for professional ${row.professional_id}, keeping ID ${keepId}`
        );

        // Update duplicate CPFs
        for (let i = 0; i < duplicateIds.length; i++) {
          const newCpf = `${row.cpf.slice(0, -2)}${String(i + 1).padStart(
            2,
            "0"
          )}`;
          await pool.query(
            "UPDATE private_patients SET cpf = $1 WHERE id = $2",
            [newCpf, duplicateIds[i]]
          );
        }
      }
    } catch (error) {
      console.log("ℹ️  No duplicate private patient CPFs found");
    }

    // Fix multiple default locations per professional
    try {
      const multipleDefaults = await pool.query(`
        SELECT professional_id, array_agg(id ORDER BY created_at) as ids
        FROM attendance_locations 
        WHERE is_default = true
        GROUP BY professional_id 
        HAVING COUNT(*) > 1
      `);

      for (const row of multipleDefaults.rows) {
        const [keepId, ...duplicateIds] = row.ids;
        console.log(
          `🔧 Found multiple default locations for professional ${row.professional_id}, keeping ID ${keepId}`
        );

        // Set others to false
        await pool.query(
          "UPDATE attendance_locations SET is_default = false WHERE id = ANY($1)",
          [duplicateIds]
        );
      }
    } catch (error) {
      console.log("ℹ️  No multiple default locations found");
    }

    // Create unique constraints and indexes
    console.log("🔄 Creating unique constraints and indexes...");

    // Users table constraints
    try {
      await pool.query(
        "CREATE UNIQUE INDEX IF NOT EXISTS users_cpf_unique ON users(cpf)"
      );
      console.log("✅ Created unique index on users.cpf");
    } catch (error) {
      console.log("ℹ️  Index users_cpf_unique already exists");
    }

    // Service categories constraints
    try {
      await pool.query(
        "CREATE UNIQUE INDEX IF NOT EXISTS service_categories_name_unique ON service_categories(name)"
      );
      console.log("✅ Created unique index on service_categories.name");
    } catch (error) {
      console.log("ℹ️  Index service_categories_name_unique already exists");
    }

    // Services constraints
    try {
      await pool.query(
        "CREATE UNIQUE INDEX IF NOT EXISTS services_name_category_unique ON services(name, category_id)"
      );
      console.log("✅ Created unique index on services(name, category_id)");
    } catch (error) {
      console.log("ℹ️  Index services_name_category_unique already exists");
    }

    // Dependents constraints
    try {
      await pool.query(
        "CREATE UNIQUE INDEX IF NOT EXISTS dependents_cpf_unique ON dependents(cpf)"
      );
      console.log("✅ Created unique index on dependents.cpf");
    } catch (error) {
      console.log("ℹ️  Index dependents_cpf_unique already exists");
    }

    // Private patients constraints
    try {
      await pool.query(
        "CREATE UNIQUE INDEX IF NOT EXISTS private_patients_cpf_professional_unique ON private_patients(cpf, professional_id)"
      );
      console.log(
        "✅ Created unique index on private_patients(cpf, professional_id)"
      );
    } catch (error) {
      console.log(
        "ℹ️  Index private_patients_cpf_professional_unique already exists"
      );
    }

    // Attendance locations constraints (only one default per professional)
    try {
      await pool.query(
        "CREATE UNIQUE INDEX IF NOT EXISTS attendance_locations_default_unique ON attendance_locations(professional_id) WHERE is_default = true"
      );
      console.log(
        "✅ Created unique partial index on attendance_locations(professional_id) WHERE is_default = true"
      );
    } catch (error) {
      console.log(
        "ℹ️  Index attendance_locations_default_unique already exists"
      );
    }

    console.log("✅ Database setup completed successfully");
  } catch (error) {
    console.error("❌ Error setting up database:", error);
    throw error;
  }
};

// Function to initialize database
const initializeDatabase = async () => {
  try {
    console.log("🔄 Initializing database...");
    await ensureStatusColumn();
    await ensureUpdatedAtColumn();
    console.log("✅ Database initialization completed");
  } catch (error) {
    console.error("❌ Database initialization error:", error);
  }
};

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    mercadopago: mercadopagoEnabled ? "enabled" : "disabled",
  });
});

// Auth routes
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

    // Validate required fields
    if (!name || !cpf || !password) {
      return res
        .status(400)
        .json({ message: "Nome, CPF e senha são obrigatórios" });
    }

    // Validate CPF format
    if (!/^\d{11}$/.test(cpf)) {
      return res
        .status(400)
        .json({ message: "CPF deve conter 11 dígitos numéricos" });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Insert user with ON CONFLICT handling
    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password, roles
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (cpf) DO NOTHING
      RETURNING id, name, cpf, roles`,
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
        ["client"],
      ]
    );

    if (result.rows.length === 0) {
      return res.status(409).json({ message: "CPF já está cadastrado" });
    }

    const user = result.rows[0];

    res.status(201).json({
      message: "Usuário criado com sucesso",
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        roles: user.roles,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: "CPF e senha são obrigatórios" });
    }

    // Find user by CPF
    const result = await pool.query(
      "SELECT id, name, cpf, password, roles FROM users WHERE cpf = $1",
      [cpf]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Credenciais inválidas" });
    }

    const user = result.rows[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: "Credenciais inválidas" });
    }

    // Return user data without token (will be created when role is selected)
    res.json({
      message: "Login realizado com sucesso",
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        roles: user.roles,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post("/api/auth/select-role", async (req, res) => {
  try {
    const { userId, role } = req.body;

    if (!userId || !role) {
      return res
        .status(400)
        .json({ message: "User ID e role são obrigatórios" });
    }

    // Get user and verify role
    const result = await pool.query(
      "SELECT id, name, cpf, roles FROM users WHERE id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const user = result.rows[0];

    if (!user.roles.includes(role)) {
      return res
        .status(403)
        .json({ message: "Role não autorizada para este usuário" });
    }

    // Create JWT token with selected role
    const token = jwt.sign(
      { id: user.id, currentRole: role },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "24h" }
    );

    // Set cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    res.json({
      message: "Role selecionada com sucesso",
      token,
      user: {
        id: user.id,
        name: user.name,
        cpf: user.cpf,
        roles: user.roles,
        currentRole: role,
      },
    });
  } catch (error) {
    console.error("Role selection error:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post("/api/auth/switch-role", authenticate, async (req, res) => {
  try {
    const { role } = req.body;

    if (!role) {
      return res.status(400).json({ message: "Role é obrigatória" });
    }

    // Verify user has this role
    if (!req.user.roles.includes(role)) {
      return res
        .status(403)
        .json({ message: "Role não autorizada para este usuário" });
    }

    // Create new JWT token with new role
    const token = jwt.sign(
      { id: req.user.id, currentRole: role },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "24h" }
    );

    // Set cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
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
    console.error("Role switch error:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout realizado com sucesso" });
});

// User management routes
app.get("/api/users", authenticate, authorize(["admin"]), async (req, res) => {
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
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Erro ao buscar usuários" });
  }
});

app.get("/api/users/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date, u.address, 
        u.address_number, u.address_complement, u.neighborhood, u.city, u.state,
        u.roles, u.percentage, u.category_id, u.subscription_status, u.subscription_expiry,
        u.photo_url, u.created_at, sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.id = $1
    `,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: "Erro ao buscar usuário" });
  }
});

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

    // Validate required fields
    if (!name || !cpf || !password || !roles || roles.length === 0) {
      return res.status(400).json({
        message: "Nome, CPF, senha e pelo menos uma role são obrigatórios",
      });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Insert user with ON CONFLICT handling
    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password, roles, percentage, category_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      ON CONFLICT (cpf) DO NOTHING
      RETURNING id, name, cpf, roles`,
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
        roles,
        percentage,
        category_id,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(409).json({ message: "CPF já está cadastrado" });
    }

    res.status(201).json({
      message: "Usuário criado com sucesso",
      user: result.rows[0],
    });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ message: "Erro ao criar usuário" });
  }
});

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

    // Check if user can edit this profile
    if (req.user.currentRole !== "admin" && req.user.id !== parseInt(id)) {
      return res
        .status(403)
        .json({ message: "Não autorizado a editar este perfil" });
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

    // Add admin-only fields
    if (req.user.currentRole === "admin" && roles) {
      updateQuery += `, roles = $${++paramCount}, percentage = $${++paramCount}, category_id = $${++paramCount}`;
      queryParams.push(roles, percentage, category_id);
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
        "SELECT password FROM users WHERE id = $1",
        [id]
      );
      if (userResult.rows.length === 0) {
        return res.status(404).json({ message: "Usuário não encontrado" });
      }

      const isValidPassword = await bcrypt.compare(
        currentPassword,
        userResult.rows[0].password
      );
      if (!isValidPassword) {
        return res.status(400).json({ message: "Senha atual incorreta" });
      }

      const newPasswordHash = await bcrypt.hash(newPassword, 10);
      updateQuery += `, password = $${++paramCount}`;
      queryParams.push(newPasswordHash);
    }

    updateQuery += ` WHERE id = $${++paramCount} RETURNING id, name, email, roles`;
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
    res.status(500).json({ message: "Erro ao atualizar usuário" });
  }
});

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
        `UPDATE users SET 
        subscription_status = 'active',
        subscription_expiry = $1,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $2 AND 'client' = ANY(roles)
      RETURNING id, name, subscription_status, subscription_expiry`,
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
      console.error("Error activating user:", error);
      res.status(500).json({ message: "Erro ao ativar cliente" });
    }
  }
);

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
      res.status(500).json({ message: "Erro ao excluir usuário" });
    }
  }
);

// Service categories routes
app.get("/api/service-categories", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM service_categories ORDER BY name"
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching service categories:", error);
    res.status(500).json({ message: "Erro ao buscar categorias" });
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
       ON CONFLICT (name) DO NOTHING
       RETURNING id, name, description`,
        [name, description]
      );

      if (result.rows.length === 0) {
        return res
          .status(409)
          .json({ message: "Categoria com este nome já existe" });
      }

      res.status(201).json({
        message: "Categoria criada com sucesso",
        category: result.rows[0],
      });
    } catch (error) {
      console.error("Error creating service category:", error);
      res.status(500).json({ message: "Erro ao criar categoria" });
    }
  }
);

// Services routes
app.get("/api/services", authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.*, sc.name as category_name 
      FROM services s
      LEFT JOIN service_categories sc ON s.category_id = sc.id
      ORDER BY sc.name, s.name
    `);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching services:", error);
    res.status(500).json({ message: "Erro ao buscar serviços" });
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

      if (!name || !base_price) {
        return res
          .status(400)
          .json({ message: "Nome e preço base são obrigatórios" });
      }

      const result = await pool.query(
        `INSERT INTO services (name, description, base_price, category_id, is_base_service) 
       VALUES ($1, $2, $3, $4, $5) 
       ON CONFLICT (name, category_id) DO NOTHING
       RETURNING id, name, description, base_price, category_id, is_base_service`,
        [name, description, base_price, category_id, is_base_service || false]
      );

      if (result.rows.length === 0) {
        return res
          .status(409)
          .json({ message: "Serviço com este nome já existe nesta categoria" });
      }

      res.status(201).json({
        message: "Serviço criado com sucesso",
        service: result.rows[0],
      });
    } catch (error) {
      console.error("Error creating service:", error);
      res.status(500).json({ message: "Erro ao criar serviço" });
    }
  }
);

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
        `UPDATE services SET 
        name = $1, description = $2, base_price = $3, category_id = $4, is_base_service = $5
       WHERE id = $6 
       RETURNING id, name, description, base_price, category_id, is_base_service`,
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
      res.status(500).json({ message: "Erro ao atualizar serviço" });
    }
  }
);

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
      res.status(500).json({ message: "Erro ao excluir serviço" });
    }
  }
);

// Dependents routes
app.get("/api/dependents/:clientId", authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    // Check if user can access this client's dependents
    if (
      req.user.currentRole !== "admin" &&
      req.user.id !== parseInt(clientId)
    ) {
      return res.status(403).json({ message: "Não autorizado" });
    }

    const result = await pool.query(
      "SELECT * FROM dependents WHERE client_id = $1 ORDER BY name",
      [clientId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching dependents:", error);
    res.status(500).json({ message: "Erro ao buscar dependentes" });
  }
});

app.get(
  "/api/dependents/lookup",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      const { cpf } = req.query;

      if (!cpf) {
        return res.status(400).json({ message: "CPF é obrigatório" });
      }

      const result = await pool.query(
        `
      SELECT 
        d.id, d.name, d.cpf, d.birth_date, d.client_id,
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
      res.status(500).json({ message: "Erro ao buscar dependente" });
    }
  }
);

app.post("/api/dependents", authenticate, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    // Check if user can add dependents for this client
    if (req.user.currentRole !== "admin" && req.user.id !== client_id) {
      return res.status(403).json({ message: "Não autorizado" });
    }

    // Validate required fields
    if (!client_id || !name || !cpf) {
      return res
        .status(400)
        .json({ message: "Client ID, nome e CPF são obrigatórios" });
    }

    const result = await pool.query(
      `INSERT INTO dependents (client_id, name, cpf, birth_date) 
       VALUES ($1, $2, $3, $4) 
       ON CONFLICT (cpf) DO NOTHING
       RETURNING id, client_id, name, cpf, birth_date`,
      [client_id, name, cpf, birth_date]
    );

    if (result.rows.length === 0) {
      return res
        .status(409)
        .json({ message: "CPF já está cadastrado como dependente" });
    }

    res.status(201).json({
      message: "Dependente criado com sucesso",
      dependent: result.rows[0],
    });
  } catch (error) {
    console.error("Error creating dependent:", error);
    res.status(500).json({ message: "Erro ao criar dependente" });
  }
});

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

    const dependent = dependentResult.rows[0];

    // Check if user can edit this dependent
    if (
      req.user.currentRole !== "admin" &&
      req.user.id !== dependent.client_id
    ) {
      return res.status(403).json({ message: "Não autorizado" });
    }

    const result = await pool.query(
      `UPDATE dependents SET name = $1, birth_date = $2 
       WHERE id = $3 
       RETURNING id, client_id, name, cpf, birth_date`,
      [name, birth_date, id]
    );

    res.json({
      message: "Dependente atualizado com sucesso",
      dependent: result.rows[0],
    });
  } catch (error) {
    console.error("Error updating dependent:", error);
    res.status(500).json({ message: "Erro ao atualizar dependente" });
  }
});

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

    const dependent = dependentResult.rows[0];

    // Check if user can delete this dependent
    if (
      req.user.currentRole !== "admin" &&
      req.user.id !== dependent.client_id
    ) {
      return res.status(403).json({ message: "Não autorizado" });
    }

    await pool.query("DELETE FROM dependents WHERE id = $1", [id]);

    res.json({ message: "Dependente excluído com sucesso" });
  } catch (error) {
    console.error("Error deleting dependent:", error);
    res.status(500).json({ message: "Erro ao excluir dependente" });
  }
});

// Client lookup route
app.get(
  "/api/clients/lookup",
  authenticate,
  authorize(["professional", "admin"]),
  async (req, res) => {
    try {
      const { cpf } = req.query;

      if (!cpf) {
        return res.status(400).json({ message: "CPF é obrigatório" });
      }

      const result = await pool.query(
        `SELECT id, name, cpf, subscription_status, subscription_expiry 
       FROM users 
       WHERE cpf = $1 AND 'client' = ANY(roles)`,
        [cpf]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Cliente não encontrado" });
      }

      res.json(result.rows[0]);
    } catch (error) {
      console.error("Error looking up client:", error);
      res.status(500).json({ message: "Erro ao buscar cliente" });
    }
  }
);

// Professionals routes
app.get("/api/professionals", authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.address, u.address_number, 
        u.address_complement, u.neighborhood, u.city, u.state, u.photo_url,
        sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching professionals:", error);
    res.status(500).json({ message: "Erro ao buscar profissionais" });
  }
});

// Admin routes for scheduling access management
app.get(
  "/api/admin/professionals-scheduling-access",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const result = await pool.query(`
      SELECT 
        u.id, u.name, u.email, u.phone, u.has_scheduling_access,
        u.access_expires_at, u.access_granted_by, u.access_granted_at,
        sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles)
      ORDER BY u.name
    `);

      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching professionals scheduling access:", error);
      res.status(500).json({ message: "Erro ao buscar dados de acesso" });
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

      if (!professional_id || !expires_at) {
        return res.status(400).json({
          message: "ID do profissional e data de expiração são obrigatórios",
        });
      }

      const result = await pool.query(
        `UPDATE users SET 
        has_scheduling_access = true,
        access_expires_at = $1,
        access_granted_by = $2,
        access_granted_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $3 AND 'professional' = ANY(roles)
      RETURNING id, name, has_scheduling_access, access_expires_at`,
        [expires_at, req.user.name, professional_id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Profissional não encontrado" });
      }

      res.json({
        message: "Acesso à agenda concedido com sucesso",
        professional: result.rows[0],
      });
    } catch (error) {
      console.error("Error granting scheduling access:", error);
      res.status(500).json({ message: "Erro ao conceder acesso" });
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

      if (!professional_id) {
        return res
          .status(400)
          .json({ message: "ID do profissional é obrigatório" });
      }

      const result = await pool.query(
        `UPDATE users SET 
        has_scheduling_access = false,
        access_expires_at = NULL,
        access_granted_by = NULL,
        access_granted_at = NULL,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $1 AND 'professional' = ANY(roles)
      RETURNING id, name, has_scheduling_access`,
        [professional_id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Profissional não encontrado" });
      }

      res.json({
        message: "Acesso à agenda revogado com sucesso",
        professional: result.rows[0],
      });
    } catch (error) {
      console.error("Error revoking scheduling access:", error);
      res.status(500).json({ message: "Erro ao revogar acesso" });
    }
  }
);

// Private patients routes
app.get(
  "/api/private-patients",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT * FROM private_patients WHERE professional_id = $1 ORDER BY name",
        [req.user.id]
      );

      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching private patients:", error);
      res.status(500).json({ message: "Erro ao buscar pacientes" });
    }
  }
);

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

      const result = await pool.query(
        `INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date, address,
        address_number, address_complement, neighborhood, city, state, zip_code
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (cpf, professional_id) DO NOTHING
      RETURNING *`,
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

      if (result.rows.length === 0) {
        return res
          .status(409)
          .json({ message: "Paciente com este CPF já está cadastrado" });
      }

      res.status(201).json({
        message: "Paciente criado com sucesso",
        patient: result.rows[0],
      });
    } catch (error) {
      console.error("Error creating private patient:", error);
      res.status(500).json({ message: "Erro ao criar paciente" });
    }
  }
);

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
        `UPDATE private_patients SET 
        name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
        address_number = $6, address_complement = $7, neighborhood = $8, 
        city = $9, state = $10, zip_code = $11
       WHERE id = $12 AND professional_id = $13
       RETURNING *`,
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
      res.status(500).json({ message: "Erro ao atualizar paciente" });
    }
  }
);

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
      res.status(500).json({ message: "Erro ao excluir paciente" });
    }
  }
);

// Attendance locations routes
app.get(
  "/api/attendance-locations",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT * FROM attendance_locations WHERE professional_id = $1 ORDER BY is_default DESC, name",
        [req.user.id]
      );

      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching attendance locations:", error);
      res.status(500).json({ message: "Erro ao buscar locais de atendimento" });
    }
  }
);

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

      // If setting as default, first remove default from others
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
      RETURNING *`,
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
        message: "Local de atendimento criado com sucesso",
        location: result.rows[0],
      });
    } catch (error) {
      console.error("Error creating attendance location:", error);
      res.status(500).json({ message: "Erro ao criar local de atendimento" });
    }
  }
);

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

      // If setting as default, first remove default from others
      if (is_default) {
        await pool.query(
          "UPDATE attendance_locations SET is_default = false WHERE professional_id = $1 AND id != $2",
          [req.user.id, id]
        );
      }

      const result = await pool.query(
        `UPDATE attendance_locations SET 
        name = $1, address = $2, address_number = $3, address_complement = $4,
        neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9, is_default = $10
       WHERE id = $11 AND professional_id = $12
       RETURNING *`,
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
        return res
          .status(404)
          .json({ message: "Local de atendimento não encontrado" });
      }

      res.json({
        message: "Local de atendimento atualizado com sucesso",
        location: result.rows[0],
      });
    } catch (error) {
      console.error("Error updating attendance location:", error);
      res
        .status(500)
        .json({ message: "Erro ao atualizar local de atendimento" });
    }
  }
);

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
        return res
          .status(404)
          .json({ message: "Local de atendimento não encontrado" });
      }

      res.json({ message: "Local de atendimento excluído com sucesso" });
    } catch (error) {
      console.error("Error deleting attendance location:", error);
      res.status(500).json({ message: "Erro ao excluir local de atendimento" });
    }
  }
);

// Consultations routes
app.get("/api/consultations", authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id, c.date, c.value, c.notes, c.created_at,
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

    let queryParams = [];

    if (req.user.currentRole === "client") {
      // For clients, show their consultations and their dependents' consultations
      query += ` WHERE (c.client_id = $1 OR d.client_id = $1)`;
      queryParams.push(req.user.id);
    } else if (req.user.currentRole === "professional") {
      // For professionals, show only their consultations
      query += ` WHERE c.professional_id = $1`;
      queryParams.push(req.user.id);
    }
    // For admin, show all consultations (no WHERE clause)

    query += ` ORDER BY c.date DESC`;

    const result = await pool.query(query, queryParams);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching consultations:", error);
    res.status(500).json({ message: "Erro ao buscar consultas" });
  }
});

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
        notes,
        appointment_date,
        appointment_time,
        create_appointment,
      } = req.body;

      // Validate that at least one patient type is provided
      if (!client_id && !dependent_id && !private_patient_id) {
        return res.status(400).json({
          message:
            "É necessário especificar um cliente, dependente ou paciente particular",
        });
      }

      // Validate required fields
      if (!service_id || !value || !date) {
        return res
          .status(400)
          .json({ message: "Serviço, valor e data são obrigatórios" });
      }

      // Insert consultation
      const consultationResult = await pool.query(
        `INSERT INTO consultations (
        client_id, dependent_id, private_patient_id, professional_id, 
        service_id, location_id, value, date, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *`,
        [
          client_id,
          dependent_id,
          private_patient_id,
          req.user.id,
          service_id,
          location_id,
          value,
          date,
          notes,
        ]
      );

      const consultation = consultationResult.rows[0];
      let appointment = null;

      // Create appointment if requested
      if (create_appointment && appointment_date && appointment_time) {
        const appointmentResult = await pool.query(
          `INSERT INTO appointments (
          professional_id, client_id, dependent_id, private_patient_id,
          service_id, location_id, appointment_date, appointment_time, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *`,
          [
            req.user.id,
            client_id,
            dependent_id,
            private_patient_id,
            service_id,
            location_id,
            appointment_date,
            appointment_time,
            "scheduled",
          ]
        );

        appointment = appointmentResult.rows[0];
      }

      res.status(201).json({
        message: "Consulta registrada com sucesso",
        consultation,
        appointment,
      });
    } catch (error) {
      console.error("Error creating consultation:", error);
      res.status(500).json({ message: "Erro ao registrar consulta" });
    }
  }
);

// Update consultation status
app.put("/api/consultations/:id/status", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    // Validate status
    const validStatuses = ["scheduled", "confirmed", "completed", "cancelled"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: "Status inválido" });
    }

    const result = await pool.query(
      `UPDATE consultations 
       SET status = $1, updated_at = NOW()
       WHERE id = $2 AND professional_id = $3
       RETURNING *`,
      [status, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Consulta não encontrada" });
    }

    res.json({
      message: "Status atualizado com sucesso",
      consultation: result.rows[0],
    });
  } catch (error) {
    console.error("Error updating consultation status:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Medical records routes
app.get(
  "/api/medical-records",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        `
      SELECT 
        mr.*,
        pp.name as patient_name
      FROM medical_records mr
      JOIN private_patients pp ON mr.private_patient_id = pp.id
      WHERE mr.professional_id = $1
      ORDER BY mr.created_at DESC
    `,
        [req.user.id]
      );
// Generate medical record document
app.post('/api/medical-records/generate-document', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { record_id, template_data } = req.body;
    
    // Verify the record belongs to the professional
    const recordResult = await pool.query(
      'SELECT * FROM medical_records WHERE id = $1 AND professional_id = $2',
      [record_id, req.user.id]
    );
    
    if (recordResult.rows.length === 0) {
      return res.status(404).json({ message: 'Prontuário não encontrado' });
    }
    
    // Generate document using the medical_record template
    const documentResult = await generateDocumentPDF('medical_record', template_data);
    
    res.json({
      message: 'Prontuário gerado com sucesso',
      documentUrl: documentResult.url,
      publicId: documentResult.public_id
    });
  } catch (error) {
    console.error('Error generating medical record document:', error);
    res.status(500).json({ 
      message: 'Erro ao gerar prontuário',
      error: error.message 
    });
  }
});


      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching medical records:", error);
      res.status(500).json({ message: "Erro ao buscar prontuários" });
    }
  }
);

app.post(
  "/api/medical-records",
  authenticate,
  authorize(["professional"]),
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
        return res
          .status(400)
          .json({ message: "ID do paciente é obrigatório" });
      }

      const result = await pool.query(
        `INSERT INTO medical_records (
        professional_id, private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, vital_signs
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *`,
        [
          req.user.id,
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
          JSON.stringify(vital_signs),
        ]
      );

      res.status(201).json({
        message: "Prontuário criado com sucesso",
        record: result.rows[0],
      });
    } catch (error) {
      console.error("Error creating medical record:", error);
      res.status(500).json({ message: "Erro ao criar prontuário" });
    }
  }
);

app.put(
  "/api/medical-records/:id",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { id } = req.params;
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

      const result = await pool.query(
        `UPDATE medical_records SET 
        chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
        medications = $4, allergies = $5, physical_examination = $6,
        diagnosis = $7, treatment_plan = $8, notes = $9, vital_signs = $10,
        updated_at = CURRENT_TIMESTAMP
       WHERE id = $11 AND professional_id = $12
       RETURNING *`,
        [
          chief_complaint,
          history_present_illness,
          past_medical_history,
          medications,
          allergies,
          physical_examination,
          diagnosis,
          treatment_plan,
          notes,
          JSON.stringify(vital_signs),
          id,
          req.user.id,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Prontuário não encontrado" });
      }

      res.json({
        message: "Prontuário atualizado com sucesso",
        record: result.rows[0],
      });
    } catch (error) {
      console.error("Error updating medical record:", error);
      res.status(500).json({ message: "Erro ao atualizar prontuário" });
    }
  }
);

app.delete(
  "/api/medical-records/:id",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { id } = req.params;

      const result = await pool.query(
        "DELETE FROM medical_records WHERE id = $1 AND professional_id = $2 RETURNING id",
        [id, req.user.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Prontuário não encontrado" });
      }

      res.json({ message: "Prontuário excluído com sucesso" });
    } catch (error) {
      console.error("Error deleting medical record:", error);
      res.status(500).json({ message: "Erro ao excluir prontuário" });
    }
  }
);

// Medical documents routes
app.get(
  "/api/medical-documents",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        `
      SELECT 
        md.*,
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
      res.status(500).json({ message: "Erro ao buscar documentos" });
    }
  }
);

app.post(
  "/api/medical-documents",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      const { title, document_type, private_patient_id, template_data } =
        req.body;

      if (!title || !document_type || !template_data) {
        return res.status(400).json({
          message:
            "Título, tipo de documento e dados do template são obrigatórios",
        });
      }

      // Generate document
      const documentResult = await generateDocumentPDF(
        document_type,
        template_data
      );

      // Save document record
      const result = await pool.query(
        `INSERT INTO medical_documents (
        professional_id, private_patient_id, title, document_type, document_url
      ) VALUES ($1, $2, $3, $4, $5)
      RETURNING *`,
        [
          req.user.id,
          private_patient_id,
          title,
          document_type,
          documentResult.url,
        ]
      );

      res.status(201).json({
        message: "Documento criado com sucesso",
        document: result.rows[0],
        title: title,
        documentUrl: documentResult.url,
      });
    } catch (error) {
      console.error("Error creating medical document:", error);
      res.status(500).json({ message: "Erro ao criar documento" });
    }
  }
);

// Image upload route
app.post(
  "/api/upload-image",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      console.log("🔄 Processing image upload...");

      // Create upload middleware instance
      const upload = createUpload();

      // Use multer middleware
      upload.single("image")(req, res, async (err) => {
        if (err) {
          console.error("❌ Upload error:", err);
          return res.status(400).json({
            message: err.message || "Erro no upload da imagem",
          });
        }

        if (!req.file) {
          return res
            .status(400)
            .json({ message: "Nenhuma imagem foi enviada" });
        }

        console.log("✅ Image uploaded successfully:", req.file.path);

        try {
          // Update user's photo_url in database
          await pool.query(
            "UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
            [req.file.path, req.user.id]
          );

          console.log("✅ User photo_url updated in database");

          res.json({
            message: "Imagem enviada com sucesso",
            imageUrl: req.file.path,
          });
        } catch (dbError) {
          console.error("❌ Database update error:", dbError);
          res.status(500).json({
            message: "Erro ao salvar URL da imagem no banco de dados",
          });
        }
      });
    } catch (error) {
      console.error("❌ Upload route error:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Reports routes
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
          .json({ message: "Datas de início e fim são obrigatórias" });
      }

      // Get total revenue
      const totalResult = await pool.query(
        "SELECT SUM(CASE WHEN private_patient_id IS NULL THEN value ELSE 0 END) as total_revenue FROM consultations WHERE date >= $1 AND date <= $2",
        [start_date, end_date]
      );

      // Get revenue by professional
      const professionalResult = await pool.query(
        `
      SELECT 
        u.name as professional_name,
        u.percentage as professional_percentage,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value ELSE 0 END) as revenue,
        COUNT(c.id) as consultation_count,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value * (u.percentage / 100) ELSE 0 END) as professional_payment,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value * ((100 - u.percentage) / 100) ELSE 0 END) as clinic_revenue
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.date >= $1 AND c.date <= $2
        AND (c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL)
      GROUP BY u.id, u.name, u.percentage
      ORDER BY revenue DESC
    `,
        [start_date, end_date]
      );

      // Get revenue by service
      const serviceResult = await pool.query(
        `
      SELECT 
        s.name as service_name,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value ELSE 0 END) as revenue,
        COUNT(c.id) as consultation_count
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      WHERE c.date >= $1 AND c.date <= $2
      GROUP BY s.id, s.name
      ORDER BY revenue DESC
    `,
        [start_date, end_date]
      );

      res.json({
        total_revenue: parseFloat(totalResult.rows[0].total_revenue || 0),
        revenue_by_professional: professionalResult.rows,
        revenue_by_service: serviceResult.rows,
      });
    } catch (error) {
      console.error("Error generating revenue report:", error);
      res.status(500).json({ message: "Erro ao gerar relatório" });
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

      if (!start_date || !end_date) {
        return res
          .status(400)
          .json({ message: "Datas de início e fim são obrigatórias" });
      }

      // Get professional's percentage
      const userResult = await pool.query(
        "SELECT percentage FROM users WHERE id = $1",
        [req.user.id]
      );

      const professionalPercentage = userResult.rows[0]?.percentage || 50;

      // Get consultations for the professional
      const consultationsResult = await pool.query(
        `
      SELECT 
        c.date,
        COALESCE(u.name, d.name, pp.name) as client_name,
        s.name as service_name,
        c.value as total_value,
        CASE 
          WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL 
          THEN c.value * ((100 - $2) / 100)
          ELSE 0
        END as amount_to_pay
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      LEFT JOIN users u ON c.client_id = u.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      WHERE c.professional_id = $1 
        AND c.date >= $3 AND c.date <= $4
      ORDER BY c.date DESC
    `,
        [req.user.id, professionalPercentage, start_date, end_date]
      );

      // Calculate summary
      const summaryResult = await pool.query(
        `
      SELECT 
        COUNT(*) as total_consultations,
        COUNT(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        SUM(c.value) as total_revenue,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value * ((100 - $2) / 100) ELSE 0 END) as amount_to_pay
      FROM consultations c
      WHERE c.professional_id = $1 
        AND c.date >= $3 AND c.date <= $4
    `,
        [req.user.id, professionalPercentage, start_date, end_date]
      );

      const summary = summaryResult.rows[0];

      res.json({
        summary: {
          professional_percentage: professionalPercentage,
          total_consultations: parseInt(summary.total_consultations || 0),
          convenio_consultations: parseInt(summary.convenio_consultations || 0),
          private_consultations: parseInt(summary.private_consultations || 0),
          total_revenue: parseFloat(summary.total_revenue || 0),
          convenio_revenue: parseFloat(summary.convenio_revenue || 0),
          private_revenue: parseFloat(summary.private_revenue || 0),
          amount_to_pay: parseFloat(summary.amount_to_pay || 0),
        },
        consultations: consultationsResult.rows,
      });
    } catch (error) {
      console.error("Error generating professional revenue report:", error);
      res.status(500).json({ message: "Erro ao gerar relatório" });
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

      if (!start_date || !end_date) {
        return res
          .status(400)
          .json({ message: "Datas de início e fim são obrigatórias" });
      }

      // Get professional's percentage
      const userResult = await pool.query(
        "SELECT percentage FROM users WHERE id = $1",
        [req.user.id]
      );

      const professionalPercentage = userResult.rows[0]?.percentage || 50;

      // Calculate detailed summary
      const summaryResult = await pool.query(
        `
      SELECT 
        COUNT(*) as total_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        SUM(c.value) as total_revenue,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        SUM(CASE WHEN c.private_patient_id IS NULL THEN c.value * ((100 - $2) / 100) ELSE 0 END) as amount_to_pay
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.professional_id = $1 
        AND c.date >= $3 AND c.date <= $4
    `,
        [req.user.id, professionalPercentage, start_date, end_date]
      );

      const summary = summaryResult.rows[0];

      res.json({
        summary: {
          professional_percentage: professionalPercentage,
          total_consultations: parseInt(summary.total_consultations || 0),
          convenio_consultations: parseInt(summary.convenio_consultations || 0),
          private_consultations: parseInt(summary.private_consultations || 0),
          total_revenue: parseFloat(summary.total_revenue || 0),
          convenio_revenue: parseFloat(summary.convenio_revenue || 0),
          private_revenue: parseFloat(summary.private_revenue || 0),
          amount_to_pay: parseFloat(summary.amount_to_pay || 0),
        },
      });
    } catch (error) {
      console.error("Error generating detailed professional report:", error);
      res.status(500).json({ message: "Erro ao gerar relatório detalhado" });
    }
  }
);

app.get(
  "/api/reports/clients-by-city",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const result = await pool.query(`
      SELECT 
        city,
        state,
        COUNT(*) as client_count,
        COUNT(CASE WHEN subscription_status = 'active' THEN 1 END) as active_clients,
        COUNT(CASE WHEN subscription_status = 'pending' THEN 1 END) as pending_clients,
        COUNT(CASE WHEN subscription_status = 'expired' THEN 1 END) as expired_clients
      FROM users 
      WHERE 'client' = ANY(roles) 
        AND city IS NOT NULL 
        AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC, city
    `);

      res.json(result.rows);
    } catch (error) {
      console.error("Error generating clients by city report:", error);
      res.status(500).json({ message: "Erro ao gerar relatório" });
    }
  }
);

app.get(
  "/api/reports/professionals-by-city",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const result = await pool.query(`
      SELECT 
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
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE 'professional' = ANY(u.roles) 
        AND u.city IS NOT NULL 
        AND u.city != ''
      GROUP BY u.city, u.state
      ORDER BY total_professionals DESC, u.city
    `);

      // Process the aggregated data
      const processedData = result.rows.map((row) => {
        const categoryMap = new Map();

        row.categories.forEach((cat) => {
          const name = cat.category_name;
          categoryMap.set(name, (categoryMap.get(name) || 0) + 1);
        });

        return {
          city: row.city,
          state: row.state,
          total_professionals: parseInt(row.total_professionals),
          categories: Array.from(categoryMap.entries()).map(
            ([category_name, count]) => ({
              category_name,
              count,
            })
          ),
        };
      });

      res.json(processedData);
    } catch (error) {
      console.error("Error generating professionals by city report:", error);
      res.status(500).json({ message: "Erro ao gerar relatório" });
    }
  }
);

// Payment routes
app.post("/api/create-subscription", authenticate, async (req, res) => {
  try {
    if (!mercadopagoEnabled || !preferenceClient) {
      return res
        .status(503)
        .json({ message: "Serviço de pagamento temporariamente indisponível" });
    }

    const { user_id, dependent_ids } = req.body;

    if (!user_id) {
      return res.status(400).json({ message: "User ID é obrigatório" });
    }

    // Calculate total amount
    const baseAmount = 250; // R$250 for titular
    const dependentAmount = (dependent_ids?.length || 0) * 50; // R$50 per dependent
    const totalAmount = baseAmount + dependentAmount;

    console.log("🔄 Creating subscription payment preference...");
    console.log("💰 Total amount:", totalAmount);

    const preferenceData = {
      items: [
        {
          title: "Assinatura Cartão Quiro Ferreira Saúde",
          unit_price: totalAmount,
          quantity: 1,
          currency_id: "BRL",
        },
      ],
      payer: {
        email: "cliente@quiroferreira.com.br",
        name: "Cliente Quiro Ferreira",
      },
      back_urls: {
        success: `${req.protocol}://${req.get("host")}/payment/success`,
        failure: `${req.protocol}://${req.get("host")}/payment/failure`,
        pending: `${req.protocol}://${req.get("host")}/payment/pending`,
      },
      auto_return: "approved",
      external_reference: `subscription_${user_id}_${Date.now()}`,
      notification_url: `${req.protocol}://${req.get(
        "host"
      )}/api/webhooks/mercadopago`,
      statement_descriptor: "QUIRO FERREIRA",
    };

    const response = await preferenceClient.create({ body: preferenceData });

    console.log("✅ Payment preference created successfully");
    console.log("🔗 Init point:", response.init_point);

    res.json({
      init_point: response.init_point,
      preference_id: response.id,
    });
  } catch (error) {
    console.error("Error creating subscription payment:", error);
    res.status(500).json({
      message: "Erro ao criar pagamento",
      details: error.message,
    });
  }
});

app.post(
  "/api/professional/create-payment",
  authenticate,
  authorize(["professional"]),
  async (req, res) => {
    try {
      if (!mercadopagoEnabled || !preferenceClient) {
        return res.status(503).json({
          message: "Serviço de pagamento temporariamente indisponível",
        });
      }

      const { amount } = req.body;

      if (!amount || amount <= 0) {
        return res
          .status(400)
          .json({ message: "Valor deve ser maior que zero" });
      }

      console.log("🔄 Creating professional payment preference...");
      console.log("💰 Amount:", amount);
      console.log("👤 Professional:", req.user.name);

      const preferenceData = {
        items: [
          {
            title: `Repasse ao Convênio Quiro Ferreira - ${req.user.name}`,
            unit_price: parseFloat(amount),
            quantity: 1,
            currency_id: "BRL",
          },
        ],
        payer: {
          email: "profissional@quiroferreira.com.br",
          name: req.user.name || "Profissional Quiro Ferreira",
        },
        back_urls: {
          success: `${req.protocol}://${req.get("host")}/payment/success`,
          failure: `${req.protocol}://${req.get("host")}/payment/failure`,
          pending: `${req.protocol}://${req.get("host")}/payment/pending`,
        },
        auto_return: "approved",
        external_reference: `professional_payment_${req.user.id}_${Date.now()}`,
        notification_url: `${req.protocol}://${req.get(
          "host"
        )}/api/webhooks/mercadopago`,
        statement_descriptor: "QUIRO FERREIRA",
      };

      const response = await preferenceClient.create({ body: preferenceData });

      console.log("✅ Professional payment preference created successfully");
      console.log("🔗 Init point:", response.init_point);

      res.json({
        init_point: response.init_point,
        preference_id: response.id,
      });
    } catch (error) {
      console.error("Error creating professional payment:", error);
      res.status(500).json({
        message: "Erro ao criar pagamento",
        details: error.message,
      });
    }
  }
);

// 🔥 NEW: MercadoPago webhook endpoint for payment notifications
app.post(
  "/api/webhooks/mercadopago",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      console.log("🔔 MercadoPago webhook received");
      console.log("📦 Webhook data:", req.body);

      // For now, just acknowledge the webhook
      // In the future, you can process payment status updates here
      res.status(200).send("OK");
    } catch (error) {
      console.error("❌ Error processing MercadoPago webhook:", error);
      res.status(500).send("Error");
    }
  }
);

// Payment result pages
app.get("/payment/success", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Pagamento Aprovado</title>
      <meta charset="UTF-8">
      <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f0f9ff; }
        .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .success { color: #059669; font-size: 24px; margin-bottom: 20px; }
        .button { background: #c11c22; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; margin-top: 20px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="success">✅ Pagamento Aprovado!</div>
        <p>Seu pagamento foi processado com sucesso.</p>
        <a href="/" class="button">Voltar ao Sistema</a>
      </div>
    </body>
    </html>
  `);
});

app.get("/payment/failure", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Pagamento Rejeitado</title>
      <meta charset="UTF-8">
      <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #fef2f2; }
        .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .error { color: #dc2626; font-size: 24px; margin-bottom: 20px; }
        .button { background: #c11c22; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; margin-top: 20px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="error">❌ Pagamento Rejeitado</div>
        <p>Houve um problema com seu pagamento. Tente novamente.</p>
        <a href="/" class="button">Voltar ao Sistema</a>
      </div>
    </body>
    </html>
  `);
});

app.get("/payment/pending", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Pagamento Pendente</title>
      <meta charset="UTF-8">
      <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #fffbeb; }
        .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .pending { color: #d97706; font-size: 24px; margin-bottom: 20px; }
        .button { background: #c11c22; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; margin-top: 20px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="pending">⏳ Pagamento Pendente</div>
        <p>Seu pagamento está sendo processado. Aguarde a confirmação.</p>
        <a href="/" class="button">Voltar ao Sistema</a>
      </div>
    </body>
    </html>
  `);
});

// Catch-all route for SPA
app.get("*", (req, res) => {
  res.sendFile(path.join(process.cwd(), "dist", "index.html"));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error("Unhandled error:", error);
  res.status(500).json({ message: "Erro interno do servidor" });
});

// 🔥 INITIALIZE DATABASE AND START SERVER
const startServer = async () => {
  try {
    console.log("🚀 Starting Convênio Quiro Ferreira Server...");

    // Setup database first
    await setupDatabase();

    // Start server
    app.listen(PORT, async () => {
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`🌐 Environment: ${process.env.NODE_ENV || "development"}`);
      console.log(`📊 Database: Connected and configured`);
      console.log(
        `💳 MercadoPago: ${mercadopagoEnabled ? "Enabled" : "Disabled"}`
      );
      console.log(`🔒 CORS enabled for production domains`);

      // Initialize database schema
      await initializeDatabase();
    });
  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
};

startServer();
