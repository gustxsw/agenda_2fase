import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { pool } from "./db.js";
import { authenticate, authorize } from "./middleware/auth.js";
import createUpload from "./middleware/upload.js";
import { generateDocumentPDF } from "./utils/documentGenerator.js";
import { MercadoPagoConfig, Preference } from "mercadopago";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// CORS configuration
const corsOptions = {
  origin: [
    "http://localhost:5173",
    "http://localhost:3000",
    "https://www.cartaoquiroferreira.com.br",
    "https://cartaoquiroferreira.com.br",
  ],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(cookieParser());

// Serve static files
app.use(express.static("dist"));

// Initialize MercadoPago
let mercadoPagoClient;
try {
  if (process.env.MP_ACCESS_TOKEN) {
    mercadoPagoClient = new MercadoPagoConfig({
      accessToken: process.env.MP_ACCESS_TOKEN,
      options: { timeout: 5000 },
    });
    console.log("✅ MercadoPago initialized successfully");
  } else {
    console.warn("⚠️ MercadoPago access token not found");
  }
} catch (error) {
  console.error("❌ Error initializing MercadoPago:", error);
}

// Database initialization
const createTables = async () => {
  try {
    console.log("🔄 Initializing database tables...");

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
        password VARCHAR(255) NOT NULL,
        roles TEXT[] DEFAULT ARRAY['client'],
        subscription_status VARCHAR(20) DEFAULT 'pending',
        subscription_expiry TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add percentage column if not exists
    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS percentage DECIMAL(5,2) DEFAULT 50.00
    `);

    // Update existing professionals without percentage
    await pool.query(`
      UPDATE users 
      SET percentage = 50.00 
      WHERE 'professional' = ANY(roles) AND percentage IS NULL
    `);

    // Create service_categories table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS service_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create services table
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

    // Create dependents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dependents (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        cpf VARCHAR(11) UNIQUE NOT NULL,
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

    // Create attendance_locations table
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

    // Create consultations table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        dependent_id INTEGER REFERENCES dependents(id),
        private_patient_id INTEGER,
        professional_id INTEGER REFERENCES users(id) NOT NULL,
        service_id INTEGER REFERENCES services(id) NOT NULL,
        location_id INTEGER REFERENCES attendance_locations(id),
        value DECIMAL(10,2) NOT NULL,
        date TIMESTAMP NOT NULL,
        status VARCHAR(20) DEFAULT 'completed',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create private_patients table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS private_patients (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
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
        zip_code VARCHAR(8),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create medical_records table
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

    // Create medical_documents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_documents (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id),
        title VARCHAR(255) NOT NULL,
        document_type VARCHAR(50) NOT NULL,
        document_url TEXT NOT NULL,
        patient_name VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log("✅ Database tables initialized successfully");
  } catch (error) {
    console.error("❌ Database initialization error:", error);
    throw error;
  }
};

// Initialize database on startup
createTables().catch((error) => {
  console.error("Failed to initialize database:", error);
  process.exit(1);
});

// Auth routes
app.post("/api/auth/login", async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: "CPF e senha são obrigatórios" });
    }

    const result = await pool.query(
      "SELECT id, name, cpf, roles, password FROM users WHERE cpf = $1",
      [cpf.replace(/\D/g, "")]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Credenciais inválidas" });
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ message: "Credenciais inválidas" });
    }

    res.json({
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
      return res.status(400).json({ message: "User ID e role são obrigatórios" });
    }

    const result = await pool.query(
      "SELECT id, name, cpf, roles FROM users WHERE id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const user = result.rows[0];

    if (!user.roles.includes(role)) {
      return res.status(403).json({ message: "Role não autorizada para este usuário" });
    }

    const token = jwt.sign(
      { id: user.id, currentRole: role },
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

    if (!req.user.roles.includes(role)) {
      return res.status(403).json({ message: "Role não autorizada para este usuário" });
    }

    const token = jwt.sign(
      { id: req.user.id, currentRole: role },
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

    if (!name || !password) {
      return res.status(400).json({ message: "Nome e senha são obrigatórios" });
    }

    if (cpf) {
      const existingUser = await pool.query(
        "SELECT id FROM users WHERE cpf = $1",
        [cpf.replace(/\D/g, "")]
      );

      if (existingUser.rows.length > 0) {
        return res.status(400).json({ message: "CPF já cadastrado" });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password, roles
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
      RETURNING id, name, cpf, roles`,
      [
        name,
        cpf ? cpf.replace(/\D/g, "") : null,
        email || null,
        phone ? phone.replace(/\D/g, "") : null,
        birth_date || null,
        address || null,
        address_number || null,
        address_complement || null,
        neighborhood || null,
        city || null,
        state || null,
        hashedPassword,
        ["client"],
      ]
    );

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

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout realizado com sucesso" });
});

// Users routes
app.get("/api/users", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, cpf, email, phone, roles, 
        subscription_status, subscription_expiry, created_at
      FROM users 
      ORDER BY created_at DESC
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

    if (req.user.currentRole !== "admin" && req.user.id !== parseInt(id)) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const result = await pool.query(
      `SELECT 
        id, name, cpf, email, phone, roles, 
        subscription_status, subscription_expiry, 
        percentage, photo_url, category_name, crm,
        created_at, updated_at
      FROM users 
      WHERE id = $1`,
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
    const { name, cpf, email, phone, password, roles } = req.body;

    if (!name || !password || !roles || roles.length === 0) {
      return res.status(400).json({ message: "Nome, senha e pelo menos uma role são obrigatórios" });
    }

    if (cpf) {
      const existingUser = await pool.query(
        "SELECT id FROM users WHERE cpf = $1",
        [cpf.replace(/\D/g, "")]
      );

      if (existingUser.rows.length > 0) {
        return res.status(400).json({ message: "CPF já cadastrado" });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (name, cpf, email, phone, password, roles) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, name, cpf, email, phone, roles`,
      [
        name,
        cpf ? cpf.replace(/\D/g, "") : null,
        email || null,
        phone ? phone.replace(/\D/g, "") : null,
        hashedPassword,
        roles,
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ message: "Erro ao criar usuário" });
  }
});

app.put("/api/users/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, phone, roles, currentPassword, newPassword } = req.body;

    if (req.user.currentRole !== "admin" && req.user.id !== parseInt(id)) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    let updateQuery = `
      UPDATE users 
      SET name = $1, email = $2, phone = $3, updated_at = CURRENT_TIMESTAMP
    `;
    let queryParams = [name, email || null, phone ? phone.replace(/\D/g, "") : null];
    let paramCount = 3;

    if (req.user.currentRole === "admin" && roles) {
      paramCount++;
      updateQuery += `, roles = $${paramCount}`;
      queryParams.push(roles);
    }

    if (newPassword) {
      if (req.user.currentRole !== "admin") {
        if (!currentPassword) {
          return res.status(400).json({ message: "Senha atual é obrigatória" });
        }

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
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      paramCount++;
      updateQuery += `, password = $${paramCount}`;
      queryParams.push(hashedPassword);
    }

    paramCount++;
    updateQuery += ` WHERE id = $${paramCount} RETURNING id, name, email, phone, roles`;
    queryParams.push(id);

    const result = await pool.query(updateQuery, queryParams);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ message: "Erro ao atualizar usuário" });
  }
});

app.delete("/api/users/:id", authenticate, authorize(["admin"]), async (req, res) => {
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
});

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

app.post("/api/service-categories", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ message: "Nome é obrigatório" });
    }

    const result = await pool.query(
      "INSERT INTO service_categories (name, description) VALUES ($1, $2) RETURNING *",
      [name, description || null]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Error creating service category:", error);
    res.status(500).json({ message: "Erro ao criar categoria" });
  }
});

// Services routes
app.get("/api/services", authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        s.*, 
        sc.name as category_name 
      FROM services s
      LEFT JOIN service_categories sc ON s.category_id = sc.id
      ORDER BY s.name
    `);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching services:", error);
    res.status(500).json({ message: "Erro ao buscar serviços" });
  }
});

app.post("/api/services", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const { name, description, base_price, category_id, is_base_service } = req.body;

    if (!name || !base_price) {
      return res.status(400).json({ message: "Nome e preço base são obrigatórios" });
    }

    const result = await pool.query(
      `INSERT INTO services (name, description, base_price, category_id, is_base_service) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [name, description || null, base_price, category_id || null, is_base_service || false]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Error creating service:", error);
    res.status(500).json({ message: "Erro ao criar serviço" });
  }
});

app.put("/api/services/:id", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, base_price, category_id, is_base_service } = req.body;

    const result = await pool.query(
      `UPDATE services 
       SET name = $1, description = $2, base_price = $3, category_id = $4, is_base_service = $5
       WHERE id = $6 RETURNING *`,
      [name, description || null, base_price, category_id || null, is_base_service || false, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Serviço não encontrado" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error updating service:", error);
    res.status(500).json({ message: "Erro ao atualizar serviço" });
  }
});

app.delete("/api/services/:id", authenticate, authorize(["admin"]), async (req, res) => {
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
});

// Consultations routes
app.get("/api/consultations", authenticate, async (req, res) => {
  try {
    let query = `
      SELECT 
        c.id,
        c.date,
        c.value,
        c.status,
        c.notes,
        s.name as service_name,
        COALESCE(u_client.name, u_dependent.name, pp.name) as client_name,
        u_prof.name as professional_name,
        CASE 
          WHEN c.dependent_id IS NOT NULL THEN true 
          ELSE false 
        END as is_dependent,
        c.created_at
      FROM consultations c
      LEFT JOIN users u_client ON c.client_id = u_client.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN users u_dependent ON d.client_id = u_dependent.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN users u_prof ON c.professional_id = u_prof.id
      LEFT JOIN services s ON c.service_id = s.id
    `;

    const queryParams = [];

    if (req.user.currentRole === "professional") {
      query += " WHERE c.professional_id = $1";
      queryParams.push(req.user.id);
    } else if (req.user.currentRole === "client") {
      query += " WHERE (c.client_id = $1 OR d.client_id = $1)";
      queryParams.push(req.user.id);
    }

    query += " ORDER BY c.date DESC";

    const result = await pool.query(query, queryParams);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching consultations:", error);
    res.status(500).json({ message: "Erro ao buscar consultas" });
  }
});

app.get("/api/consultations/client/:clientId", authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    if (req.user.currentRole !== "admin" && req.user.id !== parseInt(clientId)) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const result = await pool.query(`
      SELECT 
        c.id,
        c.date,
        c.value,
        c.status,
        s.name as service_name,
        COALESCE(u_client.name, d.name) as client_name,
        u_prof.name as professional_name,
        CASE 
          WHEN c.dependent_id IS NOT NULL THEN true 
          ELSE false 
        END as is_dependent
      FROM consultations c
      LEFT JOIN users u_client ON c.client_id = u_client.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN users u_prof ON c.professional_id = u_prof.id
      LEFT JOIN services s ON c.service_id = s.id
      WHERE (c.client_id = $1 OR d.client_id = $1)
      ORDER BY c.date DESC
    `, [clientId]);

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching client consultations:", error);
    res.status(500).json({ message: "Erro ao buscar consultas do cliente" });
  }
});

app.post("/api/consultations", authenticate, authorize(["professional"]), async (req, res) => {
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

    if (!service_id || !value || !date) {
      return res.status(400).json({ message: "Serviço, valor e data são obrigatórios" });
    }

    if (!client_id && !dependent_id && !private_patient_id) {
      return res.status(400).json({ message: "É necessário especificar um cliente, dependente ou paciente particular" });
    }

    const result = await pool.query(
      `INSERT INTO consultations 
       (client_id, dependent_id, private_patient_id, professional_id, service_id, location_id, value, date, status, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
       RETURNING *`,
      [
        client_id || null,
        dependent_id || null,
        private_patient_id || null,
        req.user.id,
        service_id,
        location_id || null,
        value,
        date,
        status || "completed",
        notes || null,
      ]
    );

    res.status(201).json({
      message: "Consulta registrada com sucesso",
      consultation: result.rows[0],
    });
  } catch (error) {
    console.error("Error creating consultation:", error);
    res.status(500).json({ message: "Erro ao registrar consulta" });
  }
});

app.put("/api/consultations/:id/status", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ message: "Status é obrigatório" });
    }

    const validStatuses = ["scheduled", "confirmed", "completed", "cancelled"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: "Status inválido" });
    }

    const result = await pool.query(
      `UPDATE consultations 
       SET status = $1, updated_at = CURRENT_TIMESTAMP 
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
    res.status(500).json({ message: "Erro ao atualizar status da consulta" });
  }
});

// Dependents routes
app.get("/api/dependents/:clientId", authenticate, async (req, res) => {
  try {
    const { clientId } = req.params;

    if (req.user.currentRole !== "admin" && req.user.id !== parseInt(clientId)) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const result = await pool.query(
      `SELECT 
        id, name, cpf, birth_date, subscription_status, subscription_expiry,
        billing_amount, payment_reference, activated_at, created_at,
        subscription_status as current_status
      FROM dependents 
      WHERE client_id = $1 
      ORDER BY created_at DESC`,
      [clientId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching dependents:", error);
    res.status(500).json({ message: "Erro ao buscar dependentes" });
  }
});

app.get("/api/admin/dependents", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        d.id, d.name, d.cpf, d.birth_date, d.subscription_status, 
        d.subscription_expiry, d.billing_amount, d.activated_at, d.created_at,
        u.name as client_name, u.subscription_status as client_status,
        d.subscription_status as current_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      ORDER BY d.created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching all dependents:", error);
    res.status(500).json({ message: "Erro ao buscar dependentes" });
  }
});

app.post("/api/dependents", authenticate, async (req, res) => {
  try {
    const { client_id, name, cpf, birth_date } = req.body;

    if (!client_id || !name || !cpf) {
      return res.status(400).json({ message: "Client ID, nome e CPF são obrigatórios" });
    }

    if (req.user.currentRole !== "admin" && req.user.id !== client_id) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const existingDependent = await pool.query(
      "SELECT id FROM dependents WHERE cpf = $1",
      [cpf.replace(/\D/g, "")]
    );

    if (existingDependent.rows.length > 0) {
      return res.status(400).json({ message: "CPF já cadastrado como dependente" });
    }

    const result = await pool.query(
      `INSERT INTO dependents (client_id, name, cpf, birth_date) 
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [client_id, name, cpf.replace(/\D/g, ""), birth_date || null]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Error creating dependent:", error);
    res.status(500).json({ message: "Erro ao criar dependente" });
  }
});

app.put("/api/dependents/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birth_date } = req.body;

    const dependentResult = await pool.query(
      "SELECT client_id FROM dependents WHERE id = $1",
      [id]
    );

    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: "Dependente não encontrado" });
    }

    const dependent = dependentResult.rows[0];

    if (req.user.currentRole !== "admin" && req.user.id !== dependent.client_id) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const result = await pool.query(
      `UPDATE dependents 
       SET name = $1, birth_date = $2, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $3 RETURNING *`,
      [name, birth_date || null, id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error updating dependent:", error);
    res.status(500).json({ message: "Erro ao atualizar dependente" });
  }
});

app.delete("/api/dependents/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const dependentResult = await pool.query(
      "SELECT client_id FROM dependents WHERE id = $1",
      [id]
    );

    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: "Dependente não encontrado" });
    }

    const dependent = dependentResult.rows[0];

    if (req.user.currentRole !== "admin" && req.user.id !== dependent.client_id) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    await pool.query("DELETE FROM dependents WHERE id = $1", [id]);

    res.json({ message: "Dependente excluído com sucesso" });
  } catch (error) {
    console.error("Error deleting dependent:", error);
    res.status(500).json({ message: "Erro ao excluir dependente" });
  }
});

app.get("/api/dependents/lookup", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: "CPF é obrigatório" });
    }

    const result = await pool.query(
      `SELECT 
        d.id, d.name, d.cpf, d.subscription_status as dependent_subscription_status,
        u.id as client_id, u.name as client_name, u.subscription_status as client_subscription_status
      FROM dependents d
      JOIN users u ON d.client_id = u.id
      WHERE d.cpf = $1`,
      [cpf.replace(/\D/g, "")]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Dependente não encontrado" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error looking up dependent:", error);
    res.status(500).json({ message: "Erro ao buscar dependente" });
  }
});

app.post("/api/admin/dependents/:id/activate", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `UPDATE dependents 
       SET subscription_status = 'active', 
           subscription_expiry = CURRENT_DATE + INTERVAL '1 year',
           activated_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1 
       RETURNING *`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Dependente não encontrado" });
    }

    res.json({
      message: "Dependente ativado com sucesso",
      dependent: result.rows[0],
    });
  } catch (error) {
    console.error("Error activating dependent:", error);
    res.status(500).json({ message: "Erro ao ativar dependente" });
  }
});

// Clients lookup routes
app.get("/api/clients/lookup", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const { cpf } = req.query;

    if (!cpf) {
      return res.status(400).json({ message: "CPF é obrigatório" });
    }

    const result = await pool.query(
      `SELECT id, name, cpf, subscription_status 
       FROM users 
       WHERE cpf = $1 AND 'client' = ANY(roles)`,
      [cpf.replace(/\D/g, "")]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Cliente não encontrado" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error looking up client:", error);
    res.status(500).json({ message: "Erro ao buscar cliente" });
  }
});

// Professionals routes
app.get("/api/professionals", authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, email, phone, roles, address, address_number, 
        address_complement, neighborhood, city, state, 
        category_name, photo_url
      FROM users 
      WHERE 'professional' = ANY(roles)
      ORDER BY name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching professionals:", error);
    res.status(500).json({ message: "Erro ao buscar profissionais" });
  }
});

app.get("/api/admin/professionals-scheduling-access", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, email, phone, category_name,
        has_scheduling_access, access_expires_at, 
        access_granted_by, access_granted_at
      FROM users 
      WHERE 'professional' = ANY(roles)
      ORDER BY name
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching professionals scheduling access:", error);
    res.status(500).json({ message: "Erro ao buscar acesso à agenda dos profissionais" });
  }
});

app.post("/api/admin/grant-scheduling-access", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const { professional_id, expires_at, reason } = req.body;

    if (!professional_id || !expires_at) {
      return res.status(400).json({ message: "ID do profissional e data de expiração são obrigatórios" });
    }

    const result = await pool.query(
      `UPDATE users 
       SET has_scheduling_access = true,
           access_expires_at = $1,
           access_granted_by = $2,
           access_granted_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $3 AND 'professional' = ANY(roles)
       RETURNING id, name`,
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
    res.status(500).json({ message: "Erro ao conceder acesso à agenda" });
  }
});

app.post("/api/admin/revoke-scheduling-access", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const { professional_id } = req.body;

    if (!professional_id) {
      return res.status(400).json({ message: "ID do profissional é obrigatório" });
    }

    const result = await pool.query(
      `UPDATE users 
       SET has_scheduling_access = false,
           access_expires_at = NULL,
           access_granted_by = NULL,
           access_granted_at = NULL,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1 AND 'professional' = ANY(roles)
       RETURNING id, name`,
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
    res.status(500).json({ message: "Erro ao revogar acesso à agenda" });
  }
});

// Attendance locations routes
app.get("/api/attendance-locations", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM attendance_locations 
       WHERE professional_id = $1 
       ORDER BY is_default DESC, name`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching attendance locations:", error);
    res.status(500).json({ message: "Erro ao buscar locais de atendimento" });
  }
});

app.post("/api/attendance-locations", authenticate, authorize(["professional"]), async (req, res) => {
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

    if (is_default) {
      await pool.query(
        "UPDATE attendance_locations SET is_default = false WHERE professional_id = $1",
        [req.user.id]
      );
    }

    const result = await pool.query(
      `INSERT INTO attendance_locations 
       (professional_id, name, address, address_number, address_complement, 
        neighborhood, city, state, zip_code, phone, is_default)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) 
       RETURNING *`,
      [
        req.user.id,
        name,
        address || null,
        address_number || null,
        address_complement || null,
        neighborhood || null,
        city || null,
        state || null,
        zip_code ? zip_code.replace(/\D/g, "") : null,
        phone ? phone.replace(/\D/g, "") : null,
        is_default || false,
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Error creating attendance location:", error);
    res.status(500).json({ message: "Erro ao criar local de atendimento" });
  }
});

app.put("/api/attendance-locations/:id", authenticate, authorize(["professional"]), async (req, res) => {
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

    if (is_default) {
      await pool.query(
        "UPDATE attendance_locations SET is_default = false WHERE professional_id = $1",
        [req.user.id]
      );
    }

    const result = await pool.query(
      `UPDATE attendance_locations 
       SET name = $1, address = $2, address_number = $3, address_complement = $4,
           neighborhood = $5, city = $6, state = $7, zip_code = $8, phone = $9, is_default = $10
       WHERE id = $11 AND professional_id = $12 
       RETURNING *`,
      [
        name,
        address || null,
        address_number || null,
        address_complement || null,
        neighborhood || null,
        city || null,
        state || null,
        zip_code ? zip_code.replace(/\D/g, "") : null,
        phone ? phone.replace(/\D/g, "") : null,
        is_default || false,
        id,
        req.user.id,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Local de atendimento não encontrado" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error updating attendance location:", error);
    res.status(500).json({ message: "Erro ao atualizar local de atendimento" });
  }
});

app.delete("/api/attendance-locations/:id", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      "DELETE FROM attendance_locations WHERE id = $1 AND professional_id = $2 RETURNING id",
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Local de atendimento não encontrado" });
    }

    res.json({ message: "Local de atendimento excluído com sucesso" });
  } catch (error) {
    console.error("Error deleting attendance location:", error);
    res.status(500).json({ message: "Erro ao excluir local de atendimento" });
  }
});

// Private patients routes
app.get("/api/private-patients", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM private_patients 
       WHERE professional_id = $1 
       ORDER BY name`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching private patients:", error);
    res.status(500).json({ message: "Erro ao buscar pacientes particulares" });
  }
});

app.post("/api/private-patients", authenticate, authorize(["professional"]), async (req, res) => {
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

    if (cpf) {
      const existingPatient = await pool.query(
        "SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2",
        [cpf.replace(/\D/g, ""), req.user.id]
      );

      if (existingPatient.rows.length > 0) {
        return res.status(400).json({ message: "CPF já cadastrado para este profissional" });
      }
    }

    const result = await pool.query(
      `INSERT INTO private_patients 
       (professional_id, name, cpf, email, phone, birth_date, address, 
        address_number, address_complement, neighborhood, city, state, zip_code)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
       RETURNING *`,
      [
        req.user.id,
        name,
        cpf ? cpf.replace(/\D/g, "") : null,
        email || null,
        phone ? phone.replace(/\D/g, "") : null,
        birth_date || null,
        address || null,
        address_number || null,
        address_complement || null,
        neighborhood || null,
        city || null,
        state || null,
        zip_code ? zip_code.replace(/\D/g, "") : null,
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Error creating private patient:", error);
    res.status(500).json({ message: "Erro ao criar paciente particular" });
  }
});

app.put("/api/private-patients/:id", authenticate, authorize(["professional"]), async (req, res) => {
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
      `UPDATE private_patients 
       SET name = $1, email = $2, phone = $3, birth_date = $4, address = $5,
           address_number = $6, address_complement = $7, neighborhood = $8,
           city = $9, state = $10, zip_code = $11, updated_at = CURRENT_TIMESTAMP
       WHERE id = $12 AND professional_id = $13 
       RETURNING *`,
      [
        name,
        email || null,
        phone ? phone.replace(/\D/g, "") : null,
        birth_date || null,
        address || null,
        address_number || null,
        address_complement || null,
        neighborhood || null,
        city || null,
        state || null,
        zip_code ? zip_code.replace(/\D/g, "") : null,
        id,
        req.user.id,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Paciente particular não encontrado" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error updating private patient:", error);
    res.status(500).json({ message: "Erro ao atualizar paciente particular" });
  }
});

app.delete("/api/private-patients/:id", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      "DELETE FROM private_patients WHERE id = $1 AND professional_id = $2 RETURNING id",
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Paciente particular não encontrado" });
    }

    res.json({ message: "Paciente particular excluído com sucesso" });
  } catch (error) {
    console.error("Error deleting private patient:", error);
    res.status(500).json({ message: "Erro ao excluir paciente particular" });
  }
});

// Medical records routes
app.get("/api/medical-records", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        mr.*, 
        pp.name as patient_name
      FROM medical_records mr
      JOIN private_patients pp ON mr.private_patient_id = pp.id
      WHERE mr.professional_id = $1
      ORDER BY mr.created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching medical records:", error);
    res.status(500).json({ message: "Erro ao buscar prontuários" });
  }
});

app.post("/api/medical-records", authenticate, authorize(["professional"]), async (req, res) => {
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
      return res.status(400).json({ message: "ID do paciente é obrigatório" });
    }

    const result = await pool.query(
      `INSERT INTO medical_records 
       (professional_id, private_patient_id, chief_complaint, history_present_illness,
        past_medical_history, medications, allergies, physical_examination,
        diagnosis, treatment_plan, notes, vital_signs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) 
       RETURNING *`,
      [
        req.user.id,
        private_patient_id,
        chief_complaint || null,
        history_present_illness || null,
        past_medical_history || null,
        medications || null,
        allergies || null,
        physical_examination || null,
        diagnosis || null,
        treatment_plan || null,
        notes || null,
        vital_signs || null,
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Error creating medical record:", error);
    res.status(500).json({ message: "Erro ao criar prontuário" });
  }
});

app.put("/api/medical-records/:id", authenticate, authorize(["professional"]), async (req, res) => {
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
      `UPDATE medical_records 
       SET chief_complaint = $1, history_present_illness = $2, past_medical_history = $3,
           medications = $4, allergies = $5, physical_examination = $6,
           diagnosis = $7, treatment_plan = $8, notes = $9, vital_signs = $10,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $11 AND professional_id = $12 
       RETURNING *`,
      [
        chief_complaint || null,
        history_present_illness || null,
        past_medical_history || null,
        medications || null,
        allergies || null,
        physical_examination || null,
        diagnosis || null,
        treatment_plan || null,
        notes || null,
        vital_signs || null,
        id,
        req.user.id,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Prontuário não encontrado" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error updating medical record:", error);
    res.status(500).json({ message: "Erro ao atualizar prontuário" });
  }
});

app.delete("/api/medical-records/:id", authenticate, authorize(["professional"]), async (req, res) => {
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
});

app.post("/api/medical-records/generate-document", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const { record_id, template_data } = req.body;

    if (!record_id || !template_data) {
      return res.status(400).json({ message: "ID do prontuário e dados do template são obrigatórios" });
    }

    const documentResult = await generateDocumentPDF("medical_record", template_data);

    res.json({
      message: "Documento gerado com sucesso",
      documentUrl: documentResult.url,
    });
  } catch (error) {
    console.error("Error generating medical record document:", error);
    res.status(500).json({ message: "Erro ao gerar documento do prontuário" });
  }
});

// Medical documents routes
app.get("/api/medical-documents", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM medical_documents 
       WHERE professional_id = $1 
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching medical documents:", error);
    res.status(500).json({ message: "Erro ao buscar documentos médicos" });
  }
});

app.post("/api/medical-documents", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const { title, document_type, private_patient_id, template_data } = req.body;

    if (!title || !document_type || !template_data) {
      return res.status(400).json({ message: "Título, tipo de documento e dados do template são obrigatórios" });
    }

    const documentResult = await generateDocumentPDF(document_type, template_data);

    const result = await pool.query(
      `INSERT INTO medical_documents 
       (professional_id, private_patient_id, title, document_type, document_url, patient_name)
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING *`,
      [
        req.user.id,
        private_patient_id || null,
        title,
        document_type,
        documentResult.url,
        template_data.patientName,
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
    res.status(500).json({ message: "Erro ao criar documento médico" });
  }
});

// Image upload route
app.post("/api/upload-image", authenticate, async (req, res) => {
  try {
    const upload = createUpload();
    console.log('🔍 Fetching user data for ID:', id);
    
    upload.single("image")(req, res, async (err) => {
      if (err) {
        console.error("Upload error:", err);
        return res.status(400).json({ message: err.message || "Erro no upload da imagem" });
      }

      if (!req.file) {
        return res.status(400).json({ message: "Nenhuma imagem foi enviada" });
      }

      try {
        const imageUrl = req.file.path;

        await pool.query(
          "UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
          [imageUrl, req.user.id]
        );

        res.json({
          message: "Imagem enviada com sucesso",
          imageUrl: imageUrl,
        });
      } catch (dbError) {
        console.error("Database error after upload:", dbError);
        res.status(500).json({ message: "Erro ao salvar URL da imagem no banco de dados" });
      }
    });
  } catch (error) {
    console.error("Error in upload route:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

// Reports routes
app.get("/api/reports/revenue", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: "Data inicial e final são obrigatórias" });
    }

    const result = await pool.query(
      `SELECT 
        SUM(c.value) as total_revenue,
        u.name as professional_name,
        COALESCE(u.percentage, 50) as professional_percentage,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count,
        SUM(c.value * (COALESCE(u.percentage, 50) / 100)) as professional_payment,
        SUM(c.value * ((100 - COALESCE(u.percentage, 50)) / 100)) as clinic_revenue
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.date BETWEEN $1 AND $2
      GROUP BY u.id, u.name, u.percentage
      ORDER BY revenue DESC`,
      [start_date, end_date]
    );

    const serviceResult = await pool.query(
      `SELECT 
        s.name as service_name,
        SUM(c.value) as revenue,
        COUNT(c.id) as consultation_count
      FROM consultations c
      JOIN services s ON c.service_id = s.id
      WHERE c.date BETWEEN $1 AND $2
      GROUP BY s.id, s.name
      ORDER BY revenue DESC`,
      [start_date, end_date]
    );

    const totalRevenue = result.rows.reduce((sum, row) => sum + parseFloat(row.revenue || 0), 0);

    res.json({
      total_revenue: totalRevenue,
      revenue_by_professional: result.rows,
      revenue_by_service: serviceResult.rows,
    });
  } catch (error) {
    console.error("Error generating revenue report:", error);
    res.status(500).json({ message: "Erro ao gerar relatório de receita" });
  }
});

app.get("/api/reports/professional-revenue", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: "Data inicial e final são obrigatórias" });
    }

    console.log("🔄 Generating professional revenue report for user:", req.user.id);
    console.log("🔄 Date range:", { start_date, end_date });

    const summaryResult = await pool.query(
      `SELECT 
        COALESCE(u.percentage, 50) as professional_percentage,
        SUM(c.value) as total_revenue,
        COUNT(c.id) as consultation_count,
        SUM(c.value * ((100 - COALESCE(u.percentage, 50)) / 100)) as amount_to_pay,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        COUNT(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.professional_id = $1 AND c.date BETWEEN $2 AND $3
      GROUP BY u.percentage`,
      [req.user.id, start_date, end_date]
    );

    const consultationsResult = await pool.query(
      `SELECT 
        c.date,
        COALESCE(u_client.name, d.name, pp.name) as client_name,
        s.name as service_name,
        c.value as total_value,
        c.value * ((100 - COALESCE(u_prof.percentage, 50)) / 100) as amount_to_pay
      FROM consultations c
      LEFT JOIN users u_client ON c.client_id = u_client.id
      LEFT JOIN dependents d ON c.dependent_id = d.id
      LEFT JOIN private_patients pp ON c.private_patient_id = pp.id
      LEFT JOIN users u_prof ON c.professional_id = u_prof.id
      LEFT JOIN services s ON c.service_id = s.id
      WHERE c.professional_id = $1 AND c.date BETWEEN $2 AND $3
      ORDER BY c.date DESC`,
      [req.user.id, start_date, end_date]
    );

    const summary = summaryResult.rows[0] || {
      professional_percentage: 50,
      total_revenue: 0,
      consultation_count: 0,
      amount_to_pay: 0,
      convenio_revenue: 0,
      private_revenue: 0,
      convenio_consultations: 0,
      private_consultations: 0,
    };

    res.json({
      summary: {
        professional_percentage: parseFloat(summary.professional_percentage) || 50,
        total_revenue: parseFloat(summary.total_revenue) || 0,
        consultation_count: parseInt(summary.consultation_count) || 0,
        amount_to_pay: parseFloat(summary.amount_to_pay) || 0,
        convenio_revenue: parseFloat(summary.convenio_revenue) || 0,
        private_revenue: parseFloat(summary.private_revenue) || 0,
        convenio_consultations: parseInt(summary.convenio_consultations) || 0,
        private_consultations: parseInt(summary.private_consultations) || 0,
      },
      consultations: consultationsResult.rows,
    });
  } catch (error) {
    console.error("Error generating professional revenue report:", error);
    res.status(500).json({ message: "Erro ao gerar relatório de receita profissional" });
  }
});

app.get("/api/reports/professional-detailed", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
      return res.status(400).json({ message: "Data inicial e final são obrigatórias" });
    }

    const result = await pool.query(
      `SELECT 
        COALESCE(u.percentage, 50) as professional_percentage,
        SUM(c.value) as total_revenue,
        COUNT(c.id) as total_consultations,
        SUM(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN c.value ELSE 0 END) as convenio_revenue,
        SUM(CASE WHEN c.private_patient_id IS NOT NULL THEN c.value ELSE 0 END) as private_revenue,
        COUNT(CASE WHEN c.client_id IS NOT NULL OR c.dependent_id IS NOT NULL THEN 1 END) as convenio_consultations,
        COUNT(CASE WHEN c.private_patient_id IS NOT NULL THEN 1 END) as private_consultations,
        SUM(c.value * ((100 - COALESCE(u.percentage, 50)) / 100)) as amount_to_pay
      FROM consultations c
      JOIN users u ON c.professional_id = u.id
      WHERE c.professional_id = $1 AND c.date BETWEEN $2 AND $3
      GROUP BY u.percentage`,
      [req.user.id, start_date, end_date]
    );

    const summary = result.rows[0] || {
      professional_percentage: 50,
      total_revenue: 0,
      total_consultations: 0,
      convenio_revenue: 0,
      private_revenue: 0,
      convenio_consultations: 0,
      private_consultations: 0,
      amount_to_pay: 0,
    };

    res.json({
      summary: {
        professional_percentage: parseFloat(summary.professional_percentage) || 50,
        total_revenue: parseFloat(summary.total_revenue) || 0,
        total_consultations: parseInt(summary.total_consultations) || 0,
        convenio_revenue: parseFloat(summary.convenio_revenue) || 0,
        private_revenue: parseFloat(summary.private_revenue) || 0,
        convenio_consultations: parseInt(summary.convenio_consultations) || 0,
        private_consultations: parseInt(summary.private_consultations) || 0,
        amount_to_pay: parseFloat(summary.amount_to_pay) || 0,
      },
    });
  } catch (error) {
    console.error("Error generating detailed professional report:", error);
    res.status(500).json({ message: "Erro ao gerar relatório detalhado" });
  }
});

app.get("/api/reports/clients-by-city", authenticate, authorize(["admin"]), async (req, res) => {
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
      WHERE 'client' = ANY(roles) AND city IS NOT NULL AND city != ''
      GROUP BY city, state
      ORDER BY client_count DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("Error generating clients by city report:", error);
    res.status(500).json({ message: "Erro ao gerar relatório de clientes por cidade" });
  }
});

app.get("/api/reports/professionals-by-city", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        city,
        state,
        COUNT(*) as total_professionals,
        json_agg(
          json_build_object(
            'category_name', COALESCE(category_name, 'Sem categoria'),
            'count', 1
          )
        ) as categories
      FROM users 
      WHERE 'professional' = ANY(roles) AND city IS NOT NULL AND city != ''
      GROUP BY city, state
      ORDER BY total_professionals DESC
    `);

    const processedResult = result.rows.map(row => ({
      ...row,
      categories: Object.values(
        row.categories.reduce((acc, cat) => {
          const key = cat.category_name;
          if (acc[key]) {
            acc[key].count += cat.count;
          } else {
            acc[key] = { ...cat };
          }
          return acc;
        }, {})
      ),
    }));

    res.json(processedResult);
  } catch (error) {
    console.error("Error generating professionals by city report:", error);
    res.status(500).json({ message: "Erro ao gerar relatório de profissionais por cidade" });
  }
});

// MercadoPago payment routes
app.post("/api/create-subscription", authenticate, async (req, res) => {
  try {
    const { user_id } = req.body;

    if (!user_id) {
      return res.status(400).json({ message: "User ID é obrigatório" });
    }

    if (!mercadoPagoClient) {
      return res.status(500).json({ message: "MercadoPago não configurado" });
    }

    const preference = new Preference(mercadoPagoClient);

    const preferenceData = {
      items: [
        {
          title: "Assinatura Convênio Quiro Ferreira - Titular",
          quantity: 1,
          unit_price: 250,
          currency_id: "BRL",
        },
      ],
      payer: {
        email: "cliente@quiroferreira.com.br",
      },
      back_urls: {
        success: `${req.protocol}://${req.get("host")}/client?payment=success&type=subscription`,
        failure: `${req.protocol}://${req.get("host")}/client?payment=failure&type=subscription`,
        pending: `${req.protocol}://${req.get("host")}/client?payment=pending&type=subscription`,
      },
      auto_return: "approved",
      external_reference: `subscription_${user_id}`,
      notification_url: `${req.protocol}://${req.get("host")}/api/webhooks/mercadopago`,
    };

    const response = await preference.create({ body: preferenceData });

    res.json({
      id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point,
    });
  } catch (error) {
    console.error("Error creating subscription payment:", error);
    res.status(500).json({ message: "Erro ao criar pagamento da assinatura" });
  }
});

app.post("/api/dependents/:id/create-payment", authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mercadoPagoClient) {
      return res.status(500).json({ message: "MercadoPago não configurado" });
    }

      'SELECT id, name, cpf, email, phone, roles, subscription_status, subscription_expiry FROM users WHERE id = $1',
      'SELECT id, name, cpf, email, phone, roles, subscription_status, subscription_expiry, created_at FROM users WHERE id = $1',
      [id]
    );

    if (dependentResult.rows.length === 0) {
      return res.status(404).json({ message: "Dependente não encontrado" });
    }

    const userData = result.rows[0];
    console.log('✅ User data found:', {
      id: userData.id,
      name: userData.name,
      subscription_status: userData.subscription_status,
      subscription_expiry: userData.subscription_expiry
    });
    
    res.json(userData);

    if (req.user.currentRole !== "admin" && req.user.id !== dependent.client_id) {
      return res.status(403).json({ message: "Acesso negado" });
    }

    const preference = new Preference(mercadoPagoClient);

    const preferenceData = {
      items: [
        {
          title: `Ativação de Dependente - ${dependent.name}`,
          quantity: 1,
          unit_price: dependent.billing_amount || 50,
          currency_id: "BRL",
        },
      ],
      payer: {
        email: "cliente@quiroferreira.com.br",
      },
      back_urls: {
        success: `${req.protocol}://${req.get("host")}/client?payment=success&type=dependent`,
        failure: `${req.protocol}://${req.get("host")}/client?payment=failure&type=dependent`,
        pending: `${req.protocol}://${req.get("host")}/client?payment=pending&type=dependent`,
      },
      auto_return: "approved",
      external_reference: `dependent_${id}`,
      notification_url: `${req.protocol}://${req.get("host")}/api/webhooks/mercadopago`,
    };

    const response = await preference.create({ body: preferenceData });

    res.json({
      id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point,
    });
  } catch (error) {
    console.error("Error creating dependent payment:", error);
    res.status(500).json({ message: "Erro ao criar pagamento do dependente" });
  }
});

app.post("/api/professional/create-payment", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: "Valor deve ser maior que zero" });
    }

    if (!mercadoPagoClient) {
      return res.status(500).json({ message: "MercadoPago não configurado" });
    }

    const preference = new Preference(mercadoPagoClient);

    const preferenceData = {
      items: [
        {
          title: `Repasse ao Convênio - ${req.user.name}`,
          quantity: 1,
          unit_price: parseFloat(amount),
          currency_id: "BRL",
        },
      ],
      payer: {
        email: "profissional@quiroferreira.com.br",
      },
      back_urls: {
        success: `${req.protocol}://${req.get("host")}/professional?payment=success`,
        failure: `${req.protocol}://${req.get("host")}/professional?payment=failure`,
        pending: `${req.protocol}://${req.get("host")}/professional?payment=pending`,
      },
      auto_return: "approved",
      external_reference: `professional_payment_${req.user.id}_${Date.now()}`,
      notification_url: `${req.protocol}://${req.get("host")}/api/webhooks/mercadopago`,
    };

    const response = await preference.create({ body: preferenceData });

    res.json({
      id: response.id,
      init_point: response.init_point,
      sandbox_init_point: response.sandbox_init_point,
    });
  } catch (error) {
    console.error("Error creating professional payment:", error);
    res.status(500).json({ message: "Erro ao criar pagamento profissional" });
  }
});

// Webhook route for MercadoPago
app.post("/api/webhooks/mercadopago", async (req, res) => {
  try {
    console.log("🔔 MercadoPago webhook received:", req.body);

    const { type, data } = req.body;

    if (type === "payment") {
      const paymentId = data.id;
      console.log("💳 Processing payment:", paymentId);

      // Here you would typically:
      // 1. Fetch payment details from MercadoPago API
      // 2. Update subscription status based on external_reference
      // 3. Send confirmation emails, etc.

      console.log("✅ Payment webhook processed successfully");
    }

    res.status(200).json({ message: "Webhook processed" });
  } catch (error) {
    console.error("Error processing webhook:", error);
    res.status(500).json({ message: "Erro ao processar webhook" });
  }
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

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || "development"}`);
});