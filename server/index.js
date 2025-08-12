import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { pool } from "./db.js";
import { authenticate, authorize } from "./middleware/auth.js";
import createUpload from "./middleware/upload.js";
import { generateDocumentPDF } from "./utils/documentGenerator.js";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// =============================================================================
// MIDDLEWARE SETUP
// =============================================================================

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:3000",
      "https://cartaoquiroferreira.com.br",
      "https://www.cartaoquiroferreira.com.br",
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());

// Serve static files from dist directory
app.use(express.static(path.join(__dirname, "../dist")));

// =============================================================================
// UPLOAD MIDDLEWARE SETUP
// =============================================================================

let upload;
let isCloudinaryConfigured = false;

try {
  upload = createUpload();
  isCloudinaryConfigured = true;
  console.log("✅ Cloudinary upload middleware configured successfully");
} catch (error) {
  console.error("❌ Failed to configure upload middleware:", error.message);
  console.warn("⚠️ Image upload will not be available");

  // Create a dummy upload middleware that returns an error
  upload = {
    single: () => (req, res, next) => {
      return res.status(500).json({
        message: "Serviço de upload não está configurado",
        error: "Cloudinary credentials missing",
      });
    },
  };
}

// =============================================================================
// DATABASE INITIALIZATION
// =============================================================================

const initializeDatabase = async () => {
  try {
    console.log("🔄 Initializing database schema...");

    // Create medical_documents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS medical_documents (
        id SERIAL PRIMARY KEY,
        professional_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        private_patient_id INTEGER REFERENCES private_patients(id) ON DELETE CASCADE,
        client_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        dependent_id INTEGER REFERENCES dependents(id) ON DELETE CASCADE,
        document_type VARCHAR(50) NOT NULL,
        title VARCHAR(255) NOT NULL,
        document_url TEXT NOT NULL,
        cloudinary_public_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        
        CONSTRAINT check_patient_reference CHECK (
          (private_patient_id IS NOT NULL AND client_id IS NULL AND dependent_id IS NULL) OR
          (private_patient_id IS NULL AND client_id IS NOT NULL AND dependent_id IS NULL) OR
          (private_patient_id IS NULL AND client_id IS NULL AND dependent_id IS NOT NULL)
        )
      )
    `);

    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_medical_documents_professional 
      ON medical_documents(professional_id)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_medical_documents_created_at 
      ON medical_documents(created_at DESC)
    `);

    console.log("✅ Database schema initialized successfully");
  } catch (error) {
    console.error("❌ Error initializing database:", error);
    throw error;
  }
};

// =============================================================================
// AUTHENTICATION ROUTES
// =============================================================================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { cpf, password } = req.body;

    if (!cpf || !password) {
      return res.status(400).json({ message: "CPF e senha são obrigatórios" });
    }

    const cleanCpf = cpf.replace(/\D/g, "");

    const result = await pool.query(
      "SELECT id, name, cpf, password_hash, roles FROM users WHERE cpf = $1",
      [cleanCpf]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Credenciais inválidas" });
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);

    if (!isValidPassword) {
      return res.status(401).json({ message: "Credenciais inválidas" });
    }

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles || [],
    };

    res.json({
      message: "Login realizado com sucesso",
      user: userData,
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
        .json({ message: "ID do usuário e role são obrigatórios" });
    }

    const result = await pool.query(
      "SELECT id, name, cpf, roles FROM users WHERE id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const user = result.rows[0];

    if (!user.roles || !user.roles.includes(role)) {
      return res
        .status(403)
        .json({ message: "Usuário não possui esta role" });
    }

    const token = jwt.sign(
      { id: user.id, currentRole: role },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "24h" }
    );

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles,
      currentRole: role,
    };

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json({
      message: "Role selecionada com sucesso",
      token,
      user: userData,
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

    const result = await pool.query(
      "SELECT id, name, cpf, roles FROM users WHERE id = $1",
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    const user = result.rows[0];

    if (!user.roles || !user.roles.includes(role)) {
      return res
        .status(403)
        .json({ message: "Usuário não possui esta role" });
    }

    const token = jwt.sign(
      { id: user.id, currentRole: role },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "24h" }
    );

    const userData = {
      id: user.id,
      name: user.name,
      cpf: user.cpf,
      roles: user.roles,
      currentRole: role,
    };

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json({
      message: "Role alterada com sucesso",
      token,
      user: userData,
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

    const cleanCpf = cpf.replace(/\D/g, "");

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res
        .status(400)
        .json({ message: "CPF deve conter 11 dígitos numéricos" });
    }

    const existingUser = await pool.query(
      "SELECT id FROM users WHERE cpf = $1",
      [cleanCpf]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "CPF já está cadastrado" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (
        name, cpf, email, phone, birth_date, address, address_number, 
        address_complement, neighborhood, city, state, password_hash, roles,
        subscription_status, subscription_expiry
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) 
      RETURNING id, name, cpf, roles`,
      [
        name,
        cleanCpf,
        email || null,
        phone || null,
        birth_date || null,
        address || null,
        address_number || null,
        address_complement || null,
        neighborhood || null,
        city || null,
        state || null,
        hashedPassword,
        JSON.stringify(["client"]),
        "pending",
        null,
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

// =============================================================================
// MEDICAL DOCUMENTS ROUTES
// =============================================================================

// Get all medical documents for the authenticated professional
app.get('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const professionalId = req.user.id;
    
    const result = await pool.query(`
      SELECT 
        md.*,
        COALESCE(pp.name, c.name, d.name) as patient_name,
        COALESCE(pp.cpf, c.cpf, d.cpf) as patient_cpf
      FROM medical_documents md
      LEFT JOIN private_patients pp ON md.private_patient_id = pp.id
      LEFT JOIN users c ON md.client_id = c.id
      LEFT JOIN dependents d ON md.dependent_id = d.id
      WHERE md.professional_id = $1
      ORDER BY md.created_at DESC
    `, [professionalId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching medical documents:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Create a new medical document
app.post('/api/medical-documents', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const professionalId = req.user.id;
    const {
      private_patient_id,
      client_id,
      dependent_id,
      document_type,
      title,
      template_data
    } = req.body;

    console.log('🔄 Creating medical document:', {
      professionalId,
      document_type,
      title,
      private_patient_id,
      client_id,
      dependent_id
    });

    // Validate required fields
    if (!document_type || !title || !template_data) {
      return res.status(400).json({ 
        message: 'Tipo de documento, título e dados do template são obrigatórios' 
      });
    }

    // Validate that at least one patient reference is provided
    if (!private_patient_id && !client_id && !dependent_id) {
      return res.status(400).json({ 
        message: 'É necessário especificar um paciente (particular, cliente ou dependente)' 
      });
    }

    // Generate PDF document
    console.log('🔄 Generating PDF with template data:', template_data);
    const documentResult = await generateDocumentPDF(document_type, template_data);
    
    console.log('✅ PDF generated successfully:', documentResult.url);

    // Save document record to database
    const insertResult = await pool.query(`
      INSERT INTO medical_documents (
        professional_id,
        private_patient_id,
        client_id,
        dependent_id,
        document_type,
        title,
        document_url,
        cloudinary_public_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `, [
      professionalId,
      private_patient_id || null,
      client_id || null,
      dependent_id || null,
      document_type,
      title,
      documentResult.url,
      documentResult.public_id
    ]);

    const document = insertResult.rows[0];
    
    console.log('✅ Document record saved to database:', document.id);

    res.status(201).json({
      message: 'Documento criado com sucesso',
      document: document,
      documentUrl: documentResult.url,
      title: title
    });
  } catch (error) {
    console.error('❌ Error creating medical document:', error);
    res.status(500).json({ 
      message: error.message || 'Erro ao criar documento médico',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Delete a medical document
app.delete('/api/medical-documents/:id', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const documentId = parseInt(req.params.id);
    const professionalId = req.user.id;
    
    // Get document info before deletion (for Cloudinary cleanup)
    const documentResult = await pool.query(
      'SELECT cloudinary_public_id FROM medical_documents WHERE id = $1 AND professional_id = $2',
      [documentId, professionalId]
    );
    
    if (documentResult.rows.length === 0) {
      return res.status(404).json({ message: 'Documento não encontrado' });
    }
    
    const document = documentResult.rows[0];
    
    // Delete from database
    await pool.query(
      'DELETE FROM medical_documents WHERE id = $1 AND professional_id = $2',
      [documentId, professionalId]
    );
    
    // Try to delete from Cloudinary (optional - don't fail if this fails)
    if (document.cloudinary_public_id) {
      try {
        const { v2: cloudinary } = await import('cloudinary');
        await cloudinary.uploader.destroy(document.cloudinary_public_id, { resource_type: 'raw' });
        console.log('✅ Document deleted from Cloudinary:', document.cloudinary_public_id);
      } catch (cloudinaryError) {
        console.warn('⚠️ Failed to delete from Cloudinary:', cloudinaryError.message);
        // Don't fail the request if Cloudinary deletion fails
      }
    }
    
    res.json({ message: 'Documento excluído com sucesso' });
  } catch (error) {
    console.error('Error deleting medical document:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// =============================================================================
// USER MANAGEMENT ROUTES
// =============================================================================

app.get("/api/users", authenticate, authorize(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date,
        u.address, u.address_number, u.address_complement, 
        u.neighborhood, u.city, u.state, u.roles, u.percentage,
        u.category_id, u.subscription_status, u.subscription_expiry,
        u.created_at, sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      ORDER BY u.created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.get("/api/users/:id", authenticate, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    if (
      req.user.currentRole !== "admin" &&
      req.user.id !== userId
    ) {
      return res.status(403).json({ message: "Acesso não autorizado" });
    }

    const result = await pool.query(
      `SELECT 
        u.id, u.name, u.cpf, u.email, u.phone, u.birth_date,
        u.address, u.address_number, u.address_complement, 
        u.neighborhood, u.city, u.state, u.roles, u.percentage,
        u.category_id, u.subscription_status, u.subscription_expiry,
        u.photo_url, u.created_at, sc.name as category_name
      FROM users u
      LEFT JOIN service_categories sc ON u.category_id = sc.id
      WHERE u.id = $1`,
      [userId]
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

// =============================================================================
// PRIVATE PATIENTS ROUTES
// =============================================================================

app.get("/api/private-patients", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const professionalId = req.user.id;

    const result = await pool.query(
      `SELECT * FROM private_patients 
       WHERE professional_id = $1 
       ORDER BY created_at DESC`,
      [professionalId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching private patients:", error);
    res.status(500).json({ message: "Erro interno do servidor" });
  }
});

app.post("/api/private-patients", authenticate, authorize(["professional"]), async (req, res) => {
  try {
    const professionalId = req.user.id;
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

    const cleanCpf = cpf.replace(/\D/g, "");

    if (!/^\d{11}$/.test(cleanCpf)) {
      return res.status(400).json({ message: "CPF deve conter 11 dígitos numéricos" });
    }

    const existingPatient = await pool.query(
      "SELECT id FROM private_patients WHERE cpf = $1 AND professional_id = $2",
      [cleanCpf, professionalId]
    );

    if (existingPatient.rows.length > 0) {
      return res.status(400).json({ message: "Paciente já cadastrado" });
    }

    const result = await pool.query(
      `INSERT INTO private_patients (
        professional_id, name, cpf, email, phone, birth_date,
        address, address_number, address_complement, neighborhood,
        city, state, zip_code
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING *`,
      [
        professionalId,
        name,
        cleanCpf,
        email || null,
        phone || null,
        birth_date || null,
        address || null,
        address_number || null,
        address_complement || null,
        neighborhood || null,
        city || null,
        state || null,
        zip_code || null,
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
});

// =============================================================================
// IMAGE UPLOAD ROUTES
// =============================================================================

app.post(
  "/api/upload-image",
  authenticate,
  authorize(["professional"]),
  upload.single("image"),
  async (req, res) => {
    try {
      console.log("🔄 Processing image upload for user:", req.user.id);

      if (!req.file) {
        return res.status(400).json({ message: "Nenhuma imagem foi enviada" });
      }

      let imageUrl;

      if (isCloudinaryConfigured && req.file.path) {
        imageUrl = req.file.path;
        console.log("✅ Image uploaded to Cloudinary:", imageUrl);
      } else {
        console.warn("⚠️ Cloudinary not configured, using fallback");
        return res
          .status(500)
          .json({ message: "Serviço de upload não configurado" });
      }

      const updateResult = await pool.query(
        "UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING photo_url",
        [imageUrl, req.user.id]
      );

      if (updateResult.rows.length === 0) {
        return res.status(404).json({ message: "Usuário não encontrado" });
      }

      res.json({
        message: "Imagem atualizada com sucesso",
        imageUrl: imageUrl,
      });
    } catch (error) {
      console.error("❌ Error uploading image:", error);
      res.status(500).json({
        message: "Erro ao fazer upload da imagem",
        error:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      });
    }
  }
);

// =============================================================================
// HEALTH CHECK
// =============================================================================

app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
    version: "1.0.0",
    services: {
      database: "connected",
      cloudinary: isCloudinaryConfigured ? "configured" : "not configured",
    },
  });
});

// =============================================================================
// ERROR HANDLING
// =============================================================================

// 404 handler for API routes
app.use("/api/*", (req, res) => {
  console.warn(`🚫 API route not found: ${req.method} ${req.path}`);
  res.status(404).json({
    message: "Endpoint não encontrado",
    path: req.path,
    method: req.method,
  });
});

// Serve React app for all other routes
app.get("*", (req, res) => {
  try {
    const indexPath = path.join(__dirname, "../dist/index.html");
    res.sendFile(indexPath);
  } catch (error) {
    console.error("Error serving index.html:", error);
    res.status(500).send("Erro interno do servidor");
  }
});

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error("🚨 Server error:", {
    message: err.message,
    stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString(),
  });

  res.status(err.status || 500).json({
    message: err.message || "Erro interno do servidor",
    error:
      process.env.NODE_ENV === "development"
        ? {
            message: err.message,
            stack: err.stack,
          }
        : undefined,
  });
});

// =============================================================================
// SERVER STARTUP
// =============================================================================

const startServer = async () => {
  try {
    // Initialize database schema
    await initializeDatabase();

    // Test database connection
    await pool.query("SELECT NOW()");
    console.log("✅ Database connection established");

    // Start server
    app.listen(PORT, () => {
      console.log("\n🚀 ===== CONVÊNIO QUIRO FERREIRA SERVER =====");
      console.log(`📱 Frontend: http://localhost:5173`);
      console.log(`🔗 API: http://localhost:${PORT}/api`);
      console.log(`🏥 Environment: ${process.env.NODE_ENV || "development"}`);
      console.log(
        `📊 Database: ${process.env.DATABASE_URL ? "Connected" : "Local"}`
      );
      console.log(
        `☁️ Cloudinary: ${
          isCloudinaryConfigured ? "Configured" : "Not configured"
        }`
      );
      console.log("============================================\n");
    });
  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
};

// Start the server
startServer();

export default app;