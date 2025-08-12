:",
        amount
      );

      const externalReference = `professional_${req.user.id}_${Date.now()}`;

      await pool.query(
        `INSERT INTO professional_payments 
       (professional_id, amount, status, external_reference)
       VALUES ($1, $2, 'pending', $3)`,
        [req.user.id, amount, externalReference]
      );

      res.json({
        preference_id: `mock_${externalReference}`,
        init_point: `${
          process.env.FRONTEND_URL || "http://localhost:5173"
        }/professional/payment-success`,
      });
    } catch (error) {
      console.error("❌ Error creating professional payment:", error);
      res.status(500).json({
        message: "Erro ao criar pagamento",
        error: error.message,
      });
    }
  }
);

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
// IMAGE UPLOAD ROUTES
// =============================================================================

// Upload professional image
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
// HEALTH CHECK AND SYSTEM INFO
// =============================================================================

// Health check endpoint
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

// System info endpoint
app.get(
  "/api/system-info",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
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
          environment: process.env.NODE_ENV || "development",
        },
        database: {
          users: userStats.rows[0],
          consultations: consultationStats.rows[0],
        },
        services: {
          cloudinary: isCloudinaryConfigured,
        },
      });
    } catch (error) {
      console.error("Error fetching system info:", error);
      res.status(500).json({ message: "Erro interno do servidor" });
    }
  }
);

// Database connection test
app.get(
  "/api/db-test",
  authenticate,
  authorize(["admin"]),
  async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT NOW() as current_time, version() as postgres_version"
      );
      res.json({
        status: "connected",
        ...result.rows[0],
      });
    } catch (error) {
      console.error("Database connection error:", error);
      res.status(500).json({
        status: "error",
        message: "Falha na conexão com o banco de dados",
      });
    }
  }
);

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

  if (err.name === "ValidationError") {
    return res.status(400).json({
      message: "Dados inválidos",
      details: err.message,
    });
  }

  if (err.name === "UnauthorizedError" || err.name === "JsonWebTokenError") {
    return res.status(401).json({
      message: "Token inválido ou expirado",
    });
  }

  if (err.code === "23505") {
    return res.status(400).json({
      message: "Dados duplicados - registro já existe",
    });
  }

  if (err.code === "23503") {
    return res.status(400).json({
      message: "Referência inválida - dados relacionados não encontrados",
    });
  }

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
// GRACEFUL SHUTDOWN
// =============================================================================

const gracefulShutdown = (signal) => {
  console.log(`\n🛑 Received ${signal}. Starting graceful shutdown...`);

  pool.end(() => {
    console.log("📊 Database connections closed");
  });

  process.exit(0);
};

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

process.on("uncaughtException", (err) => {
  console.error("🚨 Uncaught Exception:", err);
  gracefulShutdown("uncaughtException");
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("🚨 Unhandled Rejection at:", promise, "reason:", reason);
  gracefulShutdown("unhandledRejection");
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
      console.log(
        `🔐 JWT Secret: ${process.env.JWT_SECRET ? "Set" : "Using default"}`
      );
      console.log("============================================\n");

      console.log("📋 Available API routes:");
      console.log("  🔐 /api/auth/* - Authentication");
      console.log("  👥 /api/users/* - User management");
      console.log("  🏥 /api/clients/* - Client operations");
      console.log("  👨‍⚕️ /api/professionals/* - Professional operations");
      console.log("  📅 /api/consultations/* - Consultation management");
      console.log("  🗓️ /api/scheduling/* - Appointment scheduling");
      console.log("  📋 /api/medical-records/* - Medical records");
      console.log("  👤 /api/private-patients/* - Private patients");
      console.log("  📍 /api/attendance-locations/* - Attendance locations");
      console.log("  📊 /api/reports/* - Reports and analytics");
      console.log("  🏗️ /api/services/* - Service management");
      console.log("  📂 /api/service-categories/* - Service categories");
      console.log("  👶 /api/dependents/* - Dependent management");
      console.log("  🖼️ /api/upload-image - Image upload");
      console.log("  ❤️ /api/health - Health check");
      console.log("");
    });
  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
};

// Start the server
startServer();

export default app;