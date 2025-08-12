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