Payment pending page
app.get('/payment-pending', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Pagamento Pendente - Convênio Quiro Ferreira</title>
        <style>
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                background: white;
                padding: 3rem;
                border-radius: 1rem;
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
                text-align: center;
                max-width: 500px;
                width: 90%;
            }
            .pending-icon {
                width: 80px;
                height: 80px;
                background: #F59E0B;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 2rem;
            }
            .clock {
                width: 40px;
                height: 40px;
                color: white;
                stroke-width: 2;
            }
            h1 {
                color: #D97706;
                margin-bottom: 1rem;
                font-size: 2rem;
                font-weight: 700;
            }
            p {
                color: #6B7280;
                margin-bottom: 2rem;
                line-height: 1.6;
            }
            .btn {
                background: #c11c22;
                color: white;
                padding: 1rem 2rem;
                border: none;
                border-radius: 0.5rem;
                font-weight: 600;
                text-decoration: none;
                display: inline-block;
                transition: background-color 0.2s;
            }
            .btn:hover {
                background: #9a151a;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="pending-icon">
                <svg class="clock" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <circle cx="12" cy="12" r="10"></circle>
                    <polyline points="12,6 12,12 16,14"></polyline>
                </svg>
            </div>
            
            <h1>Pagamento Pendente</h1>
            
            <p>
                Seu pagamento está sendo processado. Dependendo da forma de pagamento escolhida,
                pode levar alguns minutos ou até 2 dias úteis para ser confirmado.
            </p>
            
            <p>
                <strong>Formas de pagamento e prazos:</strong><br>
                • Cartão de crédito: Aprovação imediata<br>
                • PIX: Até 2 horas<br>
                • Boleto bancário: Até 2 dias úteis<br>
                • Débito online: Aprovação imediata
            </p>
            
            <p>
                Você receberá uma confirmação por email assim que o pagamento for aprovado.
            </p>
            
            <a href="/" class="btn">Voltar ao Sistema</a>
            
            <div style="margin-top: 2rem; padding-top: 2rem; border-top: 1px solid #E5E7EB;">
                <p style="font-size: 0.875rem; color: #9CA3AF;">
                    Convênio Quiro Ferreira<br>
                    Telefone: (64) 98124-9199
                </p>
            </div>
        </div>
    </body>
    </html>
  `);
});

// =============================================================================
// IMAGE UPLOAD ROUTES
// =============================================================================

// Upload image route
app.post('/api/upload-image', authenticate, async (req, res) => {
  try {
    console.log('🔄 Image upload request received');
    
    // Create upload middleware instance
    const upload = createUpload();
    
    // Use multer middleware
    upload.single('image')(req, res, async (err) => {
      if (err) {
        console.error('❌ Multer error:', err);
        return res.status(400).json({ 
          message: err.message || 'Erro no upload da imagem' 
        });
      }

      if (!req.file) {
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
      }

      console.log('✅ Image uploaded to Cloudinary:', req.file.path);

      // Update user photo URL in database
      const user = req.user;
      await pool.query(
        'UPDATE users SET photo_url = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
        [req.file.path, user.id]
      );

      console.log('✅ User photo URL updated in database');

      res.json({
        message: 'Imagem enviada com sucesso',
        imageUrl: req.file.path
      });
    });
  } catch (error) {
    console.error('❌ Error in image upload route:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

// Upload signature endpoint
app.post('/api/upload-signature', authenticate, (req, res) => {
  const uploadSignature = createUpload('signature');
  
  uploadSignature.single('signature')(req, res, async (err) => {
    if (err) {
      console.error('❌ Signature upload error:', err);
      return res.status(400).json({ 
        message: err.message || 'Erro no upload da assinatura' 
      });
    }

    if (!req.file) {
      return res.status(400).json({ 
        message: 'Nenhuma imagem de assinatura foi enviada' 
      });
    }

    console.log('✅ Signature uploaded to Cloudinary:', req.file.path);

    try {
      // Update user signature_url in database
      await pool.query(
        'UPDATE users SET signature_url = $1 WHERE id = $2',
        [req.file.path, req.user.id]
      );

      console.log('✅ User signature_url updated in database');

      res.json({ 
        message: 'Assinatura enviada com sucesso',
        signatureUrl: req.file.path
      });
    } catch (dbError) {
      console.error('❌ Database error updating signature:', dbError);
      res.status(500).json({ 
        message: 'Erro ao salvar assinatura no banco de dados' 
      });
    }
  });
});

// =============================================================================
// HEALTH CHECK AND FALLBACK ROUTES
// =============================================================================

// Health check route
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// API status route
app.get('/api/status', (req, res) => {
  res.json({
    status: 'online',
    version: '1.0.0',
    database: 'connected',
    mercadopago: mercadoPagoClient ? 'configured' : 'not configured',
    cloudinary: process.env.CLOUDINARY_CLOUD_NAME ? 'configured' : 'not configured'
  });
});

// Catch-all route for SPA (must be last)
app.get('*', (req, res) => {
  // Don't serve index.html for API routes
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ message: 'API endpoint not found' });
  }
  
  res.sendFile('index.html', { root: 'dist' });
});

// =============================================================================
// GLOBAL ERROR HANDLER
// =============================================================================

app.use((error, req, res, next) => {
  console.error('🚨 Global error handler:', error);
  
  // Handle specific error types
  if (error.code === '23505') { // PostgreSQL unique violation
    return res.status(409).json({ message: 'Dados duplicados encontrados' });
  }
  
  if (error.code === '23503') { // PostgreSQL foreign key violation
    return res.status(400).json({ message: 'Referência inválida nos dados' });
  }
  
  if (error.code === '23514') { // PostgreSQL check violation
    return res.status(400).json({ message: 'Dados inválidos fornecidos' });
  }
  
  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json({ message: 'Token inválido' });
  }
  
  if (error.name === 'TokenExpiredError') {
    return res.status(401).json({ message: 'Token expirado' });
  }
  
  // Multer errors
  if (error.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ message: 'Arquivo muito grande' });
  }
  
  // Default error response
  res.status(500).json({ 
    message: 'Erro interno do servidor',
    ...(process.env.NODE_ENV === 'development' && { error: error.message })
  });
});

// =============================================================================
// SERVER STARTUP
// =============================================================================

const startServer = async () => {
  try {
    // Initialize database
    await initializeDatabase();
    
    // Start server
    app.listen(PORT, '0.0.0.0', () => {
      console.log('🚀 Server running on port', PORT);
      console.log('🌍 Environment:', process.env.NODE_ENV || 'development');
      console.log('💾 Database:', process.env.DATABASE_URL ? 'Connected' : 'Local');
      console.log('💳 MercadoPago:', mercadoPagoClient ? 'Configured' : 'Not configured');
      console.log('☁️ Cloudinary:', process.env.CLOUDINARY_CLOUD_NAME ? 'Configured' : 'Not configured');
      console.log('🔐 JWT Secret:', process.env.JWT_SECRET ? 'Set' : 'Using default');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully');
  process.exit(0);
});

// Start the server
startServer();