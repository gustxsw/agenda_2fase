const express = require('express');
const { MercadoPagoConfig, Preference } = require('mercadopago');
const { pool } = require('../db');
const { authenticate, authorize } = require('../middleware/auth');

const router = express.Router();

// Initialize MercadoPago with SDK v2
const client = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN || 'TEST-your-access-token',
  options: {
    timeout: 5000,
    idempotencyKey: 'abc'
  }
});

// Create subscription payment for clients
router.post('/create-subscription', authenticate, authorize(['client']), async (req, res) => {
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

    const preference = new Preference(client);

    const items = [
      {
        title: 'Assinatura Cartão Quiro Ferreira - Titular',
        description: 'Assinatura mensal do cartão de convênio',
        quantity: 1,
        unit_price: basePrice,
        currency_id: 'BRL',
      }
    ];

    // Add dependent items if any
    if (dependentCount > 0) {
      items.push({
        title: `Dependentes (${dependentCount})`,
        description: 'Taxa adicional por dependente',
        quantity: dependentCount,
        unit_price: dependentPrice,
        currency_id: 'BRL',
      });
    }

    const preferenceData = {
      items,
      payer: {
        name: req.user.name,
        email: req.user.email || `client${req.user.id}@quiroferreira.com.br`,
      },
      back_urls: {
        success: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client/payment-success`,
        failure: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client/payment-failure`,
        pending: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/client/payment-pending`,
      },
      auto_return: 'approved',
      external_reference: `subscription_${req.user.id}_${Date.now()}`,
      notification_url: `${process.env.API_URL || 'http://localhost:3001'}/api/payment/webhook`,
      statement_descriptor: 'QUIRO FERREIRA',
      expires: true,
      expiration_date_from: new Date().toISOString(),
      expiration_date_to: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hours
    };

    console.log('🔄 Creating MercadoPago preference with SDK v2:', preferenceData);

    const result = await preference.create({ body: preferenceData });

    console.log('✅ MercadoPago preference created:', result);

    // Store the payment intent in database
    await pool.query(
      `INSERT INTO client_payments 
       (client_id, mp_preference_id, amount, status, external_reference, dependent_count)
       VALUES ($1, $2, $3, 'pending', $4, $5)`,
      [req.user.id, result.id, totalAmount, preferenceData.external_reference, dependentCount]
    );

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point,
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
router.post('/create-professional-payment', authenticate, authorize(['professional']), async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valor inválido' });
    }

    console.log('🔄 Creating professional payment for:', req.user.id, 'Amount:', amount);

    const preference = new Preference(client);

    const preferenceData = {
      items: [
        {
          title: 'Repasse ao Convênio Quiro Ferreira',
          description: 'Pagamento referente às consultas realizadas',
          quantity: 1,
          unit_price: Number(amount),
          currency_id: 'BRL',
        }
      ],
      payer: {
        name: req.user.name,
        email: req.user.email || `professional${req.user.id}@quiroferreira.com.br`,
      },
      back_urls: {
        success: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/payment-success`,
        failure: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/payment-failure`,
        pending: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/professional/payment-pending`,
      },
      auto_return: 'approved',
      external_reference: `professional_${req.user.id}_${Date.now()}`,
      notification_url: `${process.env.API_URL || 'http://localhost:3001'}/api/payment/webhook`,
      statement_descriptor: 'QUIRO FERREIRA REPASSE',
    };

    const result = await preference.create({ body: preferenceData });

    // Store the payment intent in database
    await pool.query(
      `INSERT INTO professional_payments 
       (professional_id, mp_preference_id, amount, status, external_reference)
       VALUES ($1, $2, $3, 'pending', $4)`,
      [req.user.id, result.id, amount, preferenceData.external_reference]
    );

    res.json({
      preference_id: result.id,
      init_point: result.init_point,
      sandbox_init_point: result.sandbox_init_point,
    });
  } catch (error) {
    console.error('❌ Error creating professional payment:', error);
    res.status(500).json({ 
      message: 'Erro ao criar pagamento',
      error: error.message 
    });
  }
});

// Handle MercadoPago webhook
router.post('/webhook', async (req, res) => {
  try {
    console.log('🔔 Payment webhook received:', req.body);

    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;
      
      // In production, you would verify the payment with MercadoPago API
      // For MVP, we'll simulate payment approval
      
      // Find the payment record by external_reference or other identifier
      // This is a simplified version - in production you'd need proper payment verification
      
      console.log('✅ Payment webhook processed for payment ID:', paymentId);
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error('❌ Error processing payment webhook:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Get payment status
router.get('/status/:external_reference', authenticate, async (req, res) => {
  try {
    const { external_reference } = req.params;

    // Check client payments
    const clientPayment = await pool.query(
      `SELECT * FROM client_payments WHERE external_reference = $1`,
      [external_reference]
    );

    if (clientPayment.rows.length > 0) {
      return res.json(clientPayment.rows[0]);
    }

    // Check professional payments
    const professionalPayment = await pool.query(
      `SELECT * FROM professional_payments WHERE external_reference = $1`,
      [external_reference]
    );

    if (professionalPayment.rows.length > 0) {
      return res.json(professionalPayment.rows[0]);
    }

    res.status(404).json({ message: 'Pagamento não encontrado' });
  } catch (error) {
    console.error('Error fetching payment status:', error);
    res.status(500).json({ message: 'Erro interno do servidor' });
  }
});

module.exports = router;